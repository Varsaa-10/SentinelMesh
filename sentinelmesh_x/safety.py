"""M2: field provenance/trust, abstention and a fail-closed safety gate between retrieval and response.

Design rule: model confidence may only ESCALATE. The legacy formula risk = conf x severity x criticality makes a low-confidence
prediction look low-risk and routes it to `auto`; here confidence is a gate, and the impact tier (severity x criticality at
confidence 1.0) is the floor for the route.
No real action is ever performed by this module: SafeExecutor is a policy-enforcing simulator that records what it would do.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import unicodedata
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from response import risk_scoring as rs  # noqa: E402

TRUSTED, PARTIAL, UNTRUSTED = "trusted", "partial", "untrusted"
# Trust tiers by field name. Justification: Falco fields are observed by the kernel sensor (not writable by the app); the log-tail
# detectors read the application's own log, whose free-text members (username, payload, JWT claims, raw line) are attacker supplied.
# Unknown fields default to UNTRUSTED (fail closed).
_TRUSTED = [r"^container\.name$", r"^proc\.name$", r"^proc\.pname$", r"^fd\.(sport|rip|sip|cip|lport)$", r"^user\.name$", r"^event_type$", r"^result$"]
_PARTIAL = [r"^fd\.name$", r"^client_ip$", r"^service$", r"^details\.(algorithm|role|user_id|authenticated_user_id)$", r"^failure_count$", r"^window_seconds$"]
_NOISE = [r"^timestamp$", r"^evt\.time$", r"^container\.id$", r"^container\.image\..*", r"^k8s\..*"]


def classify_field(path: str) -> str:
    if any(re.match(p, path) for p in _NOISE):
        return "noise"
    if any(re.match(p, path) for p in _TRUSTED):
        return TRUSTED
    if any(re.match(p, path) for p in _PARTIAL):
        return PARTIAL
    return UNTRUSTED


def flatten(ev: Dict[str, Any], prefix: str = "") -> List[Tuple[str, Any]]:
    out = []
    for k, v in ev.items():
        p = f"{prefix}.{k}" if prefix else k
        out += flatten(v, p) if isinstance(v, dict) else [(p, v)]
    return out


def provenance(alert: Dict[str, Any]) -> List[Dict[str, str]]:
    return [{"field": p, "tier": classify_field(p)} for p, _ in flatten(alert.get("event") or {})]


def _set_path(d: Dict, path: str, v: Any):
    parts = path.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = v


def trusted_view(alert: Dict[str, Any], tiers: Sequence[str] = (TRUSTED, PARTIAL)) -> Dict[str, Any]:
    """Copy of the alert containing only fields in `tiers` (untrusted free text removed)."""
    a = {k: v for k, v in alert.items() if k != "event"}
    ev: Dict[str, Any] = {}
    for p, v in flatten(alert.get("event") or {}):
        if classify_field(p) in tiers:
            _set_path(ev, p, v)
    a["event"] = ev
    return a


def sanitise_text(s: Any, max_len: int = 2048) -> str:
    """Normalise untrusted text: NFKC, strip zero-width/control chars, cap length (oversized-input defence)."""
    t = unicodedata.normalize("NFKC", str(s))
    t = "".join(c for c in t if unicodedata.category(c) not in ("Cf", "Cc") or c in "\n\t")
    return t[:max_len]


# ------------------------------------------------------------------------------------------- policy engine
SEV_ORDER = {"auto": 0, "analyst": 1, "admin": 2}
DESTRUCTIVE = {"kill_container"}


@dataclass
class PolicyConfig:
    tau: float = 0.9                  # minimum calibrated confidence for any non-escalated route (tuned on development data only)
    min_field_coverage: float = 0.3   # share of a signature's constraint weight that must be checkable
    require_trusted_support: bool = True


@dataclass
class DecisionInput:
    predicted_technique: Optional[str]
    calibrated_confidence: Optional[float]
    supported_techniques: Sequence[str]
    field_coverage: float = 0.0
    trusted_support: bool = False
    conflict: bool = False
    integrity_ok: bool = True
    retrieval_ok: bool = True
    missing_critical: bool = False
    severity: int = 3
    asset_criticality: int = 3
    requested_action: str = "log_only"
    candidate_severities: Sequence[int] = ()      # severities of the other top-ranked candidates (used only when the decision is uncertain)


@dataclass(frozen=True)
class Decision:
    route: str
    abstain: bool
    automatic_action_permitted: bool
    reasons: Tuple[str, ...]
    requested_action: str
    token: str = ""


_SECRET = secrets.token_bytes(32)      # per-process; a forged/edited Decision cannot carry a valid token


def _tok(route, perm, action, reasons) -> str:
    return hmac.new(_SECRET, json.dumps([route, perm, action, list(reasons)]).encode(), hashlib.sha256).hexdigest()


def decision_valid(d: Decision) -> bool:
    return hmac.compare_digest(d.token, _tok(d.route, d.automatic_action_permitted, d.requested_action, d.reasons))


def impact_route(sev: int, crit: int) -> str:
    return rs.route(rs.compute_risk_score(1.0, sev, crit)["normalized"])


class PolicyEngine:
    def __init__(self, cfg: Optional[PolicyConfig] = None):
        self.cfg = cfg or PolicyConfig()

    def decide(self, x: DecisionInput) -> Decision:
        c = self.cfg
        reasons: List[str] = []
        floor = "auto"
        abstain = False
        if not x.retrieval_ok or x.predicted_technique is None or x.calibrated_confidence is None:
            reasons.append("retrieval_unavailable_or_failed"); floor = "analyst"; abstain = True
        else:
            if not x.integrity_ok:
                reasons.append("knowledge_integrity_failure")
            if x.predicted_technique not in set(x.supported_techniques):
                reasons.append("unknown_or_unsupported_technique"); abstain = True
            if x.missing_critical or x.field_coverage < c.min_field_coverage:
                reasons.append("missing_critical_evidence")
            if x.conflict:
                reasons.append("conflicting_evidence")
            if c.require_trusted_support and not x.trusted_support:
                reasons.append("no_trusted_corroboration")
            if x.calibrated_confidence < c.tau:
                reasons.append("low_calibrated_confidence")
            if reasons:
                floor = "analyst"
        sev = max([x.severity, *x.candidate_severities]) if reasons else x.severity     # uncertain -> assume the worst plausible candidate
        impact = impact_route(sev, x.asset_criticality)
        route = impact if SEV_ORDER[impact] >= SEV_ORDER[floor] else floor
        if x.requested_action in DESTRUCTIVE:
            reasons.append("destructive_action_requires_human_approval")
            route = max(route, "analyst", key=SEV_ORDER.get)
        permitted = route == "auto" and not reasons and x.requested_action not in DESTRUCTIVE
        return Decision(route, abstain, permitted, tuple(reasons), x.requested_action, _tok(route, permitted, x.requested_action, tuple(reasons)))


# ------------------------------------------------------------------------------------------- executor (simulator)
@dataclass
class ExecutionRecord:
    executed: bool
    mode: str
    reason: str
    action: str
    target: str


class SafeExecutor:
    """Independent of retrieval: re-validates the decision token, allowlists, kill switch and approvals. Never performs a real action."""

    def __init__(self, kill_switch: Optional[bool] = None):
        self.kill_switch = rs.KILL_SWITCH_ENABLED if kill_switch is None else kill_switch
        self.log: List[ExecutionRecord] = []

    def execute(self, d: Decision, action: str, target: str, human_approval: Optional[Dict[str, str]] = None) -> ExecutionRecord:
        def rec(ok, reason, mode="dry_run"):
            r = ExecutionRecord(ok, mode, reason, action, target); self.log.append(r); return r
        if not isinstance(d, Decision) or not decision_valid(d):
            return rec(False, "invalid_or_forged_decision")
        if action not in rs.ALLOWED_ACTIONS:
            return rec(False, "action_not_in_allowlist")
        if target not in rs.ALLOWED_TARGETS:
            return rec(False, "target_not_in_allowlist")
        if action != d.requested_action:
            return rec(False, "action_differs_from_decision")
        approved = bool(human_approval and human_approval.get("approver") and human_approval.get("ticket"))
        if action in DESTRUCTIVE and not approved:
            return rec(False, "destructive_action_needs_human_approval")
        if d.route != "auto" and not approved:
            return rec(False, "route_requires_human_review")
        if d.route == "auto" and not d.automatic_action_permitted and not approved:
            return rec(False, "automatic_action_not_permitted")
        if self.kill_switch:
            return rec(False, "kill_switch_enabled_dry_run", "dry_run")
        return rec(False, "simulator_only_no_real_actions", "dry_run")     # even when disarmed this module never acts
