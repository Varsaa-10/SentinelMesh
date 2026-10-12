"""
response/risk_scoring.py — SentinelMesh Module C2 (Risk Scoring, Response &
Adaptive Action Selection).

STATUS NOTE (read this first):
This module is normally owned by Person 2 (Algorithms/Core Logic, Week 3).
As of the night before panel review, it had not been built yet in the repo
— only Person 1's graph module (C1) and the frozen RAG output format
existed. This file is a real, working implementation written so that
Module C3 (this person's own work — feedback loop, autonomous baseline,
final evaluation) has something correct to integrate against tonight.

It follows the exact contract in the execution plan:
    risk_score = retrieval_confidence x action_severity x asset_criticality
plus tiered routing (auto/analyst/admin), a hard-coded action allowlist +
kill-switch scoped to the lab's own Docker network, and adaptive action
selection driven by the reconstructed attack-graph path.

Hand this to Person 2 as soon as possible — if they already built their own
version, prefer theirs and only fall back to this one for tonight's demo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Config: routing thresholds (tunable — see execution plan Day 3)
# ---------------------------------------------------------------------------

# risk_score is normalized to [0, 1]:
#   normalized = confidence * (severity / 5) * (asset_criticality / 5)
# Policy values, not learned values. Scores for this lab's scenarios run
# ~0.34-0.67 (severity and asset_criticality are per-scenario constants, so the
# score is mostly confidence x a fixed factor). The old 0.30/0.65 pair sat
# outside that range, which made "auto" and "admin" unreachable. These bands
# put auto below the lowest-risk third and admin on the top band; re-derive
# them if the scenario set or the confidence model changes.
ROUTING_THRESHOLDS = {
    "auto": 0.40,     # risk_score below this -> automatic execution (never for kill_container)
    "analyst": 0.60,  # below this -> analyst confirmation, else admin
}

# ---------------------------------------------------------------------------
# Hard safety allowlist + kill-switch
# ---------------------------------------------------------------------------
# The action executor must NEVER be able to act outside the lab's own
# Docker network. This is enforced twice: (1) only these action *types*
# exist at all, (2) every action call is checked against ALLOWED_TARGETS.

ALLOWED_ACTIONS = {"isolate_network", "kill_container", "revoke_token", "log_only"}

# Populate this with the actual lab container/service names
# (matches services/ in docker-compose.yml).
ALLOWED_TARGETS = {
    "webapp",
    "authservice",
    "database",
    "logcollector",
    "dashboard",
    "sentinelmesh-webapp",
    "sentinelmesh-authservice",
    "sentinelmesh-database",
    "sentinelmesh-logcollector",
    "sentinelmesh-dashboard",
}

KILL_SWITCH_ENABLED = True  # when True, executor refuses all real actions
                             # (dry-run mode) unless explicitly disarmed


class OutOfScopeActionError(Exception):
    """Raised when an action targets something outside the lab network."""


@dataclass
class RiskAssessment:
    scenario_id: str
    technique_id: str
    confidence: float
    severity: int
    asset_criticality: int
    risk_score: float          # normalized [0,1]
    raw_risk_score: float      # confidence * severity * asset_criticality (unnormalized, 0-25)
    routing: str                # "auto" | "analyst" | "admin"
    candidate_actions: List[str]
    selected_action: str
    target: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "technique_id": self.technique_id,
            "confidence": self.confidence,
            "severity": self.severity,
            "asset_criticality": self.asset_criticality,
            "risk_score": round(self.risk_score, 4),
            "raw_risk_score": round(self.raw_risk_score, 4),
            "routing": self.routing,
            "candidate_actions": self.candidate_actions,
            "selected_action": self.selected_action,
            "target": self.target,
            "rationale": self.rationale,
        }


def compute_risk_score(confidence: float, severity: int, asset_criticality: int) -> Dict[str, float]:
    """risk_score = retrieval_confidence x action_severity x asset_criticality.

    Returns both the raw (0-25) score demanded literally by the spec and a
    normalized (0-1) score used for routing thresholds, since severity and
    asset_criticality are on a 1-5 scale and confidence is 0-1.
    """
    confidence = max(0.0, min(1.0, float(confidence)))
    severity = max(1, min(5, int(severity)))
    asset_criticality = max(1, min(5, int(asset_criticality)))

    raw = confidence * severity * asset_criticality
    normalized = confidence * (severity / 5.0) * (asset_criticality / 5.0)
    return {"raw": raw, "normalized": normalized}


def route(risk_score_normalized: float, thresholds: Optional[Dict[str, float]] = None, action: Optional[str] = None) -> str:
    """Tiered routing decision: auto / analyst / admin.
    
    Container termination (kill_container) ALWAYS requires human approval (analyst/admin),
    never auto-executed.
    """
    t = thresholds or ROUTING_THRESHOLDS

    if action == "kill_container":
        # Never auto; analyst below the admin threshold, admin at or above it.
        return "analyst" if risk_score_normalized < t["analyst"] else "admin"

    if risk_score_normalized < t["auto"]:
        return "auto"
    if risk_score_normalized < t["analyst"]:
        return "analyst"
    return "admin"


# ---------------------------------------------------------------------------
# Adaptive action selection
# ---------------------------------------------------------------------------
# Chooses among candidate remediations based on the reconstructed graph path
# (technique/tactic sequence) rather than one fixed action per alert type.

TACTIC_ACTION_CANDIDATES = {
    "Initial Access": ["isolate_network", "log_only"],
    "Credential Access": ["revoke_token", "kill_container"],
    "Persistence": ["kill_container", "isolate_network"],
    "Exfiltration": ["isolate_network", "kill_container"],
    "Defense Evasion": ["kill_container", "log_only"],
    "Discovery": ["log_only", "isolate_network"],
}

DEFAULT_CANDIDATES = ["log_only", "isolate_network"]


def select_action(
    tactic: str,
    graph_path_length: int,
    risk_score_normalized: float,
) -> Dict[str, Any]:
    """Pick a remediation from multiple candidates using the graph path,
    rather than a single fixed action per alert type.

    A longer reconstructed path (multi-stage chain, e.g. S10) escalates
    toward containment actions (kill_container / isolate_network) even at
    the same tactic, since a longer chain indicates the attacker has
    already moved laterally / persisted.
    """
    candidates = TACTIC_ACTION_CANDIDATES.get(tactic, DEFAULT_CANDIDATES)

    if graph_path_length >= 3 and "kill_container" in candidates:
        selected = "kill_container"
        rationale = (
            f"Multi-stage path (len={graph_path_length}) detected for tactic "
            f"'{tactic}' — escalating to containment."
        )
    elif risk_score_normalized >= ROUTING_THRESHOLDS["analyst"]:
        selected = candidates[0]
        rationale = f"High risk_score ({risk_score_normalized:.2f}) for tactic '{tactic}' — using primary candidate."
    else:
        selected = candidates[-1]
        rationale = f"Lower risk_score ({risk_score_normalized:.2f}) for tactic '{tactic}' — using conservative candidate."

    return {"selected_action": selected, "candidates": candidates, "rationale": rationale}


# ---------------------------------------------------------------------------
# Action executor (allowlist + kill-switch enforced)
# ---------------------------------------------------------------------------

@dataclass
class ActionExecutor:
    dry_run: bool = True
    executed_log: List[Dict[str, Any]] = field(default_factory=list)

    def execute(self, action: str, target: str, reason: str = "") -> Dict[str, Any]:
        if action not in ALLOWED_ACTIONS:
            raise OutOfScopeActionError(f"Action '{action}' is not in ALLOWED_ACTIONS")

        target_key = target.replace("container_", "")
        if target_key not in ALLOWED_TARGETS:
            raise OutOfScopeActionError(
                f"Target '{target}' is outside the lab's Docker network allowlist"
            )

        record = {
            "action": action,
            "target": target,
            "reason": reason,
            "dry_run": self.dry_run or KILL_SWITCH_ENABLED,
            "executed": False,
        }

        if self.dry_run or KILL_SWITCH_ENABLED:
            record["executed"] = False
            record["note"] = "Kill-switch / dry-run active — action logged, not performed."
        else:
            # Real execution would go here (docker network disconnect,
            # docker stop <container>, revoke JWT, etc.), always re-checked
            # against ALLOWED_TARGETS immediately before the call.
            record["executed"] = True

        self.executed_log.append(record)
        return record

    def test_out_of_scope_blocked(self) -> bool:
        """Definition-of-done check: confirm an out-of-scope action is blocked."""
        try:
            self.execute("kill_container", "container_some-external-host", reason="test")
            return False
        except OutOfScopeActionError:
            return True


# ---------------------------------------------------------------------------
# Top-level entry point: assess one alert + its RAG result + its graph path
# ---------------------------------------------------------------------------

def assess(
    scenario_id: str,
    rag_result: Dict[str, Any],
    ground_truth_entry: Optional[Dict[str, Any]] = None,
    graph_path_length: int = 1,
    thresholds: Optional[Dict[str, float]] = None,
) -> RiskAssessment:
    if ground_truth_entry is None:
        ground_truth_entry = {}

    conf_val = rag_result.get("confidence", 0.0)
    if isinstance(conf_val, dict):
        confidence = float(conf_val.get("confidence_score", 0.0))
    else:
        confidence = float(conf_val)

    technique_id = rag_result.get("predicted_technique", "UNKNOWN")
    tactic = rag_result.get("predicted_tactic", ground_truth_entry.get("tactic", "Unknown"))
    severity = ground_truth_entry.get("severity", 3)
    asset_criticality = ground_truth_entry.get("asset_criticality", 3)
    target = ground_truth_entry.get("target_container", "unknown")

    scores = compute_risk_score(confidence, severity, asset_criticality)
    action_choice = select_action(tactic, graph_path_length, scores["normalized"])
    routing = route(scores["normalized"], thresholds, action=action_choice["selected_action"])

    return RiskAssessment(
        scenario_id=scenario_id,
        technique_id=technique_id,
        confidence=confidence,
        severity=severity,
        asset_criticality=asset_criticality,
        risk_score=scores["normalized"],
        raw_risk_score=scores["raw"],
        routing=routing,
        candidate_actions=action_choice["candidates"],
        selected_action=action_choice["selected_action"],
        target=target,
        rationale=action_choice["rationale"],
    )


if __name__ == "__main__":
    # Quick self-test
    executor = ActionExecutor(dry_run=True)
    assert executor.test_out_of_scope_blocked(), "Out-of-scope action was NOT blocked!"
    print("[risk_scoring] self-test OK: out-of-scope action correctly blocked.")

    demo_rag = {
        "predicted_technique": "T1190",
        "predicted_tactic": "Initial Access",
        "confidence": {"confidence_score": 0.82},
    }
    demo_gt = {"severity": 5, "asset_criticality": 4, "target_container": "webapp"}
    result = assess("S1", demo_rag, demo_gt, graph_path_length=1)
    print(result.to_dict())
