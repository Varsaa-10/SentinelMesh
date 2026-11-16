"""Pure alert attribution logic for SentinelMesh ENV2 captures.

Rules (docs/PLAN_ENV2.md):
- An alert inside a scenario window X is attributed to X as:
  - attribution="attack" if it comes from X's target container;
  - attribution="attack_collateral" if it comes from another lab container, from a
    non-lab container that is not "host" (e.g. a helper container), or from the
    host when proc.cmdline or proc.pcmdline contains "attack_scripts/";
  - any other host alert in a window stays "unattributed".
- If an attributed alert inside a window also falls within +/-2 s of a benign
  action on the same container, it is marked attribution="ambiguous" while
  keeping both candidate labels.
- Outside every scenario window, an alert within +/-2 s of a benign action on the
  same container is marked attribution="benign" and counted as a false positive.
- Alerts matching grafana_setup within +/-2 s on dashboard get attribution="setup"
  and are neither attack nor false positive.
- Otherwise an alert outside scenario windows is marked "unattributed".
- An attributed alert keeps X's ground_truth_technique from
  eval/ground_truth.json alongside rule_technique (the firing rule's own
  ATT&CK technique) and designated_rule (whether the firing rule matches X's
  detection.rule_name / expected_title).
- Every alert emitted during a benign-only capture (except setup) is marked as a
  false positive.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ATTCK_TAG_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DEFAULT_BENIGN_TOLERANCE_SECONDS = 2.0
NON_BENIGN_LOG_ACTIONS = frozenset({"pause", "resume"})
ATTRIBUTION_VALUES = (
    "attack",
    "attack_collateral",
    "ambiguous",
    "benign",
    "setup",
    "unattributed",
)


def parse_utc_timestamp(ts: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string or datetime into a UTC datetime."""
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if not isinstance(ts, str) or not ts.strip():
        return None
    raw = ts.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_container(name: Any, allow_host: bool = False) -> str:
    if not name or not isinstance(name, str):
        return ""
    cleaned = name.strip()
    if not cleaned or cleaned in ("<NA>", "unknown"):
        return ""
    if cleaned == "host" and not allow_host:
        return ""
    if cleaned.startswith("sentinelmesh-"):
        return cleaned[len("sentinelmesh-"):]
    return cleaned


def alert_container_name(alert: Mapping[str, Any]) -> str:
    """Extract the source container/service identifier from a normalized alert."""
    event = alert.get("event")
    if isinstance(event, Mapping):
        cname = event.get("container.name")
        if cname and cname != "<NA>":
            return str(cname).strip()
    if alert.get("container"):
        return str(alert["container"]).strip()
    service = alert.get("service")
    if service and service != "unknown":
        return str(service).strip()
    return ""


def container_matches_target(alert_container: Any, target_container: Any) -> bool:
    """Check whether an alert's container matches any target in ground truth."""
    norm_alert = _normalize_container(alert_container)
    if not norm_alert or not target_container:
        return False
    targets = [_normalize_container(part) for part in str(target_container).split(",")]
    return norm_alert in {t for t in targets if t}


def _containers_match_benign(alert_container: Any, action_container: Any) -> bool:
    """Compare container/host labels between an alert and a benign action entry."""
    norm_alert = _normalize_container(alert_container, allow_host=True)
    norm_action = _normalize_container(action_container, allow_host=True)
    return bool(norm_alert and norm_action and norm_alert == norm_action)


def extract_falco_technique(alert: Mapping[str, Any]) -> Optional[str]:
    """Return the first MITRE ATT&CK technique ID from falco_tags, if any."""
    tags = alert.get("falco_tags")
    if tags is None and isinstance(alert.get("event"), Mapping):
        tags = alert["event"].get("tags")
    for tag in tags or []:
        tag_str = str(tag).strip()
        if ATTCK_TAG_RE.match(tag_str):
            return tag_str
    return None


def _is_attack_script_host_alert(alert: Mapping[str, Any]) -> bool:
    """Return True when proc.cmdline or proc.pcmdline references attack_scripts/."""
    event = alert.get("event")
    candidates: List[Any] = [alert.get("proc.cmdline"), alert.get("proc.pcmdline")]
    if isinstance(event, Mapping):
        candidates.extend([event.get("proc.cmdline"), event.get("proc.pcmdline")])
    return any(isinstance(val, str) and "attack_scripts/" in val for val in candidates)


def _rule_matches_spec(alert: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    """Check whether an alert's title matches a scenario's detection rule_name or expected_title."""
    title = str(alert.get("title", ""))
    if not title or not isinstance(spec, Mapping):
        return False
    det = spec.get("detection")
    if not isinstance(det, Mapping):
        return False
    rule_name = det.get("rule_name")
    expected_title = det.get("expected_title")
    if rule_name and title == rule_name:
        return True
    if expected_title and title.startswith(expected_title):
        return True
    return False


def infer_rule_technique(
    alert: Mapping[str, Any],
    scenarios: Mapping[str, Any],
) -> Optional[str]:
    """Determine the firing rule's own ATT&CK technique ID.

    - Stock Falco rules: first ATT&CK technique tag (Txxxx / Txxxx.xxx).
    - Lab detectors (s05-s09 Falco rules, log-tail, Grafana detector):
      technique_id of the lab scenario whose detection.rule_name or
      expected_title matches the alert (falling back to log-tail scenario for
      multi-title lab detectors such as S7 anonymous dashboard access).
    """
    falco_tech = extract_falco_technique(alert)
    if falco_tech is not None:
        return falco_tech

    ordered_lab = [
        (sid, spec)
        for sid, spec in sorted(scenarios.items())
        if sid != "S10"
        and isinstance(spec, Mapping)
        and isinstance(spec.get("detection"), Mapping)
        and spec["detection"].get("source") != "falco-stock"
    ]

    title = str(alert.get("title", ""))
    if title:
        for _sid, spec in ordered_lab:
            rule_name = spec["detection"].get("rule_name")
            if rule_name and title == rule_name:
                return spec.get("technique_id")
        for _sid, spec in ordered_lab:
            expected_title = spec["detection"].get("expected_title")
            if expected_title and title.startswith(expected_title):
                return spec.get("technique_id")

    if alert.get("source") == "log-tail":
        scen_id = alert.get("scenario")
        for sid, spec in ordered_lab:
            if sid == scen_id:
                return spec.get("technique_id")

    return None


def is_designated_rule(
    alert: Mapping[str, Any],
    scenario_id: Optional[str],
    scenarios: Mapping[str, Any],
) -> bool:
    """Return True when the alert's rule is scenario_id's designated rule."""
    if not scenario_id or scenario_id == "unattributed":
        return False
    spec = scenarios.get(scenario_id)
    if not isinstance(spec, Mapping):
        return False
    if scenario_id == "S10":
        det = spec.get("detection")
        stages = det.get("expected_alerts_in_order") if isinstance(det, Mapping) else None
        stages = stages or []
        comp_sid = alert.get("component_scenario")
        if comp_sid in stages:
            comp_spec = scenarios.get(comp_sid)
            return isinstance(comp_spec, Mapping) and _rule_matches_spec(alert, comp_spec)
        return any(
            isinstance(scenarios.get(st), Mapping) and _rule_matches_spec(alert, scenarios[st])
            for st in stages
        )
    return _rule_matches_spec(alert, spec)


def _windows_at(
    alert_ts: datetime,
    scenario_windows: Mapping[str, Mapping[str, Any]],
    scenarios: Mapping[str, Any],
) -> List[Tuple[str, Mapping[str, Any]]]:
    ordered_windows = sorted(
        scenario_windows.items(),
        key=lambda item: (str((item[1] or {}).get("start", "")), item[0]),
    )
    hits: List[Tuple[str, Mapping[str, Any]]] = []
    for sid, win in ordered_windows:
        if not isinstance(win, Mapping):
            continue
        start_dt = parse_utc_timestamp(win.get("start"))
        end_dt = parse_utc_timestamp(win.get("end"))
        if start_dt is None or end_dt is None:
            continue
        if not (start_dt <= alert_ts <= end_dt):
            continue
        spec = scenarios.get(sid)
        if not isinstance(spec, Mapping):
            continue
        hits.append((sid, spec))
    return hits


def _match_benign_actions(
    alert_ts: datetime,
    alert_cont: str,
    benign_actions: Optional[Sequence[Mapping[str, Any]]],
    tolerance_seconds: float,
) -> List[Dict[str, Any]]:
    if not benign_actions:
        return []
    tol = timedelta(seconds=tolerance_seconds)
    matches: List[Dict[str, Any]] = []
    for entry in benign_actions:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("action") in NON_BENIGN_LOG_ACTIONS:
            continue
        b_start = parse_utc_timestamp(entry.get("start"))
        b_end = parse_utc_timestamp(entry.get("end"))
        if b_start is None and b_end is None:
            continue
        b_start = b_start or b_end
        b_end = b_end or b_start
        if not ((b_start - tol) <= alert_ts <= (b_end + tol)):
            continue
        if _containers_match_benign(alert_cont, entry.get("container")):
            matches.append(
                {
                    "action": entry.get("action"),
                    "container": entry.get("container"),
                    "start": entry.get("start"),
                    "end": entry.get("end"),
                }
            )
    return matches


def attribute_alert(
    alert: Mapping[str, Any],
    scenario_windows: Mapping[str, Mapping[str, Any]],
    ground_truth: Mapping[str, Any],
    benign_only: bool = False,
    benign_actions: Optional[Sequence[Mapping[str, Any]]] = None,
    benign_tolerance_seconds: float = DEFAULT_BENIGN_TOLERANCE_SECONDS,
) -> Dict[str, Any]:
    """Return a copy of `alert` annotated with scenario & technique attribution.

    Pure function: never mutates `alert`, `scenario_windows`, `ground_truth`,
    or `benign_actions`.
    """
    out = dict(alert)
    falco_technique = extract_falco_technique(out)
    out["falco_technique"] = falco_technique

    scenarios = ground_truth.get("scenarios", ground_truth)
    out["rule_technique"] = infer_rule_technique(out, scenarios)

    alert_ts = parse_utc_timestamp(out.get("timestamp"))
    alert_cont = alert_container_name(out)
    matched_actions: List[Dict[str, Any]] = []
    if alert_ts is not None and alert_cont:
        matched_actions = _match_benign_actions(
            alert_ts, alert_cont, benign_actions, benign_tolerance_seconds
        )

    matched_setup = [b for b in matched_actions if b.get("action") == "grafana_setup"]
    if matched_setup:
        out["attribution"] = "setup"
        out["attributed_scenario"] = "unattributed"
        out["ground_truth_technique"] = None
        out["designated_rule"] = False
        out["false_positive"] = False
        out["benign_action"] = "grafana_setup"
        out["benign_actions"] = [b["action"] for b in matched_setup if b.get("action")]
        out["candidate_labels"] = {"setup": matched_setup}
        return out

    if benign_only:
        out["attribution"] = "benign"
        out["attributed_scenario"] = "unattributed"
        out["ground_truth_technique"] = None
        out["designated_rule"] = False
        out["false_positive"] = True
        return out

    matched_benign = [b for b in matched_actions if b.get("action") != "grafana_setup"]
    matching_windows = _windows_at(alert_ts, scenario_windows, scenarios) if alert_ts is not None else []

    matched_sid: Optional[str] = None
    base_attribution: Optional[str] = None
    if matching_windows:
        for sid, spec in matching_windows:
            if container_matches_target(alert_cont, spec.get("target_container")):
                matched_sid = sid
                base_attribution = "attack"
                break
        if matched_sid is None:
            norm_cont = _normalize_container(alert_cont, allow_host=True)
            if norm_cont and norm_cont != "host":
                matched_sid = matching_windows[0][0]
                base_attribution = "attack_collateral"
            elif _is_attack_script_host_alert(out):
                matched_sid = matching_windows[0][0]
                base_attribution = "attack_collateral"

    if matched_sid is not None:
        gt_tech = scenarios[matched_sid].get("technique_id")
        out["attributed_scenario"] = matched_sid
        out["ground_truth_technique"] = gt_tech
        out["designated_rule"] = is_designated_rule(out, matched_sid, scenarios)
        out["false_positive"] = False
        if matched_benign:
            out["attribution"] = "ambiguous"
            out["benign_action"] = matched_benign[0].get("action")
            out["benign_actions"] = [b["action"] for b in matched_benign if b.get("action")]
            out["candidate_labels"] = {
                "attack": {"scenario": matched_sid, "technique": gt_tech},
                "benign": matched_benign,
            }
        else:
            out["attribution"] = base_attribution
        return out

    out["attributed_scenario"] = "unattributed"
    out["ground_truth_technique"] = None
    out["designated_rule"] = False
    if matching_windows:
        out["attribution"] = "unattributed"
        out["false_positive"] = False
    elif matched_benign:
        out["attribution"] = "benign"
        out["false_positive"] = True
        out["benign_action"] = matched_benign[0].get("action")
        out["benign_actions"] = [b["action"] for b in matched_benign if b.get("action")]
        out["candidate_labels"] = {"benign": matched_benign}
    else:
        out["attribution"] = "unattributed"
        out["false_positive"] = False
    return out


def attribute_alerts(
    alerts: Sequence[Mapping[str, Any]],
    scenario_windows: Mapping[str, Mapping[str, Any]],
    ground_truth: Mapping[str, Any],
    benign_only: bool = False,
    benign_actions: Optional[Sequence[Mapping[str, Any]]] = None,
    benign_tolerance_seconds: float = DEFAULT_BENIGN_TOLERANCE_SECONDS,
) -> List[Dict[str, Any]]:
    """Pure batch wrapper around `attribute_alert`."""
    return [
        attribute_alert(
            a,
            scenario_windows,
            ground_truth,
            benign_only=benign_only,
            benign_actions=benign_actions,
            benign_tolerance_seconds=benign_tolerance_seconds,
        )
        for a in alerts
    ]


def _summarize_single_view(alerts_view: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    by_scenario: Dict[str, int] = {}
    by_attribution: Dict[str, int] = {k: 0 for k in ATTRIBUTION_VALUES}
    unattributed = 0
    false_positives = 0
    tag_mismatches = 0
    setup_count = 0

    for a in alerts_view:
        att = a.get("attribution") or "unattributed"
        by_attribution[att] = by_attribution.get(att, 0) + 1
        if att == "setup":
            setup_count += 1
        if a.get("false_positive"):
            false_positives += 1
        sid = a.get("attributed_scenario", "unattributed")
        if sid == "unattributed":
            unattributed += 1
        else:
            by_scenario[sid] = by_scenario.get(sid, 0) + 1
            gt_tech = a.get("ground_truth_technique")
            falco_tech = a.get("falco_technique")
            if gt_tech and falco_tech and gt_tech != falco_tech:
                tag_mismatches += 1

    total = len(alerts_view)
    return {
        "total_alerts": total,
        "attributed_count": total - unattributed,
        "unattributed_count": unattributed,
        "setup_count": setup_count,
        "false_positive_count": false_positives,
        "tag_mismatches": tag_mismatches,
        "by_scenario": by_scenario,
        "by_attribution": by_attribution,
    }


def summarize_attribution(attributed_alerts: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Summarize attribution counts, reporting ambiguous alerts excluded and as attack."""
    as_attack = _summarize_single_view(attributed_alerts)
    excluded = _summarize_single_view(
        [a for a in attributed_alerts if a.get("attribution") != "ambiguous"]
    )
    by_att = as_attack["by_attribution"]
    return {
        **as_attack,
        "attack_count": by_att.get("attack", 0),
        "attack_collateral_count": by_att.get("attack_collateral", 0),
        "ambiguous_count": by_att.get("ambiguous", 0),
        "benign_count": by_att.get("benign", 0),
        "setup_count": by_att.get("setup", 0),
        "ambiguous_excluded": excluded,
        "ambiguous_as_attack": as_attack,
    }
