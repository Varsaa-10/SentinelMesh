"""Pure alert attribution logic for SentinelMesh ENV2 captures.

Rules (docs/PLAN_ENV2.md):
- An alert belongs to scenario X if its timestamp falls within X's recorded
  window and its container matches X's target container.
- If it also falls within +/-2 s of a benign action on the same container, it is
  marked attribution="ambiguous" while keeping both candidate labels.
- Outside every scenario window, an alert within +/-2 s of a benign action on the
  same container is marked attribution="benign" and counted as a false positive.
- Otherwise an alert outside scenario windows is marked "unattributed".
- An attributed alert receives X's ground-truth technique from
  eval/ground_truth.json while keeping any Falco ATT&CK tag separately for
  comparison.
- Every alert emitted during a benign-only capture is marked as a false positive.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

ATTCK_TAG_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DEFAULT_BENIGN_TOLERANCE_SECONDS = 2.0


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


def _match_scenario_window(
    alert_ts: datetime,
    alert_cont: str,
    scenario_windows: Mapping[str, Mapping[str, Any]],
    scenarios: Mapping[str, Any],
) -> Optional[str]:
    ordered_windows = sorted(
        scenario_windows.items(),
        key=lambda item: (str((item[1] or {}).get("start", "")), item[0]),
    )
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
        if container_matches_target(alert_cont, spec.get("target_container")):
            return sid
    return None


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

    if benign_only:
        out["attribution"] = "benign"
        out["attributed_scenario"] = "unattributed"
        out["ground_truth_technique"] = None
        out["false_positive"] = True
        return out

    scenarios = ground_truth.get("scenarios", ground_truth)
    alert_ts = parse_utc_timestamp(out.get("timestamp"))
    alert_cont = alert_container_name(out)

    matched_sid: Optional[str] = None
    matched_benign: List[Dict[str, Any]] = []
    if alert_ts is not None and alert_cont:
        matched_sid = _match_scenario_window(alert_ts, alert_cont, scenario_windows, scenarios)
        matched_benign = _match_benign_actions(
            alert_ts, alert_cont, benign_actions, benign_tolerance_seconds
        )

    if matched_sid is not None:
        gt_tech = scenarios[matched_sid].get("technique_id")
        out["attributed_scenario"] = matched_sid
        out["ground_truth_technique"] = gt_tech
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
            out["attribution"] = "attack"
        return out

    out["attributed_scenario"] = "unattributed"
    out["ground_truth_technique"] = None
    if matched_benign:
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
    unattributed = 0
    false_positives = 0
    tag_mismatches = 0

    for a in alerts_view:
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
        "false_positive_count": false_positives,
        "tag_mismatches": tag_mismatches,
        "by_scenario": by_scenario,
    }


def summarize_attribution(attributed_alerts: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Summarize attribution counts, reporting ambiguous alerts excluded and as attack."""
    as_attack = _summarize_single_view(attributed_alerts)
    excluded = _summarize_single_view(
        [a for a in attributed_alerts if a.get("attribution") != "ambiguous"]
    )
    return {
        **as_attack,
        "attack_count": sum(1 for a in attributed_alerts if a.get("attribution") == "attack"),
        "ambiguous_count": sum(1 for a in attributed_alerts if a.get("attribution") == "ambiguous"),
        "benign_count": sum(1 for a in attributed_alerts if a.get("attribution") == "benign"),
        "ambiguous_excluded": excluded,
        "ambiguous_as_attack": as_attack,
    }
