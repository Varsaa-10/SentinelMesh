"""Track B (detector-independent retrieval): input schema, query builder and leakage auditor. (M1, remediation item 1)

Track B input schema  (the ONLY things a method may see):
    source  : "falco" | "log-tail"                (kind of sensor, not which detector)
    event   : the sensor's own observed fields, minus the exclusions below
Excluded on purpose:
    title, scenario, chain_id, component_scenario, rule names, detector ids, registered ATT&CK ids   (detector identity / labels)
    detector-added annotations (failure_count, window_seconds)                                       (reveal the detector's threshold logic)
    the Falco rule's `output:` template text                                                         (detector-authored description)
    sensor noise (timestamps, container/pod ids, image tag)                                          (no evidence value)
The knowledge base for Track B must contain no detector-derived or lab-written signature for the covered techniques.
RESIDUAL LEAKAGE (cannot be removed): the *set of field names* an alert carries is itself a fingerprint of the detector that emitted it.
leakage_audit.json quantifies this with a key-names-only classifier.
"""
from __future__ import annotations
import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Sequence

FORBIDDEN_ALERT_KEYS = {"title", "scenario", "chain_id", "component_scenario", "rule", "detector", "detector_ref", "technique_id", "technique",
                        "ground_truth", "truth", "slot", "scenario_id", "severity"}
DETECTOR_ANNOTATION_KEYS = {"failure_count", "window_seconds"}
NOISE_KEYS = {"timestamp", "evt.time", "container.id", "container.image.repository", "container.image.tag", "k8s.ns.name", "k8s.pod.name"}
_SCEN = re.compile(r"\bS(?:10|[1-9])\b")
_TECH = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")


class LeakageError(ValueError):
    pass


def _flat(prefix: str, v: Any, out: List):
    if isinstance(v, dict):
        for k, x in v.items():
            _flat(f"{prefix}.{k}" if prefix else k, x, out)
    else:
        out.append((prefix, v))


def independent_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitised alert: source + filtered event only."""
    ev = {k: v for k, v in (alert.get("event") or {}).items() if k not in NOISE_KEYS | DETECTOR_ANNOTATION_KEYS | FORBIDDEN_ALERT_KEYS}
    return {"source": alert.get("source", ""), "event": ev}


def build_independent_query(alert: Dict[str, Any]) -> str:
    a = independent_alert(alert)
    if "raw_log_line" in a["event"]:
        return str(a["event"]["raw_log_line"])
    pairs: List = []
    for k, v in a["event"].items():
        _flat(k, v, pairs)
    return ", ".join(f"{k}={v}" for k, v in pairs)


def forbidden_phrases(detector_titles: Iterable[str], templates: Iterable[str]) -> List[str]:
    out = {t.strip().lower() for t in detector_titles if t and len(t.strip()) > 6}
    for t in templates:                                  # static prefix of the Falco output template (text before the first '(')
        head = t.split("(")[0].strip().lower()
        if len(head) > 6:
            out.add(head)
    return sorted(out)


def leakage_scan(text: str, phrases: Sequence[str] = ()) -> List[str]:
    """Return the list of leaked items found in a Track B query string (empty = clean)."""
    found = [f"scenario_id:{m}" for m in _SCEN.findall(text)] + [f"technique_id:{m}" for m in _TECH.findall(text)]
    low = text.lower()
    found += [f"detector_phrase:{p}" for p in phrases if p in low]
    found += [f"annotation_key:{k}" for k in DETECTOR_ANNOTATION_KEYS if re.search(rf"\b{k}\b", low)]
    return found


def assert_query_clean(text: str, phrases: Sequence[str] = ()) -> None:
    f = leakage_scan(text, phrases)
    if f:
        raise LeakageError(f"Track B query contains target/detector information: {f}")


def assert_alert_clean(alert: Dict[str, Any]) -> None:
    bad = sorted(set(alert) - {"source", "event"})
    bad += sorted(k for k in (alert.get("event") or {}) if k in FORBIDDEN_ALERT_KEYS | DETECTOR_ANNOTATION_KEYS)
    if bad:
        raise LeakageError(f"Track B alert carries forbidden keys: {bad}")


def assert_kb_clean(raw_records: Sequence[Dict[str, Any]], baseline_records: Sequence[Dict[str, Any]]) -> None:
    """KB records for Track B must be byte-identical (signatures + description) to the unmodified ATT&CK corpus."""
    base = {r["id"]: r for r in baseline_records}
    for r in raw_records:
        sigs = json.dumps(r.get("detection_signatures"), sort_keys=True)
        if "detector_ref" in sigs or '"generated"' in sigs:
            raise LeakageError(f"{r['id']}: detector-derived signature present in Track B knowledge base")
        b = base.get(r["id"])
        if b is None:
            raise LeakageError(f"{r['id']}: not in baseline corpus")
        if json.dumps(r.get("detection_signatures"), sort_keys=True) != json.dumps(b.get("detection_signatures"), sort_keys=True) \
                or r.get("description") != b.get("description"):
            raise LeakageError(f"{r['id']}: record differs from unmodified ATT&CK corpus (lab/detector knowledge injected)")


def input_schema_hash() -> str:
    return hashlib.sha256(json.dumps({"forbidden": sorted(FORBIDDEN_ALERT_KEYS), "annot": sorted(DETECTOR_ANNOTATION_KEYS), "noise": sorted(NOISE_KEYS)}).encode()).hexdigest()[:16]
