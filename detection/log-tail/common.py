"""
common.py — shared alert emission, ONE consistent format across all detectors.

Fixes issue #7 from review: each detector was previously returning a
differently-shaped dict (S1 had source/scenario/severity/title/event, S2
had attempts/ip, S3 had just user). Person 3's harness needs one shape,
not four.
"""
import json
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit_alert(scenario, severity, title, service, event):
    """
    scenario: "S1".."S4"
    severity: "WARNING" or "CRITICAL" (matches Falco's own priority naming,
              so Person 3 doesn't need two severity vocabularies)
    title:    human-readable rule name
    service:  which app service the event came from (webapp, authservice, ...)
    event:    the raw (or lightly-annotated) source event, kept for traceability
    """
    alert = {
        "source": "log-tail",
        "scenario": scenario,
        "severity": severity,
        "title": title,
        "timestamp": now_iso(),
        "service": service,
        "event": event,
    }
    print(json.dumps(alert), flush=True)
    return alert
