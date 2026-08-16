"""
scenario2_detector.py — Brute-Force Login (S2)

Adds the bounded-history fix from review point #3: history per key is
capped at MAX_HISTORY regardless of window, so a long-running tailer
doesn't grow memory unboundedly against a key that never gets a legitimate
success to reset it.
"""
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from common import emit_alert

WINDOW_SECONDS = 30
THRESHOLD = 5
MAX_HISTORY = 20

_history = defaultdict(deque)


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return time.time()


def check(event, service):
    # Confirmed against live webapp_events.log (2026-08-05): real keys are
    # "event_type" (not "event") and result="failure" (not "fail").
    # Checking both spellings defensively in case another service differs.
    event_name = event.get("event_type") or event.get("event")
    if event_name != "login_attempt":
        return None
    if event.get("result") not in ("fail", "failure"):
        return None

    key_id = event.get("identifier") or event.get("username") or event.get("user") or event.get("ip")
    if not key_id:
        return None

    ts_epoch = _parse_ts(event.get("timestamp") or event.get("ts"))
    key = (service, key_id)
    dq = _history[key]
    dq.append(ts_epoch)

    while len(dq) > MAX_HISTORY:
        dq.popleft()

    cutoff = ts_epoch - WINDOW_SECONDS
    while dq and dq[0] < cutoff:
        dq.popleft()

    if len(dq) >= THRESHOLD:
        return emit_alert(
            scenario="S2",
            severity="WARNING",
            title="Brute-Force Login Attempt",
            service=service,
            event={**event, "failure_count": len(dq), "window_seconds": WINDOW_SECONDS},
        )
    return None
