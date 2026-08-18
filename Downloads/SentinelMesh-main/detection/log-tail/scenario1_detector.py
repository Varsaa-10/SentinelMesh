"""
scenario1_detector.py — SQL Injection Authentication Bypass (S1)

Fixes issue #2 from review: the original only checked `event["username"]`
for SQLi syntax, which assumes Person 1 logs the payload under that exact
field name. Checking several plausible field names instead, since we
don't yet have written confirmation of the exact logging shape — ASK
PERSON 1 which field(s) actually carry the raw request payload, and trim
this list once confirmed.
"""
import re

from common import emit_alert

SQLI_PATTERN = re.compile(r"('|--|;|\bOR\b|\bUNION\b|\bAND\b\s+\d+\s*=\s*\d+)", re.IGNORECASE)
CANDIDATE_FIELDS = ("username", "payload", "request", "query", "body", "identifier")


def check(event, service):
    # Confirmed against live webapp_events.log (2026-08-05): the app emits
    # "event_type", not "event". Checking both so this keeps working if
    # authservice or a future service ever uses the other key.
    event_name = event.get("event_type") or event.get("event")
    if event_name != "login_attempt":
        return None
    if event.get("result") != "success":
        return None

    for field in CANDIDATE_FIELDS:
        value = event.get(field)
        if isinstance(value, str) and SQLI_PATTERN.search(value):
            return emit_alert(
                scenario="S1",
                severity="CRITICAL",
                title="SQL Injection Authentication Bypass",
                service=service,
                event=event,
            )
    return None
