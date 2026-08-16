"""
scenario4_detector.py — JWT Algorithm Confusion (S4)

Expanded the keyword match per review point #5: originally only checked
for "algorithm" in the reason field; added alg/hs256/rs256 as additional
signals in case Person 1's log message wording varies.

UPDATED after confirming the real attack against live authservice
(2026-08-05): the actual CVE-2022-29217 exploit isn't a *rejected*
verification with "algorithm" mentioned in an error string — it's a
*successful* one. authservice's vulnerable code accepts alg="none" and
treats it as result="valid", details={"algorithm": "none", ...}. A
successfully-verified token using an unsafe algorithm IS the compromise;
there's no exception or error text to pattern-match against at all. The
original keyword/reason check is kept as a fallback in case some other
service logs a rejected-algorithm-confusion attempt differently.
"""
import re

from common import emit_alert

ALGO_KEYWORDS = re.compile(r"(algorithm|\balg\b|hs256|rs256)", re.IGNORECASE)
UNSAFE_ALGORITHMS = {"none"}


def check(event, service):
    # Confirmed against live webapp_events.log (2026-08-05): real key is
    # "event_type" (not "event").
    event_name = event.get("event_type") or event.get("event")
    if event_name != "jwt_verification":
        return None

    details = event.get("details") or {}
    algorithm = details.get("algorithm") if isinstance(details, dict) else None

    # Primary signal, confirmed against a real exploit run: a token that
    # verified successfully using an unsafe algorithm (e.g. "none").
    if event.get("result") == "valid" and isinstance(algorithm, str) and algorithm.lower() in UNSAFE_ALGORITHMS:
        return emit_alert(
            scenario="S4",
            severity="CRITICAL",
            title="JWT Algorithm Confusion",
            service=service,
            event=event,
        )

    # Fallback: free-text reason field, for compatibility with any service
    # that logs a rejected algorithm-confusion attempt as an error string
    # instead of a successful-verification record.
    reason = event.get("reason")
    if not isinstance(reason, str):
        reason = details.get("reason", "") if isinstance(details, dict) else ""
    if isinstance(reason, str) and ALGO_KEYWORDS.search(reason):
        return emit_alert(
            scenario="S4",
            severity="CRITICAL",
            title="JWT Algorithm Confusion",
            service=service,
            event=event,
        )
    return None
