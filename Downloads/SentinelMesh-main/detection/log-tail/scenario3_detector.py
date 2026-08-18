"""
scenario3_detector.py — Default Credentials (S3)

Fixes issue #4 from review: `username == "admin"` alone would flag every
legitimate admin login, not just the default-credential one. Prefers an
explicit signal from the app (`default_credentials: true` or
`auth_method: "default_credentials"`). Falls back to the bare username
check ONLY if neither field is present — and marks that alert's title as
"unconfirmed" so it's visibly lower-confidence to whoever/whatever
consumes it (including the risk-scoring layer later in the pipeline).

LIMITATION: if Person 1 never adds either field, this detector cannot
tell a legitimate admin login from a default-credential one. That's
documented here rather than silently over-alerting without a caveat.
"""
from common import emit_alert

DEFAULT_USERNAMES = {"admin"}


def check(event, service):
    # Confirmed against live webapp_events.log (2026-08-05): real key is
    # "event_type" (not "event"); checking both defensively.
    event_name = event.get("event_type") or event.get("event")
    if event_name != "login_attempt":
        return None
    if event.get("result") != "success":
        return None

    username = event.get("identifier") or event.get("username") or event.get("user")
    if username not in DEFAULT_USERNAMES:
        return None

    explicit_flag = (
        event.get("default_credentials") is True
        or event.get("auth_method") == "default_credentials"
    )

    title = "Default Credential Login"
    if not explicit_flag:
        title += " (unconfirmed — username=admin only, no explicit default_credentials flag from app)"

    return emit_alert(
        scenario="S3",
        severity="WARNING",
        title=title,
        service=service,
        event=event,
    )
