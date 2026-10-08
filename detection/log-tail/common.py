import json
import sys
import urllib.request
from datetime import datetime, timezone

POST_URL = None


def set_post_url(url):
    global POST_URL
    POST_URL = url


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit_alert(scenario, severity, title, service, event):
    """
    scenario: "S1".."S4"
    severity: "WARNING" or "CRITICAL"
    title:    human-readable rule name
    service:  app service name
    event:    the raw or annotated event dict
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

    if POST_URL:
        try:
            req = urllib.request.Request(
                POST_URL,
                data=json.dumps(alert).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass
        except Exception as exc:
            print(f"[common.py] WARNING: failed to POST alert to {POST_URL}: {exc}", file=sys.stderr)

    return alert
