#!/usr/bin/env python3
"""
scenario7_grafana_detector.py — Grafana Default Credentials & Anonymous
Access (S7)

CALIBRATION STATUS: confirmed against real live Grafana output on
2026-08-18 (Grafana grafana/grafana:latest, with GF_LOG_LEVEL=debug,
GF_LOG_MODE=console, GF_SERVER_ROUTER_LOGGING=true set on the container).

WHY THIS IS DIFFERENT FROM scenario1-4_detector.py
----------------------------------------------------
Grafana is a third-party binary — no custom log_security_event() call
was added to it the way Person 1 instrumented webapp/authservice. This
watches Grafana's own stdout logs instead (via `docker logs -f`).

REAL LOG FORMAT (confirmed, not guessed)
------------------------------------------
Grafana does NOT emit a distinct "Successful Login" message in this
version — only a generic per-request "Request Completed" line. Example,
captured live:

    logger=context userId=0 orgId=1 uname= t=... level=info
    msg="Request Completed" method=POST path=/login status=200
    remote_addr=... time_ms=... handler=/login status_source=server

Two important, confirmed-live findings that shaped the detection logic:

1. uname= is EMPTY and userId=0 on this line even for a login request
   that succeeds with the real default admin credentials. Grafana logs
   request context before auth resolves, so the log line can't confirm
   WHICH username logged in — only that POST /login returned 200. This
   detector flags this with an "(unconfirmed)" caveat in the alert
   title, the same honest pattern used by scenario3_detector.py for the
   analogous limitation on the webapp side.

2. The SAME empty-uname/userId=0 signature appears on the anonymous
   GET /api/dashboards/home request. This is actually the correct and
   sufficient signal for anonymous access: if anonymous access were
   NOT enabled, that same unauthenticated GET would return 401/302
   instead of 200. So "GET to a dashboard/API path, status=200, no
   authenticated identity" is real evidence of the vulnerability, not
   an ambiguous signal — confirmed by comparing against
   GF_AUTH_ANONYMOUS_ENABLED=true being set in this environment.

USAGE
-----
    python3 scenario7_grafana_detector.py --container sentinelmesh-dashboard

Requires GF_LOG_LEVEL=debug, GF_LOG_MODE=console, and
GF_SERVER_ROUTER_LOGGING=true set on the dashboard container — without
these, Grafana does not emit "Request Completed" lines at all (confirmed
live: with default settings, docker logs showed zero login/request
lines even after a real successful login and anonymous access).
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from linux_run.lab_env import load_lab_env
except Exception:
    def load_lab_env():
        return {"DASHBOARD_CONTAINER": "sentinelmesh-dashboard"}
try:
    from common import emit_alert
except ImportError:
    def emit_alert(scenario, severity, title, service, event):
        alert = {
            "source": "log-tail",
            "scenario": scenario,
            "severity": severity,
            "title": title,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "service": service,
            "event": event,
        }
        print(json.dumps(alert), flush=True)
        return alert


REQUEST_COMPLETED_RE = re.compile(r'msg="Request Completed"')
LOGIN_POST_200_RE = re.compile(r'method=POST\s+path=/login\s+status=200')
DASHBOARD_GET_200_RE = re.compile(r'method=GET\s+path=(/api/\S*|/d/\S*)\s+status=200')
UNAME_EMPTY_RE = re.compile(r'\buname=\s')  # uname= immediately followed by whitespace = empty value
USERID_ZERO_RE = re.compile(r'\buserId=0\b')


def check_line(line, service="dashboard"):
    """Returns an alert dict if this log line matches a known S7 pattern, else None."""
    if not REQUEST_COMPLETED_RE.search(line):
        return None

    # Successful login POST — can't confirm WHICH username from this log
    # line alone (context is logged pre-auth), so this fires on any
    # successful login, with an explicit caveat, same pattern as S3's
    # "(unconfirmed)" default-credential title.
    if LOGIN_POST_200_RE.search(line):
        return emit_alert(
            scenario="S7",
            severity="WARNING",
            title="Grafana Login Succeeded (unconfirmed — username not visible in this log line; "
                  "default admin/admin credentials used by the attack script)",
            service=service,
            event={"raw_log_line": line.strip()},
        )

    # Anonymous access to a dashboard/API path: succeeded (200) with no
    # authenticated identity (uname empty / userId=0) — only possible
    # because GF_AUTH_ANONYMOUS_ENABLED=true. Without that setting this
    # same request would 401/302 instead.
    if DASHBOARD_GET_200_RE.search(line) and (UNAME_EMPTY_RE.search(line) or USERID_ZERO_RE.search(line)):
        return emit_alert(
            scenario="S7",
            severity="WARNING",
            title="Grafana Anonymous Dashboard Access",
            service=service,
            event={"raw_log_line": line.strip()},
        )

    return None


def follow_docker_logs(container_name):
    cmd = ["docker", "logs", "-f", "--since", "0s", container_name]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            yield line
    finally:
        proc.terminate()


def main():
    lab_env = load_lab_env()
    ap = argparse.ArgumentParser(description="S7 Grafana default-creds / anonymous-access detector")
    ap.add_argument("--container", default=lab_env["DASHBOARD_CONTAINER"])
    ap.add_argument("--service", default="dashboard")
    args = ap.parse_args()

    print(f"[grafana_detector] watching `docker logs -f {args.container}`", file=sys.stderr)
    print(f"[grafana_detector] requires GF_LOG_LEVEL=debug, GF_LOG_MODE=console, "
          f"GF_SERVER_ROUTER_LOGGING=true on the container", file=sys.stderr)

    for line in follow_docker_logs(args.container):
        try:
            check_line(line, service=args.service)
        except Exception as exc:
            print(f"[grafana_detector] ERROR processing line: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
