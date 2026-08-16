#!/usr/bin/env python3
"""
falco_shim.py — translates Falco's native JSON alert output into the
canonical 7-key alert shape defined in alert-format-spec.md, so Person 3's
harness never has to know Falco's native format exists.

alert-format-spec.md's own "Status" section flagged this as a pending gap
before Day 4/5 integration — this closes it.

USAGE
-----
Falco must be run with `-json` (or `-o json_output=true`) so it emits one
JSON object per line on stdout. Pipe that into this shim:

    sudo falco -json \
        -r detection/falco-rules/s05_db_access.yaml \
        -r detection/falco-rules/s06_log_tamper.yaml \
        -r detection/falco-rules/s07_credential_access.yaml \
        -r detection/falco-rules/s08_exfiltration.yaml \
        | python3 falco_shim.py

Each translated alert is printed to stdout as one JSON line, matching
exactly what common.py's emit_alert() produces for the log-tail detectors
— so downstream consumers (ground_truth.json comparison, dashboards,
Person 3's harness) only ever parse ONE shape regardless of source.

WHY THIS EXISTS (translation gaps this closes)
-----------------------------------------------
Falco's native JSON has none of: "scenario", "source". Its "priority"
field uses Falco's own casing ("Critical"/"Warning"), not the spec's
uppercase ("CRITICAL"/"WARNING"). Its "time" field includes nanosecond
precision and doesn't match common.py's %Y-%m-%dT%H:%M:%SZ format. And
"service" has to be derived from container.name by stripping the
"sentinelmesh-" prefix — Falco has no concept of "service" at all.
"""
import json
import re
import sys
from datetime import datetime, timezone

# Map each rule's tag (per s05-s08 yaml `tags:` lists) to its scenario ID.
# Falco rules tag scenarios as e.g. "s5", "s7-postexploit" — this regex
# pulls the leading digits out of whichever tag matches, so a rule doesn't
# need a hardcoded rule-name -> scenario lookup that silently drifts if a
# rule's `desc:` or title text ever gets edited.
SCENARIO_TAG_RE = re.compile(r"^s(\d+)", re.IGNORECASE)


def scenario_from_tags(tags):
    for tag in tags or []:
        m = SCENARIO_TAG_RE.match(tag)
        if m:
            return f"S{m.group(1)}"
    return "UNKNOWN"


def service_from_container(container_name):
    if not container_name or container_name == "<NA>":
        return "unknown"
    prefix = "sentinelmesh-"
    if container_name.startswith(prefix):
        return container_name[len(prefix):]
    return container_name


def normalize_timestamp(falco_time):
    """
    Falco's `time` field looks like '2026-08-05T04:39:00.453576000Z'
    (nanosecond precision). common.py's now_iso() produces
    '2026-08-05T04:39:00Z' (second precision, no fractional part).
    Truncate to match exactly so both sources are byte-comparable.
    """
    if not falco_time:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        # Strip everything from the '.' (fractional seconds) onward, but
        # keep the trailing 'Z'.
        if "." in falco_time:
            base = falco_time.split(".", 1)[0]
        else:
            base = falco_time.rstrip("Z")
        return base + "Z"
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def translate(falco_alert):
    """
    falco_alert: one parsed JSON object from `falco -json` stdout.
    Returns a dict matching alert-format-spec.md's canonical 7-key shape,
    or None if this isn't a rule-match event (Falco's -json stream can
    include non-alert lines depending on config).
    """
    if "rule" not in falco_alert or "priority" not in falco_alert:
        return None

    output_fields = falco_alert.get("output_fields") or {}
    tags = falco_alert.get("tags") or []

    severity = str(falco_alert.get("priority", "")).upper()
    # Falco's default priority vocabulary includes values like NOTICE,
    # ERROR, EMERGENCY that our rules never actually use (they're only
    # ever CRITICAL or WARNING per s05-s08's `priority:` fields) — but
    # normalize defensively rather than assume.
    if severity not in ("CRITICAL", "WARNING"):
        severity = "CRITICAL" if severity in ("EMERGENCY", "ALERT", "ERROR") else "WARNING"

    container_name = output_fields.get("container.name")

    return {
        "source": "falco",
        "scenario": scenario_from_tags(tags),
        "severity": severity,
        "title": falco_alert.get("rule", "Unknown Falco Rule"),
        "timestamp": normalize_timestamp(falco_alert.get("time")),
        "service": service_from_container(container_name),
        "event": output_fields,
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            falco_alert = json.loads(line)
        except json.JSONDecodeError:
            # Falco can print non-JSON banner/startup lines even with
            # -json set (e.g. before rules finish loading) — skip those
            # rather than crashing the shim.
            print(f"[falco_shim] skipping non-JSON line: {line[:200]}", file=sys.stderr)
            continue

        canonical = translate(falco_alert)
        if canonical is None:
            continue

        print(json.dumps(canonical), flush=True)


if __name__ == "__main__":
    main()
