#!/usr/bin/env python3
"""
tailer.py — watches MULTIPLE log files concurrently and runs all 4
detectors against every line from every file.

FIXES THE CORE BUG from review: the original was structured as
    for logfile in FILES:
        for line in follow(logfile):
            ...
`follow()` never returns, so the outer loop never advanced past the first
file — Scenario 4 (authservice's log) was never actually watched.

Fix: open all files up front, then poll them in a round-robin loop.
`readline()` on a regular file at EOF returns '' immediately rather than
blocking (unlike a pipe/socket), so round-robin polling works without
needing select()/asyncio/watchdog.
"""
import argparse
import json
import sys
import time

import scenario1_detector
import scenario2_detector
import scenario3_detector
import scenario4_detector

DETECTORS = [scenario1_detector, scenario2_detector, scenario3_detector, scenario4_detector]

# TODO (Person 1): confirm these are the real paths before Day 3 testing.
DEFAULT_FILES = {
    "webapp": "/var/log/sentinelmesh/webapp_events.log",
    "authservice": "/var/log/sentinelmesh/auth_events.log",
}


def process_line(raw_line, service):
    raw_line = raw_line.strip()
    if not raw_line:
        return

    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        # Fix for issue #6: catch the specific exception, not bare Exception,
        # so a real bug in a detector below doesn't get silently swallowed too.
        print(f"[tailer] WARNING: malformed JSON from {service}, skipping: {raw_line[:200]}", file=sys.stderr)
        return

    if not isinstance(event, dict):
        print(f"[tailer] WARNING: non-object JSON from {service}, skipping: {raw_line[:200]}", file=sys.stderr)
        return

    for detector in DETECTORS:
        try:
            detector.check(event, service)
        except Exception as exc:
            # A genuine bug in one detector must not crash the tailer or
            # silently disappear (issue #6) — isolate per-detector, log loudly.
            print(f"[tailer] ERROR in {detector.__name__}.check(): {exc}", file=sys.stderr)


def open_files(files):
    handles = {}
    for service, path in files.items():
        try:
            f = open(path, "r")
        except OSError as exc:
            print(f"[tailer] ERROR: cannot open {path} for {service}: {exc}", file=sys.stderr)
            sys.exit(1)
        f.seek(0, 2)  # start at end of file — only new events
        handles[service] = f
        print(f"[tailer] watching {path} (service={service})", file=sys.stderr)
    return handles


def run(handles):
    try:
        while True:
            any_line = False
            for service, f in handles.items():
                line = f.readline()
                if line:
                    any_line = True
                    process_line(line, service)
            if not any_line:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[tailer] stopped.", file=sys.stderr)
    finally:
        for f in handles.values():
            f.close()


def main():
    parser = argparse.ArgumentParser(description="SentinelMesh multi-file log-tail detector")
    parser.add_argument(
        "--files",
        nargs="+",
        metavar="SERVICE=PATH",
        help="Override default files, e.g. webapp=/path/webapp.log authservice=/path/auth.log",
    )
    args = parser.parse_args()

    files = dict(DEFAULT_FILES)
    if args.files:
        for item in args.files:
            service, _, path = item.partition("=")
            if not path:
                print(f"[tailer] ERROR: bad --files entry '{item}', expected SERVICE=PATH", file=sys.stderr)
                sys.exit(1)
            files[service] = path

    handles = open_files(files)
    run(handles)


if __name__ == "__main__":
    main()

