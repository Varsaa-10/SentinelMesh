#!/usr/bin/env python3
"""
test_detectors.py — proves each issue from the code review is actually fixed.
Calls each detector's check() directly with synthetic events; no file I/O,
no tailer loop needed for these checks.
"""
import sys

import scenario1_detector
import scenario2_detector
import scenario3_detector
import scenario4_detector


def expect(condition, message):
    print(f"[{'PASS' if condition else 'FAIL'}] {message}", file=sys.stderr)
    return condition


def test_s1_payload_field():
    # Issue #2: SQLi in `payload`, not `username` — must still be caught.
    event = {"event": "login_attempt", "result": "success", "username": "someone", "payload": "' OR '1'='1"}
    alert = scenario1_detector.check(event, "webapp")
    return expect(alert is not None and alert["scenario"] == "S1", "S1 detects SQLi in payload field, not just username")


def test_s1_negative():
    event = {"event": "login_attempt", "result": "success", "username": "alice", "payload": "hello"}
    alert = scenario1_detector.check(event, "webapp")
    return expect(alert is None, "S1 does NOT fire on a benign login")


def test_s2_threshold_and_cap():
    # Issue #3: history capped, and fires only once threshold is reached.
    alert = None
    for i in range(6):
        event = {
            "event": "login_attempt",
            "result": "fail",
            "username": "victim",
            "timestamp": f"2026-08-04T10:00:{i:02d}Z",
        }
        alert = scenario2_detector.check(event, "webapp")
    ok = expect(alert is not None and alert["scenario"] == "S2", "S2 fires after threshold reached")
    ok &= expect(
        alert["event"]["failure_count"] <= scenario2_detector.MAX_HISTORY,
        "S2 failure count never exceeds MAX_HISTORY",
    )
    return ok


def test_s3_explicit_flag_is_confident():
    # Issue #4: explicit flag -> no "unconfirmed" caveat in the title.
    event = {"event": "login_attempt", "result": "success", "username": "admin", "default_credentials": True}
    alert = scenario3_detector.check(event, "authservice")
    return expect(
        alert is not None and "unconfirmed" not in alert["title"],
        "S3 fires confidently with explicit default_credentials flag",
    )


def test_s3_fallback_is_labeled():
    event = {"event": "login_attempt", "result": "success", "username": "admin"}
    alert = scenario3_detector.check(event, "authservice")
    return expect(
        alert is not None and "unconfirmed" in alert["title"],
        "S3 falls back to a labeled-unconfirmed alert without the flag (not silently over-confident)",
    )


def test_s3_negative():
    event = {"event": "login_attempt", "result": "success", "username": "alice"}
    alert = scenario3_detector.check(event, "authservice")
    return expect(alert is None, "S3 does NOT fire for a non-admin legitimate login")


def test_s4_keyword_expansion():
    # Issue #5: matches hs256/rs256/alg, not just the literal word "algorithm".
    event = {"event": "jwt_verification", "reason": "unexpected alg field: HS256 used instead of RS256"}
    alert = scenario4_detector.check(event, "authservice")
    return expect(alert is not None and alert["scenario"] == "S4", "S4 fires on hs256/rs256/alg keywords, not just 'algorithm'")


def test_s4_negative():
    event = {"event": "jwt_verification", "reason": "token expired"}
    alert = scenario4_detector.check(event, "authservice")
    return expect(alert is None, "S4 does NOT fire on an unrelated verification failure")


def test_alert_shape_consistent():
    # Issue #7: every detector must emit the exact same top-level keys.
    events = [
        scenario1_detector.check(
            {"event": "login_attempt", "result": "success", "payload": "' OR '1'='1"}, "webapp"
        ),
        scenario2_detector.check(
            {"event": "login_attempt", "result": "fail", "username": "x", "timestamp": "2026-08-04T11:00:00Z"},
            "webapp",
        ),
    ]
    # force S2 over threshold
    for i in range(5):
        events.append(
            scenario2_detector.check(
                {
                    "event": "login_attempt",
                    "result": "fail",
                    "username": "y",
                    "timestamp": f"2026-08-04T11:01:{i:02d}Z",
                },
                "webapp",
            )
        )
    events.append(
        scenario3_detector.check(
            {"event": "login_attempt", "result": "success", "username": "admin", "default_credentials": True},
            "authservice",
        )
    )
    events.append(
        scenario4_detector.check({"event": "jwt_verification", "reason": "algorithm mismatch"}, "authservice")
    )

    expected_keys = {"source", "scenario", "severity", "title", "timestamp", "service", "event"}
    ok = True
    for alert in events:
        if alert is None:
            continue
        ok &= expect(set(alert.keys()) == expected_keys, f"alert from {alert['scenario']} has the standard 7-key shape")
    return ok


def main():
    results = [
        test_s1_payload_field(),
        test_s1_negative(),
        test_s2_threshold_and_cap(),
        test_s3_explicit_flag_is_confident(),
        test_s3_fallback_is_labeled(),
        test_s3_negative(),
        test_s4_keyword_expansion(),
        test_s4_negative(),
        test_alert_shape_consistent(),
    ]
    print(f"\n{sum(results)}/{len(results)} checks passed.", file=sys.stderr)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
