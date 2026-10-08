"""
Alert normalizer.

Finding (Day 4-5, against real captured alerts from harness.py run
20260817T025000Z): raw structured event fields -- event_type=login_attempt,
identifier=admin, fd.rip=172.18.0.7 -- look nearly IDENTICAL across
different techniques (S1 SQLi, S2 brute force, S3 default creds, S7
Grafana all emit login_attempt events; they differ only in field VALUES,
not vocabulary). TF-IDF against the KB's natural-language descriptions
can't bridge that gap well, and accuracy collapses on real data even for
flat-RAG (0.86 best case, two-layer as low as 0.36).

This module tests the fix: translate the semantically-relevant field
VALUES into short natural-language phrases that share vocabulary with the
KB's own descriptions, before embedding. This is deliberately simple
(rule-based, not learned) -- it's a demonstration that the vocabulary gap
is the problem, not a production-grade solution. A production version of
this logic plausibly belongs in the log-tail/Falco detectors themselves
(emit a human-readable summary field), not bolted onto the RAG layer.
"""
from __future__ import annotations
import json
import re
from typing import Optional


def _looks_like_sqli(identifier: str) -> bool:
    if not identifier or not isinstance(identifier, str):
        return False
    return bool(re.search(r"('|--|\bUNION\b|\bSELECT\b|'\s*OR\s*'|'\s*=\s*')", identifier, re.IGNORECASE))


def normalize_alert_text(alert: dict) -> str:
    """
    alert: one entry from placeholder_alerts.json or live ALERTS_STORE.
    Translates semantically-relevant field VALUES into natural-language phrases
    matching KB descriptions based purely on event content (without scenario shortcuts).
    """
    raw = alert.get("output", "")
    title = alert.get("title", "")
    event = alert.get("event", {})
    if not isinstance(event, dict):
        event = {}
    rule = alert.get("rule", "")

    identifier = str(event.get("identifier") or event.get("user") or event.get("payload") or "")

    combined = f"{raw} {title} {rule} {json.dumps(event)}".lower()

    # --- S4: JWT Confusion (T1212) ---
    if "jwt_verification" in combined or "algorithm=none" in combined or "alg=none" in combined or "jwt" in combined:
        return (
            "jwt_verification event, token accepted as valid despite algorithm none, "
            "signature verification bypassed, credential forgery via software exploitation"
        )

    # --- S5: Database Connection (T1021) ---
    if "5432" in combined or "postgres" in combined or "database connection" in combined:
        return (
            "unauthorized inbound network connection to the database service from a "
            "source not on the allowed client list, remote service abuse"
        )

    # --- S6: Log Tampering (T1070) ---
    if "var/log/sentinelmesh" in combined or "log directory tampering" in combined:
        return (
            "unexpected write to the security log directory by a process other than "
            "the log service itself, indicator removal, log tampering"
        )

    # --- S7: Grafana (T1078) ---
    if "grafana" in combined or "dashboards/home" in combined:
        return (
            "Grafana dashboard accessed using default admin credentials or "
            "anonymous access with no authenticated identity, valid account abuse"
        )

    # --- S8: Exfiltration / Outbound Connection (T1041) ---
    if "curl" in combined or "outbound connect" in combined or "exfiltration" in combined:
        return (
            "unexpected outbound network connection from the container to a "
            "destination outside the allowed egress list, data exfiltration over "
            "command and control channel"
        )

    # --- S9: Sensitive Credential File Read (T1003.008) ---
    if "/etc/shadow" in combined or ".ssh" in combined or ".aws" in combined or "credential file read" in combined:
        return (
            "sensitive credential file read, /etc/shadow or SSH key or cloud "
            "credential file accessed by an unexpected process, credential dumping"
        )

    # --- S2: Brute Force (T1110) ---
    if ("failure_count" in combined and "login" in combined) or "brute" in combined:
        return (
            "login_attempt event, repeated failed authentication attempts against "
            "the same identifier within a short window, brute force pattern"
        )

    # --- S3: Default Credentials (T1078) ---
    if "login" in combined and "result=success" in combined and "admin" in combined and not _looks_like_sqli(identifier):
        return (
            "login_attempt event, successful authentication using the default "
            "admin account credentials, valid account abuse"
        )

    # --- S1: SQL Injection (T1190) ---
    if _looks_like_sqli(identifier) or "sqli" in combined or "sql injection" in combined:
        return (
            "login_attempt event, authentication bypassed via SQL injection syntax "
            "in the identifier field, result success despite no valid credential"
        )

    return raw or title
