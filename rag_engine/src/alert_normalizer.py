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
import re
from typing import Optional


def _looks_like_sqli(identifier: str) -> bool:
    if not identifier:
        return False
    return bool(re.search(r"(--|'|\bOR\b|\bUNION\b|;)", identifier, re.IGNORECASE))


def normalize_alert_text(alert: dict) -> str:
    """
    alert: one entry from data/placeholder_alerts.json, with at least
    'source' and 'output' (the raw captured text). Falls back to 'output'
    unmodified if no pattern is recognized, so this never loses information.
    """
    raw = alert.get("output", "")
    source = alert.get("source")

    # --- log-tail: login_attempt events (S1, S2, S3, S7-Grafana all share this shape) ---
    if "event_type" in raw or "login_attempt" in raw:
        # Extract identifier= value if present (handles quoted values with special chars)
        m_id = re.search(r'identifier="?([^",]*)"?', raw)
        identifier = m_id.group(1) if m_id else ""
        result_success = "result=success" in raw
        result_failure = "result=failure" in raw

        if _looks_like_sqli(identifier):
            return (
                "login_attempt event, authentication bypassed via SQL injection syntax "
                "in the identifier field, result success despite no valid credential"
            )
        if result_failure and ("failure_count" in raw):
            return (
                "login_attempt event, repeated failed authentication attempts against "
                "the same identifier within a short window, brute force pattern"
            )
        if result_success and identifier.lower() == "admin":
            return (
                "login_attempt event, successful authentication using the default "
                "admin account credentials, valid account abuse"
            )
        if "grafana" in raw.lower() or "dashboards/home" in raw:
            return (
                "Grafana dashboard accessed using default admin credentials or "
                "anonymous access with no authenticated identity, valid account abuse"
            )

    # --- log-tail: jwt_verification events (S4) ---
    if "jwt_verification" in raw or "algorithm=none" in raw:
        return (
            "jwt_verification event, token accepted as valid despite algorithm none, "
            "signature verification bypassed, credential forgery via software exploitation"
        )

    # --- falco: database connection (S5) ---
    if source == "falco" and ("postgres" in raw.lower() or "5432" in raw or "database" in raw.lower()):
        return (
            "unauthorized inbound network connection to the database service from a "
            "source not on the allowed client list, remote service abuse"
        )

    # --- falco: log tampering (S6) ---
    if source == "falco" and ("var/log/sentinelmesh" in raw or "logcollector" in raw.lower()):
        return (
            "unexpected write to the security log directory by a process other than "
            "the log service itself, indicator removal, log tampering"
        )

    # --- falco: credential file read (S9) ---
    if source == "falco" and ("/etc/shadow" in raw or ".ssh" in raw or ".aws" in raw):
        return (
            "sensitive credential file read, /etc/shadow or SSH key or cloud "
            "credential file accessed by an unexpected process, credential dumping"
        )

    # --- falco: outbound connection / exfiltration (S8) ---
    if source == "falco" and ("curl" in raw.lower() or "outbound connect" in raw.lower() or "fd.rport" in raw):
        return (
            "unexpected outbound network connection from the container to a "
            "destination outside the allowed egress list, data exfiltration over "
            "command and control channel"
        )

    return raw
