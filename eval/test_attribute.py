"""Unit tests for eval/attribute.py and detection/falco-rules/falco_shim.py."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

from eval.attribute import (
    attribute_alert,
    attribute_alerts,
    summarize_attribution,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
GT_PATH = REPO_ROOT / "eval" / "ground_truth.json"
SHIM_PATH = REPO_ROOT / "detection" / "falco-rules" / "falco_shim.py"


def _load_shim():
    spec = importlib.util.spec_from_file_location("falco_shim", SHIM_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def _load_gt():
    return json.loads(GT_PATH.read_text(encoding="utf-8"))


def test_falco_shim_stock_vs_lab_rules():
    shim = _load_shim()

    lab_event = {
        "rule": "SentinelMesh Unauthorized Database Connection",
        "priority": "WARNING",
        "time": "2026-11-15T12:00:00.123456Z",
        "tags": ["sentinelmesh", "s5", "database", "network"],
        "output_fields": {"container.name": "sentinelmesh-database", "fd.rip": "172.30.0.99"},
    }
    lab_out = shim.translate(lab_event)
    assert lab_out is not None
    assert lab_out["scenario"] == "S5"
    assert lab_out["service"] == "database"
    assert "falco_tags" not in lab_out

    stock_event = {
        "rule": "Terminal shell in container",
        "priority": "NOTICE",
        "time": "2026-11-15T12:05:00.999999Z",
        "tags": ["maturity_stable", "container", "shell", "mitre_execution", "T1059"],
        "output_fields": {"container.name": "sentinelmesh-webapp", "proc.name": "sh"},
    }
    stock_out = shim.translate(stock_event)
    assert stock_out is not None
    assert stock_out["scenario"] == ""
    assert stock_out["severity"] == "WARNING"
    assert stock_out["service"] == "webapp"
    assert stock_out["falco_tags"] == stock_event["tags"]


def test_attribute_matches_window_and_target_and_preserves_tags():
    gt = _load_gt()
    windows = {
        "S11": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"},
        "S15": {"start": "2026-11-15T12:00:10Z", "end": "2026-11-15T12:00:15Z"},
    }
    raw_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Launch Suspicious Network Tool in Container",
        "timestamp": "2026-11-15T12:00:12.500Z",
        "service": "logcollector",
        "falco_tags": ["maturity_incubating", "container", "network", "mitre_execution", "T1059"],
        "event": {"container.name": "sentinelmesh-logcollector", "proc.name": "tcpdump"},
    }
    before = copy.deepcopy(raw_alert)
    att = attribute_alert(raw_alert, windows, gt, benign_only=False)

    assert raw_alert == before  # pure: input is never mutated
    assert att["attributed_scenario"] == "S15"
    assert att["ground_truth_technique"] == "T1557.002"
    assert att["falco_technique"] == "T1059"
    assert att["falco_tags"] == raw_alert["falco_tags"]
    assert att["false_positive"] is False


def test_attribute_unattributed_on_wrong_container_or_outside_window():
    gt = _load_gt()
    windows = {"S11": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"}}

    wrong_container = {
        "timestamp": "2026-11-15T12:00:02Z",
        "service": "database",
        "event": {"container.name": "sentinelmesh-database"},
        "falco_tags": ["T1059"],
    }
    outside_window = {
        "timestamp": "2026-11-15T12:00:06Z",
        "service": "webapp",
        "event": {"container.name": "sentinelmesh-webapp"},
        "falco_tags": ["T1059"],
    }
    host_event = {
        "timestamp": "2026-11-15T12:00:02Z",
        "service": "unknown",
        "event": {"container.name": "<NA>"},
        "falco_tags": ["T1059"],
    }

    res = attribute_alerts([wrong_container, outside_window, host_event], windows, gt)
    for item in res:
        assert item["attributed_scenario"] == "unattributed"
        assert item["ground_truth_technique"] is None
        assert item["falco_technique"] == "T1059"
        assert item["false_positive"] is False


def test_attribute_benign_only_marks_every_alert_false_positive():
    gt = _load_gt()
    windows = {"S11": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"}}
    alerts = [
        {
            "timestamp": "2026-11-15T12:00:02Z",
            "service": "webapp",
            "event": {"container.name": "sentinelmesh-webapp"},
            "falco_tags": ["T1059"],
        },
        {
            "timestamp": "2026-11-15T12:00:30Z",
            "service": "database",
            "event": {"container.name": "sentinelmesh-database"},
            "falco_tags": ["T1059"],
        },
    ]

    attributed = attribute_alerts(alerts, windows, gt, benign_only=True)
    assert len(attributed) == 2
    assert all(a["false_positive"] is True for a in attributed)
    assert all(a["attributed_scenario"] == "unattributed" for a in attributed)
    assert all(a["ground_truth_technique"] is None for a in attributed)

    summary = summarize_attribution(attributed)
    assert summary["false_positive_count"] == 2
    assert summary["unattributed_count"] == 2
    assert summary["attributed_count"] == 0
