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


def test_attribute_ambiguous_within_2s_of_benign_keeps_both_candidate_labels():
    gt = _load_gt()
    windows = {"S11": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"}}
    benign_actions = [
        {
            "start": "2026-11-15T12:00:04Z",
            "end": "2026-11-15T12:00:04Z",
            "container": "sentinelmesh-webapp",
            "action": "log_rotation",
        },
        {
            "start": "2026-11-15T12:00:02Z",
            "end": "2026-11-15T12:00:02Z",
            "container": "sentinelmesh-database",
            "action": "pkg_index_update",
        },
    ]

    # Inside S11 window AND exactly 2s before benign action end/start on same container -> ambiguous
    overlap_alert = {
        "timestamp": "2026-11-15T12:00:02Z",
        "service": "webapp",
        "event": {"container.name": "sentinelmesh-webapp"},
        "falco_tags": ["T1059"],
    }
    att = attribute_alert(overlap_alert, windows, gt, benign_actions=benign_actions)
    assert att["attribution"] == "ambiguous"
    assert att["attributed_scenario"] == "S11"
    assert att["ground_truth_technique"] == gt["scenarios"]["S11"]["technique_id"]
    assert att["benign_action"] == "log_rotation"
    assert att["candidate_labels"]["attack"]["scenario"] == "S11"
    assert att["candidate_labels"]["attack"]["technique"] == gt["scenarios"]["S11"]["technique_id"]
    assert att["candidate_labels"]["benign"][0]["action"] == "log_rotation"
    assert att["false_positive"] is False

    # 3s away from log_rotation (> +/-2s) and other benign is on database -> clear attack
    clear_alert = {
        "timestamp": "2026-11-15T12:00:01Z",
        "service": "webapp",
        "event": {"container.name": "sentinelmesh-webapp"},
        "falco_tags": ["T1059"],
    }
    clear = attribute_alert(clear_alert, windows, gt, benign_actions=benign_actions)
    assert clear["attribution"] == "attack"
    assert clear["attributed_scenario"] == "S11"
    assert clear["false_positive"] is False


def test_attribute_benign_outside_scenario_window_marks_false_positive():
    gt = _load_gt()
    windows = {"S11": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"}}
    benign_actions = [
        {
            "start": "2026-11-15T12:00:10Z",
            "end": "2026-11-15T12:00:11Z",
            "container": "sentinelmesh-database",
            "action": "pkg_index_update",
        },
        {
            "start": "2026-11-15T12:00:20Z",
            "end": "2026-11-15T12:00:20Z",
            "container": "host",
            "action": "outbound_https",
        },
    ]

    db_fp = {
        "timestamp": "2026-11-15T12:00:13Z",  # exactly +2s after benign end
        "service": "database",
        "event": {"container.name": "sentinelmesh-database"},
    }
    host_fp = {
        "timestamp": "2026-11-15T12:00:19Z",  # -1s from host benign action
        "service": "host",
        "event": {"container.name": "host"},
    }

    res_db = attribute_alert(db_fp, windows, gt, benign_actions=benign_actions)
    assert res_db["attribution"] == "benign"
    assert res_db["false_positive"] is True
    assert res_db["attributed_scenario"] == "unattributed"
    assert res_db["ground_truth_technique"] is None
    assert res_db["benign_action"] == "pkg_index_update"

    res_host = attribute_alert(host_fp, windows, gt, benign_actions=benign_actions)
    assert res_host["attribution"] == "benign"
    assert res_host["false_positive"] is True
    assert res_host["benign_action"] == "outbound_https"


def test_summarize_attribution_reports_ambiguous_excluded_and_as_attack():
    gt = _load_gt()
    windows = {
        "S11": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"},
        "S15": {"start": "2026-11-15T12:00:20Z", "end": "2026-11-15T12:00:25Z"},
    }
    benign_actions = [
        {
            "start": "2026-11-15T12:00:03Z",
            "end": "2026-11-15T12:00:03Z",
            "container": "sentinelmesh-webapp",
            "action": "log_rotation",
        },
        {
            "start": "2026-11-15T12:00:40Z",
            "end": "2026-11-15T12:00:40Z",
            "container": "sentinelmesh-database",
            "action": "pkg_index_update",
        },
    ]
    alerts = [
        {
            "timestamp": "2026-11-15T12:00:02Z",
            "service": "webapp",
            "event": {"container.name": "sentinelmesh-webapp"},
        },  # ambiguous (S11 + log_rotation)
        {
            "timestamp": "2026-11-15T12:00:22Z",
            "service": "logcollector",
            "event": {"container.name": "sentinelmesh-logcollector"},
        },  # attack (S15)
        {
            "timestamp": "2026-11-15T12:00:41Z",
            "service": "database",
            "event": {"container.name": "sentinelmesh-database"},
        },  # benign
        {
            "timestamp": "2026-11-15T12:01:00Z",
            "service": "webapp",
            "event": {"container.name": "sentinelmesh-webapp"},
        },  # unattributed
    ]

    attributed = attribute_alerts(alerts, windows, gt, benign_actions=benign_actions)
    summary = summarize_attribution(attributed)

    assert summary["attack_count"] == 1
    assert summary["ambiguous_count"] == 1
    assert summary["benign_count"] == 1

    excl = summary["ambiguous_excluded"]
    assert excl["total_alerts"] == 3
    assert excl["attributed_count"] == 1
    assert excl["unattributed_count"] == 2
    assert excl["false_positive_count"] == 1
    assert excl["by_scenario"] == {"S15": 1}

    as_atk = summary["ambiguous_as_attack"]
    assert as_atk["total_alerts"] == 4
    assert as_atk["attributed_count"] == 2
    assert as_atk["unattributed_count"] == 2
    assert as_atk["false_positive_count"] == 1
    assert as_atk["by_scenario"] == {"S11": 1, "S15": 1}


def test_log_tail_service_webapp_within_2s_of_correct_login_is_ambiguous():
    gt = _load_gt()
    windows = {"S1": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"}}
    benign_actions = [
        {
            "start": "2026-11-15T12:00:04Z",
            "end": "2026-11-15T12:00:04Z",
            "container": "sentinelmesh-webapp",
            "action": "correct_login",
        }
    ]
    log_tail_alert = {
        "source": "log-tail",
        "scenario": "S1",
        "severity": "HIGH",
        "title": "SQL Injection Attempt",
        "timestamp": "2026-11-15T12:00:02Z",
        "service": "webapp",
        "event": {"path": "/login"},
    }

    att = attribute_alert(log_tail_alert, windows, gt, benign_actions=benign_actions)
    assert att["attribution"] == "ambiguous"
    assert att["attributed_scenario"] == "S1"
    assert att["benign_action"] == "correct_login"
    assert att["candidate_labels"]["attack"]["scenario"] == "S1"
    assert att["candidate_labels"]["benign"][0]["action"] == "correct_login"
    assert att["false_positive"] is False


def test_attribute_grafana_setup_is_neither_attack_nor_false_positive():
    gt = _load_gt()
    windows = {"S7": {"start": "2026-11-15T12:00:00Z", "end": "2026-11-15T12:00:05Z"}}
    benign_actions = [
        {
            "start": "2026-11-15T12:00:02Z",
            "end": "2026-11-15T12:00:02Z",
            "container": "sentinelmesh-dashboard",
            "action": "grafana_setup",
        }
    ]
    setup_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Grafana Setup Activity",
        "timestamp": "2026-11-15T12:00:04Z",  # exactly +2s from grafana_setup
        "service": "dashboard",
        "event": {"container.name": "sentinelmesh-dashboard"},
    }

    att_normal = attribute_alert(setup_alert, windows, gt, benign_actions=benign_actions)
    assert att_normal["attribution"] == "setup"
    assert att_normal["attributed_scenario"] == "unattributed"
    assert att_normal["ground_truth_technique"] is None
    assert att_normal["false_positive"] is False
    assert att_normal["benign_action"] == "grafana_setup"

    att_benign_only = attribute_alert(
        setup_alert, windows, gt, benign_only=True, benign_actions=benign_actions
    )
    assert att_benign_only["attribution"] == "setup"
    assert att_benign_only["attributed_scenario"] == "unattributed"
    assert att_benign_only["false_positive"] is False

    summary = summarize_attribution([att_normal])
    assert summary["setup_count"] == 1
    assert summary["attack_count"] == 0
    assert summary["attributed_count"] == 0
    assert summary["false_positive_count"] == 0
    assert summary["by_scenario"] == {}
    assert summary["ambiguous_excluded"]["setup_count"] == 1
    assert summary["ambiguous_excluded"]["attributed_count"] == 0
    assert summary["ambiguous_excluded"]["false_positive_count"] == 0
