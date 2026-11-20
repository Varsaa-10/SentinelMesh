"""Unit tests for eval/attribute.py and detection/falco-rules/falco_shim.py."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

from eval.attribute import (
    alert_container_name,
    attribute_alert,
    attribute_alerts,
    is_designated_rule,
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

    res_wrong, res_outside, res_host = attribute_alerts(
        [wrong_container, outside_window, host_event], windows, gt
    )
    assert res_wrong["attribution"] == "attack_collateral"
    assert res_wrong["attributed_scenario"] == "S11"
    assert res_wrong["ground_truth_technique"] == "T1059"
    assert res_wrong["false_positive"] is False

    for item in (res_outside, res_host):
        assert item["attribution"] == "unattributed"
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


def test_f2_target_collateral_helper_host_attack_host_system_and_benign_outside():
    gt = _load_gt()
    windows = {
        "S4": {"start": "2026-11-16T04:27:20Z", "end": "2026-11-16T04:27:26Z"},
        "S5": {"start": "2026-11-16T04:27:27Z", "end": "2026-11-16T04:27:38Z"},
        "S11": {"start": "2026-11-16T04:28:02Z", "end": "2026-11-16T04:28:06Z"},
    }
    benign_actions = [
        {
            "start": "2026-11-16T04:27:20Z",
            "end": "2026-11-16T04:27:20Z",
            "container": "",
            "action": "pause",
        },
        {
            "start": "2026-11-16T04:27:26Z",
            "end": "2026-11-16T04:27:26Z",
            "container": "",
            "action": "resume",
        },
        {
            "start": "2026-11-16T04:28:12Z",
            "end": "2026-11-16T04:28:12Z",
            "container": "host",
            "action": "outbound_https",
        },
    ]

    # 1. Target alert inside S11 window on sentinelmesh-webapp
    target_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Terminal shell in container",
        "timestamp": "2026-11-16T04:28:03Z",
        "service": "webapp",
        "falco_tags": ["T1059", "container", "shell"],
        "event": {"container.name": "sentinelmesh-webapp", "proc.name": "sh"},
    }

    # 2. Collateral alert in another lab container inside S11 window
    collateral_lab_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Non sudo setuid",
        "timestamp": "2026-11-16T04:28:04Z",
        "service": "database",
        "falco_tags": ["T1548.001", "container"],
        "event": {"container.name": "sentinelmesh-database", "proc.name": "su"},
    }

    # 3. Helper-container alert (e.g. S5 ephemeral psql container)
    helper_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Launch Sensitive Mount Container",
        "timestamp": "2026-11-16T04:27:33Z",
        "service": "pensive_knuth",
        "falco_tags": ["T1610", "container"],
        "event": {"container.name": "pensive_knuth", "proc.name": "psql"},
    }

    # 4. Host attack-script alert (proc.cmdline and proc.pcmdline)
    host_attack_cmdline = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Unexpected UDP Traffic",
        "timestamp": "2026-11-16T04:27:23Z",
        "service": "host",
        "falco_tags": ["TA0011", "host"],
        "event": {
            "container.name": "host",
            "proc.cmdline": "python3 /home/kali/SentinelMesh/attack_scripts/scenario4_jwt_confusion.py",
        },
    }
    host_attack_pcmdline = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Unexpected UDP Traffic",
        "timestamp": "2026-11-16T04:27:24Z",
        "service": "host",
        "falco_tags": ["TA0011", "host"],
        "event": {
            "container.name": "host",
            "proc.cmdline": "curl -s http://127.0.0.1:5001/auth/verify",
            "proc.pcmdline": "bash /home/kali/SentinelMesh/attack_scripts/scenario1_sqli.sh",
        },
    }

    # 5. Host system alert in a window (e.g. runc / containerd) -> stays unattributed
    host_system_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "BPF Program Not Profiled",
        "timestamp": "2026-11-16T04:27:31Z",
        "service": "host",
        "falco_tags": ["TA0003", "host"],
        "event": {"container.name": "host", "proc.cmdline": "runc create ..."},
    }

    # 6. Benign alert outside windows
    benign_outside = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Unexpected UDP Traffic",
        "timestamp": "2026-11-16T04:28:12Z",
        "service": "host",
        "falco_tags": ["TA0011", "host"],
        "event": {"container.name": "host", "proc.cmdline": "curl https://pypi.org"},
    }

    attributed = attribute_alerts(
        [
            target_alert,
            collateral_lab_alert,
            helper_alert,
            host_attack_cmdline,
            host_attack_pcmdline,
            host_system_alert,
            benign_outside,
        ],
        windows,
        gt,
        benign_actions=benign_actions,
    )
    a_tgt, a_lab, a_hlp, a_hcmd, a_hpcmd, a_hsys, a_ben = attributed

    assert a_tgt["attribution"] == "attack"
    assert a_tgt["attributed_scenario"] == "S11"
    assert a_tgt["ground_truth_technique"] == "T1059"
    assert a_tgt["designated_rule"] is True
    assert a_tgt["false_positive"] is False

    assert a_lab["attribution"] == "attack_collateral"
    assert a_lab["attributed_scenario"] == "S11"
    assert a_lab["ground_truth_technique"] == "T1059"
    assert a_lab["false_positive"] is False

    assert a_hlp["attribution"] == "attack_collateral"
    assert a_hlp["attributed_scenario"] == "S5"
    assert a_hlp["ground_truth_technique"] == "T1021"
    assert a_hlp["false_positive"] is False

    for h_atk in (a_hcmd, a_hpcmd):
        assert h_atk["attribution"] == "attack_collateral"
        assert h_atk["attributed_scenario"] == "S4"
        assert h_atk["ground_truth_technique"] == "T1212"
        assert h_atk["false_positive"] is False

    assert a_hsys["attribution"] == "unattributed"
    assert a_hsys["attributed_scenario"] == "unattributed"
    assert a_hsys["ground_truth_technique"] is None
    assert a_hsys["designated_rule"] is False
    assert a_hsys["false_positive"] is False

    assert a_ben["attribution"] == "benign"
    assert a_ben["attributed_scenario"] == "unattributed"
    assert a_ben["ground_truth_technique"] is None
    assert a_ben["designated_rule"] is False
    assert a_ben["false_positive"] is True
    assert a_ben["benign_action"] == "outbound_https"

    summary = summarize_attribution(attributed)
    assert summary["attack_count"] == 1
    assert summary["attack_collateral_count"] == 4
    assert summary["benign_count"] == 1
    assert summary["by_attribution"] == {
        "attack": 1,
        "attack_collateral": 4,
        "ambiguous": 0,
        "benign": 1,
        "setup": 0,
        "unattributed": 1,
    }


def test_f3_rule_technique_and_designated_rule_stock_and_s09():
    gt = _load_gt()
    windows = {
        "S7": {"start": "2026-11-16T04:27:44Z", "end": "2026-11-16T04:27:47Z"},
        "S9": {"start": "2026-11-16T04:27:49Z", "end": "2026-11-16T04:27:55Z"},
        "S17": {"start": "2026-11-16T04:28:44Z", "end": "2026-11-16T04:28:47Z"},
        "S20": {"start": "2026-11-16T04:28:59Z", "end": "2026-11-16T04:29:04Z"},
    }

    # Stock rule with non-matching rule firing inside S17 (Execution from /dev/shm)
    stock_non_designated = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Non sudo setuid",
        "timestamp": "2026-11-16T04:28:44Z",
        "service": "dashboard",
        "falco_tags": ["T1548.001", "container", "users"],
        "event": {"container.name": "sentinelmesh-dashboard"},
    }
    # Stock rule matching S17's designated rule
    stock_designated = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Execution from /dev/shm",
        "timestamp": "2026-11-16T04:28:45Z",
        "service": "dashboard",
        "falco_tags": ["T1059.004", "container", "mitre_execution"],
        "event": {"container.name": "sentinelmesh-dashboard"},
    }
    # Stock rule with tactic-only tag (no Txxxx) -> rule_technique is None
    stock_tactic_only = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Unexpected UDP Traffic",
        "timestamp": "2026-11-16T04:29:10Z",
        "service": "host",
        "falco_tags": ["TA0011", "host"],
        "event": {"container.name": "host"},
    }
    # s09 firing during S9 (designated)
    s09_in_s9 = {
        "source": "falco",
        "scenario": "S9",
        "severity": "CRITICAL",
        "title": "SentinelMesh Sensitive Credential File Read",
        "timestamp": "2026-11-16T04:27:52Z",
        "service": "webapp",
        "event": {"container.name": "sentinelmesh-webapp", "fd.name": "/etc/shadow"},
    }
    # s09 firing during S20 (useradd reading /etc/shadow in database) -> non-designated for S20
    s09_in_s20 = {
        "source": "falco",
        "scenario": "S9",
        "severity": "CRITICAL",
        "title": "SentinelMesh Sensitive Credential File Read",
        "timestamp": "2026-11-16T04:29:00Z",
        "service": "database",
        "event": {"container.name": "sentinelmesh-database", "fd.name": "/etc/shadow"},
    }
    # S7 Grafana login & anonymous dashboard access
    s7_login = {
        "source": "log-tail",
        "scenario": "S7",
        "severity": "WARNING",
        "title": "Grafana Login Succeeded (unconfirmed — username not visible)",
        "timestamp": "2026-11-16T04:27:44Z",
        "service": "dashboard",
        "event": {"raw_log_line": "..."},
    }
    s7_anon = {
        "source": "log-tail",
        "scenario": "S7",
        "severity": "WARNING",
        "title": "Grafana Anonymous Dashboard Access",
        "timestamp": "2026-11-16T04:27:45Z",
        "service": "dashboard",
        "event": {"raw_log_line": "..."},
    }

    res = attribute_alerts(
        [
            stock_non_designated,
            stock_designated,
            stock_tactic_only,
            s09_in_s9,
            s09_in_s20,
            s7_login,
            s7_anon,
        ],
        windows,
        gt,
    )
    r_nd, r_d, r_tac, r_s9, r_s9_s20, r_s7_log, r_s7_anon = res

    assert r_nd["ground_truth_technique"] == "T1059.004"
    assert r_nd["rule_technique"] == "T1548.001"
    assert r_nd["designated_rule"] is False

    assert r_d["ground_truth_technique"] == "T1059.004"
    assert r_d["rule_technique"] == "T1059.004"
    assert r_d["designated_rule"] is True

    assert r_tac["ground_truth_technique"] is None
    assert r_tac["rule_technique"] is None
    assert r_tac["designated_rule"] is False

    assert r_s9["attributed_scenario"] == "S9"
    assert r_s9["ground_truth_technique"] == "T1003.008"
    assert r_s9["rule_technique"] == "T1003.008"
    assert r_s9["designated_rule"] is True

    assert r_s9_s20["attributed_scenario"] == "S20"
    assert r_s9_s20["ground_truth_technique"] == "T1098"
    assert r_s9_s20["rule_technique"] == "T1003.008"
    assert r_s9_s20["designated_rule"] is False

    assert r_s7_log["rule_technique"] == "T1078"
    assert r_s7_log["designated_rule"] is True
    assert r_s7_anon["rule_technique"] == "T1078"
    # F9: lab-detector alert whose own scenario equals the attributed scenario is designated
    assert r_s7_anon["designated_rule"] is True


def test_f9_lab_detector_scenario_field_designation():
    gt = _load_gt()
    scenarios = gt["scenarios"]

    s7_anon = {
        "source": "log-tail",
        "scenario": "S7",
        "title": "Grafana Anonymous Dashboard Access",
    }
    s09_lab_falco = {
        "source": "falco",
        "scenario": "S9",
        "title": "SentinelMesh Sensitive Credential File Read",
    }
    stock_falco = {
        "source": "falco",
        "scenario": "",
        "title": "Some Other Stock Rule",
        "falco_tags": ["T1059"],
    }

    # Lab detector, own scenario == attributed scenario -> designated (even with a non-designated title)
    assert is_designated_rule(s7_anon, "S7", scenarios) is True
    assert is_designated_rule(s09_lab_falco, "S9", scenarios) is True
    # Own scenario differs from attributed scenario -> falls back to rule matching (not designated)
    assert is_designated_rule(s7_anon, "S3", scenarios) is False
    assert is_designated_rule(s09_lab_falco, "S20", scenarios) is False
    # Stock Falco alerts never qualify via the scenario field
    assert is_designated_rule(stock_falco, "S11", scenarios) is False
    # Unattributed never designated
    assert is_designated_rule(s7_anon, "unattributed", scenarios) is False


def test_f12_unnamed_container_with_id_gets_attack_collateral():
    gt = _load_gt()
    windows = {
        "S1": {"start": "2026-11-19T10:46:20Z", "end": "2026-11-19T10:46:25Z"},
        "S5": {"start": "2026-11-19T10:46:40Z", "end": "2026-11-19T10:46:48Z"},
    }

    psql_helper_repo = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Launch Sensitive Mount Container",
        "timestamp": "2026-11-19T10:46:42Z",
        "service": "unknown",
        "falco_tags": ["container", "T1610"],
        "event": {
            "container.name": None,
            "container.id": "a1b2c3d4e5f6",
            "container.image.repository": "postgres",
        },
    }
    unnamed_id_only = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Launch Sensitive Mount Container",
        "timestamp": "2026-11-19T10:46:43Z",
        "service": "unknown",
        "falco_tags": ["container", "T1610"],
        "event": {
            "container.name": "",
            "container.id": "deadbeef1234",
            "container.image.repository": None,
        },
    }
    unnamed_matching_repo_name = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Launch Privileged Container",
        "timestamp": "2026-11-19T10:46:22Z",
        "service": "unknown",
        "falco_tags": ["container", "T1610"],
        "event": {
            "container.name": "<NA>",
            "container.id": "cafe98765432",
            "container.image.repository": "sentinelmesh-webapp",
        },
    }
    host_none_name = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Host Process Event",
        "timestamp": "2026-11-19T10:46:44Z",
        "service": "unknown",
        "event": {
            "container.name": None,
            "container.id": "host",
        },
    }

    assert alert_container_name(psql_helper_repo) == "postgres"
    assert alert_container_name(unnamed_id_only) == "deadbeef1234"
    assert alert_container_name(host_none_name) == ""

    r_repo, r_id, r_col, r_host = attribute_alerts(
        [psql_helper_repo, unnamed_id_only, unnamed_matching_repo_name, host_none_name],
        windows,
        gt,
    )
    assert r_repo["attribution"] == "attack_collateral"
    assert r_repo["attributed_scenario"] == "S5"
    assert r_repo["rule_technique"] == "T1610"
    assert r_repo["designated_rule"] is False

    assert r_id["attribution"] == "attack_collateral"
    assert r_id["attributed_scenario"] == "S5"

    assert r_col["attribution"] == "attack_collateral"
    assert r_col["attributed_scenario"] == "S1"

    assert r_host["attribution"] == "unattributed"
    assert r_host["attributed_scenario"] == "unattributed"


def test_attribute_alerts_strips_configured_prefix_from_manifest(tmp_path):
    """Manifest container_prefix maps both E1 sentinelmesh-* and E2 smx-* alerts to logical targets."""
    gt = json.loads(GT_PATH.read_text(encoding="utf-8"))
    windows = {
        "S1": {"start": "2026-11-20T10:00:00Z", "end": "2026-11-20T10:00:20Z"},
    }

    e1_manifest = tmp_path / "run_e1_manifest.txt"
    e1_manifest.write_text("env_id: E1\ncontainer_prefix: sentinelmesh\n", encoding="utf-8")

    e2_manifest = tmp_path / "run_e2_manifest.txt"
    e2_manifest.write_text("env_id: E2\n[env]\nCONTAINER_PREFIX=smx\n", encoding="utf-8")

    e1_sqli = {
        "source": "log-tail",
        "scenario": "S1",
        "severity": "HIGH",
        "title": gt["scenarios"]["S1"]["detection"]["expected_title"],
        "timestamp": "2026-11-20T10:00:05Z",
        "service": "webapp",
        "event": {"container.name": "sentinelmesh-webapp"},
    }
    e2_sqli = {
        "source": "log-tail",
        "scenario": "S1",
        "severity": "HIGH",
        "title": gt["scenarios"]["S1"]["detection"]["expected_title"],
        "timestamp": "2026-11-20T10:00:06Z",
        "service": "webapp",
        "event": {"container.name": "smx-webapp"},
    }
    e2_db_collateral = {
        "source": "falco",
        "scenario": "",
        "severity": "NOTICE",
        "title": "Read sensitive file untrusted",
        "timestamp": "2026-11-20T10:00:07Z",
        "service": "database",
        "falco_tags": ["filesystem", "T1555"],
        "event": {"container.name": "smx-database"},
    }
    e2_wrong_prefix = {
        "source": "log-tail",
        "scenario": "S1",
        "severity": "HIGH",
        "title": gt["scenarios"]["S1"]["detection"]["expected_title"],
        "timestamp": "2026-11-20T10:00:08Z",
        "service": "webapp",
        "event": {"container.name": "sentinelmesh-webapp"},
    }

    [r_e1] = attribute_alerts([e1_sqli], windows, gt, manifest_path=e1_manifest)
    assert r_e1["attribution"] == "attack"
    assert r_e1["attributed_scenario"] == "S1"
    assert r_e1["designated_rule"] is True

    r_e2, r_col, r_wrong = attribute_alerts(
        [e2_sqli, e2_db_collateral, e2_wrong_prefix],
        windows,
        gt,
        manifest_path=e2_manifest,
    )
    assert r_e2["attribution"] == "attack"
    assert r_e2["attributed_scenario"] == "S1"
    assert r_e2["designated_rule"] is True

    assert r_col["attribution"] == "attack_collateral"
    assert r_col["attributed_scenario"] == "S1"

    assert r_wrong["attribution"] == "attack_collateral"
    assert r_wrong["attributed_scenario"] == "S1"
