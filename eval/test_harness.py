"""Unit tests for eval/harness.py ENV2 additions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from eval import harness
from linux_run.lab_env import parse_env_file, read_prefix_from_manifest


def test_build_falco_command_with_stock_rules_order(tmp_path):
    rules_dir = tmp_path / "falco-rules"
    stock_dir = tmp_path / "falco-stock"
    rules_dir.mkdir()
    stock_dir.mkdir()

    s05 = rules_dir / "s05_db_access.yaml"
    s05.write_text("- rule: r1\n", encoding="utf-8")
    for fname in harness.STOCK_FALCO_FILES:
        (stock_dir / fname).write_text(f"# {fname}\n", encoding="utf-8")

    cmd_base = harness.build_falco_command(rules_dir, include_stock_falco=False)
    assert cmd_base == ["stdbuf", "-oL", "falco", "-o", "json_output=true", "-r", str(s05)]

    cmd_stock = harness.build_falco_command(rules_dir, include_stock_falco=True)
    r_args = [cmd_stock[i + 1] for i, tok in enumerate(cmd_stock) if tok == "-r"]
    assert r_args == [
        str(s05),
        str(stock_dir / "falco_rules.yaml"),
        str(stock_dir / "falco-incubating_rules.yaml"),
        str(stock_dir / "falco-sandbox_rules.yaml"),
    ]


def test_attack_order_includes_s11_to_s28_and_gates_s29():
    order_default = [sid for sid, _, _, _ in harness.build_attack_order()]
    assert [f"S{i}" for i in range(11, 29)] == [s for s in order_default if int(s[1:]) >= 11]
    assert "S29" not in order_default

    order_priv = harness.build_attack_order(privileged_debug=True, chain_script="scenario10_chain.sh")
    sids_priv = [sid for sid, _, _, _ in order_priv]
    assert "S29" in sids_priv
    assert sids_priv[-1] == "S10"
    s29_entry = next(item for item in order_priv if item[0] == "S29")
    assert s29_entry[3] == ["--privileged-debug"]


def test_run_attack_scripts_records_every_scenario_window(tmp_path, monkeypatch):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for _, fname, _ in harness.DEFAULT_ATTACK_ORDER[:2]:
        (scripts_dir / fname).write_text("exit 0\n", encoding="utf-8")

    calls = []

    def fake_run(cmd, timeout=30, capture_output=True, text=True):
        calls.append(cmd)
        return type("Res", (), {"stdout": "", "stderr": "", "returncode": 0})()

    monkeypatch.setattr(harness, "SECONDS_BETWEEN_ATTACKS", 0)
    monkeypatch.setattr(harness.time, "sleep", lambda _s: None)
    monkeypatch.setattr(harness.subprocess, "run", fake_run)

    windows, chain_win = harness.run_attack_scripts(scripts_dir)
    assert set(windows.keys()) == {"S1", "S2"}
    assert chain_win is None
    for sid in ("S1", "S2"):
        assert "start" in windows[sid] and "end" in windows[sid]
        assert windows[sid]["start"] <= windows[sid]["end"]
    assert len(calls) == 2


def test_score_against_ground_truth_stock_and_benign():
    gt = json.loads((Path(__file__).resolve().parents[1] / "eval" / "ground_truth.json").read_text(encoding="utf-8"))
    stock_alert = {
        "source": "falco",
        "scenario": "",
        "attributed_scenario": "S11",
        "severity": "WARNING",
        "title": "Terminal shell in container",
    }

    res_no_stock = harness.score_against_ground_truth([stock_alert], gt, include_stock_falco=False)
    assert "S11" not in res_no_stock
    assert "S29" not in res_no_stock

    res_stock = harness.score_against_ground_truth([stock_alert], gt, include_stock_falco=True)
    assert res_stock["S11"]["fired"] is True
    assert res_stock["S11"]["matches_expectation"] is True
    assert res_stock["S20"]["fired"] is False
    assert res_stock["S20"]["matches_expectation"] is True
    assert res_stock["S26"]["fired"] is False
    assert res_stock["S26"]["matches_expectation"] is True
    assert "S29" not in res_stock

    res_priv = harness.score_against_ground_truth([stock_alert], gt, include_stock_falco=True, privileged_debug=True)
    assert "S29" in res_priv

    assert harness.score_against_ground_truth([stock_alert], gt, benign_only=True) == {}


def test_start_benign_workload_passes_out_env(tmp_path, monkeypatch):
    captured = {}

    def fake_popen(cmd, stdout=None, stderr=None, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return type("Proc", (), {"poll": lambda self: 0})()

    monkeypatch.setattr(harness.subprocess, "Popen", fake_popen)
    out_dir = tmp_path / "run_001"
    out_dir.mkdir()
    _proc, log_f = harness.start_benign_workload(
        tmp_path / "benign_workload.sh",
        5,
        out_dir / "benign.log",
        out_dir=out_dir,
    )
    log_f.close()
    assert captured["env"]["OUT"] == str(out_dir)


def test_load_benign_actions_and_dual_reports(tmp_path):
    gt = json.loads((Path(__file__).resolve().parents[1] / "eval" / "ground_truth.json").read_text(encoding="utf-8"))
    actions_file = tmp_path / "benign_actions.jsonl"
    actions_file.write_text(
        json.dumps(
            {
                "start": "2026-11-15T12:00:02Z",
                "end": "2026-11-15T12:00:02Z",
                "container": "sentinelmesh-webapp",
                "action": "log_rotation",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    loaded = harness.load_benign_actions(actions_file)
    assert len(loaded) == 1
    assert loaded[0]["action"] == "log_rotation"
    assert harness.load_benign_actions(tmp_path / "missing.jsonl") == []

    ambiguous_s11 = {
        "source": "falco",
        "scenario": "",
        "attributed_scenario": "S11",
        "attribution": "ambiguous",
        "severity": "WARNING",
        "title": "Terminal shell in container",
    }
    clear_s25 = {
        "source": "falco",
        "scenario": "",
        "attributed_scenario": "S25",
        "attribution": "attack",
        "severity": "WARNING",
        "title": "Launch Suspicious Network Tool in Container",
    }
    att_summary = harness.summarize_attribution([ambiguous_s11, clear_s25])
    reports = harness.build_dual_reports(
        [ambiguous_s11, clear_s25],
        gt,
        att_summary,
        include_stock_falco=True,
    )
    assert reports["ambiguous_excluded"]["results"]["S11"]["fired"] is False
    assert reports["ambiguous_excluded"]["results"]["S25"]["fired"] is True
    assert reports["ambiguous_as_attack"]["results"]["S11"]["fired"] is True
    assert reports["ambiguous_as_attack"]["results"]["S25"]["fired"] is True


def test_write_run_manifest_records_container_digests(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output=True, text=True, timeout=15):
        if cmd[:2] == ["docker", "ps"]:
            return type("Res", (), {"returncode": 0, "stdout": "sentinelmesh-webapp\nsentinelmesh-debug\n"})()
        if cmd[:2] == ["docker", "inspect"]:
            name = cmd[-1]
            if name == "sentinelmesh-debug":
                return type("Res", (), {"returncode": 0, "stdout": "alpine:3.19@sha256:aaa\tsha256:111\n"})()
            return type("Res", (), {"returncode": 0, "stdout": "sentinelmesh-webapp\tsha256:222\n"})()
        if cmd[:3] == ["docker", "image", "inspect"]:
            ref = cmd[-1]
            if ref == "sha256:111":
                return type("Res", (), {"returncode": 0, "stdout": json.dumps(["alpine@sha256:aaa"])})()
            return type("Res", (), {"returncode": 0, "stdout": json.dumps([])})()
        return type("Res", (), {"returncode": 1, "stdout": ""})()

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    manifest = harness.write_run_manifest(tmp_path)
    text = manifest.read_text(encoding="utf-8")
    assert "sentinelmesh-debug image=alpine:3.19@sha256:aaa digest=alpine@sha256:aaa image_id=sha256:111" in text
    assert "sentinelmesh-webapp image=sentinelmesh-webapp digest=sha256:222 image_id=sha256:222" in text


def test_score_against_ground_truth_excludes_setup_alerts():
    gt = json.loads((Path(__file__).resolve().parents[1] / "eval" / "ground_truth.json").read_text(encoding="utf-8"))
    setup_s7 = {
        "source": "log-tail",
        "scenario": "S7",
        "attributed_scenario": "unattributed",
        "attribution": "setup",
        "severity": "WARNING",
        "title": gt["scenarios"]["S7"]["detection"]["expected_title"],
    }
    res = harness.score_against_ground_truth([setup_s7], gt, include_stock_falco=True)
    assert res["S7"]["fired"] is False
    assert res["S7"]["match_count"] == 0


def test_run_attack_scripts_lock_busy_wait_and_seconds_between_attacks(tmp_path, monkeypatch):
    assert harness.SECONDS_BETWEEN_ATTACKS == 15

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for _, fname, _ in harness.DEFAULT_ATTACK_ORDER[:2]:
        (scripts_dir / fname).write_text("exit 0\n", encoding="utf-8")

    run_dir = tmp_path / "run_001"
    run_dir.mkdir()
    lock_path = run_dir / "attack.lock"
    busy_path = Path(f"{lock_path}.busy")

    busy_path.write_text("", encoding="utf-8")
    sleeps = []
    saw_lock_during_run = []

    def fake_sleep(secs):
        sleeps.append(secs)
        # Clear busy file on the second busy poll tick before S1 runs
        if secs == 0.1 and busy_path.exists() and len(sleeps) >= 2:
            busy_path.unlink()

    def fake_run(cmd, timeout=30, capture_output=True, text=True):
        saw_lock_during_run.append((Path(cmd[1]).name, lock_path.exists(), busy_path.exists()))
        return type("Res", (), {"stdout": "", "stderr": "", "returncode": 0})()

    monkeypatch.setattr(harness.time, "sleep", fake_sleep)
    monkeypatch.setattr(harness.subprocess, "run", fake_run)

    windows, _ = harness.run_attack_scripts(scripts_dir, lock_path=lock_path)
    assert not lock_path.exists()
    assert len(saw_lock_during_run) == 2
    assert all(locked and not busy for _, locked, busy in saw_lock_during_run)

    for sid in ("S1", "S2"):
        w = windows[sid]
        assert w["lock_start"] <= w["start"] <= w["end"] <= w["lock_end"]

    # Two busy-wait 0.1s ticks + two scenarios each with
    # (quiet_margin=3, post_wait=3, lock_tail=3, inter_gap=6)
    assert sleeps == [0.1, 0.1, 3, 3, 3, 6, 3, 3, 3, 6]


def test_run_attack_scripts_window_starts_3s_after_last_benign_action_end(tmp_path, monkeypatch):
    """F8: window start >= 3 s after the benign busy file clears; lock held >= 3 s after window end."""
    from datetime import datetime as real_datetime, timedelta, timezone

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for _, fname, _ in harness.DEFAULT_ATTACK_ORDER[:2]:
        (scripts_dir / fname).write_text("exit 0\n", encoding="utf-8")

    lock_path = tmp_path / "attack.lock"
    busy_path = Path(f"{lock_path}.busy")
    busy_path.write_text("", encoding="utf-8")

    base = real_datetime(2026, 11, 16, 6, 8, 30, tzinfo=timezone.utc)
    clock = {"t": 0.0}
    benign_end = {}

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return base + timedelta(seconds=clock["t"])

    def fake_sleep(secs):
        clock["t"] += secs
        # Benign action finishes (busy file removed) at a fractional second.
        if busy_path.exists() and clock["t"] >= 0.7:
            busy_path.unlink()
            benign_end["t"] = base + timedelta(seconds=clock["t"])

    def fake_run(cmd, timeout=30, capture_output=True, text=True):
        clock["t"] += 0.4
        return type("Res", (), {"stdout": "", "stderr": "", "returncode": 0})()

    monkeypatch.setattr(harness, "datetime", FakeDatetime)
    monkeypatch.setattr(harness.time, "sleep", fake_sleep)
    monkeypatch.setattr(harness.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(harness.subprocess, "run", fake_run)

    windows, _ = harness.run_attack_scripts(scripts_dir, lock_path=lock_path)

    def parse(ts):
        return real_datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    # Benign end is recorded at whole seconds by benign_workload.sh (truncated).
    benign_end_whole = benign_end["t"].replace(microsecond=0)
    s1 = windows["S1"]
    assert (parse(s1["start"]) - benign_end_whole).total_seconds() >= 3
    for sid in ("S1", "S2"):
        w = windows[sid]
        assert (parse(w["lock_end"]) - parse(w["end"])).total_seconds() >= 3


def test_start_benign_workload_passes_attack_lock_env(tmp_path, monkeypatch):
    captured = {}

    def fake_popen(cmd, stdout=None, stderr=None, env=None):
        captured["env"] = env
        return type("Proc", (), {"poll": lambda self: 0})()

    monkeypatch.setattr(harness.subprocess, "Popen", fake_popen)
    out_dir = tmp_path / "run_002"
    out_dir.mkdir()
    lock_path = out_dir / "attack.lock"
    _proc, log_f = harness.start_benign_workload(
        tmp_path / "benign_workload.sh",
        5,
        out_dir / "benign.log",
        out_dir=out_dir,
        attack_lock_path=lock_path,
    )
    log_f.close()
    assert captured["env"]["OUT"] == str(out_dir)
    assert captured["env"]["SM_ATTACK_LOCK"] == str(lock_path)


def test_score_against_ground_truth_counts_designated_rule_and_excludes_collateral():
    gt = json.loads((Path(__file__).resolve().parents[1] / "eval" / "ground_truth.json").read_text(encoding="utf-8"))
    windows = {
        "S11": {"start": "2026-11-16T04:28:02Z", "end": "2026-11-16T04:28:06Z"},
        "S12": {"start": "2026-11-16T04:28:07Z", "end": "2026-11-16T04:28:16Z"},
        "S20": {"start": "2026-11-16T04:28:59Z", "end": "2026-11-16T04:29:04Z"},
    }
    raw_alerts = [
        # S9 lab rule firing during S20 on database -> designated_rule=False, must NOT count as S9 or S20 firing
        {
            "source": "falco",
            "scenario": "S9",
            "severity": "CRITICAL",
            "title": "SentinelMesh Sensitive Credential File Read",
            "timestamp": "2026-11-16T04:29:00Z",
            "service": "database",
            "event": {"container.name": "sentinelmesh-database", "fd.name": "/etc/shadow"},
        },
        # Non-designated stock rule during S12 -> must NOT count as S12 firing
        {
            "source": "falco",
            "scenario": "",
            "severity": "CRITICAL",
            "title": "Read ssh information",
            "timestamp": "2026-11-16T04:28:13Z",
            "service": "webapp",
            "falco_tags": ["T1005"],
            "event": {"container.name": "sentinelmesh-webapp"},
        },
        # Collateral Terminal shell in database during S11 -> must NOT count as S11 firing
        {
            "source": "falco",
            "scenario": "",
            "severity": "WARNING",
            "title": "Terminal shell in container",
            "timestamp": "2026-11-16T04:28:03Z",
            "service": "database",
            "falco_tags": ["T1059"],
            "event": {"container.name": "sentinelmesh-database"},
        },
    ]

    attributed = harness.attribute_alerts(raw_alerts, windows, gt)
    res = harness.score_against_ground_truth(attributed, gt, include_stock_falco=True)
    assert res["S9"]["fired"] is False
    assert res["S11"]["fired"] is False
    assert res["S12"]["fired"] is False
    assert res["S20"]["fired"] is False


def test_check_run_benign_only_skips_s10_and_reports_collateral(tmp_path, monkeypatch, capsys):
    import sys
    from linux_run import check_run

    # 1. Benign-only run: S10 chain skipped and exits cleanly (returns without sys.exit(2))
    benign_dir = tmp_path / "20261116T000000Z"
    benign_dir.mkdir()
    (benign_dir / "alerts.jsonl").write_text("", encoding="utf-8")
    (benign_dir / "alerts_attributed.jsonl").write_text("", encoding="utf-8")
    (benign_dir / "baseline1_results.json").write_text(
        json.dumps(
            {
                "benign_only": True,
                "single_scenario_pass_count": 0,
                "single_scenario_total": 0,
                "s10_chain_all_stages_fired": None,
                "attribution_summary": {
                    "by_attribution": {
                        "attack": 0,
                        "attack_collateral": 0,
                        "ambiguous": 0,
                        "benign": 0,
                        "setup": 0,
                        "unattributed": 0,
                    }
                },
                "results": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["check_run.py", str(benign_dir)])
    check_run.main()
    out_benign = capsys.readouterr().out
    assert "S10 chain: skipped (benign-only capture)" in out_benign
    assert "Attribution counts:" in out_benign

    # 2. Attack run with collateral alert prints collateral block
    atk_dir = tmp_path / "20261116T000100Z"
    atk_dir.mkdir()
    collateral_alert = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Launch Sensitive Mount Container",
        "timestamp": "2026-11-16T04:27:33Z",
        "service": "pensive_knuth",
        "attribution": "attack_collateral",
        "attributed_scenario": "S5",
        "rule_technique": "T1610",
        "event": {"container.name": "pensive_knuth"},
    }
    (atk_dir / "alerts.jsonl").write_text(json.dumps(collateral_alert) + "\n", encoding="utf-8")
    (atk_dir / "alerts_attributed.jsonl").write_text(json.dumps(collateral_alert) + "\n", encoding="utf-8")
    (atk_dir / "baseline1_results.json").write_text(
        json.dumps(
            {
                "benign_only": False,
                "single_scenario_pass_count": 0,
                "single_scenario_total": 0,
                "s10_chain_all_stages_fired": False,
                "attribution_summary": {
                    "by_attribution": {
                        "attack": 0,
                        "attack_collateral": 1,
                        "ambiguous": 0,
                        "benign": 0,
                        "setup": 0,
                        "unattributed": 0,
                    }
                },
                "results": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["check_run.py", str(atk_dir)])
    try:
        check_run.main()
    except SystemExit:
        pass
    out_atk = capsys.readouterr().out
    assert "Collateral alerts (1):" in out_atk
    assert "[S5] pensive_knuth / Launch Sensitive Mount Container (rule_technique=T1610)" in out_atk


def test_check_run_s5_lab_service_warning_skips_attack_collateral(tmp_path, monkeypatch, capsys):
    """F10: S5 source-IP block and lab-service warning ignore collateral of other scenarios."""
    import sys
    from linux_run import check_run

    run_dir = tmp_path / "20261116T060830Z"
    run_dir.mkdir()
    s5_collateral = {
        "source": "falco",
        "scenario": "S5",
        "severity": "WARNING",
        "title": "SentinelMesh Unauthorized Database Connection",
        "timestamp": "2026-11-16T06:10:00Z",
        "service": "database",
        "event": {"container.name": "sentinelmesh-database", "fd.rip": "172.30.0.6"},
        "attribution": "attack_collateral",
        "attributed_scenario": "S7",
    }
    s5_attack = dict(
        s5_collateral,
        event={"container.name": "sentinelmesh-database", "fd.rip": "172.30.0.7"},
        attribution="attack",
        attributed_scenario="S5",
    )
    lines = "\n".join(json.dumps(a) for a in (s5_collateral, s5_attack)) + "\n"
    (run_dir / "alerts.jsonl").write_text(lines, encoding="utf-8")
    (run_dir / "alerts_attributed.jsonl").write_text(lines, encoding="utf-8")
    (run_dir / "baseline1_results.json").write_text(
        json.dumps(
            {
                "benign_only": False,
                "single_scenario_pass_count": 1,
                "single_scenario_total": 1,
                "s10_chain_all_stages_fired": None,
                "attribution_summary": {},
                "results": {"S5": {"fired": True, "match_count": 1}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["check_run.py", str(run_dir)])
    try:
        check_run.main()
    except SystemExit:
        pass
    out = capsys.readouterr().out
    s5_block = out.split("S5 alerts by source IP:", 1)[1].split("S6 writes:", 1)[0]
    assert "172.30.0.7" in s5_block
    assert "172.30.0.6" not in s5_block
    assert "S5 fired for lab service" not in out


def test_check_run_matched_column_uses_designated_rule_and_attack(tmp_path, monkeypatch, capsys):
    """F11: matched column counts designated_rule=True alerts with attribution in attack."""
    import sys
    from linux_run import check_run

    run_dir = tmp_path / "20261119T104620Z"
    run_dir.mkdir()
    s7_login = {
        "source": "log-tail",
        "scenario": "S7",
        "severity": "WARNING",
        "title": "Grafana Login Succeeded (unconfirmed)",
        "timestamp": "2026-11-19T10:47:00Z",
        "service": "dashboard",
        "attribution": "attack",
        "attributed_scenario": "S7",
        "designated_rule": True,
    }
    s7_anon = {
        "source": "log-tail",
        "scenario": "S7",
        "severity": "WARNING",
        "title": "Grafana Anonymous Dashboard Access",
        "timestamp": "2026-11-19T10:47:01Z",
        "service": "dashboard",
        "attribution": "attack",
        "attributed_scenario": "S7",
        "designated_rule": True,
    }
    s7_non_designated = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Terminal shell in container",
        "timestamp": "2026-11-19T10:47:01Z",
        "service": "dashboard",
        "attribution": "attack",
        "attributed_scenario": "S7",
        "designated_rule": False,
    }
    s7_collateral = {
        "source": "falco",
        "scenario": "",
        "severity": "WARNING",
        "title": "Grafana Login Succeeded",
        "timestamp": "2026-11-19T10:47:01Z",
        "service": "webapp",
        "attribution": "attack_collateral",
        "attributed_scenario": "S7",
        "designated_rule": True,
    }
    raw_lines = "\n".join(json.dumps(a) for a in (s7_login, s7_anon)) + "\n"
    att_lines = "\n".join(
        json.dumps(a) for a in (s7_login, s7_anon, s7_non_designated, s7_collateral)
    ) + "\n"
    (run_dir / "alerts.jsonl").write_text(raw_lines, encoding="utf-8")
    (run_dir / "alerts_attributed.jsonl").write_text(att_lines, encoding="utf-8")
    (run_dir / "baseline1_results.json").write_text(
        json.dumps(
            {
                "benign_only": False,
                "single_scenario_pass_count": 1,
                "single_scenario_total": 1,
                "s10_chain_all_stages_fired": None,
                "attribution_summary": {},
                "results": {"S7": {"fired": True, "match_count": 1}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["check_run.py", str(run_dir)])
    try:
        check_run.main()
    except SystemExit:
        pass
    out = capsys.readouterr().out
    s7_line = next(line for line in out.splitlines() if line.strip().startswith("S7 "))
    assert "matched=2" in s7_line


def test_reattribute_rebuilds_outputs_writes_prev_and_keeps_raw(tmp_path, capsys):
    """F13: eval/reattribute.py backs up old derived files to *.prev without altering raw files."""
    from eval import reattribute

    run_dir = tmp_path / "20261119T104620Z"
    run_dir.mkdir()
    raw_falco = '{"rule":"Launch Sensitive Mount Container"}\n'
    (run_dir / "falco_alerts_raw.jsonl").write_text(raw_falco, encoding="utf-8")

    windows = {
        "S5": {"start": "2026-11-19T10:46:40Z", "end": "2026-11-19T10:46:48Z"},
        "S7": {"start": "2026-11-19T10:47:00Z", "end": "2026-11-19T10:47:05Z"},
    }
    (run_dir / "scenario_windows.json").write_text(json.dumps(windows), encoding="utf-8")
    (run_dir / "benign_actions.jsonl").write_text("", encoding="utf-8")

    alerts = [
        {
            "source": "falco",
            "scenario": "",
            "severity": "WARNING",
            "title": "Launch Sensitive Mount Container",
            "timestamp": "2026-11-19T10:46:42Z",
            "service": "unknown",
            "falco_tags": ["container", "T1610"],
            "event": {
                "container.name": None,
                "container.id": "abc12345",
                "container.image.repository": "postgres",
            },
        },
        {
            "source": "log-tail",
            "scenario": "S7",
            "severity": "WARNING",
            "title": "Grafana Anonymous Dashboard Access",
            "timestamp": "2026-11-19T10:47:02Z",
            "service": "dashboard",
        },
    ]
    raw_alerts_text = "\n".join(json.dumps(a) for a in alerts) + "\n"
    (run_dir / "alerts.jsonl").write_text(raw_alerts_text, encoding="utf-8")

    old_att_text = (
        json.dumps(dict(alerts[0], attribution="unattributed", attributed_scenario="unattributed"))
        + "\n"
        + json.dumps(dict(alerts[1], attribution="attack", attributed_scenario="S7", designated_rule=False))
        + "\n"
    )
    old_res_text = json.dumps({"include_stock_falco": True, "benign_only": False, "results": {}})
    old_rep_text = "old report\n"
    (run_dir / "alerts_attributed.jsonl").write_text(old_att_text, encoding="utf-8")
    (run_dir / "baseline1_results.json").write_text(old_res_text, encoding="utf-8")
    (run_dir / "run_report.txt").write_text(old_rep_text, encoding="utf-8")

    rc = reattribute.main([str(run_dir)])
    assert rc == 0

    # *.prev backups keep previous contents cleanly; raw files are untouched
    assert (run_dir / "alerts_attributed.jsonl.prev").read_text(encoding="utf-8") == old_att_text
    assert (run_dir / "baseline1_results.json.prev").read_text(encoding="utf-8") == old_res_text
    assert (run_dir / "run_report.txt.prev").read_text(encoding="utf-8") == old_rep_text
    assert (run_dir / "falco_alerts_raw.jsonl").read_text(encoding="utf-8") == raw_falco
    assert (run_dir / "alerts.jsonl").read_text(encoding="utf-8") == raw_alerts_text

    new_att = [
        json.loads(line)
        for line in (run_dir / "alerts_attributed.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert new_att[0]["attribution"] == "attack_collateral"
    assert new_att[0]["attributed_scenario"] == "S5"
    assert new_att[1]["attribution"] == "attack"
    assert new_att[1]["designated_rule"] is True

    new_res = json.loads((run_dir / "baseline1_results.json").read_text(encoding="utf-8"))
    assert new_res["attribution_summary"]["attack_collateral_count"] == 1
    assert new_res["attribution_summary"]["attack_count"] == 1

    report_text = (run_dir / "run_report.txt").read_text(encoding="utf-8")
    s7_line = next(line for line in report_text.splitlines() if line.strip().startswith("S7 "))
    assert "matched=1" in s7_line
    assert "postgres / Launch Sensitive Mount Container" in report_text

    printed = capsys.readouterr().out
    assert "attack_collateral" in printed
    assert "unattributed" in printed


def test_write_run_manifest_records_env_profile_and_host_versions(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    e2_env_path = repo_root / "env" / "E2.env"
    e2_values = parse_env_file(e2_env_path)

    def fake_run(cmd, capture_output=True, text=True, timeout=15):
        if cmd == ["docker", "--version"]:
            return type("Res", (), {"returncode": 0, "stdout": "Docker version 27.3.1, build test\n"})()
        if cmd == ["falco", "--version"]:
            return type("Res", (), {"returncode": 0, "stdout": "Falco version: 0.45.0\n"})()
        if cmd[:2] == ["docker", "ps"]:
            return type("Res", (), {"returncode": 0, "stdout": ""})()
        return type("Res", (), {"returncode": 1, "stdout": ""})()

    fake_os_release = tmp_path / "os-release"
    fake_os_release.write_text('PRETTY_NAME="Ubuntu 24.04.1 LTS"\n', encoding="utf-8")
    monkeypatch.setattr(harness, "_OS_RELEASE_PATH", fake_os_release)
    monkeypatch.setattr(harness.subprocess, "run", fake_run)

    manifest = harness.write_run_manifest(tmp_path, env_file=e2_env_path)
    text = manifest.read_text(encoding="utf-8")

    assert "env_id: E2" in text
    assert "container_prefix: smx" in text
    assert "host_os: Ubuntu 24.04.1 LTS" in text
    assert "kernel:" in text
    assert "docker_version: Docker version 27.3.1, build test" in text
    assert "falco_version: Falco version: 0.45.0" in text
    for key, val in e2_values.items():
        assert f"{key}={val}" in text
    assert read_prefix_from_manifest(manifest) == "smx"


def _find_working_bash() -> str | None:
    candidates = []
    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ])
    which_bash = shutil.which("bash")
    if which_bash and not which_bash.lower().endswith(r"\system32\bash.exe"):
        candidates.append(which_bash)
    for cand in candidates:
        if cand and Path(cand).exists():
            return cand
    return None


def _copy_managed_tree(src_root: Path, dst_root: Path) -> None:
    rel_paths = [
        "env",
        "linux_run/set_env.sh",
        "linux_run/set_subnet.sh",
        "linux_run/preflight.sh",
        "linux_run/check_run.py",
        "docker-compose.yml",
        "docker-compose.debug.yml",
        "detection/falco-rules",
        "detection/log-tail/tailer.py",
        "services/logcollector/Dockerfile",
        "services/logcollector/fluent.conf",
        "services/database/init.sql",
        "services/dashboard/provisioning/datasources.yml",
    ]
    for rel in rel_paths:
        src = src_root / rel
        dst = dst_root / rel
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def test_set_env_roundtrip_and_leftover_refusal(tmp_path):
    bash_bin = _find_working_bash()
    if bash_bin is None:
        pytest.skip("No working bash executable available for set_env.sh test")

    repo_root = Path(__file__).resolve().parents[1]
    _copy_managed_tree(repo_root, tmp_path)

    managed_files = [
        "docker-compose.yml",
        "docker-compose.debug.yml",
        "detection/falco-rules/s05_db_access.yaml",
        "detection/falco-rules/s06_log_tamper.yaml",
        "detection/falco-rules/s08_exfiltration.yaml",
        "detection/falco-rules/s09_credential_access.yaml",
        "detection/log-tail/tailer.py",
        "linux_run/preflight.sh",
        "linux_run/check_run.py",
        "services/logcollector/Dockerfile",
        "services/logcollector/fluent.conf",
        "services/database/init.sql",
        "services/dashboard/provisioning/datasources.yml",
    ]
    e1_snapshot = {rel: (tmp_path / rel).read_text(encoding="utf-8") for rel in managed_files}

    def run_sh(*args: str):
        snap = {
            rel: (tmp_path / rel).read_bytes()
            for rel in [*managed_files, ".env"]
            if (tmp_path / rel).exists()
        }
        had_dot_env = (tmp_path / ".env").exists()
        last = None
        for _ in range(3 if os.name == "nt" else 1):
            last = subprocess.run(
                [bash_bin, *args],
                cwd=tmp_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if (
                os.name == "nt"
                and last.returncode != 0
                and ("cygheap" in (last.stderr or "") or "Win32 error" in (last.stderr or ""))
            ):
                for rel, data in snap.items():
                    (tmp_path / rel).write_bytes(data)
                if not had_dot_env and (tmp_path / ".env").exists():
                    (tmp_path / ".env").unlink()
                continue
            return last
        return last

    res_e2 = run_sh("linux_run/set_env.sh", "E2")
    assert res_e2.returncode == 0, res_e2.stderr

    dot_env = parse_env_file(tmp_path / ".env")
    assert dot_env["ENV_ID"] == "E2"
    assert dot_env["CONTAINER_PREFIX"] == "smx"
    assert dot_env["WEBAPP_PORT"] == "6000"

    compose_e2 = (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")
    assert "smx-webapp" in compose_e2
    assert "smx_net" in compose_e2
    assert "127.0.0.1:6000:5000" in compose_e2
    assert "LOG_DIR=/srv/smx/logs" in compose_e2
    assert "JWT_SECRET=smx_jwt_4b8e2f91c7d360a5e8b1d4f2" in compose_e2
    assert "POSTGRES_DB=smx" in compose_e2
    assert "sentinelmesh-webapp" not in compose_e2
    assert "/var/log/sentinelmesh" not in compose_e2

    s09_e2 = (tmp_path / "detection/falco-rules/s09_credential_access.yaml").read_text(encoding="utf-8")
    assert 'container.name startswith "smx-"' in s09_e2

    # Subnet switch commutes with E2 and reverts cleanly
    assert run_sh("linux_run/set_subnet.sh", "172.18").returncode == 0
    assert "172.18.0." in (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")
    assert "smx-webapp" in (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")

    # Switching back to E1 keeps current 172.18 subnet untouched
    assert run_sh("linux_run/set_env.sh", "E1").returncode == 0
    assert "172.18.0." in (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")
    assert "sentinelmesh-webapp" in (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")

    # Restoring subnet produces byte-identical E1 files
    assert run_sh("linux_run/set_subnet.sh", "172.30").returncode == 0
    for rel, original in e1_snapshot.items():
        assert (tmp_path / rel).read_text(encoding="utf-8") == original

    # Refuses to finish when a leftover deployment value cannot be cleared by rewriting s05
    s05 = tmp_path / "detection/falco-rules/s05_db_access.yaml"
    s05.write_text(s05.read_text(encoding="utf-8") + "\n# leftover /var/log/sentinelmesh\n", encoding="utf-8")
    res_fail = run_sh("linux_run/set_env.sh", "E2")
    assert res_fail.returncode != 0
    assert "LEFTOVER" in res_fail.stderr
