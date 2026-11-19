"""Unit tests for eval/harness.py ENV2 additions."""

from __future__ import annotations

import json
from pathlib import Path

from eval import harness


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
