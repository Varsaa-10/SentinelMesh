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
