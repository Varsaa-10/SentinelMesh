#!/usr/bin/env python3
"""Relabel and rescore one or more existing ENV2 run folders without modifying raw files.

Usage:
    python3 eval/reattribute.py eval/runs_smoke/20261119T104620Z [...]
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.attribute import (  # noqa: E402
    ATTRIBUTION_VALUES,
    attribute_alerts,
    summarize_attribution,
)
from eval.harness import build_dual_reports, load_benign_actions  # noqa: E402
from linux_run import check_run  # noqa: E402


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if raw:
                records.append(json.loads(raw))
    return records


def _backup_to_prev(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    prev_path = Path(f"{path}.prev")
    shutil.copy2(path, prev_path)
    return prev_path


def _resolve_ground_truth_path(
    old_summary: Mapping[str, Any],
    override_path: Optional[Path],
) -> Path:
    if override_path is not None:
        return Path(override_path)
    recorded = old_summary.get("ground_truth_file")
    if isinstance(recorded, str) and recorded.strip():
        candidate = Path(recorded)
        if candidate.exists():
            return candidate
    return REPO_ROOT / "eval" / "ground_truth.json"


def _render_check_run_report(run_dir: Path) -> str:
    buf = io.StringIO()
    old_argv = sys.argv
    sys.argv = ["check_run.py", str(run_dir)]
    try:
        with redirect_stdout(buf):
            try:
                check_run.main()
            except SystemExit:
                pass
    finally:
        sys.argv = old_argv
    return buf.getvalue()


def _count_attributions(records: Sequence[Mapping[str, Any]]) -> Counter:
    return Counter((a.get("attribution") or "unattributed") for a in records)


def reattribute_run(
    run_dir: Path,
    ground_truth_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Rebuild derived attribution, scoring, and report outputs for `run_dir`."""
    run_path = Path(run_dir)
    alerts_path = run_path / "alerts.jsonl"
    if not alerts_path.exists():
        raise FileNotFoundError(f"Missing alerts.jsonl in {run_path}")

    alerts = _load_jsonl(alerts_path)

    windows_path = run_path / "scenario_windows.json"
    scenario_windows: Dict[str, Any] = (
        json.loads(windows_path.read_text(encoding="utf-8"))
        if windows_path.exists()
        else {}
    )
    benign_actions = load_benign_actions(run_path / "benign_actions.jsonl")

    results_path = run_path / "baseline1_results.json"
    old_summary: Dict[str, Any] = (
        json.loads(results_path.read_text(encoding="utf-8"))
        if results_path.exists()
        else {}
    )

    gt_file = _resolve_ground_truth_path(old_summary, ground_truth_path)
    ground_truth = json.loads(gt_file.read_text(encoding="utf-8"))

    attributed_path = run_path / "alerts_attributed.jsonl"
    before_counts = _count_attributions(
        _load_jsonl(attributed_path) if attributed_path.exists() else []
    )

    report_path = run_path / "run_report.txt"
    for target in (attributed_path, results_path, report_path):
        _backup_to_prev(target)

    benign_only = bool(old_summary.get("benign_only", False))
    include_stock_falco = bool(old_summary.get("include_stock_falco", False))
    privileged_debug = bool(old_summary.get("privileged_debug", False))

    attributed = attribute_alerts(
        alerts,
        scenario_windows,
        ground_truth,
        benign_only=benign_only,
        benign_actions=benign_actions,
    )
    attribution_summary = summarize_attribution(attributed)
    dual_reports = build_dual_reports(
        attributed,
        ground_truth,
        attribution_summary,
        include_stock_falco=include_stock_falco,
        privileged_debug=privileged_debug,
        benign_only=benign_only,
    )
    as_attack = dual_reports["ambiguous_as_attack"]

    with open(attributed_path, "w", encoding="utf-8") as f:
        for alert in attributed:
            f.write(json.dumps(alert) + "\n")

    new_summary = dict(old_summary)
    new_summary.setdefault("run_id", run_path.name)
    new_summary.setdefault("run_timestamp_utc", run_path.name)
    new_summary.setdefault(
        "baseline",
        "Baseline 1 (Falco-only + log-tail + S7 Grafana detector, no RAG/graph/response)",
    )
    new_summary.update(
        {
            "include_stock_falco": include_stock_falco,
            "privileged_debug": privileged_debug,
            "benign_only": benign_only,
            "benign_minutes": old_summary.get("benign_minutes", 0),
            "benign_actions_count": sum(
                1 for a in benign_actions if a.get("action") not in ("pause", "resume")
            ),
            "scenario_windows": scenario_windows,
            "attribution_summary": attribution_summary,
            "ground_truth_file": old_summary.get("ground_truth_file", str(gt_file.resolve())),
            "total_alerts_captured": len(alerts),
            "single_scenario_pass_count": as_attack["single_scenario_pass_count"],
            "single_scenario_total": as_attack["single_scenario_total"],
            "s10_chain_all_stages_fired": as_attack["s10_chain_all_stages_fired"],
            "results": as_attack["results"],
            "reports": dual_reports,
        }
    )
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(new_summary, f, indent=2, default=str)

    report_text = _render_check_run_report(run_path)
    report_path.write_text(report_text, encoding="utf-8")

    after_counts = _count_attributions(attributed)
    return {
        "run_dir": str(run_path),
        "total_alerts": len(alerts),
        "before_counts": dict(before_counts),
        "after_counts": dict(after_counts),
    }


def _print_diff(info: Mapping[str, Any]) -> None:
    before = info["before_counts"]
    after = info["after_counts"]
    extras = sorted((set(before) | set(after)) - set(ATTRIBUTION_VALUES))
    keys = list(ATTRIBUTION_VALUES) + extras
    print(f"[reattribute] {info['run_dir']} ({info['total_alerts']} alerts)")
    print(f"  {'attribution':<20} {'before':>6} {'after':>6} {'delta':>7}")
    for key in keys:
        b = int(before.get(key, 0))
        a = int(after.get(key, 0))
        print(f"  {key:<20} {b:>6} {a:>6} {a - b:>+7}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Relabel saved alerts.jsonl into updated attribution, scoring, and run_report.txt."
    )
    ap.add_argument("run_dirs", nargs="+", help="One or more run folders (e.g. eval/runs/2026...)")
    ap.add_argument(
        "--ground-truth",
        default=None,
        help="Optional path to ground_truth.json (defaults to run's file if present or eval/ground_truth.json)",
    )
    args = ap.parse_args(argv)
    gt_override = Path(args.ground_truth) if args.ground_truth else None

    for run_dir in args.run_dirs:
        info = reattribute_run(Path(run_dir), ground_truth_path=gt_override)
        _print_diff(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
