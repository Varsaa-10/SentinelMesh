"""
eval/repeated_run_harness.py — SentinelMesh Module C3.

Runs the same scenario set multiple iterations with feedback accumulating
between runs, logging results per iteration, and computing the four
adaptation metrics defined in the execution plan:

  1. reduction in unnecessary human approvals
  2. reduction in unsafe automated actions
  3. MTTR improvement after feedback
  4. convergence of approval thresholds across iterations

A `human_reviewer` callback decides approve/reject/modify for each routed
alert. By default this harness uses a *simulated* reviewer driven by
ground truth (so it can run unattended tonight); swap in a real callback
(e.g. reading from a UI/queue) for an actual human-in-the-loop run later
— the harness itself doesn't change.
"""

from __future__ import annotations

import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from response.risk_scoring import assess, ROUTING_THRESHOLDS  # noqa: E402
from eval.feedback_loop import FeedbackLoop  # noqa: E402

# Synthetic processing time per routing tier, in seconds — used only to
# make MTTR concrete and comparable across iterations for a lab-scale
# reproducible demo (real deployments would log actual wall-clock time).
TIER_LATENCY_SECONDS = {"auto": 2.0, "analyst": 45.0, "admin": 180.0}


def simulated_human_reviewer(
    routing: str,
    scenario_id: str,
    predicted_technique: str,
    ground_truth_entry: Dict[str, Any],
) -> str:
    """A stand-in for a real analyst. Approves correct, appropriately-routed
    decisions; rejects auto-routed decisions on high-severity scenarios
    (the human catching what the system under-routed); modifies analyst/
    admin routes on low-severity scenarios (the human correcting an
    over-cautious route) — this asymmetry is exactly what the feedback
    loop should learn to reduce over iterations.
    """
    severity = ground_truth_entry.get("severity", 3)
    technique_correct = predicted_technique == ground_truth_entry.get("technique_id")

    if routing == "auto" and severity >= 4:
        return "reject"          # should not have been auto-approved
    if routing in ("analyst", "admin") and severity <= 2 and technique_correct:
        return "modify"          # over-cautious; could have been auto
    if technique_correct:
        return "approve"
    return "modify"


def run_iteration(
    alerts_with_rag: List[Dict[str, Any]],
    ground_truth: Dict[str, Any],
    thresholds: Dict[str, float],
    graph_paths: Dict[str, int],
    human_reviewer: Callable[..., str],
) -> Dict[str, Any]:
    """One pass over all alerts using the given thresholds. Returns the
    per-alert assessments + human decisions + this iteration's raw metrics.
    """
    records = []
    for item in alerts_with_rag:
        scenario_id = item["scenario_id"]
        rag_result = item["rag_result"]
        gt_entry = ground_truth.get(scenario_id, {})
        if not gt_entry:
            continue

        path_len = graph_paths.get(scenario_id, 1)
        result = assess(scenario_id, rag_result, gt_entry, graph_path_length=path_len, thresholds=thresholds)

        decision = human_reviewer(
            routing=result.routing,
            scenario_id=scenario_id,
            predicted_technique=result.technique_id,
            ground_truth_entry=gt_entry,
        )

        records.append({**result.to_dict(), "human_decision": decision})

    unnecessary_approvals = sum(
        1 for r in records if r["routing"] in ("analyst", "admin") and r["human_decision"] == "modify"
    )
    unsafe_auto = sum(
        1 for r in records if r["routing"] == "auto" and r["human_decision"] == "reject"
    )
    mttr = statistics.mean(TIER_LATENCY_SECONDS[r["routing"]] for r in records) if records else None

    return {
        "records": records,
        "unnecessary_approvals": unnecessary_approvals,
        "unsafe_auto_actions": unsafe_auto,
        "mttr_seconds": round(mttr, 2) if mttr is not None else None,
    }


def run_repeated_evaluation(
    alerts_with_rag: List[Dict[str, Any]],
    ground_truth: Dict[str, Any],
    graph_paths: Optional[Dict[str, int]] = None,
    iterations: int = 5,
    human_reviewer: Callable[..., str] = simulated_human_reviewer,
) -> Dict[str, Any]:
    graph_paths = graph_paths or {}
    loop = FeedbackLoop(auto_threshold=ROUTING_THRESHOLDS["auto"], analyst_threshold=ROUTING_THRESHOLDS["analyst"])

    iteration_summaries = []
    for i in range(iterations):
        thresholds = loop.current_thresholds()
        result = run_iteration(alerts_with_rag, ground_truth, thresholds, graph_paths, human_reviewer)

        feedback_summary = loop.record_iteration(
            [{"routing": r["routing"], "human_decision": r["human_decision"]} for r in result["records"]]
        )

        iteration_summaries.append(
            {
                "iteration": i,
                "thresholds_used": thresholds,
                "unnecessary_approvals": result["unnecessary_approvals"],
                "unsafe_auto_actions": result["unsafe_auto_actions"],
                "mttr_seconds": result["mttr_seconds"],
                "feedback": feedback_summary,
            }
        )

    first, last = iteration_summaries[0], iteration_summaries[-1]

    def pct_change(a, b):
        if a in (0, None):
            return None
        return round((a - b) / a * 100, 2)

    adaptation_metrics = {
        "unnecessary_approvals_reduction_pct": pct_change(
            first["unnecessary_approvals"], last["unnecessary_approvals"]
        ),
        "unsafe_auto_actions_reduction_pct": pct_change(
            first["unsafe_auto_actions"], last["unsafe_auto_actions"]
        ),
        "mttr_improvement_pct": pct_change(first["mttr_seconds"], last["mttr_seconds"]),
        "threshold_convergence_score": loop.convergence_score(),
        "first_iteration": {
            "unnecessary_approvals": first["unnecessary_approvals"],
            "unsafe_auto_actions": first["unsafe_auto_actions"],
            "mttr_seconds": first["mttr_seconds"],
        },
        "last_iteration": {
            "unnecessary_approvals": last["unnecessary_approvals"],
            "unsafe_auto_actions": last["unsafe_auto_actions"],
            "mttr_seconds": last["mttr_seconds"],
        },
    }

    return {
        "iterations_run": iterations,
        "iteration_summaries": iteration_summaries,
        "adaptation_metrics": adaptation_metrics,
        "final_thresholds": loop.current_thresholds(),
    }


def _load_alerts_with_rag(repo_root: Path) -> List[Dict[str, Any]]:
    """Builds the (scenario_id, rag_result) pairs this harness needs from
    Person 2 / Week 2's frozen RAG eval results (one result per alert,
    already scored against ground truth in rag_engine/data/eval_results.json).
    """
    rag_eval = json.loads((repo_root / "rag_engine" / "data" / "eval_results.json").read_text())
    key = "two-layer__tfidf-word__raw"
    per_alert = rag_eval[key]["per_alert"]

    out = []
    for item in per_alert:
        out.append(
            {
                "scenario_id": item["scenario_id"],
                "rag_result": {
                    "predicted_technique": item["predicted_technique"],
                    "predicted_tactic": None,  # filled from ground truth in assess() fallback
                    "confidence": item["confidence"],
                    "evidence": item["evidence"],
                },
            }
        )
    return out


if __name__ == "__main__":
    ground_truth = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text())["scenarios"]
    alerts_with_rag = _load_alerts_with_rag(REPO_ROOT)

    # graph_paths: scenario_id -> reconstructed path length. Without a live
    # graph run wired in yet, single-technique scenarios default to 1; the
    # chain scenario (S10) is set explicitly if present in ground truth.
    graph_paths = {sid: (5 if sid == "S10" else 1) for sid in ground_truth}

    output = run_repeated_evaluation(alerts_with_rag, ground_truth, graph_paths, iterations=5)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = REPO_ROOT / "eval" / "runs" / f"{run_id}_repeated_feedback"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "repeated_run_results.json").write_text(json.dumps(output, indent=2))

    print(json.dumps(output["adaptation_metrics"], indent=2))
    print(f"\nFull results written to {out_dir / 'repeated_run_results.json'}")
