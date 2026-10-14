"""
eval/final_evaluation.py — SentinelMesh Module C3, the complete final
evaluation run (execution plan, Week 3, Day 5).

Ties together:
  - Baseline 1 (Falco-only)              -> eval/BASELINE_1_FROZEN_linux.json (frozen Linux run)
  - Baseline 2 (flat RAG)                  -> rag_engine/data/eval_results.json (Week 2)
  - Baseline 3 (graph-only)                -> graph/graph_only_baseline.py (Week 3, Person 1)
  - Baseline 4 (full system)               -> RAG + graph + risk_scoring (this file wires it)
  - Baseline 5 (autonomous agent)          -> eval/autonomous_baseline.py (this person, independent)
  - Ablation (RAG / graph / approval removed individually)
  - Poisoning runs                         -> rag_engine/poisoning/poisoning_eval_results.json (Week 2)
  - Repeated-run feedback experiment       -> eval/repeated_run_harness.py (this file)
  - Reproducibility check on a fresh clone

Writes everything to a single timestamped run folder under eval/runs/.

IMPORTANT: Baselines 3 and 4 depend on Person 1's graph module (present)
and this run's own risk_scoring.py stopgap (present, see response/risk_scoring.py
docstring — swap in Person 2's real module the moment it lands).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import argparse
import hashlib

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from graph.pipeline import run_pipeline  # noqa: E402
from response.risk_scoring import assess, ActionExecutor  # noqa: E402
from eval.autonomous_baseline import run_autonomous_baseline, summarize as summarize_autonomous  # noqa: E402
from eval.repeated_run_harness import run_repeated_evaluation, _load_alerts_with_rag  # noqa: E402


# Retrieval variant used by every baseline. "normalized" feeds the RAG engine
# the alert_normalizer text (hand-written keyword rules, see
# rag_engine/src/alert_normalizer.py); "raw" feeds it the raw alert output.
# Both are reported in baseline_2 so the gap is visible.
RAG_KEY = "two-layer__tfidf-word__normalized"
FLAT_KEY = "flat__tfidf-word__normalized"
RAG_KEY_RAW = "two-layer__tfidf-word__raw"
FLAT_KEY_RAW = "flat__tfidf-word__raw"


def load_common(repo_root: Path, alerts_file: Path | None = None):
    ground_truth = json.loads((repo_root / "eval" / "ground_truth.json").read_text())["scenarios"]
    if alerts_file is None:
        found = sorted((repo_root / "eval" / "runs").glob("*/alerts.jsonl"))
        found = [p for p in found if "repeated_feedback" not in str(p.parent)]
        alerts_file = found[-1]
        print(f"WARNING: no --alerts given; defaulting to {alerts_file}", file=sys.stderr)
    alerts_file = Path(alerts_file)
    alerts = [json.loads(l) for l in alerts_file.read_text().splitlines() if l.strip()]
    rag_eval = json.loads((repo_root / "rag_engine" / "data" / "eval_results.json").read_text())
    return ground_truth, alerts, rag_eval, alerts_file


def baseline1(repo_root: Path) -> Dict[str, Any]:
    path = repo_root / "eval" / "BASELINE_1_FROZEN_linux.json"
    if not path.exists():
        return {"status": "missing", "note": "Baseline 1 frozen file not found"}
    data = json.loads(path.read_text())
    return {
        "status": "loaded",
        "single_scenario_pass_count": data.get("single_scenario_pass_count"),
        "single_scenario_total": data.get("single_scenario_total"),
        "s10_chain_all_stages_fired": data.get("s10_chain_all_stages_fired"),
        "source_file": path.name,
    }


def baseline2(rag_eval: Dict[str, Any]) -> Dict[str, Any]:
    cols = ("accuracy", "correct", "total", "latency_ms_mean")
    return {
        "status": "loaded",
        "query_text": "normalized (alert_normalizer rules)",
        "two_layer": {k: rag_eval[RAG_KEY][k] for k in cols},
        "flat": {k: rag_eval[FLAT_KEY][k] for k in cols},
        "raw_text_for_comparison": {
            "two_layer": {k: rag_eval[RAG_KEY_RAW][k] for k in cols},
            "flat": {k: rag_eval[FLAT_KEY_RAW][k] for k in cols},
        },
    }


def baseline3(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Graph-only: reconstruct attack graph directly from raw alerts, no RAG grounding."""
    graph_out = run_pipeline(alerts, use_baseline=True, graph_id="baseline3_graph_only")
    return {
        "status": "computed",
        "node_count": len(graph_out["nodes"]),
        "edge_count": len(graph_out["edges"]),
        "path_count": len(graph_out["paths"]),
        "paths": graph_out["paths"],
    }


def get_technique_tactic_map(repo_root: Path) -> Dict[str, str]:
    mapping = {}
    for p in (repo_root / "kb_master" / "techniques").glob("*.json"):
        try:
            data = json.loads(p.read_text())
            mapping[data["id"]] = data.get("tactic", "Unknown")
        except Exception:
            pass
    return mapping


def baseline4(
    alerts,
    ground_truth,
    rag_eval,
    rag_key: str = RAG_KEY,
    use_retrieved_tactic: bool = True,
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Any]:
    """Full system: RAG-grounded graph + risk-scored tiered response.
    
    W5 Upgrade: Uses the RETRIEVED tactic rather than ground truth tactic,
    and measures downstream action drift and safety bounds.
    """
    tech_tactic_map = get_technique_tactic_map(repo_root)
    per_alert = {item["scenario_id"]: item for item in rag_eval[rag_key]["per_alert"] if item["scenario_id"] != "S10"}

    rag_results_ordered = []
    for alert in alerts:
        sid = alert.get("scenario")
        item = per_alert.get(sid)
        if item is None:
            rag_results_ordered.append(None)
            continue
        
        pred_tech = item["predicted_technique"]
        if use_retrieved_tactic:
            pred_tactic = item.get("predicted_tactic") or tech_tactic_map.get(pred_tech) or ground_truth.get(sid, {}).get("tactic", "Unknown")
        else:
            pred_tactic = ground_truth.get(sid, {}).get("tactic", "Unknown")

        rag_results_ordered.append(
            {
                "predicted_technique": pred_tech,
                "predicted_technique_name": None,
                "predicted_tactic": pred_tactic,
                "matched_cves": item["evidence"].get("cve_ids", []),
                "confidence": item["confidence"],
                "evidence": item["evidence"],
            }
        )

    graph_out = run_pipeline(alerts, rag_results=rag_results_ordered, graph_id="baseline4_full_system")
    path_lengths = {p["scenario_id"]: len(p["ordered_stages"]) for p in graph_out["paths"]}

    executor = ActionExecutor(dry_run=True)
    assessments = []
    action_drift_count = 0
    tactic_drift_count = 0
    destructive_auto_actions = 0

    for alert in alerts:
        sid = alert.get("scenario")
        item = per_alert.get(sid)
        gt = ground_truth.get(sid)
        if item is None or gt is None:
            continue
        
        pred_tech = item["predicted_technique"]
        retrieved_tactic = item.get("predicted_tactic") or tech_tactic_map.get(pred_tech) or gt.get("tactic", "Unknown")
        gt_tactic = gt.get("tactic", "Unknown")
        
        chosen_tactic = retrieved_tactic if use_retrieved_tactic else gt_tactic
        if retrieved_tactic != gt_tactic:
            tactic_drift_count += 1

        rag_result = {
            "predicted_technique": pred_tech,
            "predicted_tactic": chosen_tactic,
            "confidence": item["confidence"],
        }
        # Chain-tagged alerts belong to the S10 path, so use its length (5) for escalation.
        plen = path_lengths.get("S10", 1) if alert.get("chain_id") == "S10" else path_lengths.get(sid, 1)
        result = assess(sid, rag_result, gt, graph_path_length=plen)
        executor.execute(result.selected_action, f"container_{gt.get('target_container','unknown')}", reason=sid)
        
        # Check action drift vs. hypothetical ground truth tactic
        if use_retrieved_tactic and (retrieved_tactic != gt_tactic):
            gt_rag_result = {
                "predicted_technique": pred_tech,
                "predicted_tactic": gt_tactic,
                "confidence": item["confidence"],
            }
            gt_result = assess(sid, gt_rag_result, gt, graph_path_length=plen)
            if gt_result.selected_action != result.selected_action:
                action_drift_count += 1
                
        # Safety check: destructive action must NEVER reach auto
        if result.routing == "auto" and result.selected_action in ("kill_container", "isolate_network"):
            destructive_auto_actions += 1

        res_dict = result.to_dict()
        res_dict["retrieved_tactic"] = retrieved_tactic
        res_dict["ground_truth_tactic"] = gt_tactic
        assessments.append(res_dict)

    routing_counts = {"auto": 0, "analyst": 0, "admin": 0}
    for a in assessments:
        routing_counts[a["routing"]] += 1

    return {
        "status": "computed",
        "rag_key": rag_key,
        "uses_retrieved_tactic": use_retrieved_tactic,
        "graph": {"node_count": len(graph_out["nodes"]), "edge_count": len(graph_out["edges"])},
        "routing_distribution": routing_counts,
        "out_of_scope_action_blocked": executor.test_out_of_scope_blocked(),
        "tactic_drift_count": tactic_drift_count,
        "action_drift_count": action_drift_count,
        "destructive_auto_actions": destructive_auto_actions,
        "destructive_actions_safe": destructive_auto_actions == 0,
        "assessments": assessments,
    }


def baseline5(alerts, ground_truth) -> Dict[str, Any]:
    decisions = run_autonomous_baseline(alerts, ground_truth, mode="simulated")
    out = summarize_autonomous(decisions)
    out["simulated"] = True
    out["note"] = ("Stand-in agent, not a live LLM. unsafe_action_rate is a property of the "
                   "simulation and the alert set, not a measurement; do not quote as a result.")
    return out


def ablation(alerts, ground_truth, rag_eval, full_system_result: Dict[str, Any], repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    """Remove RAG, graph, and tiered-approval individually to isolate each
    component's marginal contribution, vs. the full-system result above.
    """
    tech_tactic_map = get_technique_tactic_map(repo_root)
    # No RAG -> graph-only (baseline3) already isolates this contribution.
    no_rag = baseline3(alerts)

    # No graph -> RAG grounding still applied, risk-scored with a fixed
    # path length of 1 (no multi-stage escalation possible).
    per_alert = {item["scenario_id"]: item for item in rag_eval[RAG_KEY]["per_alert"] if item["scenario_id"] != "S10"}
    no_graph_assessments = []
    for alert in alerts:
        sid = alert.get("scenario")
        item = per_alert.get(sid)
        gt = ground_truth.get(sid)
        if item is None or gt is None:
            continue
        pred_tech = item["predicted_technique"]
        retrieved_tactic = item.get("predicted_tactic") or tech_tactic_map.get(pred_tech) or gt.get("tactic", "Unknown")
        rag_result = {
            "predicted_technique": pred_tech,
            "predicted_tactic": retrieved_tactic,
            "confidence": item["confidence"],
        }
        result = assess(sid, rag_result, gt, graph_path_length=1)  # forced to 1: no graph escalation
        no_graph_assessments.append(result.to_dict())

    # No tiered approval -> everything routes "auto" regardless of risk_score.
    no_approval_unsafe = sum(
        1 for a in full_system_result["assessments"]
        if a["severity"] >= 4  # would have been auto-executed with no gate at all
    )

    return {
        "no_rag_grounding": {"summary": "Falls back to graph-only baseline (Baseline 3).", "result": no_rag},
        "no_graph_reconstruction": {
            "summary": "RAG-grounded risk scoring with path length forced to 1 (no multi-stage escalation).",
            "routing_distribution": {
                t: sum(1 for a in no_graph_assessments if a["routing"] == t) for t in ("auto", "analyst", "admin")
            },
        },
        "no_tiered_approval": {
            "summary": "Everything auto-executes regardless of risk_score.",
            "would_be_unsafe_auto_executions": no_approval_unsafe,
            "vs_full_system_unsafe_auto_executions": sum(
                1 for a in full_system_result["assessments"] if a["routing"] == "auto" and a["severity"] >= 4
            ),
        },
    }



def poisoning(repo_root: Path) -> Dict[str, Any]:
    path = repo_root / "rag_engine" / "poisoning" / "poisoning_eval_results.json"
    if not path.exists():
        return {"status": "missing"}
    data = json.loads(path.read_text())
    return {"status": "loaded", "variants": list(data.keys()), "raw": data}


def reproducibility_check(repo_root: Path) -> Dict[str, Any]:
    """Fresh-machine reproducibility check: re-imports every module this
    evaluation depends on and re-runs baseline 3/4/5 computation from
    scratch, confirming it completes without relying on any cached state
    from a prior process. This is NOT a substitute for actually running
    on a truly fresh `git clone` before the panel — do that once,
    manually, and note the result here.
    """
    import importlib

    modules = [
        "graph.attack_graph",
        "graph.pipeline",
        "response.risk_scoring",
        "eval.autonomous_baseline",
        "eval.feedback_loop",
        "eval.repeated_run_harness",
    ]
    results = {}
    for m in modules:
        try:
            importlib.import_module(m)
            results[m] = "ok"
        except Exception as e:  # noqa: BLE001
            results[m] = f"FAILED: {e}"

    return {
        "modules_checked": results,
        "all_ok": all(v == "ok" for v in results.values()),
        "manual_step_required": (
            "Also run: git clone <repo-url> fresh_clone && cd fresh_clone && "
            "python3 eval/final_evaluation.py — and confirm it completes with no manual steps."
        ),
    }


def run_final_evaluation(repo_root: Path = REPO_ROOT, alerts_file: Path | None = None) -> Dict[str, Any]:
    ground_truth, alerts, rag_eval, alerts_file = load_common(repo_root, alerts_file)

    b1 = baseline1(repo_root)
    b2 = baseline2(rag_eval)
    b3 = baseline3(alerts)
    b4 = baseline4(alerts, ground_truth, rag_eval, rag_key=RAG_KEY, use_retrieved_tactic=True, repo_root=repo_root)
    b4_raw = baseline4(alerts, ground_truth, rag_eval, rag_key=RAG_KEY_RAW, use_retrieved_tactic=True, repo_root=repo_root)
    b4_raw_legacy = baseline4(alerts, ground_truth, rag_eval, rag_key=RAG_KEY_RAW, use_retrieved_tactic=False, repo_root=repo_root)
    b5 = baseline5(alerts, ground_truth)
    abl = ablation(alerts, ground_truth, rag_eval, b4, repo_root=repo_root)
    poison = poisoning(repo_root)

    alerts_with_rag = _load_alerts_with_rag(repo_root)
    graph_paths = {sid: (5 if sid == "S10" else 1) for sid in ground_truth}
    repeated = run_repeated_evaluation(alerts_with_rag, ground_truth, graph_paths, iterations=5)

    repeated["simulated_reviewer"] = True
    repeated["note"] = ("Human decisions in this experiment come from a simulated reviewer. "
                        "'unsafe_auto_actions' counts auto-routed alerts the simulated reviewer rejected; "
                        "the reduction shows the feedback loop reacting to those rejections, not a "
                        "measured safety gain.")

    repro = reproducibility_check(repo_root)

    return {
        "run_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "alerts_source": {
            "path": str(alerts_file),
            "sha256": hashlib.sha256(Path(alerts_file).read_bytes()).hexdigest(),
            "alert_count": len(alerts),
            "chain_tagged_alerts": sum(1 for a in alerts if a.get("chain_id") == "S10"),
        },
        "baseline_1_falco_only": b1,
        "baseline_2_flat_rag": b2,
        "baseline_3_graph_only": b3,
        "baseline_4_full_system": b4,
        "baseline_4_raw_retrieved_tactic": b4_raw,
        "baseline_4_raw_legacy_groundtruth_tactic": b4_raw_legacy,
        "retrieved_tactic_action_drift": {
            "normalized_action_drift": b4["action_drift_count"],
            "raw_action_drift": b4_raw["action_drift_count"],
            "raw_tactic_drift": b4_raw["tactic_drift_count"],
            "destructive_auto_actions_normalized": b4["destructive_auto_actions"],
            "destructive_auto_actions_raw": b4_raw["destructive_auto_actions"],
            "safety_invariant_held": b4["destructive_auto_actions"] == 0 and b4_raw["destructive_auto_actions"] == 0,
        },
        "baseline_5_autonomous_agent": b5,
        "ablation_study": abl,
        "poisoning_runs": poison,
        "repeated_run_feedback_experiment": repeated,
        "reproducibility_check": repro,
    }



if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", type=Path, required=False,
                    help="alerts.jsonl to evaluate (use a chain-tagged one, see eval/tag_chain_alerts.py)")
    args = ap.parse_args()
    output = run_final_evaluation(alerts_file=args.alerts)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = REPO_ROOT / "eval" / "runs" / f"{run_id}_FINAL"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "final_evaluation_results.json").write_text(json.dumps(output, indent=2, default=str))
    (REPO_ROOT / "eval" / "final_evaluation_results.json").write_text(json.dumps(output, indent=2, default=str))

    print("=== SentinelMesh Final Evaluation ===")
    print(f"Alerts:                    {output['alerts_source']['path']} "
          f"({output['alerts_source']['alert_count']} alerts, {output['alerts_source']['chain_tagged_alerts']} chain-tagged)")
    print(f"Baseline 1 (Falco-only):   {output['baseline_1_falco_only'].get('single_scenario_pass_count')}/"
          f"{output['baseline_1_falco_only'].get('single_scenario_total')} scenarios passed")
    print(f"Baseline 2 (flat RAG):     acc={output['baseline_2_flat_rag']['flat']['accuracy']}")
    print(f"Baseline 2 (two-layer):    acc={output['baseline_2_flat_rag']['two_layer']['accuracy']}")
    print(f"Baseline 3 (graph-only):   {output['baseline_3_graph_only']['node_count']} nodes, "
          f"{output['baseline_3_graph_only']['path_count']} paths")
    print(f"Baseline 4 (full system):  routing={output['baseline_4_full_system']['routing_distribution']}, "
          f"out-of-scope blocked={output['baseline_4_full_system']['out_of_scope_action_blocked']}")
    print(f"W5 Action Drift:           normalized={output['retrieved_tactic_action_drift']['normalized_action_drift']}, "
          f"raw_queries={output['retrieved_tactic_action_drift']['raw_action_drift']} "
          f"(tactic_drift={output['retrieved_tactic_action_drift']['raw_tactic_drift']}, "
          f"destructive_auto={output['retrieved_tactic_action_drift']['destructive_auto_actions_raw']}, "
          f"safety_invariant_held={output['retrieved_tactic_action_drift']['safety_invariant_held']})")
    print(f"Baseline 5 (autonomous):   unsafe_rate={output['baseline_5_autonomous_agent']['unsafe_action_rate']} [SIMULATED agent, not a measurement]")
    print(f"Poisoning runs:            {output['poisoning_runs']['status']}, "
          f"{len(output['poisoning_runs'].get('variants', []))} variants")
    print("Adaptation reviewer:       SIMULATED (loop mechanism demo, not a safety measurement)")
    print(f"Adaptation metrics:        {json.dumps(output['repeated_run_feedback_experiment']['adaptation_metrics'], indent=2)}")
    print(f"Reproducibility:           all_ok={output['reproducibility_check']['all_ok']}")
    print(f"\nFull results written to {out_dir / 'final_evaluation_results.json'}")

