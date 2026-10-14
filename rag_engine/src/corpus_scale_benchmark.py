"""
rag_engine/src/corpus_scale_benchmark.py — SentinelMesh Module W1: Multi-Scale Retrieval Benchmark.

Evaluates retrieval accuracy and latency across:
- 4 Corpus Settings:
    1. corpus_36: 36 official MITRE Enterprise techniques (100% clean MITRE STIX text).
    2. corpus_200: 227 official live MITRE parent techniques (100% clean MITRE STIX text).
    3. corpus_full: 706 official live MITRE techniques and sub-techniques (100% clean MITRE STIX text).
    4. corpus_lab_tuned_36: 36 baseline records with lab-specific wording and bespoke Falco rules (ablation comparison).
- 3 Query Forms:
    1. raw
    2. title_raw
    3. rewrite (normalized)
- Retrievers:
    1. TwoLayerRAG
    2. TwoLayerRAG with Fallback (calibrated threshold)
    3. FlatRAG
- Dual Scoring:
    - Exact match (predicted == ground_truth)
    - Parent-level match (T1003 counts as correct for T1003.008 in parent-only corpora)

Outputs comprehensive results JSON artifact with full audit trails.
"""

from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import EMBEDDERS
from rag_engine import TwoLayerRAG
from flat_rag import FlatRAG
from alert_normalizer import normalize_alert_text
from eval.stats_utils import wilson_score_interval
from eval.alert_query import select_alerts, build_query, load_alerts, QUERY_FORMS

CORPORA_ROOT = REPO_ROOT / "rag_engine" / "kb" / "corpora"
CVES_DIR = REPO_ROOT / "kb_master" / "cves"
GROUND_TRUTH_PATH = REPO_ROOT / "eval" / "ground_truth.json"
OCT_CAPTURE_PATH = REPO_ROOT / "eval" / "runs" / "20261012T140201Z" / "alerts.jsonl"
RESULTS_PATH = REPO_ROOT / "rag_engine" / "data" / "corpus_scale_results.json"

CALIBRATED_FALLBACK_THRESHOLD = 0.08  # Calibrated on similarity distribution to trigger on genuine low-confidence queries


def evaluate_corpus_run(
    engine,
    selected_items: List[Dict[str, Any]],
    query_form: str,
) -> Dict[str, Any]:
    exact_correct = 0
    parent_correct = 0
    fallback_count = 0
    total = len(selected_items)
    latencies = []
    per_alert = []

    for item in selected_items:
        alert = item["alert"]
        q_text = build_query(alert, query_form)
        assert q_text.strip(), f"Empty query generated for {item['slot']}"

        t0 = time.perf_counter()
        res = engine.query(
            alert_output_text=q_text,
            container_id=alert.get("service", ""),
            falco_rule=alert.get("title", ""),
            alert_source=(alert.get("source") or "").replace("-", "_"),
        )
        lat = (time.perf_counter() - t0) * 1000
        latencies.append(lat)

        if getattr(res, "engine", "") == "two-layer-fallback":
            fallback_count += 1

        is_exact = res.predicted_technique == item["ground_truth_technique"]
        pred_parent = res.predicted_technique.split(".")[0] if res.predicted_technique else ""
        gt_parent = item["ground_truth_technique"].split(".")[0]
        is_parent = is_exact or (pred_parent == gt_parent)

        if is_exact:
            exact_correct += 1
        if is_parent:
            parent_correct += 1

        per_alert.append({
            "slot": item["slot"],
            "scenario_id": item["scenario_id"],
            "predicted": res.predicted_technique,
            "ground_truth": item["ground_truth_technique"],
            "exact_correct": is_exact,
            "parent_correct": is_parent,
            "engine": res.engine,
            "latency_ms": round(lat, 2),
        })

    acc_exact, low_e, high_e = wilson_score_interval(exact_correct, total)
    acc_parent, low_p, high_p = wilson_score_interval(parent_correct, total)
    lat_sorted = sorted(latencies)
    p95_idx = int(len(lat_sorted) * 0.95) - 1
    p95 = lat_sorted[max(0, p95_idx)] if lat_sorted else 0.0

    return {
        "accuracy": round(acc_exact, 4),  # Standard exact match accuracy
        "ci_95": [round(low_e, 4), round(high_e, 4)],
        "correct": exact_correct,
        "parent_accuracy": round(acc_parent, 4),  # Parent-level accuracy (e.g. T1003 counts for T1003.008)
        "parent_ci_95": [round(low_p, 4), round(high_p, 4)],
        "parent_correct": parent_correct,
        "total": total,
        "fallback_count": fallback_count,
        "fallback_rate": round(fallback_count / total, 4) if total > 0 else 0.0,
        "latency_ms_mean": round(float(sum(latencies) / len(latencies)), 2) if latencies else 0.0,
        "latency_ms_p95": round(float(p95), 2),
        "per_alert": per_alert,
    }


def run_corpus_scale_benchmark(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    corpora_dirs = {
        "corpus_36": CORPORA_ROOT / "corpus_36",
        "corpus_200": CORPORA_ROOT / "corpus_200",
        "corpus_full": CORPORA_ROOT / "corpus_full",
        "corpus_lab_tuned_36": CORPORA_ROOT / "corpus_lab_tuned_36",
    }

    gt = json.loads((repo_root / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    raw_alerts = load_alerts(OCT_CAPTURE_PATH)
    selected_items, missing = select_alerts(raw_alerts, gt)
    assert not missing, f"Missing slots in 12 Oct capture: {missing}"

    query_forms = ["raw", "title_raw", "rewrite"]
    all_results = {}

    print(f"Loaded {len(selected_items)} evaluation alerts from {OCT_CAPTURE_PATH.name} (missing={missing}).")

    for corpus_name, corpus_dir in corpora_dirs.items():
        if not corpus_dir.exists():
            print(f"Skipping {corpus_name} (directory not found).")
            continue

        records, cves = load_kb_dir(str(corpus_dir), str(CVES_DIR))
        cve_map = build_cve_lookup(cves)
        print(f"\n--- Benchmark on {corpus_name} ({len(records)} records) ---")

        embedder_name = "tfidf-word"

        # Build fresh, independent engine instances so vocabulary spaces are isolated
        for qf in query_forms:
            two_layer = TwoLayerRAG(records, EMBEDDERS[embedder_name](), cve_lookup=cve_map)
            two_layer_fallback = TwoLayerRAG(records, EMBEDDERS[embedder_name](), cve_lookup=cve_map, fallback_threshold=CALIBRATED_FALLBACK_THRESHOLD)
            flat = FlatRAG(records, EMBEDDERS[embedder_name](), cve_lookup=cve_map)

            k_2l = f"{corpus_name}__two_layer__{embedder_name}__{qf}"
            k_2l_fb = f"{corpus_name}__two_layer_fallback__{embedder_name}__{qf}"
            k_flat = f"{corpus_name}__flat__{embedder_name}__{qf}"

            all_results[k_2l] = evaluate_corpus_run(two_layer, selected_items, qf)
            all_results[k_2l_fb] = evaluate_corpus_run(two_layer_fallback, selected_items, qf)
            all_results[k_flat] = evaluate_corpus_run(flat, selected_items, qf)

            print(
                f"[{corpus_name:<20} | {qf:<9}] "
                f"TwoLayer: exact={all_results[k_2l]['correct']}/{all_results[k_2l]['total']} ({all_results[k_2l]['accuracy']*100:.1f}%), parent={all_results[k_2l]['parent_correct']}/{all_results[k_2l]['total']} ({all_results[k_2l]['parent_accuracy']*100:.1f}%) | "
                f"Fallback: exact={all_results[k_2l_fb]['correct']}/{all_results[k_2l_fb]['total']} ({all_results[k_2l_fb]['accuracy']*100:.1f}%), fb_rate={all_results[k_2l_fb]['fallback_rate']*100:.1f}% | "
                f"Flat: exact={all_results[k_flat]['correct']}/{all_results[k_flat]['total']} ({all_results[k_flat]['accuracy']*100:.1f}%), parent={all_results[k_flat]['parent_correct']}/{all_results[k_flat]['total']} ({all_results[k_flat]['parent_accuracy']*100:.1f}%)"
            )

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nBenchmark completed. Results written to {RESULTS_PATH}")
    return all_results


if __name__ == "__main__":
    run_corpus_scale_benchmark()
