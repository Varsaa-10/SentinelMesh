"""
Day 3-4 evaluation: given Week 1's logged alerts (placeholder for now),
run both engines (two-layer, flat) against both embedders (tfidf-word,
tfidf-char), score technique-ID accuracy against ground_truth_technique,
and record latency. Prints a results table and writes results JSON.

Updated Day 3 for the real kb_master directory layout:
  kb_master/techniques/*.json, kb_master/cves/*.json (per Person 1's
  handoff doc), loaded via kb_loader.load_kb_dir().

Swap-in when the rest of the real KB lands: point TECHNIQUES_DIR /
CVES_DIR at the full kb_master/ export (currently only the 8
scenario-critical technique files + 1 CVE are populated here as
schema-correct placeholders -- see kb/kb_master_real/techniques/*.json
for which files still say "_placeholder_note"). Point ALERTS_PATH at
Week 1's real logged alerts + ground_truth.json once available.
"""
from __future__ import annotations
import json
import os
import statistics
import sys

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import EMBEDDERS
try:
    from rag_engine.src.rag_engine import TwoLayerRAG
except ImportError:
    from rag_engine import TwoLayerRAG
from flat_rag import FlatRAG
from alert_normalizer import normalize_alert_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TECHNIQUES_DIR = os.path.join(ROOT, "kb", "kb_master_real", "techniques")
CVES_DIR = os.path.join(ROOT, "kb", "kb_master_real", "cves")
ALERTS_PATH = os.path.join(ROOT, "data", "placeholder_alerts.json")
RESULTS_PATH = os.path.join(ROOT, "data", "eval_results.json")


def load_alerts(path: str) -> list:
    with open(path) as f:
        raw = json.load(f)
    return raw["alerts"]


def run_engine(engine_cls, records, cve_map, embedder_name, alerts, use_normalized=False):
    embedder = EMBEDDERS[embedder_name]()
    engine = engine_cls(records, embedder, cve_lookup=cve_map)
    results = []
    correct = 0
    latencies = []
    for alert in alerts:
        query_text = normalize_alert_text(alert) if use_normalized else alert["output"]
        r = engine.query(
            alert_output_text=query_text,
            container_id=alert["container_id"],
            falco_rule=alert["rule"],
            alert_source=alert.get("source"),
        )
        is_correct = r.predicted_technique == alert["ground_truth_technique"]
        correct += int(is_correct)
        latencies.append(r.latency_ms)
        results.append({
            "alert_id": alert["alert_id"],
            "scenario_id": alert["scenario_id"],
            "predicted_technique": r.predicted_technique,
            "ground_truth_technique": alert["ground_truth_technique"],
            "correct": is_correct,
            "confidence": r.confidence.as_dict(),
            "evidence": r.evidence,
            "latency_ms": round(r.latency_ms, 3),
        })
    accuracy = correct / len(alerts) if alerts else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "correct": correct,
        "total": len(alerts),
        "latency_ms_mean": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "latency_ms_p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 3) if latencies else 0.0,
        "per_alert": results,
    }


def main():
    records, cves = load_kb_dir(TECHNIQUES_DIR, CVES_DIR)
    cve_map = build_cve_lookup(cves)
    alerts = load_alerts(ALERTS_PATH)

    print(f"Loaded {len(records)} technique record(s), {len(cves)} CVE record(s), {len(alerts)} alert(s).\n")

    all_results = {}
    for use_norm in (False, True):
        tag = "normalized" if use_norm else "raw"
        for embedder_name in EMBEDDERS:
            all_results[f"two-layer__{embedder_name}__{tag}"] = run_engine(TwoLayerRAG, records, cve_map, embedder_name, alerts, use_normalized=use_norm)
            all_results[f"flat__{embedder_name}__{tag}"] = run_engine(FlatRAG, records, cve_map, embedder_name, alerts, use_normalized=use_norm)

    with open(RESULTS_PATH, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"{'Engine':<12} {'Embedder':<12} {'Text':<12} {'Accuracy':<10} {'Mean latency (ms)':<20} {'P95 latency (ms)'}")
    print("-" * 90)
    for key, res in all_results.items():
        engine, embedder, tag = key.split("__")
        print(f"{engine:<12} {embedder:<12} {tag:<12} {res['accuracy']:<10} {res['latency_ms_mean']:<20} {res['latency_ms_p95']}")

    print(f"\nFull results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
