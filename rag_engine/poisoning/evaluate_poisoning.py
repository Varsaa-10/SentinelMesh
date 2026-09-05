"""
Module B3 — Person 3, Day 5: preliminary pass.

For each of the 5 poisoned variants:
  1. Run the static KB integrity scan (poison_detection.scan_kb).
  2. Query it with the real scenario-critical alerts (same alert set B2
     uses, word-TF-IDF + normalization -- the Day-5 recommended config
     from docs/embedding_comparison.md) via TwoLayerRAG.
  3. Record: predicted technique, whether it's WRONG vs. the true ground
     truth (i.e. would this have produced an unsafe/incorrect
     recommendation), and whether score_retrieval_result flagged it.

Reports pass/fail honestly per variant -- some poisoning types are
by-design undetectable by one of the two methods (see poison_detection.py's
module docstring), and this script's job is to confirm exactly that with
real numbers, not to claim a clean sweep.
"""
import json
import os
import sys

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import WordTfidfEmbedder
from rag_engine import TwoLayerRAG
from alert_normalizer import normalize_alert_text
from poison_detection import scan_kb, score_retrieval_result

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VARIANTS_DIR = os.path.join(ROOT, "poisoning", "variants")
ALERTS_PATH = os.path.join(ROOT, "data", "placeholder_alerts.json")
RESULTS_PATH = os.path.join(ROOT, "poisoning", "poisoning_eval_results.json")

VARIANTS = [
    "variant_1_mislabeled_cve",
    "variant_2_fake_entry",
    "variant_3_near_duplicate",
    "variant_4_adversarial_embedding",
    "variant_5_stale_contradictory",
]


def load_alerts():
    with open(ALERTS_PATH) as f:
        raw = json.load(f)
    # Only single-technique alerts (skip S10's chain-stage duplicates -- they
    # repeat S1/S3/S4/S9/S8's own alert content, no new signal for this check)
    return [a for a in raw["alerts"] if a["scenario_id"] != "S10"]


def run_variant(variant_name: str, alerts: list) -> dict:
    variant_dir = os.path.join(VARIANTS_DIR, variant_name)
    techniques, cves = load_kb_dir(
        os.path.join(variant_dir, "techniques"),
        os.path.join(variant_dir, "cves"),
    )
    cve_map = build_cve_lookup(cves)

    static_findings = scan_kb(techniques, cves)

    engine = TwoLayerRAG(techniques, WordTfidfEmbedder(), cve_lookup=cve_map)

    query_results = []
    for alert in alerts:
        text = normalize_alert_text(alert)
        result = engine.query(
            alert_output_text=text,
            container_id=alert["container_id"],
            falco_rule=alert["rule"],
            alert_source=alert.get("source"),
        )
        suspicion = score_retrieval_result(result)
        wrong_recommendation = result.predicted_technique != alert["ground_truth_technique"]
        query_results.append({
            "scenario_id": alert["scenario_id"],
            "ground_truth_technique": alert["ground_truth_technique"],
            "predicted_technique": result.predicted_technique,
            "wrong_recommendation": wrong_recommendation,
            "confidence_score": result.confidence.score,
            "retrieval_flagged_suspect": suspicion.is_suspect,
            "suspicion_reason": suspicion.reason,
        })

    return {
        "static_findings_count": len(static_findings),
        "static_findings": [
            {"severity": f.severity, "record_type": f.record_type, "record_id": f.record_id, "finding": f.finding}
            for f in static_findings
        ],
        "wrong_recommendations": sum(1 for q in query_results if q["wrong_recommendation"]),
        "wrong_recommendations_flagged_as_suspect": sum(
            1 for q in query_results if q["wrong_recommendation"] and q["retrieval_flagged_suspect"]
        ),
        "query_results": query_results,
    }


def main():
    alerts = load_alerts()
    all_results = {}
    for variant in VARIANTS:
        all_results[variant] = run_variant(variant, alerts)

    with open(RESULTS_PATH, "w") as f:
        json.dump(all_results, f, indent=2)

    # Baseline (clean master) static findings, to isolate the incremental
    # signal each variant's poisoning actually adds -- avoids conflating
    # "findings" with "poisoning-caused findings."
    baseline_techniques, baseline_cves = load_kb_dir(
        os.path.join(ROOT, "kb", "kb_master_real", "techniques"),
        os.path.join(ROOT, "kb", "kb_master_real", "cves"),
    )
    baseline_count = len(scan_kb(baseline_techniques, baseline_cves))

    print(f"Baseline (clean master KB) static findings: {baseline_count} (pre-existing, not poisoning)\n")
    print(f"{'Variant':<35} {'New static findings':<21} {'Wrong recs':<12} {'Caught (either layer)'}")
    print("-" * 95)
    for variant, res in all_results.items():
        new_findings = res["static_findings_count"] - baseline_count
        # "Caught" means: static scan added a NEW finding beyond baseline
        # (i.e. actually flagged this variant's specific corruption), OR
        # every wrong recommendation this variant caused was flagged at
        # retrieval time. Variants with 0 wrong recs (like variant 4 here)
        # are judged on static detection alone.
        wrong = res["wrong_recommendations"]
        flagged = res["wrong_recommendations_flagged_as_suspect"]
        caught = (new_findings > 0) or (wrong > 0 and flagged == wrong)
        print(f"{variant:<35} {new_findings:<21} {wrong:<12} {'YES' if caught else 'NO'}")

    print(f"\nFull results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
