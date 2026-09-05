"""
Diagnostic: for each alert, run TwoLayerRAG (tfidf-word, raw text -- the
0.36 accuracy config) and report:
  - predicted tactic vs. ground-truth tactic (looked up from the KB record
    matching ground_truth_technique)
  - predicted technique vs. ground-truth technique
  - whether the failure (if any) is a Layer-1 tactic misroute or a
    Layer-2 within-tactic pick error

Run from rag_engine/src/:
    python3 diagnose.py
"""
from __future__ import annotations
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import EMBEDDERS
from rag_engine import TwoLayerRAG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TECHNIQUES_DIR = os.path.join(ROOT, "kb", "kb_master_real", "techniques")
CVES_DIR = os.path.join(ROOT, "kb", "kb_master_real", "cves")
ALERTS_PATH = os.path.join(ROOT, "data", "placeholder_alerts.json")  # swap when real alerts land


def main():
    records, cves = load_kb_dir(TECHNIQUES_DIR, CVES_DIR)
    cve_map = build_cve_lookup(cves)

    with open(ALERTS_PATH) as f:
        alerts = json.load(f)["alerts"]

    # ground-truth technique -> ground-truth tactic, via the KB
    tech_to_tactic = {r.id: r.tactic for r in records}

    embedder = EMBEDDERS["tfidf-word"]()
    engine = TwoLayerRAG(records, embedder, cve_lookup=cve_map)

    tactic_right_total = 0
    technique_right_total = 0
    rows = []

    for alert in alerts:
        gt_technique = alert["ground_truth_technique"]
        gt_tactic = tech_to_tactic.get(gt_technique, "UNKNOWN-not-in-KB")

        r = engine.query(
            alert_output_text=alert["output"],
            container_id=alert["container_id"],
            falco_rule=alert["rule"],
            alert_source=alert.get("source"),
        )

        tactic_right = r.predicted_tactic == gt_tactic
        technique_right = r.predicted_technique == gt_technique
        tactic_right_total += int(tactic_right)
        technique_right_total += int(technique_right)

        if technique_right:
            mode = "CORRECT"
        elif not tactic_right:
            mode = "LAYER-1 MISROUTE (wrong tactic bucket)"
        else:
            mode = "LAYER-2 MISS (right tactic, wrong technique)"

        rows.append({
            "alert_id": alert["alert_id"],
            "text_snippet": alert["output"][:70],
            "gt_tactic": gt_tactic,
            "pred_tactic": r.predicted_tactic,
            "gt_technique": gt_technique,
            "pred_technique": r.predicted_technique,
            "mode": mode,
        })

    print(f"{'alert_id':<10} {'mode':<38} {'gt_tactic':<20} {'pred_tactic':<20} {'gt_tech':<8} {'pred_tech'}")
    print("-" * 120)
    for row in rows:
        print(f"{row['alert_id']:<10} {row['mode']:<38} {row['gt_tactic']:<20} {row['pred_tactic']:<20} {row['gt_technique']:<8} {row['pred_technique']}")

    n = len(alerts)
    print(f"\nTactic-level accuracy (Layer 1 alone): {tactic_right_total}/{n} = {tactic_right_total/n:.4f}")
    print(f"Technique-level accuracy (end-to-end): {technique_right_total}/{n} = {technique_right_total/n:.4f}")

    misroutes = sum(1 for r in rows if "MISROUTE" in r["mode"])
    layer2_misses = sum(1 for r in rows if "LAYER-2" in r["mode"])
    print(f"\nOf {n - technique_right_total} total misses:")
    print(f"  {misroutes} were Layer-1 tactic misroutes (Layer 2 never had a chance)")
    print(f"  {layer2_misses} were Layer-2 picking wrong technique within the correct tactic")


if __name__ == "__main__":
    main()
