"""
eval/fallback_threshold_heldout.py -- choose the tactic-fallback threshold without looking at the test alerts.

Leave-one-run-out over the 5 cross-capture runs (60 clean alerts, faulty S8 slots excluded):
for each run, pick the threshold that maximises two-layer-with-fallback accuracy on the OTHER
runs (grid 0.00-0.30, step 0.01; ties broken towards the threshold that falls back least),
then score the held-out run with it. Pooled held-out accuracy is the honest estimate.

Done per query form, on the lab-written corpus (kb_master), which is the corpus the
cross-capture benchmark uses. The firing rate of each chosen threshold is also reported on
the official MITRE corpora, to show whether a threshold tuned on one corpus carries over.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(os.environ.get("SENTINELMESH_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup  # noqa: E402
from embeddings import EMBEDDERS  # noqa: E402
from rag_engine import TwoLayerRAG  # noqa: E402
from flat_rag import FlatRAG  # noqa: E402
from eval.alert_query import QUERY_FORMS  # noqa: E402
from eval.kb_curation_ablation import alert_sets, RUNS  # noqa: E402
from eval.stats_utils import wilson_score_interval  # noqa: E402

GRID = [round(float(x), 2) for x in np.arange(0.0, 0.301, 0.01)]


def layer_scores(records, rows, form):
    """Per alert: best tactic similarity, two-layer prediction, flat prediction (fallback = flat search)."""
    cve_map = {}
    tl = TwoLayerRAG(records, EMBEDDERS["tfidf-word"](), cve_lookup=cve_map)
    fl = FlatRAG(records, EMBEDDERS["tfidf-word"](), cve_lookup=cve_map)
    out = []
    for row in rows:
        q = row["queries"][form]
        kw = dict(container_id=row["alert"].get("service", ""), falco_rule=row["alert"].get("title", ""),
                  alert_source=(row["alert"].get("source") or "").replace("-", "_"))
        r_tl = tl.query(alert_output_text=q, **kw)
        r_fl = fl.query(alert_output_text=q, **kw)
        out.append({"run": row["run"], "truth": row["truth"], "sim": r_tl.evidence.get("layer1_similarity"),
                    "tl": r_tl.predicted_technique, "flat": r_fl.predicted_technique})
    return out


def acc_at(items, th):
    ok = fb = 0
    for it in items:
        use_flat = it["sim"] < th
        fb += use_flat
        ok += (it["flat"] if use_flat else it["tl"]) == it["truth"]
    return ok, fb


def main():
    gt = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    rows = alert_sets(gt)["clean_60"]
    lab, _ = load_kb_dir(str(REPO_ROOT / "kb_master" / "techniques"))
    mitre = {c: load_kb_dir(str(REPO_ROOT / "rag_engine" / "kb" / "corpora" / c))[0]
             for c in ("corpus_36", "corpus_200", "corpus_full")}
    results = {"grid": GRID, "forms": {}}
    for form in QUERY_FORMS:
        items = layer_scores(lab, rows, form)
        folds, ok_tot, fb_tot, n_tot, chosen = [], 0, 0, 0, []
        for held in RUNS:
            train = [i for i in items if i["run"] != held]
            test = [i for i in items if i["run"] == held]
            best = max(GRID, key=lambda th: (acc_at(train, th)[0], -acc_at(train, th)[1], -th))
            ok, fb = acc_at(test, best)
            folds.append({"held_out_run": held, "threshold": best, "correct": int(ok), "n": len(test), "fallbacks": int(fb)})
            ok_tot += int(ok); fb_tot += int(fb); n_tot += len(test); chosen.append(best)
        tl_only = sum(i["tl"] == i["truth"] for i in items)
        flat_only = sum(i["flat"] == i["truth"] for i in items)
        _, lo, hi = wilson_score_interval(ok_tot, n_tot)
        mitre_rates = {}
        for c, recs in mitre.items():
            sims = [i["sim"] for i in layer_scores(recs, rows, form)]
            mitre_rates[c] = {str(th): round(float(np.mean([s < th for s in sims])), 3) for th in sorted(set(chosen))}
        results["forms"][form] = {
            "folds": folds, "heldout_correct": ok_tot, "n": n_tot, "heldout_wilson_95": [round(lo, 3), round(hi, 3)],
            "heldout_fallback_rate": round(fb_tot / n_tot, 3), "two_layer_no_fallback_correct": tl_only,
            "flat_correct": flat_only,
            "layer1_similarity_range_lab": [round(min(i["sim"] for i in items), 4), round(max(i["sim"] for i in items), 4)],
            "fallback_rate_of_chosen_thresholds_on_mitre_corpora": mitre_rates,
        }
        print(f"{form:<10} held-out {ok_tot}/{n_tot}  fb={fb_tot}  thresholds={chosen}  "
              f"two-layer={tl_only}/{n_tot} flat={flat_only}/{n_tot}  mitre fb rates={mitre_rates}")
    out = REPO_ROOT / "eval" / "fallback_threshold_heldout_results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"written {out}")


if __name__ == "__main__":
    main()
