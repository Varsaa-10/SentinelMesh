"""
eval/poisoning_per_record.py -- knowledge-base poisoning with one corruption per record, counted per alert.

Replaces the 300-query suite (9 alerts copied ~34 times each), whose p-values treated copies
of one alert as independent evidence. Here every case is a distinct (corrupted corpus, alert)
pair, and results are also counted per distinct alert.

Corpus: kb_master (the lab-written 36 records the pipeline uses).
Alerts: the 9 standalone alerts of the 12 Oct capture, rendered as raw / title+raw / rewrite.
Attacks (each corrupted copy differs from the clean corpus in exactly one record):
  copied_description  every non-target record r gets the description of target technique s
                      (35 x 8 = 280 corpora); all 9 alerts are scored on each.
  targeted_stuffing   for alert a, one record r (not a's answer) gets a's own raw query text
                      appended to its description (35 x 9 = 315 corpus-alert pairs). This is the
                      PoisonedRAG-style case: the attacker writes text that matches one alert.
  tactic_relabel      each of the 8 target records is filed under each other tactic
                      (8 x ~9 corpora); all 9 alerts are scored on each.
An induced error = the alert is answered correctly on the clean corpus and wrongly on the
corrupted one. Clean baselines are computed per retriever and query form.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(os.environ.get("SENTINELMESH_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from kb_loader import load_kb_dir  # noqa: E402
from embeddings import EMBEDDERS  # noqa: E402
from rag_engine import TwoLayerRAG  # noqa: E402
from flat_rag import FlatRAG  # noqa: E402
from eval.alert_query import QUERY_FORMS, build_query, load_alerts, select_alerts  # noqa: E402
from eval.stats_utils import exact_mcnemar_test, wilson_score_interval  # noqa: E402

ENGINES = {"two_layer": TwoLayerRAG, "flat": FlatRAG}


def predict(engine_cls, records, row, form):
    eng = engine_cls(records, EMBEDDERS["tfidf-word"](), cve_lookup={})
    return predict_with(eng, row, form)


def predict_with(eng, row, form):
    a = row["alert"]
    return eng.query(alert_output_text=row["queries"][form], container_id=a.get("service", ""),
                     falco_rule=a.get("title", ""), alert_source=(a.get("source") or "").replace("-", "_")).predicted_technique


def main():
    gt = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    sel, _ = select_alerts(load_alerts(REPO_ROOT / "eval" / "runs" / "20261012T140201Z" / "alerts.jsonl"), gt)
    rows = [{"slot": s["slot"], "truth": s["ground_truth_technique"], "alert": s["alert"],
             "queries": {f: build_query(s["alert"], f) for f in QUERY_FORMS}} for s in sel if not s["slot"].startswith("S10")]
    clean, _ = load_kb_dir(str(REPO_ROOT / "kb_master" / "techniques"))
    targets = sorted({r["truth"] for r in rows})
    tactics = sorted({r.tactic for r in clean})
    by_id = {r.id: r for r in clean}

    # clean baselines
    base = {(e, f, row["slot"]): predict(cls, clean, row, f) == row["truth"]
            for e, cls in ENGINES.items() for f in QUERY_FORMS for row in rows}

    cases = defaultdict(list)   # (attack, form) -> list of dicts {slot, record, e1_correct_clean, ...}

    def score(attack, records, scored_rows, record_id, extra=""):
        engines = {e: cls(records, EMBEDDERS["tfidf-word"](), cve_lookup={}) for e, cls in ENGINES.items()}
        for f in QUERY_FORMS:
            for row in scored_rows:
                rec = {"slot": row["slot"], "corrupted_record": record_id, "detail": extra}
                for e, eng in engines.items():
                    ok_clean = base[(e, f, row["slot"])]
                    ok_now = predict_with(eng, row, f) == row["truth"]
                    rec[e] = {"clean_correct": ok_clean, "induced": ok_clean and not ok_now}
                cases[(attack, f)].append(rec)

    # 1. copied description
    for s in targets:
        for r in clean:
            if r.id == s:
                continue
            recs = copy.deepcopy(clean)
            for x in recs:
                if x.id == r.id:
                    x.description = by_id[s].description
            score("copied_description", recs, rows, r.id, f"gets description of {s}")
    # 2. targeted stuffing
    for row in rows:
        for r in clean:
            if r.id == row["truth"]:
                continue
            recs = copy.deepcopy(clean)
            for x in recs:
                if x.id == r.id:
                    x.description = f"{x.description} {row['queries']['raw']}"
            score("targeted_stuffing", recs, [row], r.id, f"stuffed with {row['slot']} alert text")
    # 3. tactic relabel
    for s in targets:
        for t in tactics:
            if t == by_id[s].tactic:
                continue
            recs = copy.deepcopy(clean)
            for x in recs:
                if x.id == s:
                    x.tactic = t
            score("tactic_relabel", recs, rows, s, f"filed under {t}")

    summary = {}
    for (attack, f), lst in sorted(cases.items()):
        s = {}
        for e in ENGINES:
            elig = [c for c in lst if c[e]["clean_correct"]]
            ind = [c for c in elig if c[e]["induced"]]
            p, lo, hi = wilson_score_interval(len(ind), len(elig)) if elig else (0, 0, 0)
            s[e] = {"induced": len(ind), "eligible_pairs": len(elig), "rate": round(p, 4),
                    "wilson_95": [round(lo, 4), round(hi, 4)],
                    "alerts_affected": sorted({c["slot"] for c in ind}),
                    "records_involved": len({c["corrupted_record"] for c in ind})}
        both = [c for c in lst if c["two_layer"]["clean_correct"] and c["flat"]["clean_correct"]]
        b = sum(c["two_layer"]["induced"] and not c["flat"]["induced"] for c in both)
        cc = sum(c["flat"]["induced"] and not c["two_layer"]["induced"] for c in both)
        s["paired_pairs_both_clean_correct"] = len(both)
        s["mcnemar_pairs"] = exact_mcnemar_test(b, cc)
        # per-alert view: alert counts as hit if any corruption induced an error
        alerts = sorted({c["slot"] for c in both})
        hit = {e: {a for a in alerts if any(c[e]["induced"] for c in both if c["slot"] == a)} for e in ENGINES}
        bb = len(hit["two_layer"] - hit["flat"]); cc2 = len(hit["flat"] - hit["two_layer"])
        s["per_alert"] = {"alerts": len(alerts), "two_layer_hit": sorted(hit["two_layer"]),
                          "flat_hit": sorted(hit["flat"]), "mcnemar_alerts": exact_mcnemar_test(bb, cc2)}
        summary[f"{attack}__{f}"] = s
        print(f"{attack:<20}{f:<10} two-layer {s['two_layer']['induced']:>3}/{s['two_layer']['eligible_pairs']:<4} "
              f"(alerts {s['two_layer']['alerts_affected']})  flat {s['flat']['induced']:>3}/{s['flat']['eligible_pairs']:<4} "
              f"(alerts {s['flat']['alerts_affected']})  pairs p={s['mcnemar_pairs']['p_value']:.3g}  "
              f"alerts p={s['per_alert']['mcnemar_alerts']['p_value']:.3g}")
    out = REPO_ROOT / "eval" / "poisoning_per_record_results.json"
    out.write_text(json.dumps({"alerts": [r["slot"] for r in rows], "summary": summary,
                               "clean_baseline": {f"{e}__{f}": sum(base[(e, f, r['slot'])] for r in rows)
                                                  for e in ENGINES for f in QUERY_FORMS}}, indent=2), encoding="utf-8")
    print(f"written {out}")


if __name__ == "__main__":
    main()
