"""
eval/poisoning_v2.py -- one-record knowledge-base corruption on more alerts, with clean baselines,
explicit denominators and three defences.

Corpus: kb_master (the 36 lab-written technique records the pipeline uses).
Alerts: --alerts fresh70 (default): all 14 slots of the first test capture on each of the five
subnets (70 alerts, distinct texts); --alerts ref9: the 9 standalone alerts of the reference run.
Attacks (each corrupted copy differs from the clean corpus in exactly one record):
  copied_description  each non-answer record gets the description of one answer technique (280 corpora)
  tactic_relabel      each answer record is filed under each other tactic (72 corpora)
  targeted_stuffing   for one alert, one record that is not its answer has the alert's raw text
                      appended to its description (35 corpora per alert)
Counting: an eligible pair is (corrupted corpus, alert) where the alert is answered correctly on the
clean corpus by that retriever and query form; an induced error is an eligible pair answered wrongly
on the corrupted corpus.

Defences, each judged on whether it flags the corrupted record, and on false alarms over the
clean 36 records and over the 706 MITRE records:
  D1 duplicate text   a record whose description has TF-IDF cosine >= 0.90 with another record's
  D2 alert-like text  description contains an IPv4 address, a key=value pair, or a lab container name
  D3 upstream tactic  the record's tactic is not among the tactics MITRE STIX v20 lists for that ID
Record versioning (a signed hash per record) would flag every corruption here by construction; it is
reported as such, not measured.
Usage: python3 eval/poisoning_v2.py [--alerts fresh70|ref9]
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(os.environ.get("SENTINELMESH_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.metrics.pairwise import cosine_similarity  # noqa: E402
from kb_loader import load_kb_dir  # noqa: E402
from embeddings import EMBEDDERS  # noqa: E402
from rag_engine import TwoLayerRAG  # noqa: E402
from flat_rag import FlatRAG  # noqa: E402
from eval.alert_query import QUERY_FORMS, build_query, load_alerts, select_alerts  # noqa: E402

ENGINES = {"tactic_first": TwoLayerRAG, "flat": FlatRAG}
FRESH70 = ["20261014T104641Z", "20261014T113310Z", "20261014T130955Z", "20261014T134019Z", "20261014T140601Z"]
REF = "20261012T140201Z"
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
KV_RE = re.compile(r"\b[a-z_][a-z0-9_.]*=[^\s,;]+", re.I)
LAB_RE = re.compile(r"sentinelmesh-[a-z]+", re.I)


def alert_rows(which, gt):
    rows = []
    runs = FRESH70 if which == "fresh70" else [REF]
    for run in runs:
        sel, _ = select_alerts(load_alerts(REPO_ROOT / "eval" / "runs" / run / "alerts.jsonl"), gt)
        for s in sel:
            if which == "ref9" and s["slot"].startswith("S10"):
                continue
            rows.append({"id": f"{run}:{s['slot']}", "slot": s["slot"], "truth": s["ground_truth_technique"],
                         "alert": s["alert"], "queries": {f: build_query(s["alert"], f) for f in QUERY_FORMS}})
    return rows


def predict(eng, row, form):
    a = row["alert"]
    return eng.query(alert_output_text=row["queries"][form], container_id=a.get("service", ""),
                     falco_rule=a.get("title", ""), alert_source=(a.get("source") or "").replace("-", "_")).predicted_technique


def build(records):
    return {e: cls(records, EMBEDDERS["tfidf-word"](), cve_lookup={}) for e, cls in ENGINES.items()}


# ---------------- defences
def d1_duplicates(records, thr=0.90):
    texts = [r.description or "" for r in records]
    v = TfidfVectorizer(stop_words="english").fit_transform(texts)
    s = cosine_similarity(v); flagged = set()
    for i in range(len(records)):
        for j in range(len(records)):
            if i != j and s[i, j] >= thr:
                flagged.add(records[i].id)
    return flagged


def d2_alert_text(records):
    return {r.id for r in records if IP_RE.search(r.description or "") or KV_RE.search(r.description or "")
            or LAB_RE.search(r.description or "")}


def stix_tactics():
    path = REPO_ROOT / "rag_engine" / "kb" / "corpora" / "corpus_full"
    out = {}
    for p in path.glob("*.json"):
        r = json.loads(p.read_text(encoding="utf-8"))
        out[r["id"]] = set(r.get("tactics") or [r["tactic"]])
    return out


def main(which):
    gt = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    rows = alert_rows(which, gt)
    clean, _ = load_kb_dir(str(REPO_ROOT / "kb_master" / "techniques"))
    by_id = {r.id: r for r in clean}
    targets = sorted({r["truth"] for r in rows})
    tactics = sorted({r.tactic for r in clean})
    upstream = stix_tactics()

    def d3_upstream(records):
        return {r.id for r in records if r.id in upstream and r.tactic not in upstream[r.id]}

    eng0 = build(clean)
    base = {(e, f, row["id"]): predict(eng0[e], row, f) == row["truth"] for e in ENGINES for f in QUERY_FORMS for row in rows}
    clean_flags = {"D1": sorted(d1_duplicates(clean)), "D2": sorted(d2_alert_text(clean)), "D3": sorted(d3_upstream(clean))}
    mitre_full, _ = load_kb_dir(str(REPO_ROOT / "rag_engine" / "kb" / "corpora" / "corpus_full"))
    mitre_flags = {"D1": len(d1_duplicates(mitre_full)), "D2": len(d2_alert_text(mitre_full)), "D3": len(d3_upstream(mitre_full)),
                   "records": len(mitre_full)}

    stats = defaultdict(lambda: defaultdict(lambda: {"eligible": 0, "induced": 0, "alerts_hit": set(), "slots_hit": set(),
                                                     "induced_unflagged": 0}))
    detect = defaultdict(lambda: {"corpora": 0, "D1": 0, "D2": 0, "D3": 0, "any": 0})

    def run_case(attack, records, scored_rows, corrupted_id):
        flags = {"D1": corrupted_id in d1_duplicates(records), "D2": corrupted_id in d2_alert_text(records),
                 "D3": corrupted_id in d3_upstream(records)}
        anyf = any(flags.values())
        dd = detect[attack]; dd["corpora"] += 1; dd["any"] += anyf
        for k, v in flags.items():
            dd[k] += v
        engs = build(records)
        for f in QUERY_FORMS:
            for row in scored_rows:
                for e in ENGINES:
                    if not base[(e, f, row["id"])]:
                        continue
                    st = stats[(attack, f)][e]; st["eligible"] += 1
                    if predict(engs[e], row, f) != row["truth"]:
                        st["induced"] += 1; st["alerts_hit"].add(row["id"]); st["slots_hit"].add(row["slot"].replace("S10:", ""))
                        st["induced_unflagged"] += not anyf

    for s in targets:
        for r in clean:
            if r.id == s:
                continue
            recs = copy.deepcopy(clean)
            for x in recs:
                if x.id == r.id:
                    x.description = by_id[s].description
            run_case("copied_description", recs, rows, r.id)
    print("copied done", flush=True)
    for s in targets:
        for t in tactics:
            if t == by_id[s].tactic:
                continue
            recs = copy.deepcopy(clean)
            for x in recs:
                if x.id == s:
                    x.tactic = t
            run_case("tactic_relabel", recs, rows, s)
    print("relabel done", flush=True)
    for row in rows:
        for r in clean:
            if r.id == row["truth"]:
                continue
            recs = copy.deepcopy(clean)
            for x in recs:
                if x.id == r.id:
                    x.description = f"{x.description} {row['queries']['raw']}"
            run_case("targeted_stuffing", recs, [row], r.id)
    print("stuffing done", flush=True)

    summary = {}
    for (attack, f), per in sorted(stats.items()):
        summary[f"{attack}__{f}"] = {e: {"eligible_pairs": v["eligible"], "induced": v["induced"],
                                         "rate": round(v["induced"] / v["eligible"], 4) if v["eligible"] else None,
                                         "alerts_hit": len(v["alerts_hit"]), "scenarios_hit": sorted(v["slots_hit"]),
                                         "induced_after_defences": v["induced_unflagged"]} for e, v in per.items()}
    out = {"alerts": which, "n_alerts": len(rows),
           "clean_correct": {f"{e}__{f}": sum(base[(e, f, r['id'])] for r in rows) for e in ENGINES for f in QUERY_FORMS},
           "summary": summary, "detection": {k: dict(v) for k, v in detect.items()},
           "false_alarms_clean_lab": clean_flags, "false_alarms_mitre_706": mitre_flags,
           "record_versioning": "a signed per-record hash checked before indexing flags every corrupted corpus by construction"}
    path = REPO_ROOT / "eval" / f"poisoning_v2_results_{which}.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("n_alerts", "clean_correct", "detection", "false_alarms_clean_lab", "false_alarms_mitre_706")}, indent=1))
    for k, v in summary.items():
        print(k, {e: (x["induced"], x["eligible_pairs"], x["alerts_hit"], x["scenarios_hit"], x["induced_after_defences"]) for e, x in v.items()})
    print("written", path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default="fresh70", choices=["fresh70", "ref9"])
    main(ap.parse_args().alerts)
