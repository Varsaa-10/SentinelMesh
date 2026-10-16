"""
eval/kb_curation_ablation.py -- which part of the lab-written knowledge base makes retrieval work?

Starting point: the official MITRE ATT&CK corpora (corpus_36 / corpus_200 / corpus_full,
built by rag_engine/src/build_attack_corpus.py from STIX v20). Retrieval on raw alerts
collapses on that text. The lab-written records in kb_master/ differ from MITRE text in
three places, and this script adds them back one at a time, ONLY for the 8 techniques the
lab's detectors cover (the ground-truth answers). Every other record stays MITRE text.

  lab_detection    kb_master detection_signatures (event types, patterns, Falco rule text)
  lab_description  the lab-specific sentences of the kb_master description
                   (the text from "In the SentinelMesh lab" onwards), appended to MITRE's
  lab_other        kb_master mitigation text and related CVE ids

Variants: mitre, +detection, +description, +detection+description, +all.
MITRE "(Citation: ...)" markers are stripped everywhere; the uncleaned text is also run once
(`mitre_with_citations`) to show the markers do not matter.

Alerts: the 12 Oct capture (14 alerts), the 60 clean development alerts (5 runs, faulty S8 slots
excluded), the 140 alerts of the ten fresh captures, and the 5 alerts of the held-out variant run,
selected and rendered exactly as in eval/cross_capture_evaluation.py. The sets are scored separately.
Embedders: tfidf-word (default), tfidf-char, dense-minilm (truncates at 256 tokens) and
dense-minilm-chunked (reads the whole record in overlapping windows; use this one for the paper).
Scoring: exact technique id; for corpus_200 (no sub-techniques) the parent id also counts,
so T1003 is accepted for T1003.008.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(os.environ.get("SENTINELMESH_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from kb_loader import _parse_technique, load_kb_dir, cve_lookup as build_cve_lookup  # noqa: E402
from embeddings import EMBEDDERS  # noqa: E402
from rag_engine import TwoLayerRAG  # noqa: E402
from flat_rag import FlatRAG  # noqa: E402
from eval.alert_query import QUERY_FORMS, build_query, load_alerts, select_alerts  # noqa: E402
from eval.stats_utils import wilson_score_interval  # noqa: E402

CORPORA = {"corpus_36": 36, "corpus_200": 227, "corpus_full": 706}
DEV_RUNS = ["20260818T052007Z", "20260818T052217Z_chaintagged", "20261012T030225Z_chaintagged",
            "20261012T031032Z_chaintagged", "20261012T140201Z"]
# fresh captures 2026-10-14, five subnets, two runs each (the main test set)
FRESH_RUNS = ["20261014T104641Z", "20261014T111618Z", "20261014T113310Z", "20261014T122816Z",
              "20261014T130955Z", "20261014T132438Z", "20261014T134019Z", "20261014T135319Z",
              "20261014T140601Z", "20261014T141640Z"]
HELDOUT_RUNS = ["20261015T051907Z"]  # eval/runs_heldout/
RUNS = DEV_RUNS + FRESH_RUNS
RUNS_WITH_FAULTY_S8 = {"20260818T052007Z", "20260818T052217Z_chaintagged", "20261012T030225Z_chaintagged"}
OCT = "20261012T140201Z"
CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
LAB_MARK = "In the SentinelMesh lab"


def strip_citations(text: str) -> str:
    return CITATION_RE.sub("", text or "").strip()


def lab_parts(kb_master_dir: Path) -> Dict[str, Dict[str, Any]]:
    parts = {}
    for p in kb_master_dir.glob("*.json"):
        r = json.loads(p.read_text(encoding="utf-8"))
        desc = r.get("description", "")
        lab_desc = desc[desc.index(LAB_MARK):] if LAB_MARK in desc else ""
        parts[r["id"]] = {"detection_signatures": r.get("detection_signatures"), "lab_description": lab_desc,
                          "mitigation": r.get("mitigation", ""), "related_cves": r.get("related_cves", [])}
    return parts


def build_variant(base: List[Dict[str, Any]], lab: Dict[str, Dict[str, Any]], targets: set,
                  detection: bool, description: bool, other: bool, clean: bool = True) -> List[Any]:
    out = []
    for r in base:
        r = copy.deepcopy(r)
        if clean:
            r["description"] = strip_citations(r["description"])
            r["mitigation"] = strip_citations(r.get("mitigation", ""))
            sig = r.get("detection_signatures") or {}
            for k in ("log_tail", "falco"):
                if isinstance(sig.get(k), dict):
                    sig[k] = {kk: strip_citations(vv) if isinstance(vv, str) else vv for kk, vv in sig[k].items()}
        if r["id"] in targets and r["id"] in lab:
            L = lab[r["id"]]
            if detection:
                r["detection_signatures"] = copy.deepcopy(L["detection_signatures"])
            if description and L["lab_description"]:
                r["description"] = f"{r['description']} {L['lab_description']}"
            if other:
                r["mitigation"] = L["mitigation"]
                r["related_cves"] = list(L["related_cves"])
        out.append(_parse_technique(r))
    return out


VARIANTS = {
    "mitre_with_citations": dict(detection=False, description=False, other=False, clean=False),
    "mitre": dict(detection=False, description=False, other=False),
    "+detection": dict(detection=True, description=False, other=False),
    "+description": dict(detection=False, description=True, other=False),
    "+detection+description": dict(detection=True, description=True, other=False),
    "+all_lab_fields": dict(detection=True, description=True, other=True),
}


def alert_sets(gt) -> Dict[str, List[Dict[str, Any]]]:
    """oct12_14: reference run. clean_60: the five development runs (faulty S8 slots dropped).
    fresh_140: the ten fresh captures. heldout_5: alerts from the held-out variant run.
    Sets are kept separate so development and test alerts are never pooled."""
    sets = {"oct12_14": [], "clean_60": [], "fresh_140": [], "heldout_5": []}
    plan = [(r, "runs") for r in DEV_RUNS + FRESH_RUNS] + [(r, "runs_heldout") for r in HELDOUT_RUNS]
    for run, folder in plan:
        sel, _ = select_alerts(load_alerts(REPO_ROOT / "eval" / folder / run / "alerts.jsonl"), gt)
        for it in sel:
            faulty = run in RUNS_WITH_FAULTY_S8 and it["slot"] in ("S8", "S10:S8")
            row = {"run": run, "slot": it["slot"], "truth": it["ground_truth_technique"],
                   "alert": it["alert"], "queries": {f: build_query(it["alert"], f) for f in QUERY_FORMS}}
            if run == OCT:
                sets["oct12_14"].append(row)
            if run in DEV_RUNS and not faulty:
                sets["clean_60"].append(row)
            elif run in FRESH_RUNS:
                sets["fresh_140"].append(row)
            elif run in HELDOUT_RUNS:
                sets["heldout_5"].append(row)
    return sets


def correct(pred: str, truth: str, parent_ok: bool) -> Tuple[bool, bool]:
    exact = pred == truth
    parent = exact or (parent_ok and "." in truth and pred == truth.split(".")[0])
    return exact, parent


def main(embedder: str = "tfidf-word") -> Dict[str, Any]:
    gt = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    targets = {v["technique_id"] for v in gt.values()}
    lab = lab_parts(REPO_ROOT / "kb_master" / "techniques")
    _, cves = load_kb_dir(str(REPO_ROOT / "kb_master" / "techniques"), str(REPO_ROOT / "kb_master" / "cves"))
    cve_map = build_cve_lookup(cves)
    sets = alert_sets(gt)
    print({k: len(v) for k, v in sets.items()})

    results: Dict[str, Any] = {"targets": sorted(targets), "embedder": embedder, "alert_counts": {k: len(v) for k, v in sets.items()},
                               "rows": []}
    for corpus, n_expected in CORPORA.items():
        base = [json.loads(p.read_text(encoding="utf-8"))
                for p in sorted((REPO_ROOT / "rag_engine" / "kb" / "corpora" / corpus).glob("*.json"))]
        present = {r["id"] for r in base}
        for vname, vargs in VARIANTS.items():
            recs = build_variant(base, lab, targets, **vargs)
            # a pretrained dense model is not refitted, so one loaded instance can serve both engines
            shared = EMBEDDERS[embedder]() if embedder.startswith("dense") else None
            engines = {"two_layer": TwoLayerRAG(recs, shared or EMBEDDERS[embedder](), cve_lookup=cve_map),
                       "flat": FlatRAG(recs, shared or EMBEDDERS[embedder](), cve_lookup=cve_map)}
            for set_name, rows in sets.items():
                for form in QUERY_FORMS:
                    for ename, eng in engines.items():
                        ex = pa = 0
                        wrong = []
                        for row in rows:
                            r = eng.query(alert_output_text=row["queries"][form],
                                          container_id=row["alert"].get("service", ""),
                                          falco_rule=row["alert"].get("title", ""),
                                          alert_source=(row["alert"].get("source") or "").replace("-", "_"))
                            e, p = correct(r.predicted_technique, row["truth"], corpus == "corpus_200")
                            ex += e
                            pa += p
                            if not p:
                                wrong.append(f"{row['slot']}->{r.predicted_technique}")
                        n = len(rows)
                        _, lo, hi = wilson_score_interval(pa, n)
                        results["rows"].append({"corpus": corpus, "records": len(base), "variant": vname,
                                                "alerts": set_name, "form": form, "engine": ename,
                                                "exact": ex, "parent_or_exact": pa, "n": n,
                                                "wilson_95": [round(lo, 3), round(hi, 3)],
                                                "wrong_examples": sorted(set(wrong))[:12]})
            print(f"{corpus:<12} {vname:<24} done", flush=True)
    suffix = "" if embedder == "tfidf-word" else f"_{embedder}"
    out = REPO_ROOT / "eval" / f"kb_curation_ablation_results{suffix}.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"written {out}")
    return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--embedder", default="tfidf-word", choices=sorted(EMBEDDERS))
    args = ap.parse_args()
    main(embedder=args.embedder)
