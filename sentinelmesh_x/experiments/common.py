"""Shared helpers for the SentinelMesh-X experiments."""
from __future__ import annotations
import copy
import json
import math
import random
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinelmesh_x.data import ROOT, alert_sets, clean_record, correct, ground_truth, load_corpus, CORPORA, QUERY_FORMS, build_query  # noqa: E402
from sentinelmesh_x.knowledge_gen import generate_all, to_kb_signature, DetectorKnowledge  # noqa: E402
from sentinelmesh_x.retrieval import (KBIndex, make_records, rank_tfidf, rank_bm25, rank_rrf, rank_dahr, rank_registry_lookup,  # noqa: E402
                                      DAHRConfig, dahr_components, dahr_combine)
from kb_loader import _parse_technique, load_kb_dir, cve_lookup as build_cve_lookup  # noqa: E402
from eval.kb_curation_ablation import lab_parts  # noqa: E402

OUT = ROOT / "results_x"
OUT.mkdir(exist_ok=True)
SEED = 20261105




_DKS: Optional[List[DetectorKnowledge]] = None


def detectors() -> List[DetectorKnowledge]:
    global _DKS
    if _DKS is None:
        _DKS = generate_all(ROOT)
    return _DKS


def targets() -> set:
    return {v["technique_id"] for k, v in ground_truth().items() if k != "S10"}


def build_raw_condition(corpus: str, cond: str, drop_knowledge_for: Sequence[str] = ()) -> List[Dict[str, Any]]:
    """cond: mitre | expert | auto | auto_lex.  Only the 8 covered technique records differ between conditions
    (as in the original ablation); every other record stays MITRE text."""
    base = [clean_record(r) for r in load_corpus(corpus)]
    lab = lab_parts(ROOT / "kb_master/techniques")
    tg = targets() - set(drop_knowledge_for)
    out = []
    for r in base:
        r = copy.deepcopy(r)
        if r["id"] in tg and cond != "mitre":
            if cond == "expert" and r["id"] in lab:
                r["detection_signatures"] = copy.deepcopy(lab[r["id"]]["detection_signatures"])
                if lab[r["id"]]["lab_description"]:
                    r["description"] = f"{r['description']} {lab[r['id']]['lab_description']}"
            elif cond in ("auto", "auto_lex"):
                r["detection_signatures"] = to_kb_signature(detectors(), r["id"], lexicon=(cond == "auto_lex"))
        out.append(r)
    return out


def make_index(corpus: str, cond: str, with_field: Optional[bool] = None, drop_knowledge_for: Sequence[str] = (), **kw) -> KBIndex:
    raw = build_raw_condition(corpus, cond, drop_knowledge_for)
    recs = make_records(raw, use_mitre_sigs=True)
    use_field = (cond in ("auto", "auto_lex")) if with_field is None else with_field
    dks = [d for d in detectors() if d.technique not in drop_knowledge_for] if use_field else None
    return KBIndex(recs, dks, **kw)


# ------------------------------------------------------------------------------ metrics -------------------
def rank_of_truth(ids: List[str], truth: str, corpus: str) -> int:
    for k, i in enumerate(ids, 1):
        if correct(i, truth, corpus):
            return k
    return len(ids) + 1


def metrics_from_ranks(ranks: Sequence[int], preds: Sequence[str], truths: Sequence[str]) -> Dict[str, float]:
    r = np.array(ranks, float)
    n = len(r)
    m = {"n": n, "P@1": float((r == 1).mean()), "R@3": float((r <= 3).mean()), "R@5": float((r <= 5).mean()),
         "MRR": float((1.0 / r).mean()), "nDCG@5": float(np.where(r <= 5, 1.0 / np.log2(r + 1), 0.0).mean())}
    # macro F1 of the top-1 decision over the techniques that occur in the truth set
    labs = sorted(set(truths))
    f1s = []
    for l in labs:
        tp = sum(p == l and t == l for p, t in zip(preds, truths))
        fp = sum(p == l and t != l for p, t in zip(preds, truths))
        fn = sum(p != l and t == l for p, t in zip(preds, truths))
        f1s.append(2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0)
    m["macroF1"] = float(np.mean(f1s))
    return m


# ------------------------------------------------------------------------------ perturbations ------------
SYN = {"event_type": "evt", "result": "status", "identifier": "principal", "client_ip": "src", "details": "meta"}


def perturb_alert(alert: Dict[str, Any], mode: str, p: float, rng: random.Random) -> Dict[str, Any]:
    a = copy.deepcopy(alert)
    ev = a.get("event") or {}
    keep = {"timestamp", "service"}
    if mode == "drop":
        for k in list(ev):
            if k not in keep and rng.random() < p and len(ev) > 2:
                del ev[k]
    elif mode == "rename":
        for k in list(ev):
            if k in SYN and rng.random() < p:
                ev[SYN[k]] = ev.pop(k)
    elif mode == "noise":
        def noise(s):
            out = []
            for ch in s:
                u = rng.random()
                if u < p / 2:
                    continue
                out.append(chr(ord("a") + rng.randrange(26)) if u < p else ch)
            return "".join(out)
        for k, v in list(ev.items()):
            if k in keep:
                continue
            if isinstance(v, str):
                ev[k] = noise(v)
            elif isinstance(v, dict):
                ev[k] = {kk: (noise(vv) if isinstance(vv, str) else vv) for kk, vv in v.items()}
    a["event"] = ev
    return a


def requery(row: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, Any]:
    r = dict(row)
    r["alert"] = alert
    try:
        r["queries"] = {f: build_query(alert, f) for f in QUERY_FORMS}
    except ValueError:      # every informative field was lost: raw/rewrite are empty, only the detector title remains
        t = (alert.get("title") or "").strip()
        r["queries"] = {"raw": "", "title_raw": t, "rewrite": ""}
    return r


def save(name: str, obj: Any) -> Path:
    p = OUT / name
    p.write_text(json.dumps(obj, indent=1, default=str))
    return p
