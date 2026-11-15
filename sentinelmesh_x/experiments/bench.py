"""Method runners shared by the benchmark / generalisation / ablation experiments."""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Sequence
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from common import *
from common import _parse_technique
from sentinelmesh_x.retrieval import tokenize, Ranked
from embeddings import EMBEDDERS
from rag_engine import TwoLayerRAG
from flat_rag import FlatRAG


def tuned_cfg() -> DAHRConfig:
    p = OUT / "dahr_tuned.json"
    if p.exists():
        d = json.loads(p.read_text())["best"]
        return DAHRConfig(**d)
    return DAHRConfig()


class RepoEngines:
    """The two retrievers of the original paper (TF-IDF word embedder), with full rankings reconstructed."""

    def __init__(self, raw: List[Dict[str, Any]], cve_map):
        recs = [_parse_technique(r) for r in raw]
        self.recs = recs
        self.flat = FlatRAG(recs, EMBEDDERS["tfidf-word"](), cve_lookup=cve_map)
        self.two = TwoLayerRAG(recs, EMBEDDERS["tfidf-word"](), cve_lookup=cve_map)
        self.ids = [r.id for r in recs]

    def rank_flat(self, q: str) -> List[str]:
        e = self.flat.embedder
        sims = e.similarity_matrix(e.embed([q]), self.flat._record_vecs)[0]
        return [self.ids[i] for i in np.argsort(-sims, kind="stable")]

    def rank_two(self, q: str) -> List[str]:
        t = self.two
        e = t.embedder
        qv = e.embed([q])
        ts = e.similarity_matrix(qv, t._tactic_vecs)[0]
        best = t._tactics[int(np.argmax(ts))]
        scoped = [i for i, r in enumerate(t.records) if r.tactic == best] or list(range(len(t.records)))
        sims = e.similarity_matrix(qv, t._record_vecs[scoped])[0]
        first = [scoped[i] for i in np.argsort(-sims, kind="stable")]
        rest = [i for i in np.argsort(-e.similarity_matrix(qv, t._record_vecs)[0], kind="stable") if i not in set(first)]
        return [self.ids[i] for i in first + list(rest)]


class Supervised:
    """TF-IDF + logistic regression over query text, trained on labelled alerts (the 'supervised ATT&CK classifier' baseline).
    It can only predict techniques seen in training; everything else is ranked after the known classes."""

    def __init__(self, train_rows: Sequence[Dict[str, Any]], form: str):
        self.form = form
        self.vec = TfidfVectorizer(tokenizer=lambda s: tokenize(s, True), lowercase=False, token_pattern=None, sublinear_tf=True)
        X = self.vec.fit_transform([r["queries"][form] or "empty" for r in train_rows])
        y = [r["truth"] for r in train_rows]
        self.clf = LogisticRegression(C=10, max_iter=2000).fit(X, y) if len(set(y)) > 1 else None
        self.classes = sorted(set(y))

    def rank(self, q: str) -> List[str]:
        if self.clf is None:
            return list(self.classes)
        p = self.clf.predict_proba(self.vec.transform([q or "empty"]))[0]
        return [self.clf.classes_[i] for i in np.argsort(-p, kind="stable")]


def ranks_for(method: str, row: Dict[str, Any], form: str, ix: KBIndex, corpus: str, cfg: DAHRConfig, repo: Optional[RepoEngines] = None,
              sup: Optional[Supervised] = None, truth_map: Optional[Dict[str, str]] = None, disabled: Sequence[str] = ()) -> List[str]:
    q, a = row["queries"][form], row["alert"]
    if method == "tfidf":
        return rank_tfidf(ix, q).ids
    if method == "bm25":
        return rank_bm25(ix, q).ids
    if method == "rrf":
        return rank_rrf(ix, q).ids
    if method == "dahr_default":
        return rank_dahr(ix, q, a, DAHRConfig(), disabled).ids
    if method == "dahr":
        return rank_dahr(ix, q, a, cfg, disabled).ids
    if method == "repo_flat":
        return repo.rank_flat(q)
    if method == "repo_two_layer":
        return repo.rank_two(q)
    if method == "supervised":
        return sup.rank(q)
    if method == "registry":
        return rank_registry_lookup(ix, a, truth_map).ids
    raise KeyError(method)


def truth_map() -> Dict[str, str]:
    return {k: v["technique_id"] for k, v in ground_truth().items() if k != "S10"}


def score_rows(method: str, rows: Sequence[Dict[str, Any]], form: str, ix: KBIndex, corpus: str, cfg: DAHRConfig, repo=None, sup=None, disabled=()) -> Dict[str, Any]:
    tm = truth_map()
    ranks, preds, truths = [], [], []
    for r in rows:
        ids = ranks_for(method, r, form, ix, corpus, cfg, repo, sup, tm, disabled)
        ranks.append(rank_of_truth(ids, r["truth"], corpus))
        preds.append(ids[0])
        truths.append(r["truth"])
    return {"ranks": ranks, "preds": preds, "metrics": metrics_from_ranks(ranks, preds, truths)}
