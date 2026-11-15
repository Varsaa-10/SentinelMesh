"""Detector-Aware Hybrid Retrieval (DAHR) and baselines (SentinelMesh-X, improvement items 4 and 5).

Notation. KB = {d_1..d_N} ATT&CK records, alert a with query text q (one of three forms) and structured event.
 s_sem(q,d)   TF-IDF cosine, numeric-token-suppressing tokenizer             O(|q| + nnz) per query with a sparse index
 s_bm25(q,d)  Okapi BM25 (k1=1.5, b=0.75)
 s_fld(a,d)   max over detector signatures sigma of d of  [m - gamma (c - m)] / t   (weighted constraint match;
              m,c,t = matched / checkable / total constraint weight, weights = IDF over the constraint set).
              Execution conditions are the Falco conditions and the analysed Python guards (knowledge_gen.py).
              Alert identity (title, scenario) is never read.
 s_hier(d)    ATT&CK relationship evidence: 0.5 * tactic evidence + 0.5 * parent/sub-technique evidence, both taken from
              the semantic scores of related records (mean of the top-m records of the tactic; max over parent/children).
 DAHR(a,d) = w_f s_fld + w_s s^_sem + w_b s^_bm25 + w_h s^_hier, with ^ = division by the max over the KB, and the
 weights adapted per alert:  w_f ∝ w_f0 (0.5 + cov), w_s ∝ w_s0 (0.5 + oov), w_b ∝ w_b0, w_h ∝ w_h0 (0.5 + sharp_low),
 where cov = checkable fraction of the best signature, oov = fraction of query tokens in the KB vocabulary, and
 sharp_low = 1 - margin of the semantic channel (hierarchy helps when the semantic channel is torn).
 Complexity per query: O(nnz(q)·avg posting) for sem/bm25, O(S·L) for the field channel (S signatures, L leaves, both
 independent of N because only records with signatures are scored), O(N) for hierarchy with precomputed groups.
"""
from __future__ import annotations
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

from .falco_cond import leaves, score as fscore
from .knowledge_gen import DetectorKnowledge, _flat

STOP = set("a an the of to in on for and or is are was were be by with as at from that this it its into than then not no may can could which such these those other".split())


def tokenize(text: str, suppress_numeric: bool = True) -> List[str]:
    toks = re.findall(r"[a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", text.replace("_", " ").replace(".", " ")).lower())
    out = []
    for t in toks:
        if len(t) < 2 or t in STOP:
            continue
        if suppress_numeric and t.isdigit():
            continue
        out.append(t)
    return out


@dataclass
class XRecord:
    id: str
    name: str
    tactic: str
    tactics: List[str]
    parent: Optional[str]
    text: str                       # semantic text (name + description + signature text)
    sources: List[str] = field(default_factory=list)   # detector sources declared (log_tail / falco)


def make_records(raw: List[Dict[str, Any]], sig_text: Optional[Dict[str, str]] = None, sources: Optional[Dict[str, List[str]]] = None,
                 use_mitre_sigs: bool = False) -> List[XRecord]:
    recs = []
    sig_text = sig_text or {}
    for r in raw:
        base = f"{r.get('technique_name','')}. {r.get('description','')}"
        extra = sig_text.get(r["id"], "")
        if use_mitre_sigs and not extra:
            sig = r.get("detection_signatures") or {}
            for k in ("log_tail", "falco"):
                if isinstance(sig, dict) and isinstance(sig.get(k), dict):
                    extra += " " + " ".join(str(v) for v in sig[k].values() if isinstance(v, str))
                    ms = sig[k].get("match_fields")
                    if isinstance(ms, dict):
                        extra += " " + " ".join(f"{a} {b}" for a, b in ms.items())
        recs.append(XRecord(r["id"], r.get("technique_name", ""), r.get("tactic", ""), r.get("tactics") or [r.get("tactic", "")],
                            r.get("sub_technique_of"), (base + " " + extra).strip(), (sources or {}).get(r["id"], [])))
    return recs


# ------------------------------------------------------------------------------------ lexical indexes ----
class TfidfIndex:
    def __init__(self, texts: Sequence[str], suppress_numeric=True, ngram=(1, 1)):
        self.sn = suppress_numeric
        self.vec = TfidfVectorizer(tokenizer=lambda s: tokenize(s, suppress_numeric), lowercase=False, token_pattern=None,
                                   sublinear_tf=True, ngram_range=ngram)
        self.M = self.vec.fit_transform(texts)
        self.vocab = self.vec.vocabulary_

    def scores(self, q: str) -> np.ndarray:
        v = self.vec.transform([q])
        return (self.M @ v.T).toarray().ravel()

    def oov_ratio(self, q: str) -> float:
        toks = tokenize(q, self.sn)
        return sum(t in self.vocab for t in toks) / len(toks) if toks else 0.0


class BM25Index:
    def __init__(self, texts: Sequence[str], k1=1.5, b=0.75, suppress_numeric=True):
        self.sn, self.k1, self.b = suppress_numeric, k1, b
        docs = [tokenize(t, suppress_numeric) for t in texts]
        self.N = len(docs)
        self.dl = np.array([len(d) for d in docs], float)
        self.avg = self.dl.mean() or 1.0
        df = Counter(t for d in docs for t in set(d))
        self.idf = {t: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for t, n in df.items()}
        self.post: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        for i, d in enumerate(docs):
            for t, c in Counter(d).items():
                self.post[t].append((i, c))

    def scores(self, q: str) -> np.ndarray:
        s = np.zeros(self.N)
        for t in set(tokenize(q, self.sn)):
            if t not in self.post:
                continue
            idf = self.idf[t]
            for i, c in self.post[t]:
                s[i] += idf * c * (self.k1 + 1) / (c + self.k1 * (1 - self.b + self.b * self.dl[i] / self.avg))
        return s


# ------------------------------------------------------------------------------------ field channel -------
def _get_path(ev: Dict[str, Any], path: str) -> Any:
    cur: Any = ev
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def _eval_atom(a: dict, ev: Dict[str, Any]) -> Optional[bool]:
    if a["kind"] == "in":
        vals = [_get_path(ev, p) for p in a["paths"]]
        vals = [v for v in vals if v is not None]
        if not vals:
            return None
        hit = any(str(v).lower() in {str(x).lower() for x in a["values"]} for v in vals)
        return (not hit) if a["neg"] else hit
    if a["kind"] == "regex":
        paths = a["paths"]
        vals = [_get_path(ev, p) for p in paths]
        vals = [v for v in vals if isinstance(v, str)]
        if not vals:
            return None
        hit = any(re.search(a["pattern"], v, re.I) for v in vals)
        return (not hit) if a["neg"] else hit
    if a["kind"] == "window_count":
        vals = [_get_path(ev, p) for p in a.get("paths", [])]
        vals = [v for v in vals if isinstance(v, (int, float))]
        if not vals:
            return None
        v = vals[0]
        return {">=": v >= a["value"], ">": v > a["value"], "<": v < a["value"], "<=": v <= a["value"]}[a["op"]]
    return None


def _atom_key(a: dict) -> tuple:
    return (a["kind"], tuple(a.get("paths", [])), tuple(map(str, a.get("values", []))), a.get("pattern", ""), a.get("neg", False), a.get("op", ""))


def _score_py_branch(br: List[dict], ev: Dict[str, Any], wfn) -> Tuple[float, float, float]:
    m = c = t = 0.0
    for a in br:
        if a["kind"] == "or":
            parts = []
            for it in a["items"]:
                w = wfn(it)
                r = _eval_atom(it, ev)
                parts.append((w if r else 0.0, w if r is not None else 0.0, w))
            if parts:
                b = max(parts, key=lambda p: (p[0] / p[2] if p[2] else 0, p[1]))
                m, c, t = m + b[0], c + b[1], t + max(p[2] for p in parts)
            continue
        w = wfn(a)
        r = _eval_atom(a, ev)
        m += w if r else 0.0
        c += w if r is not None else 0.0
        t += w
    return m, c, t


class FieldChannel:
    """Executes detector constraints against an alert's structured event."""

    def __init__(self, dks: List[DetectorKnowledge], gamma: float = 1.0, use_source_gate: bool = True):
        self.dks, self.gamma, self.gate = dks, gamma, use_source_gate
        df: Counter = Counter()
        for dk in dks:
            keys = set()
            if dk.kind == "falco":
                keys |= {("f",) + (l[1], l[2], str(l[3]), l[4]) for l in leaves(dk.cond_ast)}
            for br in dk.branches:
                keys |= {_atom_key(a) for a in _flat(br)}
            df.update(keys)
        self.n = max(1, len(dks))
        self.df = df

    def _w_py(self, a):
        return math.log((self.n + 1) / (self.df[_atom_key(a)] + 0.5)) + 0.25

    def _w_falco(self, l):
        return math.log((self.n + 1) / (self.df[("f", l[1], l[2], str(l[3]), l[4])] + 0.5)) + 0.25

    def score_dk(self, dk: DetectorKnowledge, alert: Dict[str, Any]) -> Tuple[float, float]:
        ev = dict(alert.get("event") or {})
        src = (alert.get("source") or "").replace("-", "_")
        if self.gate and src and dk.kind != src:
            return 0.0, 0.0
        if dk.kind == "falco":
            m, c, t = fscore(dk.cond_ast, ev, self._w_falco)
        else:
            if not dk.branches:
                return 0.0, 0.0
            best = max((_score_py_branch(b, ev, self._w_py) for b in dk.branches), key=lambda p: (p[0] / p[2] if p[2] else 0, p[1]))
            m, c, t = best
            et_ok = (not dk.event_types) or str(ev.get("event_type") or ev.get("event")) in dk.event_types
            if dk.event_types and (ev.get("event_type") or ev.get("event")) and not et_ok:
                m = 0.0
        if t <= 0:
            return 0.0, 0.0
        s = max(0.0, (m - self.gamma * (c - m)) / t)
        return s, c / t

    def per_technique(self, alert: Dict[str, Any]) -> Dict[str, Tuple[float, float]]:
        out: Dict[str, Tuple[float, float]] = {}
        for dk in self.dks:
            s, cov = self.score_dk(dk, alert)
            if dk.technique not in out or s > out[dk.technique][0]:
                out[dk.technique] = (s, cov)
        return out


# ------------------------------------------------------------------------------------ rankers ------------
@dataclass
class Ranked:
    ids: List[str]
    scores: List[float]
    parts: Dict[str, float] = field(default_factory=dict)
    latency_ms: float = 0.0


class KBIndex:
    """Shared index over one knowledge base (build once, query many)."""

    def __init__(self, records: List[XRecord], dks: Optional[List[DetectorKnowledge]] = None, suppress_numeric=True, ngram=(1, 1)):
        t0 = time.perf_counter()
        self.recs = records
        self.ids = [r.id for r in records]
        self.pos = {r.id: i for i, r in enumerate(records)}
        self.tf = TfidfIndex([r.text for r in records], suppress_numeric, ngram)
        self.bm = BM25Index([r.text for r in records], suppress_numeric=suppress_numeric)
        self.field = FieldChannel(dks or []) if dks else None
        self.tactic_members: Dict[str, List[int]] = defaultdict(list)
        for i, r in enumerate(records):
            for t in r.tactics or [r.tactic]:
                self.tactic_members[t].append(i)
        self.children: Dict[str, List[int]] = defaultdict(list)
        for i, r in enumerate(records):
            if r.parent:
                self.children[r.parent].append(i)
        self.build_ms = (time.perf_counter() - t0) * 1000

    def tactic_matrix(self) -> Tuple[List[str], np.ndarray]:
        tac = sorted(self.tactic_members)
        return tac, np.array([[1.0 if i in set(self.tactic_members[t]) else 0.0 for i in range(len(self.recs))] for t in tac])


def _rank(scores: np.ndarray, ids: List[str]) -> Tuple[List[str], List[float]]:
    o = np.argsort(-scores, kind="stable")
    return [ids[i] for i in o], [float(scores[i]) for i in o]


def rank_tfidf(ix: KBIndex, q: str) -> Ranked:
    t0 = time.perf_counter()
    i, s = _rank(ix.tf.scores(q), ix.ids)
    return Ranked(i, s, latency_ms=(time.perf_counter() - t0) * 1000)


def rank_bm25(ix: KBIndex, q: str) -> Ranked:
    t0 = time.perf_counter()
    i, s = _rank(ix.bm.scores(q), ix.ids)
    return Ranked(i, s, latency_ms=(time.perf_counter() - t0) * 1000)


def rank_rrf(ix: KBIndex, q: str, k: int = 60) -> Ranked:
    """Conventional hybrid: reciprocal-rank fusion of BM25 and TF-IDF (no structure, no hierarchy)."""
    t0 = time.perf_counter()
    fused = np.zeros(len(ix.ids))
    for sc in (ix.tf.scores(q), ix.bm.scores(q)):
        order = np.argsort(-sc, kind="stable")
        rk = np.empty(len(sc))
        rk[order] = np.arange(1, len(sc) + 1)
        fused += 1.0 / (k + rk)
    i, s = _rank(fused, ix.ids)
    return Ranked(i, s, latency_ms=(time.perf_counter() - t0) * 1000)


@dataclass
class DAHRConfig:
    w_f: float = 0.45
    w_s: float = 0.30
    w_b: float = 0.10
    w_h: float = 0.15
    top_m: int = 3
    adaptive: bool = True
    use_field: bool = True
    use_sem: bool = True
    use_bm25: bool = True
    use_hier: bool = True


def _hier_scores(ix: KBIndex, sem: np.ndarray, top_m: int) -> np.ndarray:
    N = len(ix.recs)
    tau = {}
    for t, mem in ix.tactic_members.items():
        v = np.sort(sem[mem])[::-1][:top_m]
        tau[t] = float(v.mean()) if len(v) else 0.0
    mx = max(tau.values()) if tau else 0.0
    h = np.zeros(N)
    for i, r in enumerate(ix.recs):
        tac = max((tau.get(t, 0.0) for t in (r.tactics or [r.tactic])), default=0.0)
        rel = 0.0
        if r.parent and r.parent in ix.pos:
            rel = max(rel, sem[ix.pos[r.parent]])
        ch = ix.children.get(r.id)
        if ch:
            rel = max(rel, float(sem[ch].max()))
        h[i] = 0.5 * (tac / mx if mx else 0.0) + 0.5 * rel
    return h


@dataclass
class Components:
    """Per-query channel scores (so weights can be re-combined without re-scoring)."""
    sem_n: np.ndarray
    bm_n: np.ndarray
    fld: np.ndarray
    hier_n: Dict[int, np.ndarray]
    cov: float
    oov: float
    margin: float
    sem_top: float
    ids: List[str]
    latency_ms: float = 0.0


def dahr_components(ix: KBIndex, q: str, alert: Optional[Dict[str, Any]], top_ms: Sequence[int] = (3,),
                    disabled_techniques: Sequence[str] = (), use_field: bool = True) -> Components:
    t0 = time.perf_counter()
    N = len(ix.recs)
    sem = ix.tf.scores(q)
    bm = ix.bm.scores(q)
    sem_n = sem / (sem.max() or 1.0)
    bm_n = bm / (bm.max() or 1.0)
    fld = np.zeros(N)
    cov = 0.0
    if use_field and ix.field is not None and alert is not None:
        for tid, (s, c) in ix.field.per_technique(alert).items():
            if tid in ix.pos and tid not in disabled_techniques:
                fld[ix.pos[tid]] = s
                cov = max(cov, c if s > 0 else 0.0)
    hier = {}
    for m in top_ms:
        h = _hier_scores(ix, sem, m)
        hier[m] = h / (h.max() or 1.0)
    top2 = np.sort(sem_n)[::-1][:2]
    margin = float(top2[0] - top2[1]) if len(top2) == 2 else 1.0
    return Components(sem_n, bm_n, fld, hier, cov, ix.tf.oov_ratio(q), margin, float(sem.max()), ix.ids, (time.perf_counter() - t0) * 1000)


def dahr_combine(c: Components, cfg: DAHRConfig = DAHRConfig()) -> Ranked:
    w = np.array([cfg.w_f * cfg.use_field, cfg.w_s * cfg.use_sem, cfg.w_b * cfg.use_bm25, cfg.w_h * cfg.use_hier], float)
    if cfg.adaptive:
        w = w * np.array([0.5 + c.cov, 0.5 + c.oov, 1.0, 0.5 + (1.0 - c.margin)])
    w = w / (w.sum() or 1.0)
    h = c.hier_n[cfg.top_m if cfg.top_m in c.hier_n else next(iter(c.hier_n))]
    z = w[0] * c.fld + w[1] * c.sem_n + w[2] * c.bm_n + w[3] * h
    i, s = _rank(z, c.ids)
    parts = {"field_top": float(c.fld.max()), "sem_top": c.sem_top, "w_field": float(w[0]), "w_sem": float(w[1]), "w_bm25": float(w[2]),
             "w_hier": float(w[3]), "field_cov": c.cov, "oov": c.oov, "sem_margin": c.margin}
    return Ranked(i, s, parts, latency_ms=c.latency_ms)


def rank_dahr(ix: KBIndex, q: str, alert: Optional[Dict[str, Any]], cfg: DAHRConfig = DAHRConfig(), disabled_techniques: Sequence[str] = ()) -> Ranked:
    t0 = time.perf_counter()
    comp = dahr_components(ix, q, alert, (cfg.top_m,), disabled_techniques, use_field=cfg.use_field)
    r = dahr_combine(comp, cfg)
    r.latency_ms = (time.perf_counter() - t0) * 1000
    return r


def rank_registry_lookup(ix: KBIndex, alert: Dict[str, Any], truth_map: Dict[str, str]) -> Ranked:
    """Trivial upper bound: the technique the operator registered for the emitting detector (uses scenario id)."""
    tid = truth_map.get(alert.get("component_scenario") or alert.get("scenario"))
    ids = [tid] + [i for i in ix.ids if i != tid] if tid else list(ix.ids)
    return Ranked(ids, [1.0] + [0.0] * (len(ids) - 1))
