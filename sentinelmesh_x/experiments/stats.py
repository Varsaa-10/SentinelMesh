"""Statistics helpers: two-way cluster bootstrap (captures x scenarios), exact McNemar, effect sizes."""
from __future__ import annotations
import math
from typing import Any, Dict, Sequence
import numpy as np
from scipy.stats import binomtest

B = 4000


def _clusters(rows: Sequence[Dict[str, Any]]):
    runs = sorted({r["run"] for r in rows})
    scen = sorted({r["scenario"] for r in rows})
    return (np.array([runs.index(r["run"]) for r in rows]), np.array([scen.index(r["scenario"]) for r in rows]), len(runs), len(scen))


def cluster_bootstrap(x: np.ndarray, rows: Sequence[Dict[str, Any]], seed: int = 20261105, b: int = B):
    """Two-way (pigeonhole) bootstrap: resample captures and scenarios independently; weight = count_cap * count_scen."""
    cap, sc, nc, ns = _clusters(rows)
    rng = np.random.default_rng(seed)
    vals = np.empty(b)
    for i in range(b):
        cc = np.bincount(rng.integers(0, nc, nc), minlength=nc)
        ss = np.bincount(rng.integers(0, ns, ns), minlength=ns)
        w = cc[cap] * ss[sc]
        vals[i] = (w @ x) / w.sum() if w.sum() else np.nan
    return float(np.nanpercentile(vals, 2.5)), float(np.nanpercentile(vals, 97.5))


def cohens_h(p1: float, p2: float) -> float:
    return 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))


def paired_report(a: np.ndarray, b: np.ndarray, rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    n10 = int(((a == 1) & (b == 0)).sum())   # A right, B wrong
    n01 = int(((a == 0) & (b == 1)).sum())
    p = 1.0 if n10 + n01 == 0 else float(binomtest(min(n10, n01), n10 + n01, 0.5).pvalue)
    d = (a - b).astype(float)
    lo, hi = cluster_bootstrap(d, rows)
    alo, ahi = cluster_bootstrap(a.astype(float), rows)
    return {"acc_A": float(a.mean()), "acc_A_ci95": [alo, ahi], "acc_B": float(b.mean()), "diff": float(d.mean()), "diff_ci95_cluster": [lo, hi],
            "n_A_only": n10, "n_B_only": n01, "p_mcnemar_exact": p, "cohens_h": float(cohens_h(min(max(a.mean(), 1e-9), 1 - 1e-9), min(max(b.mean(), 1e-9), 1 - 1e-9))),
            "n": int(len(a))}
