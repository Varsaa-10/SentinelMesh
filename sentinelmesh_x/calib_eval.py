"""Cluster-aware calibration evaluation (M1, remediation item 3)."""
from __future__ import annotations
from typing import Callable, Dict, Sequence
import numpy as np
from sklearn.linear_model import LogisticRegression
from .calibration import brier, ece


def clusters_index(cluster_ids: Sequence) -> Dict:
    d: Dict = {}
    for i, c in enumerate(cluster_ids):
        d.setdefault(c, []).append(i)
    return {k: np.array(v) for k, v in d.items()}


def draw_cluster_sample(idx: Dict, rng: np.random.Generator) -> np.ndarray:
    """Resample whole clusters with replacement; every row of a drawn cluster is kept together (never row-level resampling)."""
    keys = list(idx)
    pick = rng.integers(0, len(keys), len(keys))
    return np.concatenate([idx[keys[i]] for i in pick])


def cluster_bootstrap(p, y, cluster_ids, metric: Callable, b: int = 2000, seed: int = 20261106) -> Dict:
    p, y = np.asarray(p, float), np.asarray(y, float)
    idx = clusters_index(cluster_ids)
    rng = np.random.default_rng(seed)
    vals = np.array([metric(p[s], y[s]) for s in (draw_cluster_sample(idx, rng) for _ in range(b))])
    return {"value": float(metric(p, y)), "ci95": [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))], "n_clusters": len(idx), "n_rows": int(len(p))}


def slope_intercept(p, y):
    """Calibration slope/intercept: logistic regression of the outcome on logit(p). Ideal: slope 1, intercept 0."""
    p = np.clip(np.asarray(p, float), 1e-4, 1 - 1e-4)
    z = np.log(p / (1 - p)).reshape(-1, 1)
    y = np.asarray(y, int)
    if len(set(y)) < 2:
        return None
    m = LogisticRegression(C=1e6, max_iter=1000).fit(z, y)
    return {"slope": float(m.coef_[0][0]), "intercept": float(m.intercept_[0])}


def check_split_integrity(rows: Sequence[Dict], train_runs: Sequence[str], test_runs: Sequence[str]) -> None:
    """Raises if train/test share a capture or an original alert, if an original id appears in two captures, or ids are not unique per (id, variant)."""
    assert not (set(train_runs) & set(test_runs)), "capture appears in both train and test"
    seen_variant = set()
    owner: Dict = {}
    for r in rows:
        key = (r["original_alert_id"], r["pert"], r["form"], r["cond"])
        assert key not in seen_variant, f"duplicate observation {key}"
        seen_variant.add(key)
        assert owner.setdefault(r["original_alert_id"], r["run"]) == r["run"], "original alert spans captures"
