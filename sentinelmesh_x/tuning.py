"""Nested leave-one-capture-out hyper-parameter tuning for DAHR (M1, remediation item 2).

select_config() sees ONLY the examples it is given. nested_loco() hands it the training captures of each fold and evaluates the
selected config exactly once on the held-out capture; nothing derived from the held-out capture (shortlist, scaling, thresholds)
exists before that evaluation.
"""
from __future__ import annotations
import itertools
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

from .retrieval import DAHRConfig, dahr_combine

Example = Tuple[str, str, object]          # (capture_id, true technique id, Components)


def candidate_grid(with_field: bool = True) -> List[DAHRConfig]:
    wf = [0.1, 0.25, 0.4, 0.55] if with_field else [0.0]
    return [DAHRConfig(w_f=a, w_s=b, w_b=c, w_h=d, top_m=m, adaptive=ad, use_field=with_field)
            for a, b, c, d, m, ad in itertools.product(wf, [0.1, 0.2, 0.3, 0.45], [0.0, 0.1, 0.2], [0.0, 0.1, 0.2, 0.3], [2, 3, 5], [True, False])]


def mrr(cfg: DAHRConfig, ex: Sequence[Example]) -> float:
    return float(np.mean([1.0 / (dahr_combine(c, cfg).ids.index(t) + 1) for _, t, c in ex])) if ex else 0.0


def _dist_to_default(c: DAHRConfig) -> float:
    d = DAHRConfig()
    return abs(c.w_f - d.w_f) + abs(c.w_s - d.w_s) + abs(c.w_b - d.w_b) + abs(c.w_h - d.w_h)


def select_config(train: Sequence[Example], grid: Optional[Sequence[DAHRConfig]] = None, shortlist: int = 25) -> Tuple[DAHRConfig, Dict]:
    """1) shortlist on a fixed subsample of `train`; 2) rank the shortlist by inner leave-one-capture-out MRR over `train`; ties -> closest to defaults."""
    grid = list(grid or candidate_grid())
    sub = list(train)[::3]
    first = sorted(range(len(grid)), key=lambda i: -mrr(grid[i], sub))[:shortlist]
    runs = sorted({r for r, _, _ in train})
    by = defaultdict(list)
    for e in train:
        by[e[0]].append(e)
    scored = []
    for i in first:
        inner = float(np.mean([mrr(grid[i], by[r]) for r in runs]))       # mean over inner folds (configs have no fitted parameters)
        scored.append((-inner, _dist_to_default(grid[i]), i))
    scored.sort()
    best = grid[scored[0][2]]
    return best, {"inner_mrr": -scored[0][0], "shortlist_size": len(first), "train_captures": runs}


def nested_loco(examples: Sequence[Example], grid: Optional[Sequence[DAHRConfig]] = None,
                selector: Callable = select_config) -> List[Dict]:
    out = []
    for held in sorted({r for r, _, _ in examples}):
        train = [e for e in examples if e[0] != held]
        test = [e for e in examples if e[0] == held]
        assert held not in {e[0] for e in train}
        cfg, info = selector(train, grid)
        out.append({"held_out_capture": held, "n_heldout": len(test), "mrr_nested": mrr(cfg, test), "mrr_default": mrr(DAHRConfig(use_field=cfg.use_field), test),
                    "chosen": {k: getattr(cfg, k) for k in ("w_f", "w_s", "w_b", "w_h", "top_m", "adaptive")}, **info})
    return out


def old_leaky_loco(examples: Sequence[Example], grid: Optional[Sequence[DAHRConfig]] = None, shortlist: int = 25) -> List[Dict]:
    """The PRE-M1 procedure, kept only so the old and corrected numbers can be compared: the shortlist is built from ALL captures."""
    grid = list(grid or candidate_grid())
    sub = list(examples)[::3]
    first = sorted(range(len(grid)), key=lambda i: -mrr(grid[i], sub))[:shortlist]
    out = []
    for held in sorted({r for r, _, _ in examples}):
        tr = [e for e in examples if e[0] != held]
        te = [e for e in examples if e[0] == held]
        i = max(first, key=lambda j: mrr(grid[j], tr[::2]))
        out.append({"held_out_capture": held, "mrr_old_leaky": mrr(grid[i], te)})
    return out
