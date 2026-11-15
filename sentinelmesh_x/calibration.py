"""Learned confidence calibration + derived severity / asset-criticality (improvement item 6)."""
from __future__ import annotations
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence
import numpy as np
from sklearn.linear_model import LogisticRegression

FEATURES = ["z_top", "z_margin", "field_top", "sem_top", "w_field", "oov", "field_cov", "sem_margin", "src_agree"]


def features(parts: Dict[str, float], z_scores: Sequence[float], src_agree: float) -> List[float]:
    zt = z_scores[0]
    zm = z_scores[0] - z_scores[1] if len(z_scores) > 1 else zt
    return [zt, zm, parts["field_top"], parts["sem_top"], parts["w_field"], parts["oov"], parts["field_cov"], parts["sem_margin"], src_agree]


class Calibrator:
    def __init__(self, C: float = 1.0):
        self.m = LogisticRegression(C=C, max_iter=2000)

    def fit(self, X, y):
        self.m.fit(np.array(X), np.array(y))
        return self

    def predict(self, X) -> np.ndarray:
        return self.m.predict_proba(np.array(X))[:, 1]


def brier(p, y) -> float:
    p, y = np.asarray(p, float), np.asarray(y, float)
    return float(np.mean((p - y) ** 2))


def ece(p, y, bins: int = 10, adaptive: bool = False) -> float:
    p, y = np.asarray(p, float), np.asarray(y, float)
    if adaptive:
        edges = np.quantile(p, np.linspace(0, 1, bins + 1))
    else:
        edges = np.linspace(0, 1, bins + 1)
    tot, n = 0.0, len(p)
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= edges[i + 1]))
        if m.any():
            tot += m.sum() / n * abs(p[m].mean() - y[m].mean())
    return float(tot)


def reliability(p, y, bins: int = 10):
    p, y = np.asarray(p, float), np.asarray(y, float)
    edges = np.linspace(0, 1, bins + 1)
    out = []
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= edges[i + 1]))
        if m.any():
            out.append({"bin": i, "conf": float(p[m].mean()), "acc": float(y[m].mean()), "n": int(m.sum())})
    return out


# ------------------------------------------------ derived (independent) severity / asset criticality ------
TACTIC_IMPACT = {"Initial Access": 4, "Execution": 4, "Persistence": 3, "Privilege Escalation": 4, "Defense Evasion": 3, "Credential Access": 4,
                 "Discovery": 2, "Lateral Movement": 4, "Collection": 3, "Command and Control": 3, "Exfiltration": 5, "Impact": 5}


def derived_severity(technique_tactic: str, cvss: float | None) -> int:
    """CVSS v3 base score (when a CVE is in the KB) mapped by NVD bands; otherwise a public tactic-impact prior."""
    if cvss is not None:
        return 5 if cvss >= 9.0 else 4 if cvss >= 7.0 else 3 if cvss >= 4.0 else 2
    return TACTIC_IMPACT.get(technique_tactic, 3)


def derived_criticality(root: Path) -> Dict[str, int]:
    """Asset criticality from the compose file: dependents (services that depend on it), secrets/credential stores,
    and whether it exposes an administrative interface. Score is rank-normalised to 1..5."""
    import yaml
    dc = yaml.safe_load((root / "docker-compose.yml").read_text())["services"]
    deps = {s: 0 for s in dc}
    for s, v in dc.items():
        d = v.get("depends_on") or []
        for t in (d if isinstance(d, list) else d.keys()):
            deps[t] = deps.get(t, 0) + 1
    raw = {}
    for s, v in dc.items():
        env = " ".join(map(str, v.get("environment") or []))
        secrets = 2 if re.search(r"PASS|SECRET|TOKEN", env, re.I) or "postgres" in str(v.get("image", "")) else 0
        raw[s] = 2 * deps.get(s, 0) + secrets + (1 if s in ("authservice", "dashboard") else 0)
    mx = max(raw.values()) or 1
    return {s: max(1, round(1 + 4 * r / mx)) for s, r in raw.items()}
