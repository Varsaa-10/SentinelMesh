"""M4: independent-annotation support: blinded packet builder and agreement statistics. NO annotations exist yet; this only prepares the study."""
from __future__ import annotations
import csv, hashlib, json, random
from pathlib import Path
from collections import Counter
from typing import Dict, List, Sequence
import numpy as np


def cohens_kappa(a: Sequence, b: Sequence) -> float:
    assert len(a) == len(b) and len(a) > 0
    labs = sorted(set(a) | set(b)); n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca[l] / n) * (cb[l] / n) for l in labs)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def fleiss_kappa(ratings: Sequence[Sequence]) -> float:
    """ratings[i] = labels given to item i by each rater (same number of raters per item)."""
    n_r = len(ratings[0]); assert all(len(r) == n_r for r in ratings) and n_r > 1
    labs = sorted({l for r in ratings for l in r}); N = len(ratings)
    M = np.array([[Counter(r)[l] for l in labs] for r in ratings], float)
    Pi = ((M ** 2).sum(1) - n_r) / (n_r * (n_r - 1)); Pbar = Pi.mean()
    pj = M.sum(0) / (N * n_r); Pe = (pj ** 2).sum()
    return 1.0 if Pe == 1 else float((Pbar - Pe) / (1 - Pe))


def percent_agreement(ratings: Sequence[Sequence]) -> float:
    return float(np.mean([len(set(r)) == 1 for r in ratings]))


def build_blinded_packet(items: List[Dict], seed: int, out_csv, out_key) -> str:
    """items: {"alert_id","source","event_text","label"}. Packet has random ids and NO labels/predictions/detector titles; the key is written elsewhere."""
    rng = random.Random(seed); order = list(range(len(items))); rng.shuffle(order)
    with open(out_csv, "w", newline="", encoding="utf-8") as f, open(out_key, "w", newline="", encoding="utf-8") as k:
        w, kw = csv.writer(f), csv.writer(k)
        w.writerow(["item", "sensor_type", "observed_fields", "attack_technique_id", "evidence_fields", "malicious_benign_uncertain", "severity_1_to_5", "escalation_auto_analyst_admin", "notes"])
        kw.writerow(["item", "alert_id", "team_label"])
        for j, i in enumerate(order, 1):
            it = items[i]; iid = f"A{j:03d}"
            w.writerow([iid, it["source"], it["event_text"], "", "", "", "", "", ""]); kw.writerow([iid, it["alert_id"], it["label"]])
    return hashlib.sha256(Path(out_key).read_bytes()).hexdigest()
