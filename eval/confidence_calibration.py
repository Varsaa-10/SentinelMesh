"""Is retrieval confidence a reliable signal of a correct answer? Test alerts only.
Reports, per setting, mean confidence of correct and wrong answers, AUROC of confidence
for separating them, and expected calibration error (10 equal-width bins).
Usage: python3 eval/confidence_calibration.py eval/results/scores_<embedder>.json OUT.json"""
import json, sys
import numpy as np
d = json.load(open(sys.argv[1])); A = d["alerts"]
idx = [i for i, a in enumerate(A) if a["set"] == "fresh"]

def ok(p, t, c):
    return p == t or (c == "corpus_200" and "." in t and p == t.split(".")[0])

def auroc(pos, neg):
    if not len(pos) or not len(neg):
        return None
    pos = np.asarray(pos); neg = np.asarray(neg)
    gt = (pos[:, None] > neg[None, :]).mean(); eq = (pos[:, None] == neg[None, :]).mean()
    return float(gt + 0.5 * eq)

def ece(conf, corr, bins=10):
    conf = np.asarray(conf); corr = np.asarray(corr, float); e = 0.0
    edges = np.linspace(0, 1, bins + 1)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf >= lo) & (conf < hi if hi < 1 else conf <= hi)
        if m.any():
            e += m.mean() * abs(conf[m].mean() - corr[m].mean())
    return float(e)

out = {"settings": []}
pool = {"tl": ([], []), "fl": ([], [])}
for r in d["results"]:
    for eng in ("tl", "fl"):
        conf = [r["preds"][i][f"{eng}_conf"] for i in idx]
        corr = [ok(r["preds"][i][eng], A[i]["truth"], r["corpus"]) for i in idx]
        pos = [c for c, k in zip(conf, corr) if k]; neg = [c for c, k in zip(conf, corr) if not k]
        pool[eng][0].extend(conf); pool[eng][1].extend(corr)
        out["settings"].append({"corpus": r["corpus"], "variant": r["variant"], "form": r["form"], "engine": eng,
                                "accuracy": float(np.mean(corr)), "mean_conf": float(np.mean(conf)),
                                "mean_conf_correct": float(np.mean(pos)) if pos else None,
                                "mean_conf_wrong": float(np.mean(neg)) if neg else None,
                                "auroc": auroc(pos, neg), "ece": ece(conf, corr)})
for eng, (conf, corr) in pool.items():
    pos = [c for c, k in zip(conf, corr) if k]; neg = [c for c, k in zip(conf, corr) if not k]
    edges = np.linspace(0, 1, 11); conf_a = np.array(conf); corr_a = np.array(corr, float)
    rel = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf_a >= lo) & (conf_a < hi)
        if m.any():
            rel.append([round(lo, 1), round(hi, 1), int(m.sum()), round(float(conf_a[m].mean()), 3), round(float(corr_a[m].mean()), 3)])
    out[f"pooled_{eng}"] = {"n": len(conf), "accuracy": float(corr_a.mean()), "mean_conf": float(conf_a.mean()),
                            "mean_conf_correct": float(np.mean(pos)), "mean_conf_wrong": float(np.mean(neg)),
                            "auroc": auroc(pos, neg), "ece": ece(conf, corr), "reliability": rel}
json.dump(out, open(sys.argv[2], "w"), indent=1)
for eng in ("tl", "fl"):
    p = out[f"pooled_{eng}"]
    print(eng, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in p.items() if k != "reliability"})
    for row in p["reliability"]: print("   ", row)
for s in out["settings"]:
    if (s["corpus"], s["variant"]) in (("lab", "lab"), ("corpus_full", "+detection"), ("corpus_full", "mitre")) and s["form"] != "rewrite":
        print({k: (round(v, 3) if isinstance(v, float) else v) for k, v in s.items()})
