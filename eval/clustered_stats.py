"""Capture-level and clustered statistics for the 140 test alerts.

Each test alert belongs to one capture (10) and one scenario (9; a chain stage belongs to the
scenario it replays). Alerts are not independent: the same scenario repeats in every capture,
and retrieval is deterministic given the alert text. We report
  * per-capture accuracy (mean, min, max over the ten captures),
  * a 95% interval from a two-way cluster bootstrap that resamples captures and scenarios
    independently (pigeonhole bootstrap), which reflects both kinds of dependence,
  * for flat against tactic-first: the per-capture difference, an exact sign test over captures
    and over subnets, and the two-way bootstrap interval of the difference.
Also reports the effect of adding lab text with paired intervals, and whether the two captures on
each subnet agree.
Usage: python3 eval/clustered_stats.py <per-alert scores from score_fresh_heldout.py> out.json
"""
import json, sys, math
from collections import defaultdict
import numpy as np

SEED = 20261016
B = 10000
d = json.load(open(sys.argv[1]))
A = d["alerts"]
SUB = {"20261014T104641Z": "172.30", "20261014T111618Z": "172.30", "20261014T113310Z": "172.18",
       "20261014T122816Z": "172.18", "20261014T130955Z": "10.20", "20261014T132438Z": "10.20",
       "20261014T134019Z": "10.40", "20261014T135319Z": "10.40", "20261014T140601Z": "172.25",
       "20261014T141640Z": "172.25"}
idx = [i for i, a in enumerate(A) if a["set"] == "fresh"]
runs = sorted(SUB)
scen = sorted({A[i]["slot"].replace("S10:", "") for i in idx})
cap_of = np.array([runs.index(A[i]["run"]) for i in idx])
sc_of = np.array([scen.index(A[i]["slot"].replace("S10:", "")) for i in idx])

def ok(p, t, c):
    return p == t or (c == "corpus_200" and "." in t and p == t.split(".")[0])

def vec(res, eng):
    return np.array([ok(res["preds"][i][eng], A[i]["truth"], res["corpus"]) for i in idx], dtype=float)

rng = np.random.default_rng(SEED)
# pre-draw resamples so every configuration uses the same bootstrap samples (paired)
DRAWS = [(rng.integers(0, len(runs), len(runs)), rng.integers(0, len(scen), len(scen))) for _ in range(B)]
# weight of each alert in a resample = (#times its capture drawn) * (#times its scenario drawn)
W = np.empty((B, len(idx)))
for b, (cr, sr) in enumerate(DRAWS):
    cc = np.bincount(cr, minlength=len(runs)); sc = np.bincount(sr, minlength=len(scen))
    W[b] = cc[cap_of] * sc[sc_of]

def boot(x):
    tot = W.sum(1)
    m = (W @ x) / np.where(tot > 0, tot, 1)
    return np.percentile(m, [2.5, 97.5])

def per_capture(x):
    return np.array([x[cap_of == k].mean() for k in range(len(runs))])

def sign_test(diffs):
    pos = int((diffs > 0).sum()); neg = int((diffs < 0).sum()); n = pos + neg
    if n == 0:
        return pos, neg, 1.0
    k = min(pos, neg)
    p = sum(math.comb(n, j) for j in range(0, k + 1)) / 2 ** n * 2
    return pos, neg, min(1.0, p)

out = {"seed": SEED, "bootstrap_samples": B, "captures": runs, "scenarios": scen, "configs": []}
for res in d["results"]:
    if res["variant"] not in ("lab", "mitre", "+detection", "+description", "+detection+description", "+all_lab_fields"):
        continue
    row = {"corpus": res["corpus"], "variant": res["variant"], "form": res["form"]}
    xs = {}
    for e in ("tl", "fl"):
        x = vec(res, e); xs[e] = x
        pc = per_capture(x)
        lo, hi = boot(x)
        row[e] = {"correct": int(x.sum()), "n": len(x), "acc": round(100 * x.mean(), 1),
                  "capture_mean": round(100 * pc.mean(), 1), "capture_min": round(100 * pc.min(), 1),
                  "capture_max": round(100 * pc.max(), 1), "ci2way": [round(100 * lo, 1), round(100 * hi, 1)]}
    diff = xs["fl"] - xs["tl"]
    pcd = per_capture(xs["fl"]) - per_capture(xs["tl"])
    subd = defaultdict(list)
    for k, r in enumerate(runs):
        subd[SUB[r]].append(pcd[k])
    sd = np.array([np.mean(v) for v in subd.values()])
    lo, hi = boot(diff)
    tot = W.sum(1); bd = (W @ diff) / np.where(tot > 0, tot, 1)
    row["flat_minus_tl"] = {"points": round(100 * diff.mean(), 1), "ci2way": [round(100 * lo, 1), round(100 * hi, 1)],
                            "share_boot_le0": round(float((bd <= 0).mean()), 4),
                            "sign_test_captures": list(sign_test(pcd)), "sign_test_subnets": list(sign_test(sd))}
    out["configs"].append(row)
# effect of adding lab text (paired, same resamples)
def _get(c, v, f):
    return next(r for r in d["results"] if r["corpus"] == c and r["variant"] == v and r["form"] == f)
out["kb_effects"] = []
tot = W.sum(1)
for c in ("corpus_36", "corpus_200", "corpus_full"):
    for f in ("raw", "title_raw"):
        for e in ("fl", "tl"):
            for a_v, b_v in (("mitre", "+detection"), ("+description", "+detection"), ("mitre", "+all_lab_fields")):
                x = vec(_get(c, b_v, f), e) - vec(_get(c, a_v, f), e)
                bd = (W @ x) / np.where(tot > 0, tot, 1)
                out["kb_effects"].append({"corpus": c, "form": f, "engine": e, "contrast": f"{b_v} minus {a_v}",
                                          "points": round(100 * x.mean(), 1),
                                          "ci2way": [round(float(v), 1) for v in np.percentile(100 * bd, [2.5, 97.5])],
                                          "capture_min": round(100 * min(x[cap_of == k].mean() for k in range(len(runs))), 1)})
# do the two captures on each subnet agree?
pairs = same = 0
for res in d["results"]:
    for e in ("tl", "fl"):
        pc = per_capture(vec(res, e))
        for s_ in sorted(set(SUB.values())):
            ks = [k for k, r in enumerate(runs) if SUB[r] == s_]
            pairs += 1; same += int(pc[ks[0]] == pc[ks[1]])
out["same_subnet_capture_pairs"] = {"pairs": pairs, "same_accuracy": same}
json.dump(out, open(sys.argv[2], "w"), indent=1)

def show(c, v, f):
    r = next(x for x in out["configs"] if x["corpus"] == c and x["variant"] == v and x["form"] == f)
    t, fl, df = r["tl"], r["fl"], r["flat_minus_tl"]
    print(f"{c:<11} {v:<22} {f:<9} TL {t['correct']:>3} [{t['capture_min']:.0f}-{t['capture_max']:.0f}] ci{t['ci2way']}  "
          f"FL {fl['correct']:>3} [{fl['capture_min']:.0f}-{fl['capture_max']:.0f}] ci{fl['ci2way']}  "
          f"diff {df['points']:+.1f} ci{df['ci2way']} signC{df['sign_test_captures']} signS{df['sign_test_subnets']}")
for f in ("raw", "title_raw", "rewrite"):
    show("lab", "lab", f)
for c in ("corpus_36", "corpus_200", "corpus_full"):
    for v in ("mitre", "+detection", "+all_lab_fields"):
        for f in ("raw", "title_raw"):
            show(c, v, f)
