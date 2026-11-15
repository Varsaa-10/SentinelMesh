"""M8: cluster-aware paired comparison of Sigma rules and text retrieval on the Sigma x Atomic events.

Implements the statistics reported in Table 3 of the manuscript, which were not in the repository:
  - clustered McNemar test of Durkalski et al. (2003): X2 = (sum_k b_k - sum_k c_k)^2 / sum_k (b_k - c_k)^2, 1 df,
    where b_k / c_k are the discordant pairs (Sigma right & TF-IDF wrong / the reverse) in cluster k;
    computed with clusters = Atomic tests and clusters = techniques;
  - technique-level sign-flip permutation test of the summed per-cluster difference (two-sided);
  - technique-cluster bootstrap 95% interval for the difference in proportion;
  - Holm adjustment over the three subsets, separately for each test.
Usage: python m8_external_clustered_stats.py EVENTS_JSON OUT_JSON [--dedup]
EVENTS_JSON rows need: event_id, test_guid, technique, fired, pred, covers, rank_tfidf.
--dedup keeps one copy of events that share event_id and technique (Atomic's index lists a test once per tactic).
"""
import json, sys
import numpy as np
from scipy.stats import chi2

B_BOOT, B_PERM = 2000, 20000


def holm(ps):
    ps = np.asarray(ps, float); order = np.argsort(ps); adj = np.empty(len(ps)); run = 0.0
    for r, i in enumerate(order):
        run = max(run, (len(ps) - r) * ps[i]); adj[i] = min(1.0, run)
    return adj


def durkalski(a, b, clusters):
    bk, ck = {}, {}
    for x, y, g in zip(a, b, clusters):
        bk[g] = bk.get(g, 0) + int(x == 1 and y == 0); ck[g] = ck.get(g, 0) + int(x == 0 and y == 1)
    num = (sum(bk.values()) - sum(ck.values())) ** 2
    den = sum((bk[g] - ck[g]) ** 2 for g in bk)
    if den == 0:
        return float("nan"), 1.0
    x2 = num / den
    return float(x2), float(chi2.sf(x2, 1))


def per_cluster(d, clusters):
    keys = sorted(set(clusters)); pos = {k: i for i, k in enumerate(keys)}
    tot = np.zeros(len(keys)); cnt = np.zeros(len(keys))
    for v, g in zip(d, clusters):
        tot[pos[g]] += v; cnt[pos[g]] += 1
    return tot, cnt


def signflip(d, clusters, seed=11):
    tot, cnt = per_cluster(d, clusters); obs = tot.sum()
    rng = np.random.default_rng(seed)
    s = rng.choice([-1.0, 1.0], size=(B_PERM, len(tot)))
    null = s @ tot
    return float((np.sum(np.abs(null) >= abs(obs) - 1e-12) + 1) / (B_PERM + 1))


def boot(d, clusters, seed=7):
    tot, cnt = per_cluster(d, clusters); rng = np.random.default_rng(seed); v = []
    for _ in range(B_BOOT):
        i = rng.integers(0, len(tot), len(tot)); v.append(tot[i].sum() / cnt[i].sum())
    return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]


def main(path, out, dedup):
    ev = json.load(open(path))
    n_in = len(ev)
    if dedup:
        seen, keep = set(), []
        for e in ev:
            k = (e["event_id"], e["technique"])
            if k not in seen:
                seen.add(k); keep.append(e)
        ev = keep
    sig = np.array([e["pred"] == e["technique"] for e in ev], float)
    txt = np.array([e["rank_tfidf"] == 1 for e in ev], float)
    subsets = [("All (abstain = error)", np.ones(len(ev), bool)),
               ("Technique has a rule", np.array([e["covers"] for e in ev], bool)),
               ("A rule fired", np.array([e["fired"] for e in ev], bool))]
    rows = []
    for name, m in subsets:
        idx = np.where(m)[0]; a, b = sig[idx], txt[idx]; d = a - b
        tests = [ev[i]["test_guid"] for i in idx]; techs = [ev[i]["technique"] for i in idx]
        rows.append({"subset": name, "events": int(len(idx)), "atomic_tests": len(set(tests)), "techniques": len(set(techs)),
                     "sigma": float(a.mean()), "tfidf": float(b.mean()), "diff": float(d.mean()),
                     "diff_ci95_technique_bootstrap": boot(d, techs),
                     "x2_test": durkalski(a, b, tests)[0], "p_test": durkalski(a, b, tests)[1],
                     "x2_tech": durkalski(a, b, techs)[0], "p_tech": durkalski(a, b, techs)[1],
                     "p_perm_tech": signflip(d, techs)})
    for key in ("p_test", "p_tech", "p_perm_tech"):
        for r, p in zip(rows, holm([r[key] for r in rows])):
            r[key + "_holm"] = float(p)
    res = {"input": path, "events_in": n_in, "events_used": len(ev), "dedup": dedup,
           "bootstrap_draws": B_BOOT, "permutation_draws": B_PERM, "seeds": {"bootstrap": 7, "permutation": 11}, "rows": rows}
    json.dump(res, open(out, "w"), indent=1)
    for r in rows:
        print(f'{r["subset"]:24s} n={r["events"]:5d} tests={r["atomic_tests"]:4d} tech={r["techniques"]:3d} sigma={r["sigma"]:.3f} tfidf={r["tfidf"]:.3f} '
              f'diff={r["diff"]:+.3f} {np.round(r["diff_ci95_technique_bootstrap"],3)} p_test={r["p_test_holm"]:.1e} p_tech={r["p_tech_holm"]:.1e} p_perm={r["p_perm_tech_holm"]:.1e}')


if __name__ == "__main__":
    a = sys.argv[1:]
    main(a[0], a[1], "--dedup" in a)
