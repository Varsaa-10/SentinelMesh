"""Comprehensive comparative benchmark (improvement item 5) on the 140 test alerts and 5 held-out alerts.
Same alerts, same splits, same metrics for every method. Tuning used development captures only."""
import time
from bench import *
from stats import paired_report
from scipy.stats import binomtest

S = alert_sets()
cfg = tuned_cfg()
cve_map = build_cve_lookup(load_kb_dir(str(ROOT / "kb_master/techniques"), str(ROOT / "kb_master/cves"))[1])
METHODS = ["registry", "repo_flat", "repo_two_layer", "tfidf", "bm25", "rrf", "supervised", "dahr_default", "dahr"]
import os
PART = OUT / "benchmark_partial.json"
res = json.loads(PART.read_text()) if PART.exists() else {"config_dahr": cfg.__dict__, "rows": [], "done": []}
t0 = time.time()
for corpus in CORPORA:
    for cond in ("mitre", "expert", "auto"):
        if f"{corpus}/{cond}" in res["done"]:
            continue
        ix = make_index(corpus, cond)
        raw = build_raw_condition(corpus, cond)
        repo = RepoEngines(raw, cve_map)
        for form in QUERY_FORMS:
            sup = Supervised(S["dev"], form)
            for setname in ("test", "heldout"):
                rows = S[setname]
                for m in METHODS:
                    if m == "dahr" and cond != "auto":
                        pass
                    out = score_rows(m, rows, form, ix, corpus, cfg, repo, sup)
                    res["rows"].append({"corpus": corpus, "kb": cond, "form": form, "set": setname, "method": m, "n_records": len(ix.recs),
                                        "ranks": out["ranks"], "preds": out["preds"], **out["metrics"]})
        res["done"].append(f"{corpus}/{cond}")
        PART.write_text(json.dumps(res))
        print(corpus, cond, round(time.time() - t0), "s", flush=True)
save("benchmark.json", res)

# ---- statistics: DAHR (tuned) against every other method, per corpus x kb x form, test set, Holm corrected
test_rows = S["test"]
stats_rows = []
for corpus in CORPORA:
    for cond in ("mitre", "expert", "auto"):
        for form in QUERY_FORMS:
            by = {r["method"]: r for r in res["rows"] if r["corpus"] == corpus and r["kb"] == cond and r["form"] == form and r["set"] == "test"}
            for m in METHODS:
                if m == "dahr":
                    continue
                a = np.array([int(x == 1) for x in by["dahr"]["ranks"]])
                b = np.array([int(x == 1) for x in by[m]["ranks"]])
                stats_rows.append({"corpus": corpus, "kb": cond, "form": form, "A": "dahr", "B": m, **paired_report(a, b, test_rows)})
# Holm-Bonferroni over the whole family
ps = np.array([r["p_mcnemar_exact"] for r in stats_rows])
order = np.argsort(ps)
adj = np.empty(len(ps))
running = 0.0
for rank, i in enumerate(order):
    running = max(running, (len(ps) - rank) * ps[i])
    adj[i] = min(1.0, running)
for r, p in zip(stats_rows, adj):
    r["p_holm"] = float(p)
save("benchmark_stats.json", {"family_size": len(stats_rows), "comparisons": stats_rows})
print("stats done; family size", len(stats_rows))
