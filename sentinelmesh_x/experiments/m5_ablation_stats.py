"""M5: channel ablation with cluster-aware paired statistics (captures x scenarios), Holm-corrected. Track A (detector-aware), 140 test alerts."""
import random, time
from m1_common import *
from stats import cluster_bootstrap
from scipy.stats import wilcoxon
OUT3 = ROOT / "results_x_v3"; S = alert_sets(); cfg = tuned_cfg(); test = S["test"]; t0 = time.time(); rng = random.Random(SEED)
PERT = [("none", 0.0), ("drop", 0.3), ("noise", 0.15), ("rename", 0.5)]; FORMS = ("raw", "rewrite")
ix = make_index("corpus_full", "auto"); ixm = make_index("corpus_full", "mitre")
comps = {}
for i, row in enumerate(test):
    for mode, p in PERT:
        a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng); r = requery(row, a)
        for f in FORMS:
            comps[(i, mode, f)] = (dahr_components(ix, r["queries"][f], a, top_ms=(2, 3, 5)), dahr_components(ixm, r["queries"][f], a, top_ms=(2, 3, 5)))
print("comps", round(time.time() - t0), "s", flush=True)
def v(**kw): d = dict(cfg.__dict__); d.update(kw); return DAHRConfig(**d)
VARIANTS = {"full (tuned)": (cfg, 0), "default weights": (DAHRConfig(), 0), "- field matching": (v(use_field=False), 0), "- semantic TF-IDF": (v(use_sem=False), 0), "- BM25": (v(use_bm25=False), 0),
            "- hierarchy (already w_h=0 in tuned config)": (v(use_hier=False), 0), "- adaptive weights": (v(adaptive=False), 0), "- generated knowledge (MITRE-only KB)": (v(use_field=False), 1)}
def rr(cfgx, kb, key, truth): return 1.0 / (dahr_combine(comps[key][kb], cfgx).ids.index(truth) + 1)
per = {n: np.zeros(len(test)) for n in VARIANTS}; per1 = {n: np.zeros(len(test)) for n in VARIANTS}; by_mode = {m: {n: np.zeros(len(test)) for n in VARIANTS} for m, _ in PERT}
for n, (c, kb) in VARIANTS.items():
    for i, row in enumerate(test):
        vals = []
        for mode, _ in PERT:
            m_ = [rr(c, kb, (i, mode, f), row["truth"]) for f in FORMS]; by_mode[mode][n][i] = np.mean(m_); vals += m_
        per[n][i] = np.mean(vals); per1[n][i] = np.mean([x == 1.0 for x in vals])
out = {"note": "unit = original alert (140); each value averages 4 perturbation modes x 2 query forms. CIs: two-way cluster bootstrap over captures and scenarios.", "variants": {}, "paired_vs_full": [], "by_perturbation_mrr": {}}
for n in VARIANTS:
    lo, hi = cluster_bootstrap(per[n], test, b=2000); out["variants"][n] = {"MRR": float(per[n].mean()), "MRR_ci95": [lo, hi], "P@1": float(per1[n].mean())}
ps = []
for n in list(VARIANTS)[1:]:
    d = per[n] - per["full (tuned)"]; lo, hi = cluster_bootstrap(d, test, b=2000)
    try: p = float(wilcoxon(d).pvalue) if np.any(d != 0) else 1.0
    except ValueError: p = 1.0
    out["paired_vs_full"].append({"variant": n, "mean_diff_MRR": float(d.mean()), "diff_ci95_cluster": [lo, hi], "wilcoxon_p_alert_level_NOT_cluster_aware": p}); ps.append(p)
order = np.argsort(ps); run = 0.0
for k, i in enumerate(order): run = max(run, (len(ps) - k) * ps[i]); out["paired_vs_full"][i]["p_holm_alert_level"] = min(1.0, run)
out["paired_vs_full_interpretation"] = "Use the cluster CI for inference; the Wilcoxon p-values treat alerts as independent and are shown only for comparison."
for m, _ in PERT: out["by_perturbation_mrr"][m] = {n: float(by_mode[m][n].mean()) for n in VARIANTS}
(OUT3 / "m5_ablation_stats.json").write_text(json.dumps(out, indent=1)); print({n: (round(x["MRR"], 3), [round(y, 3) for y in x["MRR_ci95"]]) for n, x in out["variants"].items()}); print([(p["variant"], round(p["mean_diff_MRR"], 3), [round(y, 3) for y in p["diff_ci95_cluster"]]) for p in out["paired_vs_full"]])
