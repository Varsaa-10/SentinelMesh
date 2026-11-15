"""M5: paired, cluster-aware comparison on the independent Sigma x Atomic events (cluster = atomic test)."""
import json, numpy as np
from m1_common import *
from sentinelmesh_x import calib_eval
from scipy.stats import binomtest
OUT3 = ROOT / "results_x_v3"; ev = json.loads((OUT3 / "m4_external_events.json").read_text())
cl = [e["test_guid"] for e in ev]; idx = calib_eval.clusters_index(cl)
sig = np.array([e["pred"] == e["technique"] for e in ev], float); txt = np.array([e["rank_tfidf"] == 1 for e in ev], float); fired = np.array([e["fired"] for e in ev], bool); cov = np.array([e["covers"] for e in ev], bool)
def paired(mask, name):
    m = np.where(mask)[0]; a, b = sig[m], txt[m]; d = a - b; rng = np.random.default_rng(5); mm = np.zeros(len(ev), bool); mm[m] = True; vs = []
    for _ in range(2000):
        s = calib_eval.draw_cluster_sample(idx, rng); s = s[mm[s]]
        if len(s): vs.append((sig[s] - txt[s]).mean())
    n10, n01 = int(((a == 1) & (b == 0)).sum()), int(((a == 0) & (b == 1)).sum())
    return {"subset": name, "n_events": int(len(m)), "n_atomic_tests": len({cl[i] for i in m}), "sigma_top1": float(a.mean()), "tfidf_top1": float(b.mean()), "diff": float(d.mean()), "diff_ci95_test_cluster": [float(np.percentile(vs, 2.5)), float(np.percentile(vs, 97.5))],
            "sigma_only_correct": n10, "tfidf_only_correct": n01, "p_mcnemar_exact_event_level_NOT_cluster_aware": 1.0 if n10 + n01 == 0 else float(binomtest(min(n10, n01), n10 + n01, .5).pvalue)}
res = {"comparisons": [paired(np.ones(len(ev), bool), "all events (Sigma abstention counts as wrong)"), paired(cov, "events whose technique has a Sigma rule"), paired(fired, "events where a Sigma rule fired")],
       "interpretation": "Sigma rules fire rarely but, when they fire, compare their precision with text retrieval only on the fired subset; the all-events row penalises abstention."}
ps = np.array([c["p_mcnemar_exact_event_level_NOT_cluster_aware"] for c in res["comparisons"]]); order = np.argsort(ps); run = 0.0
for k, i in enumerate(order): run = max(run, (len(ps) - k) * ps[i]); res["comparisons"][i]["p_holm"] = min(1.0, run)
(OUT3 / "m5_external_stats.json").write_text(json.dumps(res, indent=1)); print(json.dumps(res["comparisons"], indent=0)[:2400])
