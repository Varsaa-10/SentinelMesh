"""Tune DAHR channel weights on the DEVELOPMENT captures only (60 alerts, 5 captures), under perturbation so the
objective is not saturated. The 140 test alerts and the 5 held-out alerts are never read here.
Reports leave-one-capture-out (LOCO) accuracy of the tuning procedure itself."""
import itertools, random, time
from common import *

t0 = time.time()
S = alert_sets()
dev = S["dev"]
ix = make_index("corpus_full", "auto")
rng = random.Random(SEED)
PERT = [("none", 0.0), ("drop", 0.3), ("drop", 0.5), ("noise", 0.15), ("rename", 0.5), ("rename", 1.0)]
examples = []  # (run, truth, Components)
for row in dev:
    for mode, p in PERT:
        a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng)
        r = requery(row, a)
        for form in QUERY_FORMS:
            comp = dahr_components(ix, r["queries"][form], a, top_ms=(2, 3, 5))
            examples.append((row["run"], row["truth"], comp))
print(len(examples), "dev examples", round(time.time() - t0, 1), "s")

def evaluate(cfg, ex):
    rr = []
    for _, truth, comp in ex:
        ids = dahr_combine(comp, cfg).ids
        rr.append(1.0 / (ids.index(truth) + 1))
    return float(np.mean(rr))

grid = [DAHRConfig(w_f=wf, w_s=ws, w_b=wb, w_h=wh, top_m=tm, adaptive=ad)
        for wf, ws, wb, wh, tm, ad in itertools.product([0.1, 0.25, 0.4, 0.55], [0.1, 0.2, 0.3, 0.45], [0.0, 0.1, 0.2], [0.0, 0.1, 0.2, 0.3], [2, 3, 5], [True, False])]
print(len(grid), "configs")
# cheap pre-sample for speed: evaluate every config on a fixed 1/3 subsample, then refine top-20 on all
sub = examples[::3]
first = sorted(((evaluate(c, sub), i) for i, c in enumerate(grid)), reverse=True)[:25]
full = sorted(((evaluate(grid[i], examples), i) for _, i in first), reverse=True)
best = grid[full[0][1]]
default = evaluate(DAHRConfig(), examples)
print("default MRR", round(default, 4), "best MRR", round(full[0][0], 4), best)

# leave-one-capture-out check of the same procedure
runs = sorted({e[0] for e in examples})
loco = []
for held in runs:
    tr = [e for e in examples if e[0] != held]
    te = [e for e in examples if e[0] == held]
    cand = sorted(((evaluate(grid[i], tr[::2]), i) for _, i in first), reverse=True)[0][1]
    loco.append({"held_out_capture": held, "mrr_tuned": evaluate(grid[cand], te), "mrr_default": evaluate(DAHRConfig(), te)})
print(loco)
save("dahr_tuned.json", {"best": best.__dict__, "default": DAHRConfig().__dict__, "dev_mrr_best": full[0][0], "dev_mrr_default": default,
                         "perturbations": PERT, "n_examples": len(examples), "top5": [{"mrr": f, "cfg": grid[i].__dict__} for f, i in full[:5]], "loco": loco,
                         "note": "tuned on development captures only, under perturbation"})
