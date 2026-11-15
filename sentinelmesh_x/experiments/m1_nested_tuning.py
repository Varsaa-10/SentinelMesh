"""M1 item 2: nested LOCO tuning (corrected) vs the old leaky procedure, for Track A and Track B. Development captures only."""
import random, time
from m1_common import *
from sentinelmesh_x import tuning
S = alert_sets(); dev = S["dev"]; t0 = time.time()
PERT = [("none", 0.0), ("drop", 0.3), ("drop", 0.5), ("noise", 0.15), ("rename", 0.5), ("rename", 1.0)]

def examples(track):
    rng = random.Random(SEED)
    ix = make_index("corpus_full", "auto") if track == "A" else make_index_B("corpus_full")
    ex = []
    for row in dev:
        for mode, p in PERT:
            a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng)
            if track == "A":
                r = requery(row, a)
                for f in QUERY_FORMS:
                    ex.append((row["run"], row["truth"], dahr_components(ix, r["queries"][f], a, top_ms=(2, 3, 5))))
            else:
                r = trackb_row(row, a)
                ex.append((row["run"], row["truth"], dahr_components(ix, r["queries"]["indep"], r["alert"], top_ms=(2, 3, 5), use_field=False)))
    return ex

out = {"note": "Development captures only (60 alerts, 5 captures). Old numbers are the pre-M1 procedure, shown for comparison; they are optimistic because the shortlist saw the held-out capture."}
for track in ("A", "B"):
    ex = examples(track); grid = tuning.candidate_grid(with_field=(track == "A"))
    nested = tuning.nested_loco(ex, grid); old = tuning.old_leaky_loco(ex, grid)
    final, info = tuning.select_config(ex, grid)
    out[track] = {"n_examples": len(ex), "n_configs": len(grid), "nested_loco": nested, "old_leaky_loco": old,
                  "mean_mrr_nested": float(np.mean([r["mrr_nested"] for r in nested])), "mean_mrr_old_leaky": float(np.mean([r["mrr_old_leaky"] for r in old])),
                  "mean_mrr_default_weights": float(np.mean([r["mrr_default"] for r in nested])),
                  "final_config_all_dev": {k: getattr(final, k) for k in ("w_f", "w_s", "w_b", "w_h", "top_m", "adaptive", "use_field")}, "final_info": info}
    print(track, round(out[track]["mean_mrr_default_weights"], 4), round(out[track]["mean_mrr_old_leaky"], 4), round(out[track]["mean_mrr_nested"], 4), out[track]["final_config_all_dev"], round(time.time() - t0), "s", flush=True)
save2("tuning_nested.json", out)
