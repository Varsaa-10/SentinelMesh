"""M5: redesigned zero-shot evaluation. known / unseen (technique knowledge withheld) / unsupported (external events, see M4) with abstention.
Dev only: calibrator + abstention threshold. Test: evaluation. Historical LOTO result (results_x/generalisation_ablation.json) is untouched."""
import random, time
from m1_common import *
from sentinelmesh_x.calibration import Calibrator, features
from sentinelmesh_x import calib_eval
OUT3 = ROOT / "results_x_v3"; S = alert_sets(); cfg = tuned_cfg(); t0 = time.time(); TECH = sorted(targets()); FORMS = ("raw", "rewrite")
raw = {c: [clean_record(r) for r in load_corpus("corpus_full")] for c in ("x",)}["x"]; parent_of = {r["id"]: r.get("sub_technique_of") for r in raw}; tactic_of = {r["id"]: r.get("tactic") for r in raw}
def obs(rows, tech):
    ixd = make_index("corpus_full", "auto", drop_knowledge_for=[tech]); out = []
    for row in rows:
        for f in FORMS:
            c = dahr_components(ixd, row["queries"][f], row["alert"]); rk = dahr_combine(c, cfg); top = rk.ids[0]; rec = ixd.recs[ixd.pos[top]]
            src = (row["alert"].get("source") or "").replace("-", "_")
            ids = rk.ids; t = row["truth"]
            out.append({"orig": f"{row['run']}|{row['slot']}", "run": row["run"], "tech_withheld": tech, "regime": "unseen" if row["truth"] == tech else "known", "truth": t, "pred": top,
                        "x": features(rk.parts, rk.scores, 0.5 if not rec.sources else float(src in rec.sources)), "rank": ids.index(t) + 1,
                        "parent_in_top5": bool(parent_of.get(t) and parent_of[t] in ids[:5]), "same_tactic_top1": tactic_of.get(top) == tactic_of.get(t),
                        "tfidf_top": rank_tfidf(ixd, row["queries"][f]).ids[0], "bm25_top": rank_bm25(ixd, row["queries"][f]).ids[0]})
    return out
dev = [o for t in TECH for o in obs(S["dev"], t)]; print("dev", len(dev), round(time.time() - t0), "s", flush=True)
test = [o for t in TECH for o in obs(S["test"], t)]; print("test", len(test), round(time.time() - t0), "s", flush=True)
cal = Calibrator().fit([o["x"] for o in dev], [int(o["pred"] == o["truth"]) for o in dev])
for o in dev: o["conf"] = float(cal.predict([o["x"]])[0])
for o in test: o["conf"] = float(cal.predict([o["x"]])[0])
# tau: smallest threshold such that non-abstained dev predictions are wrong <= 5%
tau = 1.01
for t in np.arange(0.05, 1.0, 0.01):
    kept = [o for o in dev if o["conf"] >= t]
    if len(kept) >= 30 and np.mean([o["pred"] != o["truth"] for o in kept]) <= 0.05: tau = float(round(t, 2)); break
def block(rows, tau):
    n = len(rows); idx = calib_eval.clusters_index([o["orig"] for o in rows]); a = lambda f: np.array([f(o) for o in rows], float)
    ab = a(lambda o: o["conf"] < tau); wrong = a(lambda o: o["pred"] != o["truth"]); rng = np.random.default_rng(3)
    def ci(v):
        vs = [v[calib_eval.draw_cluster_sample(idx, rng)].mean() for _ in range(1000)]; return [float(np.percentile(vs, 2.5)), float(np.percentile(vs, 97.5))]
    r = {"n_observations": n, "n_original_alerts": len(idx), "top1": float(1 - wrong.mean()), "R@5": float(a(lambda o: o["rank"] <= 5).mean()), "parent_in_top5": float(a(lambda o: o["parent_in_top5"]).mean()),
         "same_tactic_top1": float(a(lambda o: o["same_tactic_top1"]).mean()), "tfidf_top1": float(a(lambda o: o["tfidf_top"] == o["truth"]).mean()), "bm25_top1": float(a(lambda o: o["bm25_top"] == o["truth"]).mean()),
         "no_abstention_false_confident_rate": float(wrong.mean()), "no_abstention_false_confident_ci95": ci(wrong), "abstain_rate": float(ab.mean()), "abstain_rate_ci95": ci(ab),
         "false_confident_after_abstention": float(((1 - ab) * wrong).mean()), "false_confident_after_abstention_ci95": ci((1 - ab) * wrong)}
    kept = ab == 0; r["selective_accuracy_on_answered"] = float(1 - wrong[kept].mean()) if kept.any() else None; r["coverage"] = float(kept.mean())
    return r
res = {"note": "regimes: known = knowledge for the alert's technique present; unseen = that technique's knowledge withheld (truth is one of the 8 lab techniques); unsupported = see m4_external_eval.json (92% abstained by Sigma-based detector-aware path)",
       "calibrator_and_tau_fit_on": "development captures only (all 8 withhold-one-technique configurations)", "tau": tau, "n_dev_observations": len(dev),
       "known": block([o for o in test if o["regime"] == "known"], tau), "unseen": block([o for o in test if o["regime"] == "unseen"], tau),
       "historical_baseline": "results_x/generalisation_ablation.json leave_one_technique_out (DAHR ~12% top-1), preserved unchanged"}
res["unknown_class_detection_unseen"] = res["unseen"]["abstain_rate"]
(OUT3 / "m5_zero_shot.json").write_text(json.dumps(res, indent=1)); print(json.dumps({k: res[k] for k in ("tau", "known", "unseen")}, indent=0)[:2500])
