"""M1 item 3: calibration re-evaluated with original-alert identifiers, cluster bootstrap and strict dev/test separation."""
import random, time
from m1_common import *
from sentinelmesh_x.calibration import Calibrator, features, brier, ece, reliability
from sentinelmesh_x import calib_eval
from rag_engine.src.confidence import compute_confidence
S = alert_sets(); t0 = time.time(); cfgA = tuned_cfg()
tun = json.loads((OUT2 / "tuning_nested.json").read_text()); cfgB = DAHRConfig(**tun["B"]["final_config_all_dev"])
PERT = [("none", 0.0), ("drop", 0.3), ("noise", 0.15), ("rename", 0.5)]

def pool(track, rows, seed):
    rng = random.Random(seed); out = []
    ixs = {c: make_index("corpus_full", c) for c in ("mitre", "expert", "auto")} if track == "A" else {"mitre": make_index_B("corpus_full")}
    cfg = cfgA if track == "A" else cfgB
    for row in rows:
        for mode, p in PERT:
            a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng)
            r = requery(row, a) if track == "A" else trackb_row(row, a)
            for form in (QUERY_FORMS if track == "A" else ("indep",)):
                for cond, ix in ixs.items():
                    aa = a if track == "A" else r["alert"]
                    c = dahr_combine(dahr_components(ix, r["queries"][form], aa, use_field=(track == "A")), cfg)
                    top = c.ids[0]; rec = ix.recs[ix.pos[top]]; src = (aa.get("source") or "").replace("-", "_")
                    sa = 0.5 if not rec.sources else float(src in rec.sources)
                    man = compute_confidence(c.scores[:3], [ix.recs[ix.pos[i]].tactic for i in c.ids[:3]], alert_source=src, winning_record_sources=rec.sources or None).score
                    out.append({"original_alert_id": f"{row['run']}|{row['slot']}", "run": row["run"], "pert": mode, "form": form, "cond": cond, "ok": int(top == row["truth"]),
                                "x": features(c.parts, c.scores, sa), "manual": float(man), "z_top": float(c.scores[0])})
    return out

res = {"note": "Calibrator fitted on development captures only. Test rows are transformed variants of the 140 test alerts; CIs resample ORIGINAL ALERTS (clusters), not rows."}
for track in ("A", "B"):
    for k in ("dev", "test"): attach_trackb(S[k])
    dev, test = pool(track, S["dev"], 1), pool(track, S["test"], 2)
    calib_eval.check_split_integrity(dev, sorted({r["run"] for r in dev}), [])
    calib_eval.check_split_integrity(test, [], sorted({r["run"] for r in test}))
    assert not ({r["original_alert_id"] for r in dev} & {r["original_alert_id"] for r in test}) and not ({r["run"] for r in dev} & {r["run"] for r in test})
    cal = Calibrator().fit([r["x"] for r in dev], [r["ok"] for r in dev]); learned = cal.predict([r["x"] for r in test])
    y = np.array([r["ok"] for r in test]); preds = {"manual_confidence_original": np.array([r["manual"] for r in test]), "raw_fused_score": np.array([r["z_top"] for r in test]), "learned_LR": learned}
    oid = np.array([r["original_alert_id"] for r in test]); runid = np.array([r["run"] for r in test])
    def block(mask):
        o = {"n_original_alerts": int(len(set(oid[mask]))), "n_transformed_observations": int(mask.sum()), "accuracy": float(y[mask].mean())}
        for name, p in preds.items():
            o[name] = {"brier": calib_eval.cluster_bootstrap(p[mask], y[mask], oid[mask], brier, b=1000), "ece10": calib_eval.cluster_bootstrap(p[mask], y[mask], oid[mask], ece, b=1000),
                       "slope_intercept": calib_eval.slope_intercept(p[mask], y[mask])}
        return o
    allm = np.ones(len(y), bool); t = {"overall": block(allm)}
    for name, p in preds.items():
        t["overall"][name]["brier_ci95_capture_cluster"] = calib_eval.cluster_bootstrap(p, y, runid, brier, b=1000)["ci95"]
        t["overall"][name]["reliability"] = reliability(p, y)
    t["by_perturbation"] = {m: block(np.array([r["pert"] == m for r in test])) for m, _ in PERT}
    t["by_knowledge_base"] = {c: block(np.array([r["cond"] == c for r in test])) for c in sorted({r["cond"] for r in test})}
    t["by_query_form"] = {f: block(np.array([r["form"] == f for r in test])) for f in sorted({r["form"] for r in test})}
    t["n_dev_original_alerts"] = len({r["original_alert_id"] for r in dev}); t["n_dev_observations"] = len(dev)
    t["coef"] = dict(zip(__import__("sentinelmesh_x.calibration", fromlist=["FEATURES"]).FEATURES, cal.m.coef_[0].round(3).tolist()))
    res[track] = t
    print(track, {k: (round(v["brier"]["value"], 4), [round(x, 4) for x in v["brier"]["ci95"]]) for k, v in t["overall"].items() if k in preds}, round(time.time() - t0), "s", flush=True)
save2("calibration_v2.json", res)
