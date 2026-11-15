"""Learned confidence calibration and risk assessment. Calibrator trained on DEV pooled predictions, evaluated on TEST."""
import random, sys, time
from bench import *
from sentinelmesh_x.calibration import *
sys.path.insert(0, str(ROOT))
from rag_engine.src.confidence import compute_confidence
from response.risk_scoring import compute_risk_score, route
from scipy.stats import spearmanr

S = alert_sets(); cfg = tuned_cfg(); CORPUS = "corpus_full"; gt = ground_truth()
ixs = {c: make_index(CORPUS, c) for c in ("mitre", "expert", "auto")}
PERT = [("none", 0.0), ("drop", 0.3), ("noise", 0.15), ("rename", 0.5)]

def pool(rows, seed):
    rng = random.Random(seed); out = []
    for row in rows:
        for mode, p in PERT:
            a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng)
            r = requery(row, a)
            for form in QUERY_FORMS:
                for cond, ix in ixs.items():
                    c = dahr_components(ix, r["queries"][form], a)
                    rk = dahr_combine(c, cfg)
                    top = rk.ids[0]; rec = ix.recs[ix.pos[top]]
                    src = (a.get("source") or "").replace("-", "_")
                    sa = 0.5 if not rec.sources else (1.0 if src in rec.sources else 0.0)
                    tactics = [ix.recs[ix.pos[i]].tactic for i in rk.ids[:3]]
                    manual = compute_confidence(rk.scores[:3], tactics, alert_source=src, winning_record_sources=rec.sources or None).score
                    out.append({"run": row["run"], "scenario": row["scenario"], "truth": row["truth"], "pred": top, "ok": int(top == row["truth"]),
                                "cond": cond, "form": form, "pert": mode, "x": features(rk.parts, rk.scores, sa), "manual": float(manual),
                                "z_top": float(rk.scores[0])})
    return out

t0 = time.time()
dev = pool(S["dev"], 1); test = pool(S["test"], 2)
print("pooled", len(dev), len(test), round(time.time() - t0), "s", flush=True)
Xd, yd = [r["x"] for r in dev], [r["ok"] for r in dev]
Xt, yt = [r["x"] for r in test], np.array([r["ok"] for r in test])
cal = Calibrator(C=1.0).fit(Xd, yd)
pt = cal.predict(Xt)
man = np.array([r["manual"] for r in test]); ztop = np.array([r["z_top"] for r in test])
res = {"n_dev": len(dev), "n_test": len(test), "test_accuracy_pooled": float(yt.mean()), "features": FEATURES,
       "coef": dict(zip(FEATURES, cal.m.coef_[0].round(3).tolist()))}
for name, p in [("manual_weights (original)", man), ("raw_fused_score", ztop), ("learned_LR", pt)]:
    res[name] = {"brier": brier(p, yt), "ECE10": ece(p, yt), "ECE_adaptive": ece(p, yt, adaptive=True), "reliability": reliability(p, yt)}
# per condition
res["by_condition"] = {c: {"acc": float(np.mean([r["ok"] for r in test if r["cond"] == c])),
                           "brier_manual": brier([r["manual"] for r in test if r["cond"] == c], [r["ok"] for r in test if r["cond"] == c]),
                           "brier_learned": brier([p for p, r in zip(pt, test) if r["cond"] == c], [r["ok"] for r in test if r["cond"] == c])} for c in ixs}
# leave-one-capture-out check on dev (calibrator robustness)
loco = []
for held in sorted({r["run"] for r in dev}):
    tr = [r for r in dev if r["run"] != held]; te = [r for r in dev if r["run"] == held]
    c2 = Calibrator().fit([r["x"] for r in tr], [r["ok"] for r in tr]); pp = c2.predict([r["x"] for r in te]); yy = [r["ok"] for r in te]
    loco.append({"held": held, "brier": brier(pp, yy), "brier_manual": brier([r["manual"] for r in te], yy)})
res["dev_loco"] = loco

# ---------- risk assessment and routing decisions on test ----------
sev_h = {k: v["severity"] for k, v in gt.items()}; crit_h = {k: v["asset_criticality"] for k, v in gt.items()}
def decision(conf, scen):
    return route(compute_risk_score(conf, sev_h[scen], crit_h[scen])["normalized"])
rows = []
for r, pc in zip(test, pt):
    oracle = decision(1.0, r["scenario"])
    rows.append({"oracle": oracle, "manual": decision(r["manual"], r["scenario"]), "learned": decision(float(pc), r["scenario"]),
                 "risk_oracle": compute_risk_score(1.0, sev_h[r["scenario"]], crit_h[r["scenario"]])["normalized"],
                 "risk_manual": compute_risk_score(r["manual"], sev_h[r["scenario"]], crit_h[r["scenario"]])["normalized"],
                 "risk_learned": compute_risk_score(float(pc), sev_h[r["scenario"]], crit_h[r["scenario"]])["normalized"],
                 "ok": r["ok"], "cond": r["cond"]})
order = {"auto": 0, "analyst": 1, "admin": 2}
risk = {}
for k in ("manual", "learned"):
    dec = [order[x[k]] for x in rows]; orc = [order[x["oracle"]] for x in rows]
    wrong = [x for x in rows if not x["ok"]]
    risk[k] = {"decision_accuracy": float(np.mean([a == b for a, b in zip(dec, orc)])),
               "under_escalation_rate": float(np.mean([a < b for a, b in zip(dec, orc)])),
               "over_escalation_rate": float(np.mean([a > b for a, b in zip(dec, orc)])),
               "auto_on_wrong_prediction": float(np.mean([x[k] == "auto" for x in wrong])) if wrong else 0.0,
               "spearman_risk_vs_oracle": float(spearmanr([x[f"risk_{k}"] for x in rows], [x["risk_oracle"] for x in rows])[0])}
res["risk_routing_test"] = risk
# derived severity / criticality vs hand-assigned
crit_d = derived_criticality(ROOT)
cves = {json.loads(p.read_text())["cve_id"]: json.loads(p.read_text()) for p in (ROOT / "kb_master/cves").glob("*.json")}
cmp_ = []
for sid, g in gt.items():
    if sid == "S10": continue
    cvss = next((cves[c]["cvss_score"] for c in ([g["cve"]] if g.get("cve") else []) if c in cves), None)
    tgt = g["target_container"].replace("sentinelmesh-", "")
    cmp_.append({"scenario": sid, "sev_hand": g["severity"], "sev_derived": derived_severity(g["tactic"], cvss), "crit_hand": g["asset_criticality"], "crit_derived": crit_d.get(tgt)})
res["derived_vs_hand"] = cmp_
res["derived_corr"] = {"severity_spearman": float(spearmanr([c["sev_hand"] for c in cmp_], [c["sev_derived"] for c in cmp_])[0]),
                       "criticality_spearman": float(spearmanr([c["crit_hand"] for c in cmp_], [c["crit_derived"] for c in cmp_])[0]),
                       "criticality_by_service": crit_d}
save("calibration.json", res); print("done", round(time.time() - t0), "s")
print({k: (round(res[k]["brier"], 4), round(res[k]["ECE10"], 4)) for k in ("manual_weights (original)", "raw_fused_score", "learned_LR")}); print(risk); print(res["derived_corr"])
