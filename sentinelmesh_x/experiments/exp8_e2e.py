"""End-to-end pipeline validation (item 9): alerts -> retrieval -> attack graph -> risk -> routing, on all alerts of the
10 test captures. P0 = original system (TwoLayerRAG, lab-written 36-record KB, manual confidence);
PX = SentinelMesh-X (DAHR, 706-record corpus + generated knowledge, learned calibration)."""
import random, time
from bench import *
from sentinelmesh_x.calibration import Calibrator, features
from eval.alert_query import load_alerts
from graph.pipeline import run_pipeline
from response.risk_scoring import compute_risk_score, route, assess
from rag_engine.src.confidence import compute_confidence
S = alert_sets(); cfg = tuned_cfg(); gt = ground_truth(); tm = truth_map()
EXPECTED_CHAIN = ["T1190", "T1078", "T1212", "T1003.008", "T1041"]
cve_map = build_cve_lookup(load_kb_dir(str(ROOT / "kb_master/techniques"), str(ROOT / "kb_master/cves"))[1])
ix = make_index("corpus_full", "auto"); ixs = {"mitre": make_index("corpus_full", "mitre"), "expert": make_index("corpus_full", "expert"), "auto": ix}
repo0 = RepoEngines(build_raw_condition("corpus_36", "expert"), cve_map)
# calibrator from DEV only (pooled over knowledge conditions and perturbations)
rng = random.Random(7); X, y = [], []
for row in S["dev"]:
    for mode, p in [("none", 0), ("drop", .3), ("noise", .15), ("rename", .5)]:
        a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng); r = requery(row, a)
        for cond, ixc in ixs.items():
            c = dahr_combine(dahr_components(ixc, r["queries"]["raw"], a), cfg)
            rec = ixc.recs[ixc.pos[c.ids[0]]]; src = (a.get("source") or "").replace("-", "_")
            X.append(features(c.parts, c.scores, 0.5 if not rec.sources else float(src in rec.sources))); y.append(int(c.ids[0] == row["truth"]))
cal = Calibrator().fit(X, y)

def rag_dict(tid, conf, ixr):
    rec = ixr.recs[ixr.pos[tid]] if tid in ixr.pos else None
    return {"predicted_technique": tid, "predicted_technique_name": rec.name if rec else "", "predicted_tactic": rec.tactic if rec else "Unknown",
            "matched_cves": [], "confidence": {"confidence_score": float(conf)}, "evidence": {}}

def label(a):
    s = a.get("component_scenario") or a.get("scenario"); return s, tm.get(s)
order = {"auto": 0, "analyst": 1, "admin": 2}
res = {"captures": []}
for run in sorted({r["run"] for r in S["test"]}):
    alerts = load_alerts(ROOT / "eval/runs" / run / "alerts.jsonl")
    rows = []
    for a in alerts:
        try: q = build_query(a, "raw")
        except ValueError: continue
        rows.append((a, q))
    per = {}
    for name in ("P0", "PX"):
        t0 = time.perf_counter(); recs = []
        for a, q in rows:
            scen, truth = label(a)
            if name == "P0":
                r = repo0.two.query(alert_output_text=q, container_id=a.get("service", ""), falco_rule=a.get("title", ""), alert_source=(a.get("source") or "").replace("-", "_"))
                tid, conf, ixr = r.predicted_technique, float(r.confidence.score), None
                rd = {"predicted_technique": tid, "predicted_technique_name": r.predicted_technique_name, "predicted_tactic": r.predicted_tactic, "matched_cves": r.matched_cves,
                      "confidence": {"confidence_score": conf}, "evidence": r.evidence}
            else:
                c = dahr_combine(dahr_components(ix, q, a), cfg); tid = c.ids[0]; rec = ix.recs[ix.pos[tid]]
                src = (a.get("source") or "").replace("-", "_")
                conf = float(cal.predict([features(c.parts, c.scores, 0.5 if not rec.sources else float(src in rec.sources))])[0])
                rd = rag_dict(tid, conf, ix)
            recs.append((a, scen, truth, tid, conf, rd))
        retr_ms = (time.perf_counter() - t0) * 1000
        chain = [(a, rd) for a, s, t, tid, c, rd in recs if a.get("chain_id") == "S10"]
        t1 = time.perf_counter()
        g = run_pipeline([a for a, _ in chain], rag_results=[rd for _, rd in chain]) if chain else {}
        paths = g.get("paths", []) if isinstance(g, dict) else []
        seqs = [p.get("technique_sequence") for p in paths]
        graph_ms = (time.perf_counter() - t1) * 1000
        plen = max([len(p.get("ordered_stages", [])) for p in paths] or [1])
        dec_ok = under = auto_wrong = 0
        for a, scen, truth, tid, conf, rd in recs:
            if scen not in gt or scen == "S10": continue
            orc = route(compute_risk_score(1.0, gt[scen]["severity"], gt[scen]["asset_criticality"])["normalized"])
            as_ = assess(scen, rd, gt[scen], graph_path_length=plen if a.get("chain_id") == "S10" else 1)
            dec_ok += as_.routing == orc; under += order[as_.routing] < order[orc]
            auto_wrong += (as_.routing == "auto" and tid != truth)
        n = len(recs)
        slots = {(a.get("component_scenario") if a.get("chain_id") == "S10" else a.get("scenario"), a.get("chain_id") == "S10") for a, *_ in recs}
        expected = {(s, False) for s in [f"S{i}" for i in range(1, 10)]} | {(s, True) for s in ["S1", "S3", "S4", "S9", "S8"]}
        per[name] = {"n_alerts": n, "retrieval_acc": float(np.mean([tid == truth for a, s, truth, tid, c, rd in recs if truth])),
                     "detected_slots": len(slots & expected), "missed_slots": len(expected - slots),
                     "chain_path_exact": any(sq == EXPECTED_CHAIN for sq in seqs), "chain_technique_seqs": seqs[:2],
                     "chain_stage_acc": float(np.mean([tid == truth for a, s, truth, tid, c, rd in recs if a.get("chain_id") == "S10" and truth] or [0])),
                     "routing_matches_oracle": dec_ok / max(1, n), "under_escalated": under / max(1, n), "auto_on_wrong_prediction": int(auto_wrong),
                     "latency_ms_per_alert_retrieval": retr_ms / max(1, n), "graph_ms": graph_ms}
    res["captures"].append({"run": run, **per})
for name in ("P0", "PX"):
    ks = ["retrieval_acc", "chain_stage_acc", "routing_matches_oracle", "under_escalated", "latency_ms_per_alert_retrieval", "missed_slots", "auto_on_wrong_prediction"]
    res[f"mean_{name}"] = {k: float(np.mean([c[name][k] for c in res["captures"]])) for k in ks}
    res[f"mean_{name}"]["chain_path_exact_captures"] = sum(c[name]["chain_path_exact"] for c in res["captures"])
save("end_to_end.json", res); print(res["mean_P0"]); print(res["mean_PX"]); print(res["captures"][0]["P0"]["chain_technique_seqs"], res["captures"][0]["PX"]["chain_technique_seqs"])
