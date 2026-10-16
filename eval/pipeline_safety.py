"""Full pipeline (retrieval -> attack graph -> risk score -> action -> routing) on every alert
of the ten test captures and the reference run, for several retrieval settings.

Reference action for an alert = the action the same pipeline selects when the retrieved tactic
is replaced by the ground-truth tactic (same confidence, same graph path length). Containment
order used to call a response weaker or stronger:
    log_only (0) < revoke_token (1) < isolate_network (2) < kill_container (3)
Also sweeps the two routing thresholds.
Usage: SENTINELMESH_ROOT=$PWD python3 eval/pipeline_safety.py eval/results/pipeline_safety.json
"""
import json, os, sys
from collections import Counter, defaultdict
from pathlib import Path
ROOT = Path(os.environ["SENTINELMESH_ROOT"])
sys.path.insert(0, str(ROOT / "rag_engine" / "src")); sys.path.insert(0, str(ROOT))
from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import EMBEDDERS
from rag_engine import TwoLayerRAG
from flat_rag import FlatRAG
from eval.alert_query import build_query, load_alerts
from graph.pipeline import run_pipeline
from response import risk_scoring as RS

RANK = {"log_only": 0, "revoke_token": 1, "isolate_network": 2, "kill_container": 3}
FRESH = ["20261014T104641Z", "20261014T111618Z", "20261014T113310Z", "20261014T122816Z", "20261014T130955Z",
         "20261014T132438Z", "20261014T134019Z", "20261014T135319Z", "20261014T140601Z", "20261014T141640Z"]
REF = "20261012T140201Z"
gt = json.loads((ROOT / "eval/ground_truth.json").read_text())["scenarios"]
techs, cves = load_kb_dir(str(ROOT / "kb_master/techniques"), str(ROOT / "kb_master/cves"))
cve_map = build_cve_lookup(cves)
GRAPHS = {}
engines = {"tactic-first": TwoLayerRAG(techs, EMBEDDERS["tfidf-word"](), cve_lookup=cve_map),
           "flat": FlatRAG(techs, EMBEDDERS["tfidf-word"](), cve_lookup=cve_map)}

def scen_of(a):
    return a.get("component_scenario") or a.get("scenario")

def run_capture(run, eng_name, form, thresholds=None):
    alerts = load_alerts(ROOT / "eval/runs" / run / "alerts.jsonl")
    eng = engines[eng_name]
    rag = []
    for a in alerts:
        q = build_query(a, form)
        r = eng.query(alert_output_text=q, container_id=a.get("service", ""), falco_rule=a.get("title", ""),
                      alert_source=(a.get("source") or "").replace("-", "_"))
        rag.append({"predicted_technique": r.predicted_technique, "predicted_technique_name": None,
                    "predicted_tactic": r.predicted_tactic, "matched_cves": r.evidence.get("cve_ids", []),
                    "confidence": r.confidence.as_dict(), "evidence": r.evidence})
    g = run_pipeline(alerts, rag_results=rag, graph_id=f"{run}_{eng_name}_{form}")
    plen = {p["scenario_id"]: len(p["ordered_stages"]) for p in g["paths"]}
    GRAPHS[(run, eng_name, form)] = {"nodes": len(g["nodes"]), "edges": len(g["edges"]), "paths": len(g["paths"]),
                                     "S10_order": next(([s if isinstance(s, str) else (s.get("scenario_id") or s.get("technique_id")) for s in p["ordered_stages"]]
                                                        for p in g["paths"] if p["scenario_id"] == "S10"), None)}
    out = []
    for a, r in zip(alerts, rag):
        sid = scen_of(a); e = gt[sid]
        L = plen.get("S10", 1) if a.get("chain_id") == "S10" else plen.get(sid, 1)
        got = RS.assess(sid, r, e, graph_path_length=L, thresholds=thresholds)
        ref = RS.assess(sid, {**r, "predicted_tactic": e["tactic"]}, e, graph_path_length=L, thresholds=thresholds)
        out.append({"run": run, "scenario": sid, "chain": a.get("chain_id") == "S10",
                    "technique_ok": r["predicted_technique"] == e["technique_id"],
                    "tactic_ok": r["predicted_tactic"] == e["tactic"],
                    "confidence": got.confidence, "risk": round(got.risk_score, 4),
                    "action": got.selected_action, "route": got.routing,
                    "ref_action": ref.selected_action, "ref_route": ref.routing})
    return out

def summarise(rows):
    s = Counter()
    for x in rows:
        s["alerts"] += 1
        s["technique_errors"] += not x["technique_ok"]
        s["tactic_errors"] += not x["tactic_ok"]
        s["route_" + x["route"]] += 1
        d = RANK[x["action"]] - RANK[x["ref_action"]]
        if d < 0:
            s["under_response"] += 1
            s["under_response_auto"] += x["route"] == "auto"
        elif d > 0:
            s["over_response"] += 1
            s["over_response_auto"] += x["route"] == "auto"
        s["kill_auto"] += x["action"] == "kill_container" and x["route"] == "auto"
        s["isolate_auto"] += x["action"] == "isolate_network" and x["route"] == "auto"
    return dict(s)

res = {"configs": {}, "threshold_sweep": {}}
for eng_name in engines:
    for form in ("raw", "rewrite"):
        rows = [x for run in FRESH for x in run_capture(run, eng_name, form)]
        ref_rows = run_capture(REF, eng_name, form)
        key = f"{eng_name}|{form}"
        per_run = {run: summarise([x for x in rows if x["run"] == run]) for run in FRESH}
        under_by = Counter((x["scenario"], x["action"], x["ref_action"], x["route"]) for x in rows
                           if RANK[x["action"]] < RANK[x["ref_action"]])
        over_by = Counter((x["scenario"], x["action"], x["ref_action"], x["route"]) for x in rows
                          if RANK[x["action"]] > RANK[x["ref_action"]])
        res["configs"][key] = {"test": summarise(rows), "reference_run": summarise(ref_rows), "reference_rows": ref_rows,
                               "reference_graph": GRAPHS[(REF, eng_name, form)],
                               "per_run": per_run,
                               "under_response_cases": [list(k) + [v] for k, v in under_by.items()],
                               "over_response_cases": [list(k) + [v] for k, v in over_by.items()],
                               "risk_range": [min(x["risk"] for x in rows), max(x["risk"] for x in rows)],
                               "rows": rows, "confidence_range_wrong": [min((x["confidence"] for x in rows if not x["technique_ok"]), default=None),
                                                     max((x["confidence"] for x in rows if not x["technique_ok"]), default=None)],
                               "confidence_range_right": [min(x["confidence"] for x in rows if x["technique_ok"]),
                                                     max(x["confidence"] for x in rows if x["technique_ok"])]}
        print(key, res["configs"][key]["test"], "ref:", res["configs"][key]["reference_run"], flush=True)
        print("   under:", res["configs"][key]["under_response_cases"], "over:", res["configs"][key]["over_response_cases"])
# threshold sweep (tactic-first, raw and rewrite)
for eng_name in engines:
    for form in ("raw", "rewrite"):
        for t_auto in (0.30, 0.35, 0.40, 0.45, 0.50):
            for t_an in (0.50, 0.55, 0.60, 0.65, 0.70):
                if t_an <= t_auto:
                    continue
                th = {"auto": t_auto, "analyst": t_an}
                RS.ROUTING_THRESHOLDS.update(th)  # select_action reads the module constant
                rows = [x for run in FRESH for x in run_capture(run, eng_name, form, thresholds=th)]
                res["threshold_sweep"][f"{eng_name}|{form}|{t_auto}|{t_an}"] = summarise(rows)
        RS.ROUTING_THRESHOLDS.update({"auto": 0.40, "analyst": 0.60})
        print("sweep done", eng_name, form, flush=True)
Path(sys.argv[1]).write_text(json.dumps(res, indent=1))
