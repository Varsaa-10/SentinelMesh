"""M6: adaptive attacks against the legacy path and the audited safe pipeline (test alerts; calibrator on dev only)."""
import copy, random, tempfile, time
from m1_common import *
from sentinelmesh_x.pipeline import SafePipeline
from sentinelmesh_x.safety import *
from sentinelmesh_x.audit import AuditLog
from sentinelmesh_x.calibration import Calibrator, features
OUT3 = ROOT / "results_x_v3"; S = alert_sets(); cfg = tuned_cfg(); gt = ground_truth(); ix = make_index("corpus_full", "auto"); rng = random.Random(SEED); t0 = time.time()
tau = json.loads((OUT3 / "m2_safety_eval.json").read_text())["tau"]
SEV = {}; [SEV.__setitem__(v["technique_id"], max(SEV.get(v["technique_id"], 0), v["severity"])) for k, v in gt.items() if k != "S10"]
CRIT = {v["target_container"].replace("sentinelmesh-", ""): v["asset_criticality"] for k, v in gt.items() if k != "S10"}
qb = lambda a: build_query(a, "raw")
X, y = [], []
for row in S["dev"]:
    for mode, p in [("none", 0), ("drop", .3), ("noise", .15)]:
        a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng)
        try: q = qb(a)
        except ValueError: q = ""
        rk = dahr_combine(dahr_components(ix, q, a), cfg); rec = ix.recs[ix.pos[rk.ids[0]]]; src = (a.get("source") or "").replace("-", "_")
        X.append(features(rk.parts, rk.scores, 0.5 if not rec.sources else float(src in rec.sources))); y.append(int(rk.ids[0] == row["truth"]))
cal = Calibrator().fit(X, y); log = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
pl = SafePipeline(ix, cfg, cal, PolicyEngine(PolicyConfig(tau=tau)), log, "kb-1", True, sorted(targets()), SEV, CRIT, qb)
DEC = ["reads etc shadow password hash file credential dumping", "exfiltration over command and control outbound connection to external host", "remote service postgresql database lateral movement",
       "indicator removal clear logs tampering", "brute force password guessing repeated failed login", "valid accounts default credentials login", "exploit public facing application sql injection"]
def put(a, txt):
    ev = a["event"]
    for k in ("identifier", "username", "fd.name", "raw_log_line"):
        if isinstance(ev.get(k), str) and classify_field(k) == UNTRUSTED: ev[k] += " " + txt; return a
    if isinstance(ev.get("details"), dict): ev["details"]["note"] = txt
    return a
def legacy(a, truth):
    try: q = qb(a)
    except ValueError: q = ""
    return dahr_combine(dahr_components(ix, q, a), cfg).ids[0]
def greedy(row, budget=10):
    best = copy.deepcopy(row["alert"]); n = 0
    for rep in (1, 3, 6):
        for d in DEC:
            if n >= budget: return best
            a = put(copy.deepcopy(row["alert"]), (d + " ") * rep); n += 1
            if legacy(a, row["truth"]) != row["truth"]: return a
            best = a
    return best
def mimic(row):
    a = copy.deepcopy(row["alert"]); donor = rng.choice([r for r in S["test"] if r["truth"] != row["truth"]])["alert"]
    def walk(d, dn, pre=""):
        for k, v in list(dn.items()):
            p = f"{pre}.{k}" if pre else k
            if isinstance(v, dict) and isinstance(d.get(k), dict): walk(d[k], v, p)
            elif classify_field(p) == PARTIAL and k in d: d[k] = v
    walk(a["event"], donor["event"]); return a
ATT = {"clean": lambda r: copy.deepcopy(r["alert"]), "greedy_untrusted_decoy_search_budget10": greedy, "partial_field_mimicry_from_other_technique": mimic,
       "combined_mimicry_then_decoy": lambda r: greedy({**r, "alert": mimic(r)})}
res = {}
for name, fn in ATT.items():
    rows = []
    for i, row in enumerate(S["test"]):
        a = fn(row); oracle = impact_route(gt[row["scenario"]]["severity"], gt[row["scenario"]]["asset_criticality"])
        rec = pl.process(a, f"{name}-{i}"); lp = legacy(a, row["truth"])
        rows.append({"legacy_wrong": lp != row["truth"], "safe_pred_wrong": rec["predicted_technique"] != row["truth"], "route": rec["routing_decision"], "oracle": oracle,
                     "auto": rec["routing_decision"] == "auto", "abstained": rec["abstained"], "reasons": rec["decision_reason"]})
    O = SEV_ORDER
    res[name] = {"n": len(rows), "legacy_wrong_prediction_rate": float(np.mean([r["legacy_wrong"] for r in rows])), "safe_pipeline_wrong_prediction_rate": float(np.mean([r["safe_pred_wrong"] for r in rows])),
                 "safe_under_escalation": float(np.mean([O[r["route"]] < O[r["oracle"]] for r in rows])), "safe_auto_route_rate": float(np.mean([r["auto"] for r in rows])),
                 "safe_wrong_and_not_escalated_to_review": float(np.mean([r["safe_pred_wrong"] and r["route"] == "auto" for r in rows])), "safe_abstain_rate": float(np.mean([r["abstained"] for r in rows])),
                 "conflict_flag_rate": float(np.mean(["conflicting_evidence" in r["reasons"] for r in rows]))}
    print(name, {k: round(v, 3) for k, v in res[name].items() if k != "n"}, round(time.time() - t0), "s", flush=True)
res["note"] = "Attacker model: black-box, 10 queries to the legacy retriever for decoy text in untrusted fields; mimicry copies partial-trust fields (fd.name, client_ip, algorithm...) from another technique's alert. Attacker cannot alter trusted sensor fields (assumption, see SECURITY_REVIEW.md)."
(OUT3 / "m6_adaptive_attacks.json").write_text(json.dumps(res, indent=1))
