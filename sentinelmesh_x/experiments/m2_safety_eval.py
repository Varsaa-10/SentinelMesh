"""M2: safety gate + field trust under missing / corrupted / attacker-controlled fields. Dev: calibrator, trust tiers, tau. Test: evaluation only."""
import copy, random, time
from m1_common import *
from m1_common import OUT2
from sentinelmesh_x.safety import *
from sentinelmesh_x.calibration import Calibrator, features
from rag_engine.src.confidence import compute_confidence
OUT3 = ROOT / "results_x_v3"; OUT3.mkdir(exist_ok=True)
S = alert_sets(); cfg = tuned_cfg(); gt = ground_truth(); SUP = sorted(targets()); t0 = time.time()
SEV_T = {}; [SEV_T.__setitem__(v["technique_id"], max(SEV_T.get(v["technique_id"], 0), v["severity"])) for k, v in gt.items() if k != "S10"]
ixs = {"auto": make_index("corpus_full", "auto"), "mitre": make_index("corpus_full", "mitre")}
FORMS = ("raw", "rewrite")
DECOY = ["reads etc shadow password hash file credential dumping", "exfiltration over command and control outbound connection to external host",
         "remote service postgresql database lateral movement", "indicator removal clear logs tampering", "brute force password guessing repeated failed login"]

def put_text(a, txt):
    ev = a["event"]
    for key in ("identifier", "username", "fd.name", "raw_log_line"):
        if isinstance(ev.get(key), str): ev[key] += " " + txt; return a
    if isinstance(ev.get("details"), dict): ev["details"]["note"] = txt
    return a
def attack(name, row, rng):
    a = copy.deepcopy(row["alert"]); donors = [d for d in DECOY]; d = rng.choice(donors)
    if name == "clean": return a
    if name == "missing_30": return perturb_alert(a, "drop", .3, rng)
    if name == "missing_80": return perturb_alert(a, "drop", .8, rng)
    if name == "corrupt_noise15": return perturb_alert(a, "noise", .15, rng)
    if name == "rename_50": return perturb_alert(a, "rename", .5, rng)
    if name == "substitute_shuffle":
        ev = a["event"]; ks = [k for k, v in ev.items() if isinstance(v, str) and k not in ("timestamp", "service")]; vs = [ev[k] for k in ks]; rng.shuffle(vs)
        for k, v in zip(ks, vs): ev[k] = v
        return a
    if name == "inject_decoy": return put_text(a, d)
    if name == "repeat_vocab_x20": return put_text(a, (d + " ") * 20)
    if name == "oversized_8KB": return put_text(a, (d + " ") * 150)
    if name == "unicode_obfuscated": return put_text(a, "".join(c + "\u200b" for c in d).replace("a", "\uff41"))
    if name == "conflict_struct_vs_text": return put_text(a, d + " " + rng.choice(donors))
    raise KeyError(name)
ATTACKS = ["clean", "missing_30", "missing_80", "corrupt_noise15", "rename_50", "substitute_shuffle", "inject_decoy", "repeat_vocab_x20", "oversized_8KB", "unicode_obfuscated", "conflict_struct_vs_text"]

def san_alert(a):
    a = copy.deepcopy(a)
    def walk(d):
        for k, v in d.items():
            if isinstance(v, dict): walk(v)
            elif isinstance(v, str) and classify_field(k) == UNTRUSTED: d[k] = sanitise_text(v)
    walk(a["event"]); return a

def comp(ix, row, alert, form):
    r = requery(row, alert); return dahr_components(ix, r["queries"][form], alert)

def observe(rows, seed, tiers_list=((TRUSTED, PARTIAL),)):
    rng = random.Random(seed); obs = []
    for row in rows:
        for an in ATTACKS:
            a = attack(an, row, rng)
            for kb, ix in ixs.items():
                for form in FORMS:
                    cF = comp(ix, row, a, form); cS = comp(ix, row, san_alert(a), form)
                    rec = {"orig": f"{row['run']}|{row['slot']}", "run": row["run"], "scenario": row["scenario"], "truth": row["truth"], "attack": an, "kb": kb, "form": form,
                           "F": (cF, dahr_combine(cF, cfg)), "S": (cS, dahr_combine(cS, cfg)), "T": {}}
                    for ti, tiers in enumerate(tiers_list):
                        tv = trusted_view(san_alert(a), tiers); cT = comp(ix, row, tv, form); rec["T"][ti] = (cT, dahr_combine(cT, cfg))
                    obs.append(rec)
    return obs
def top(x): return x[1].ids[0]
def sa(ix, id_, src):
    rec = ix.recs[ix.pos[id_]]; return 0.5 if not rec.sources else float(src in rec.sources)
def feat(ix, x, row_alert):
    src = (row_alert.get("source") or "").replace("-", "_"); return features(x[1].parts, x[1].scores, sa(ix, top(x), src))
alert_of = {f"{r['run']}|{r['slot']}": r for k in ("dev", "test") for r in S[k]}

dev_obs = observe(S["dev"], 11, ((TRUSTED,), (TRUSTED, PARTIAL))); print("dev obs", len(dev_obs), round(time.time() - t0), "s", flush=True)
# --- development-only tuning: trust tiers, calibrator, tau
tier_acc = {ti: float(np.mean([top(o["T"][ti]) == o["truth"] for o in dev_obs if o["attack"] != "clean" and o["kb"] == "auto"])) for ti in (0, 1)}
best_ti = 1 if tier_acc[1] >= tier_acc[0] else 0; tiers_chosen = ((TRUSTED,), (TRUSTED, PARTIAL))[best_ti]
cal = Calibrator().fit([feat(ixs[o["kb"]], o["S"], alert_of[o["orig"]]["alert"]) for o in dev_obs], [int(top(o["S"]) == o["truth"]) for o in dev_obs])
def gate_inputs(o, ix, al, ti):
    F, Sx, T = o["F"], o["S"], o["T"][ti]
    conf = float(cal.predict([feat(ix, Sx, al)])[0]); pred = top(Sx); tpred = top(T)
    trusted_support = (tpred == pred) and T[0].fld.max() > 0 and any(True for _ in [0])
    return conf, pred, tpred, trusted_support
def to_input(o, ix, al, ti, conf, pred, tpred, ts):
    sev = SEV_T.get(pred, 3); crit = gt[o["scenario"]]["asset_criticality"]
    return DecisionInput(pred, conf, SUP, float(o["S"][0].cov), bool(ts), tpred != pred, True, True, False, sev, crit, "log_only", tuple(SEV_T.get(i, 3) for i in o["S"][1].ids[:3]))
# tau: smallest value for which dev eligible predictions (all other gates passing) are wrong <= 1% (else never auto)
elig = []
for o in dev_obs:
    ix = ixs[o["kb"]]; al = alert_of[o["orig"]]["alert"]; ti = 0 if best_ti == 0 else 1
    conf, pred, tpred, ts = gate_inputs(o, ix, al, ti if False else best_ti)
    d = PolicyEngine(PolicyConfig(tau=0.0)).decide(to_input(o, ix, al, best_ti, conf, pred, tpred, ts))
    if not d.reasons: elig.append((conf, int(pred == o["truth"])))
tau = 1.01
for t in np.arange(0.5, 1.0, 0.01):
    sel = [ok for c, ok in elig if c >= t]
    if len(sel) >= 20 and (1 - np.mean(sel)) <= 0.01: tau = float(round(t, 2)); break
print("tiers", tiers_chosen, tier_acc, "tau", tau, "eligible dev", len(elig), flush=True)
test_obs = observe(S["test"], 22, (tiers_chosen,)); print("test obs", len(test_obs), round(time.time() - t0), "s", flush=True)
eng = PolicyEngine(PolicyConfig(tau=tau)); ORD = SEV_ORDER
rows = []
for o in test_obs:
    ix = ixs[o["kb"]]; al = alert_of[o["orig"]]["alert"]; src = (al.get("source") or "").replace("-", "_")
    conf, pred, tpred, ts = gate_inputs(o, ix, al, 0)
    crit = gt[o["scenario"]]["asset_criticality"]; oracle = impact_route(gt[o["scenario"]]["severity"], crit)
    Fx = o["F"]; predF = top(Fx); recF = ix.recs[ix.pos[predF]]
    man = compute_confidence(Fx[1].scores[:3], [ix.recs[ix.pos[i]].tactic for i in Fx[1].ids[:3]], alert_source=src, winning_record_sources=recF.sources or None).score
    confF = float(cal.predict([feat(ix, Fx, al)])[0])
    r0 = rs.route(rs.compute_risk_score(man, SEV_T.get(predF, 3), crit)["normalized"]); r1 = rs.route(rs.compute_risk_score(confF, SEV_T.get(predF, 3), crit)["normalized"])
    d = eng.decide(to_input(o, ix, al, 0, conf, pred, tpred, ts))
    rows.append({"orig": o["orig"], "run": o["run"], "attack": o["attack"], "kb": o["kb"], "form": o["form"], "ok_legacy": int(predF == o["truth"]), "ok_san": int(pred == o["truth"]), "ok_trusted_view": int(tpred == o["truth"]),
                 "oracle": oracle, "P0_legacy_manual": r0, "P1_learned_conf_legacy_formula": r1, "P2_safety_gate": d.route, "P2_abstain": d.abstain, "P2_auto_permitted": d.automatic_action_permitted,
                 "pred_legacy": predF, "pred_safe": pred})
def summ(rs_):
    o = {"n_observations": len(rs_), "n_original_alerts": len({r["orig"] for r in rs_}), "acc_legacy_view": float(np.mean([r["ok_legacy"] for r in rs_])), "acc_sanitised_view": float(np.mean([r["ok_san"] for r in rs_])),
         "acc_trusted_view": float(np.mean([r["ok_trusted_view"] for r in rs_]))}
    for p, ok in (("P0_legacy_manual", "ok_legacy"), ("P1_learned_conf_legacy_formula", "ok_legacy"), ("P2_safety_gate", "ok_san")):
        rt = [r[p] for r in rs_]; orc = [r["oracle"] for r in rs_]
        o[p] = {"under_escalation": float(np.mean([ORD[a] < ORD[b] for a, b in zip(rt, orc)])), "over_escalation": float(np.mean([ORD[a] > ORD[b] for a, b in zip(rt, orc)])),
                "auto_rate": float(np.mean([a == "auto" for a in rt])), "auto_on_wrong_prediction": float(np.mean([a == "auto" and not r[ok] for a, r in zip(rt, rs_)])),
                "n_auto_on_wrong": int(sum(a == "auto" and not r[ok] for a, r in zip(rt, rs_))), "route_matches_oracle": float(np.mean([a == b for a, b in zip(rt, orc)]))}
    o["P2_safety_gate"]["abstain_rate"] = float(np.mean([r["P2_abstain"] for r in rs_]))
    o["P2_safety_gate"]["automatic_action_permitted_rate"] = float(np.mean([r["P2_auto_permitted"] for r in rs_]))
    return o
res = {"note": "Dev-only: trust tiers, calibrator, tau. Test: 140 original alerts x attacks x 2 KB conditions x 2 query forms. Oracle route = impact tier of the TRUE technique at confidence 1.0.",
       "chosen_trusted_tiers": tiers_chosen, "dev_tier_accuracy_under_attack": {str(k): v for k, v in tier_acc.items()}, "tau": tau, "n_dev_eligible_for_tau": len(elig),
       "oracle_route_distribution": {k: int(sum(r["oracle"] == k for r in rows)) for k in ("auto", "analyst", "admin")}, "overall": summ(rows), "by_attack": {a: summ([r for r in rows if r["attack"] == a]) for a in ATTACKS}, "by_kb": {k: summ([r for r in rows if r["kb"] == k]) for k in ixs}}
(OUT3 / "m2_safety_eval.json").write_text(json.dumps(res, indent=1, default=str))
for p in ("P0_legacy_manual", "P1_learned_conf_legacy_formula", "P2_safety_gate"): print(p, {k: round(v, 3) for k, v in res["overall"][p].items()})
