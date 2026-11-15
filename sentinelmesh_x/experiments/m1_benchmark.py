"""M1 item 1: leakage audit + Track A (detector-aware) re-report + Track B (detector-independent) benchmark. Writes results_x_v2/ only."""
import time
from m1_common import *
from stats import paired_report, cluster_bootstrap
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
S = alert_sets(); t0 = time.time()
for k in S: attach_trackb(S[k])
test, held, dev = S["test"], S["heldout"], S["dev"]
ph = phrases()
tun = json.loads((OUT2 / "tuning_nested.json").read_text())
cfgB = DAHRConfig(**{**tun["B"]["final_config_all_dev"]})
cve_map = build_cve_lookup(load_kb_dir(str(ROOT / "kb_master/techniques"), str(ROOT / "kb_master/cves"))[1])

# ---------------------------------------------------------------- leakage audit
audit = {"track_b_input_schema_hash": input_schema_hash(), "forbidden_phrase_count": len(ph), "channels": {
    "field_matching": "Executes detector-derived constraints that are registered to a technique -> Track A only; disabled in Track B (no constraints are loaded).",
    "tfidf_bm25": "Text only. Leaks exactly what the query contains; Track B query = filtered event fields only.",
    "hierarchy": "Operates on KB records (tactic/parent) -> no query information; no leakage.",
    "query_construction": "FINDING: eval.alert_query renders Falco 'raw' text from the rule's own output template, looked up by rule title; 'title_raw' prepends the detector title; 'rewrite' uses hand-written scenario rules keyed on title/rule. All three carry detector-authored wording.",
    "knowledge_generation": "FINDING: generated knowledge is attached to the technique the operator registered for each detector (registry from ground_truth.json) -> Track A only; Track B KB is the unmodified ATT&CK corpus (assert_kb_clean).",
    "metadata_lookup": "Registry lookup uses scenario id -> diagnostic upper bound, never a Track B method."}}
hits = {}
for form in QUERY_FORMS:
    kinds = {}
    n_hit = 0
    for r in test:
        f = leakage_scan(r["queries"][form], ph)
        n_hit += bool(f)
        for x in f: kinds[x.split(":")[0]] = kinds.get(x.split(":")[0], 0) + 1
    hits[form] = {"queries_with_leakage": n_hit, "of": len(test), "fraction": n_hit / len(test), "by_kind_counts": kinds}
audit["existing_query_forms_test_set"] = hits
audit["track_b_queries_with_leakage"] = sum(bool(leakage_scan(r["qB"], ph)) for k in S for r in S[k])
audit["track_b_queries_total"] = sum(len(S[k]) for k in S)
audit["kb_clean_check"] = {}
for c in CORPORA:
    assert_kb_clean(build_raw_condition(c, "mitre"), [clean_record(r) for r in load_corpus(c)]); audit["kb_clean_check"][c] = "passed"
# residual leakage: can a classifier read the technique from event KEY NAMES alone (no values)?
def keys_doc(r): return " ".join(sorted(r["alertB"]["event"].keys())) + " src_" + r["alertB"]["source"]
cv = CountVectorizer(token_pattern=r"\S+", lowercase=False); Xd = cv.fit_transform([keys_doc(r) for r in dev])
lr = LogisticRegression(C=10, max_iter=2000).fit(Xd, [r["truth"] for r in dev])
pred = lr.predict(cv.transform([keys_doc(r) for r in test]))
audit["residual_key_name_fingerprint"] = {"accuracy_keys_only_test": float(np.mean([p == r["truth"] for p, r in zip(pred, test)])),
    "majority_class_accuracy": float(max(np.bincount([sorted(targets()).index(r["truth"]) for r in test])) / len(test)),
    "interpretation": "Accuracy far above the majority rate means field-name schema alone identifies the detector; Track B cannot remove this."}
save2("leakage_audit.json", audit); print("audit", audit["existing_query_forms_test_set"]["raw"]["fraction"], audit["residual_key_name_fingerprint"]["accuracy_keys_only_test"], flush=True)

# ---------------------------------------------------------------- Track A (re-report with CI, per technique, per capture)
bm = json.loads((ROOT / "results_x/benchmark.json").read_text())
techs = sorted(targets()); runs = sorted({r["run"] for r in test}); A = []
for row in bm["rows"]:
    if row["set"] != "test": continue
    x = np.array([1.0 if k == 1 else 0.0 for k in row["ranks"]])
    lo, hi = cluster_bootstrap(x, test, b=1000)
    A.append({**{k: row[k] for k in ("corpus", "kb", "form", "method", "P@1", "R@3", "R@5", "MRR", "nDCG@5", "macroF1")}, "P@1_ci95_cluster": [lo, hi],
              "per_technique_P@1": {t: float(np.mean([x[i] for i, r in enumerate(test) if r["truth"] == t])) for t in techs},
              "per_capture_P@1": {c: float(np.mean([x[i] for i, r in enumerate(test) if r["run"] == c])) for c in runs}})
save2("detector_aware_benchmark.json", {"track": "A (detector-aware: detector identity, constraints, generated knowledge and registry permitted)",
    "source": "recomputed from results_x/benchmark.json (unchanged baseline run, same ranks)", "n_unique_alerts": len(test), "n_captures": len(runs), "rows": A})
print("trackA saved", round(time.time() - t0), "s", flush=True)

# ---------------------------------------------------------------- Track B
METHODS = ["tfidf", "bm25", "rrf", "dahr_default", "dahr", "repo_flat", "repo_two_layer", "supervised"]
B = {"track": "B (detector-independent)", "input_schema_hash": input_schema_hash(), "dahr_config_B": cfgB.__dict__,
     "config_source": "results_x_v2/tuning_nested.json (selected on development captures only; field channel off)",
     "dense_baselines": "BLOCKED: sentence-transformer / security-domain weights cannot be downloaded in this environment (huggingface not reachable). Not simulated.",
     "rows": [], "diagnostic_registry_upper_bound": []}
conv = lambda rows: [trackb_row(r, r["alert"]) for r in rows]
dev_B, test_B, held_B = conv(dev), conv(test), conv(held)
for corpus in CORPORA:
    ix = make_index_B(corpus); repo = RepoEngines(build_raw_condition(corpus, "mitre"), cve_map); sup = Supervised(dev_B, "indep")
    for setname, rows_B, rows in (("test", test_B, test), ("heldout", held_B, held)):
        for m in METHODS:
            out = score_rows(m, rows_B, "indep", ix, corpus, cfgB, repo, sup)
            x = np.array([1.0 if k == 1 else 0.0 for k in out["ranks"]])
            rec = {"corpus": corpus, "set": setname, "method": m, "n_records": len(ix.recs), **out["metrics"], "ranks": out["ranks"], "preds": out["preds"]}
            if setname == "test":
                lo, hi = cluster_bootstrap(x, rows, b=1000); rec["P@1_ci95_cluster"] = [lo, hi]
                rec["per_technique_P@1"] = {t: float(np.mean([x[i] for i, r in enumerate(rows) if r["truth"] == t])) for t in techs}
                rec["per_capture_P@1"] = {c: float(np.mean([x[i] for i, r in enumerate(rows) if r["run"] == c])) for c in runs}
            B["rows"].append(rec)
        tm = truth_map(); rk = [rank_of_truth(rank_registry_lookup(ix, r["alert"], tm).ids, r["truth"], corpus) for r in rows]
        B["diagnostic_registry_upper_bound"].append({"corpus": corpus, "set": setname, "P@1": float(np.mean([k == 1 for k in rk])), "note": "uses scenario id = detector identity; NOT a Track B method"})
    print("B", corpus, round(time.time() - t0), "s", flush=True)
# paired stats, declared family = DAHR(B) vs each of the 7 other Track B methods x 3 corpora (test set)
fam = []
for corpus in CORPORA:
    by = {r["method"]: r for r in B["rows"] if r["corpus"] == corpus and r["set"] == "test"}
    a = np.array([int(k == 1) for k in by["dahr"]["ranks"]])
    for m in METHODS:
        if m == "dahr": continue
        b = np.array([int(k == 1) for k in by[m]["ranks"]])
        fam.append({"corpus": corpus, "A": "dahr", "B": m, **paired_report(a, b, test)})
ps = np.array([f["p_mcnemar_exact"] for f in fam]); order = np.argsort(ps); run = 0.0; adj = np.empty(len(ps))
for rk_, i in enumerate(order): run = max(run, (len(ps) - rk_) * ps[i]); adj[i] = min(1.0, run)
for f, p in zip(fam, adj): f["p_holm"] = float(p)
B["paired_stats"] = {"family": "DAHR vs each other Track B method, 3 corpora (21 hypotheses), exact McNemar, Holm", "n_unique_alerts": len(test), "n_captures": len(runs), "comparisons": fam}
save2("detector_independent_benchmark.json", B); print("done", round(time.time() - t0), "s")
