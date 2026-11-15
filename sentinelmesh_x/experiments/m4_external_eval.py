"""M4: independent validation on Sigma rules x Atomic Red Team (third-party authored). Cross-source agreement, coverage, abstention. Not real telemetry; no benign data."""
import hashlib, time, collections
from m1_common import *
from sentinelmesh_x.external import load_sigma_process_creation, load_atomic_events
from sentinelmesh_x import calib_eval
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sentinelmesh_x.retrieval import tokenize
OUT3 = ROOT / "results_x_v3"; t0 = time.time()
SIG, ATOM = Path("/tmp/ext/sigma.tgz"), Path("/tmp/ext/atomic_index.yaml")
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
rules, sstats = load_sigma_process_creation(SIG); events, astats = load_atomic_events(ATOM)
print("rules", len(rules), sstats, "events", astats, round(time.time() - t0), "s", flush=True)
corpus = [clean_record(r) for r in load_corpus("corpus_full")]; cid = {r["id"] for r in corpus}; tactic_of = {r["id"]: r.get("tactic", "") for r in corpus}
covered = collections.Counter(t for r in rules for t in r.techniques)
events = [e for e in events if e["technique"] in cid]; print("events with technique in ATT&CK corpus", len(events), flush=True)
# ---- detector-aware (Sigma) predictions
for e in events:
    ev = {"Image": e["Image"], "CommandLine": e["CommandLine"]}
    sc = collections.Counter()
    for r in rules:
        if r.fires(ev):
            for t in r.techniques: sc[t] += 1.0 / len(r.techniques)
    e["fired"] = bool(sc); e["pred"] = sorted(sc, key=lambda t: (-sc[t], t))[0] if sc else None; e["fired_techs"] = sorted(sc)
    e["sigma_covers_truth"] = e["technique"] in covered
print("sigma eval", round(time.time() - t0), "s", flush=True)
parent = lambda t: t.split(".")[0] if t else t
ok1 = lambda e: e["pred"] == e["technique"]
okp = lambda e: parent(e["pred"]) == parent(e["technique"])
oka = lambda e: e["technique"] in e["fired_techs"]
cl = [e["test_guid"] for e in events]; idx = calib_eval.clusters_index(cl)
def ci(vals, mask, b=1000, seed=1):
    v = np.array(vals, float); m = np.array(mask, bool); rng = np.random.default_rng(seed); out = []
    for _ in range(b):
        s = calib_eval.draw_cluster_sample(idx, rng); s = s[m[s]]
        if len(s): out.append(v[s].mean())
    return [float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))]
fired = [e["fired"] for e in events]; n_fired = sum(fired)
R = {"provenance": {"sigma": {"url": "https://github.com/SigmaHQ/sigma (master, tarball via codeload.github.com)", "sha256": sha(SIG), "retrieved": "2026-11-06", "licence_note": "Detection Rule License 1.1 per Sigma repository documentation (not verified through the API in this environment); not redistributed in this package"},
        "atomic_red_team": {"url": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml", "sha256": sha(ATOM), "retrieved": "2026-11-06", "licence_note": "MIT per repository documentation (not verified through the API here); not redistributed"},
        "commit_ids": "UNAVAILABLE: GitHub API not reachable from this environment; tarball/file sha256 recorded instead"},
     "scope_limits": ["Atomic Red Team gives command definitions, not captured telemetry", "Image field is inferred from the command (assumption)", "only windows/process_creation Sigma rules and Windows command_prompt/powershell atomics", "no benign data exists in either source; none was synthesised", "rules using unsupported constructs are excluded (counted below)"],
     "sigma_rules": {"windows_process_creation_files": sstats["files"], "with_technique_tag": sstats["tagged"], "usable_after_parsing": len(rules), "unsupported_or_unparseable": sstats["unsupported"], "distinct_techniques_tagged": len(covered)},
     "atomic": {**astats, "events_with_technique_in_corpus": len(events), "distinct_techniques": len({e['technique'] for e in events}), "distinct_tests": len(idx)}}
cov_ev = [e["sigma_covers_truth"] for e in events]; unc = [not c for c in cov_ev]
R["detector_aware_sigma"] = {"events": len(events), "events_where_a_rule_fired": n_fired, "fire_rate": n_fired / len(events),
    "events_whose_technique_has_any_sigma_rule": sum(cov_ev), "recall_on_covered_events_top1": float(np.mean([ok1(e) for e in events if e["sigma_covers_truth"]])),
    "precision_top1_given_fired": float(np.mean([ok1(e) for e in events if e["fired"]])), "precision_top1_given_fired_ci95_test_cluster": ci([ok1(e) for e in events], fired),
    "precision_parent_level_given_fired": float(np.mean([okp(e) for e in events if e["fired"]])), "truth_among_fired_techniques_given_fired": float(np.mean([oka(e) for e in events if e["fired"]])),
    "false_confident_rate_given_fired": float(1 - np.mean([ok1(e) for e in events if e["fired"]])),
    "unsupported_technique_events": sum(unc), "abstained_on_unsupported": float(np.mean([not e["fired"] for e in events if not e["sigma_covers_truth"]])),
    "false_confident_on_unsupported": float(np.mean([e["fired"] for e in events if not e["sigma_covers_truth"]]))}
# per-technique (techniques with >=3 events and any firing)
pt = collections.defaultdict(list)
for e in events: pt[e["technique"]].append(e)
R["per_technique_top1_given_fired"] = {t: {"events": len(v), "fired": sum(x["fired"] for x in v), "precision": (float(np.mean([ok1(x) for x in v if x["fired"]])) if any(x["fired"] for x in v) else None)} for t, v in sorted(pt.items()) if sum(x["fired"] for x in v)}
# ---- text-only baselines (ATT&CK corpus text; query = command line) on the same events
recs = make_records(corpus); ix = KBIndex(recs); ids = ix.ids
svd_vec = TfidfVectorizer(tokenizer=lambda s: tokenize(s, True), lowercase=False, token_pattern=None, sublinear_tf=True); X = svd_vec.fit_transform([r.text for r in recs])
svd = TruncatedSVD(200, random_state=0).fit(X); D = svd.transform(X); D /= (np.linalg.norm(D, axis=1, keepdims=True) + 1e-9)
def lsa_scores(q): v = svd.transform(svd_vec.transform([q])); v /= (np.linalg.norm(v) + 1e-9); return D @ v.ravel()
def rk(scores, truth): return int((scores > scores[ids.index(truth)]).sum()) + 1
base = {"tfidf": lambda q: ix.tf.scores(q), "bm25": lambda q: ix.bm.scores(q), "lsa_dense_nonpretrained": lsa_scores}
R["text_only_baselines"] = {}
for name, fn in base.items():
    ranks = np.array([rk(fn(e["CommandLine"]), e["technique"]) for e in events]); 
    R["text_only_baselines"][name] = {"P@1": float((ranks == 1).mean()), "P@1_ci95_test_cluster": ci(ranks == 1, [True] * len(events)), "R@5": float((ranks <= 5).mean()), "MRR": float((1 / ranks).mean()),
        "P@1_on_sigma_covered_events": float((ranks[[e["sigma_covers_truth"] for e in events]] == 1).mean()), "n_events": len(events)}
# ---- coverage table (tactic level, from ATT&CK corpus)
def tac(techs): return collections.Counter(tactic_of.get(t, "?") for t in techs)
lab = sorted(targets()); R["coverage"] = {"lab_8_techniques": {"techniques": len(lab), "tactics": len(tac(lab))},
    "sigma_tagged_techniques_in_corpus": {"techniques": len([t for t in covered if t in cid]), "tactics": len(tac([t for t in covered if t in cid])), "by_tactic": dict(tac([t for t in covered if t in cid]))},
    "atomic_windows_techniques": {"techniques": len({e['technique'] for e in events}), "tactics": len(tac({e['technique'] for e in events})), "by_tactic": dict(tac({e['technique'] for e in events}))},
    "executable_detector_knowledge_AND_independent_test_events": {"techniques": len({e['technique'] for e in events if e['sigma_covers_truth']}), "tactics": len(tac({e['technique'] for e in events if e['sigma_covers_truth']}))}}
dump = [{"event_id": e["event_id"], "test_guid": e["test_guid"], "technique": e["technique"], "fired": e["fired"], "pred": e["pred"], "covers": e["sigma_covers_truth"],
         "rank_tfidf": int((ix.tf.scores(e["CommandLine"]) > ix.tf.scores(e["CommandLine"])[ids.index(e["technique"])]).sum()) + 1} for e in events]
(OUT3 / "m4_external_events.json").write_text(json.dumps(dump))
(OUT3 / "m4_external_eval.json").write_text(json.dumps(R, indent=1, default=str)); print(json.dumps({k: R[k] for k in ("sigma_rules", "atomic", "detector_aware_sigma", "text_only_baselines", "coverage")}, indent=0, default=str)[:3500])
