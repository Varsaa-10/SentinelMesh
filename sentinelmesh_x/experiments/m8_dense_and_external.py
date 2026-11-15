"""M8: pretrained dense baselines (all-MiniLM-L6-v2, ONNX) on Track A, Track B and the deduplicated
Sigma x Atomic events, together with the lexical baselines recomputed on the same deduplicated events.

Model files: SENTINELMESH_MINILM_ONNX folder with tokenizer.json and onnx/model.onnx; the script checks the
sha256 values recorded in REPRODUCE.md and the 0.755 functional check before running.
Methods: dense (cut at 256 word pieces), dense_windowed (overlapping 256-piece windows, stride 32, averaged),
hybrid = reciprocal rank fusion (k=60) of BM25 and dense_windowed.
Outputs (results_x_v4/): m8_dense_lab.json, m8_external_dedup.json, m8_external_events_dedup.json
"""
import hashlib, os, time, collections
from m1_common import *
from stats import cluster_bootstrap, paired_report
from sentinelmesh_x.external import load_atomic_events
from sentinelmesh_x import calib_eval
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sentinelmesh_x.retrieval import tokenize
from embeddings import EMBEDDERS

OUT4 = ROOT / "results_x_v4"; OUT4.mkdir(exist_ok=True); t0 = time.time()
md = os.environ["SENTINELMESH_MINILM_ONNX"]
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
CHK = {"model.onnx": ("onnx/model.onnx", "759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e"),
       "tokenizer.json": ("tokenizer.json", "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0")}
for k, (rel, h) in CHK.items():
    assert sha(os.path.join(md, rel)) == h, f"{k} checksum mismatch"
E = {"dense": EMBEDDERS["dense-minilm-onnx"](), "dense_windowed": EMBEDDERS["dense-minilm-onnx-chunked"]()}
v = E["dense"].embed(["A man is eating food.", "A man is eating a piece of bread."]); fc = float(v[0] @ v[1])
assert abs(fc - 0.755) < 0.001, fc
model_info = {"model": "sentence-transformers/all-MiniLM-L6-v2, ONNX export (Xenova)", "model_onnx_sha256": CHK["model.onnx"][1],
              "tokenizer_sha256": CHK["tokenizer.json"][1], "functional_check_cosine": round(fc, 4)}


def rrf(*scores, k=60):
    s = np.zeros(len(scores[0]))
    for sc in scores:
        o = np.argsort(-sc); r = np.empty(len(sc)); r[o] = np.arange(1, len(sc) + 1); s += 1 / (k + r)
    return s


def dense_scores(name, D, q):
    return D[name] @ E[name].embed([q])[0]


# ------------------------------------------------------------------ lab: Track A (raw, auto KB) and Track B
S = alert_sets(); [attach_trackb(S[k]) for k in S]; test = S["test"]; runs = sorted({r["run"] for r in test})
lab = {"model": model_info, "n_test_alerts": len(test), "n_captures": len(runs), "rows": [], "paired_vs_bm25": []}
settings = [("A", "raw", "auto"), ("A", "title_raw", "auto"), ("A", "rewrite", "auto"), ("B", "indep", "mitre")]
for track, form, cond in settings:
    recs = make_records(build_raw_condition("corpus_full", cond), use_mitre_sigs=True); ids = [r.id for r in recs]
    if track == "B":
        ix = make_index_B("corpus_full"); qs = [r["qB"] for r in test]
    else:
        ix = make_index("corpus_full", cond); qs = [r["queries"][form] for r in test]
    D = {n: E[n].embed([r.text for r in recs]) for n in E}
    meth = {"bm25": lambda q: ix.bm.scores(q), "tfidf": lambda q: ix.tf.scores(q),
            "dense": lambda q: dense_scores("dense", D, q), "dense_windowed": lambda q: dense_scores("dense_windowed", D, q)}
    meth["hybrid_bm25_dense"] = lambda q: rrf(ix.bm.scores(q), dense_scores("dense_windowed", D, q))
    ranks = {}
    for m, fn in meth.items():
        lat, rk, pr = [], [], []
        for q, r in zip(qs, test):
            t = time.perf_counter(); s = fn(q); order = [ids[i] for i in np.argsort(-s)]; lat.append(time.perf_counter() - t)
            rk.append(rank_of_truth(order, r["truth"], "corpus_full")); pr.append(order[0])
        x = np.array([k == 1 for k in rk], float); lo, hi = cluster_bootstrap(x, test, b=1000)
        ranks[m] = np.array(rk)
        lab["rows"].append({"track": track, "form": form, "kb": cond, "method": m, **metrics_from_ranks(rk, pr, [r["truth"] for r in test]),
                            "P@1_ci95_cluster": [lo, hi], "median_query_ms": 1000 * float(np.median(lat))})
    for m in ("tfidf", "dense", "dense_windowed", "hybrid_bm25_dense"):
        a = (ranks[m] == 1).astype(int); b = (ranks["bm25"] == 1).astype(int)
        lab["paired_vs_bm25"].append({"track": track, "form": form, "A": m, "B": "bm25", **paired_report(a, b, test)})
    print(track, form, {r["method"]: round(r["P@1"], 3) for r in lab["rows"] if r["track"] == track and r["form"] == form}, round(time.time() - t0), "s", flush=True)
(OUT4 / "m8_dense_lab.json").write_text(json.dumps(lab, indent=1, default=str))

# ------------------------------------------------------------------ independent: deduplicated Sigma x Atomic events
saved = json.loads((ROOT / "results_x_v3/m4_external_events.json").read_text())
events, astats = load_atomic_events(Path("/tmp/ext/atomic_index.yaml"))
corpus = [clean_record(r) for r in load_corpus("corpus_full")]; cid = {r["id"] for r in corpus}
events = [e for e in events if e["technique"] in cid]
assert [e["event_id"] for e in events] == [s["event_id"] for s in saved], "event order differs from the evaluated set"
for e, s in zip(events, saved):
    e.update({"fired": s["fired"], "pred": s["pred"], "covers": s["covers"]})
seen, dd = set(), []
for e in events:
    k = (e["event_id"], e["technique"])
    if k not in seen:
        seen.add(k); dd.append(e)
recs = make_records(corpus); ix = KBIndex(recs); ids = ix.ids
svd_vec = TfidfVectorizer(tokenizer=lambda s: tokenize(s, True), lowercase=False, token_pattern=None, sublinear_tf=True); X = svd_vec.fit_transform([r.text for r in recs])
svd = TruncatedSVD(200, random_state=0).fit(X); DL = svd.transform(X); DL /= (np.linalg.norm(DL, axis=1, keepdims=True) + 1e-9)
def lsa(q): v = svd.transform(svd_vec.transform([q])); v /= (np.linalg.norm(v) + 1e-9); return DL @ v.ravel()
D = {n: E[n].embed([r.text for r in recs]) for n in E}
base = {"tfidf": lambda q: ix.tf.scores(q), "bm25": lambda q: ix.bm.scores(q), "lsa": lsa,
        "dense": lambda q: dense_scores("dense", D, q), "dense_windowed": lambda q: dense_scores("dense_windowed", D, q),
        "hybrid_bm25_dense": lambda q: rrf(ix.bm.scores(q), dense_scores("dense_windowed", D, q))}
def rk(scores, truth): return int((scores > scores[ids.index(truth)]).sum()) + 1
cl = [e["test_guid"] for e in dd]; idx = calib_eval.clusters_index(cl)
def ci(vals, mask, b=1000, seed=1):
    vals = np.asarray(vals, float); mask = np.asarray(mask, bool); rng = np.random.default_rng(seed); out = []
    for _ in range(b):
        s = calib_eval.draw_cluster_sample(idx, rng); s = s[mask[s]]
        if len(s): out.append(vals[s].mean())
    return [float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))]
ext = {"model": model_info, "events_before_dedup": len(events), "events_after_dedup": len(dd),
       "dedup_rule": "keep one copy of events with the same event_id and technique; Atomic's index.yaml lists each test once under every tactic of its technique",
       "atomic_index_sha256": sha("/tmp/ext/atomic_index.yaml"), "atomic_tests": len(set(cl)), "techniques": len({e["technique"] for e in dd}), "text_only": {}}
ok1 = [e["pred"] == e["technique"] for e in dd]; fired = [e["fired"] for e in dd]; cov = [e["covers"] for e in dd]
ext["sigma"] = {"fire_rate": float(np.mean(fired)), "precision_given_fired": float(np.mean([o for o, f in zip(ok1, fired) if f])),
                "precision_given_fired_ci95_test_cluster": ci(ok1, fired),
                "precision_parent_given_fired": float(np.mean([e["pred"].split(".")[0] == e["technique"].split(".")[0] for e in dd if e["fired"]])),
                "events_uncovered": int(sum(not c for c in cov)), "abstain_on_uncovered": float(np.mean([not f for f, c in zip(fired, cov) if not c])),
                "top1_all_events": float(np.mean(ok1))}
dump = [{k: e[k] for k in ("event_id", "test_guid", "technique", "fired", "pred", "covers")} for e in dd]
for name, fn in base.items():
    lat, rr = [], []
    for e in dd:
        t = time.perf_counter(); rr.append(rk(fn(e["CommandLine"]), e["technique"])); lat.append(time.perf_counter() - t)
    rr = np.array(rr)
    for e, k in zip(dump, rr): e[f"rank_{name}"] = int(k)
    ext["text_only"][name] = {"P@1": float((rr == 1).mean()), "P@1_ci95_test_cluster": ci(rr == 1, [True] * len(dd)), "R@5": float((rr <= 5).mean()),
                              "MRR": float((1 / rr).mean()), "nDCG@5": float(np.where(rr <= 5, 1 / np.log2(rr + 1), 0).mean()),
                              "P@1_on_fired": float((rr[np.array(fired)] == 1).mean()), "median_query_ms": 1000 * float(np.median(lat))}
    print("ext", name, round(ext["text_only"][name]["P@1"], 3), round(time.time() - t0), "s", flush=True)
(OUT4 / "m8_external_events_dedup.json").write_text(json.dumps(dump))
(OUT4 / "m8_external_dedup.json").write_text(json.dumps(ext, indent=1))
print(json.dumps(ext["sigma"], indent=0)); print("done", round(time.time() - t0), "s")
