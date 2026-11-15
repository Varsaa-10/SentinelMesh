"""M8: cost of the dense baselines at 706 records (CPU, one process, empty embedding cache).
Query latency over 300 distinct Atomic command lines; index build = embedding all 706 records."""
import os, time, resource, json
from m1_common import *
from embeddings import EMBEDDERS, _ONNX_CACHE
OUT4 = ROOT / "results_x_v4"
recs = make_records([clean_record(r) for r in load_corpus("corpus_full")]); ix = KBIndex(recs)
ev = json.loads(Path("/tmp/ext/cmds.json").read_text())
rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
out = {"hardware": "same container as this run; 1 process; CPU only", "n_queries": len(ev), "methods": {}}
for name in ("dense-minilm-onnx", "dense-minilm-onnx-chunked"):
    _ONNX_CACHE.clear(); e = EMBEDDERS[name]()
    t = time.perf_counter(); D = e.embed([r.text for r in recs]); build = time.perf_counter() - t
    lat = []
    for q in ev:
        t = time.perf_counter(); s = D @ e.embed([q])[0]; np.argsort(-s); lat.append(1000 * (time.perf_counter() - t))
    out["methods"][name] = {"index_build_s": build, "p50_ms": float(np.median(lat)), "p95_ms": float(np.percentile(lat, 95)), "throughput_qps": 1000 / float(np.mean(lat))}
for name, fn in (("bm25", lambda q: ix.bm.scores(q)), ("tfidf", lambda q: ix.tf.scores(q))):
    lat = []
    for q in ev:
        t = time.perf_counter(); s = fn(q); np.argsort(-s); lat.append(1000 * (time.perf_counter() - t))
    out["methods"][name] = {"p50_ms": float(np.median(lat)), "p95_ms": float(np.percentile(lat, 95)), "throughput_qps": 1000 / float(np.mean(lat))}
out["max_rss_MB"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024; out["rss_before_model_MB"] = rss0
out["model_file_MB"] = os.path.getsize(os.path.join(os.environ["SENTINELMESH_MINILM_ONNX"], "onnx", "model.onnx")) / 1e6
(OUT4 / "m8_dense_cost.json").write_text(json.dumps(out, indent=1)); print(json.dumps(out, indent=1))
