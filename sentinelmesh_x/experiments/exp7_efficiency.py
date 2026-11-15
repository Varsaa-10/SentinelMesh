"""Computational efficiency (item 12): CPU only. Synthetic scale-up replicates records with suffixed ids (documented as synthetic)."""
import os, platform, time, tracemalloc, resource
from bench import *
S = alert_sets(); cfg = tuned_cfg(); rows = S["test"]
dks = detectors(); res = {"cpu": platform.processor() or platform.machine(), "cores": os.cpu_count(), "python": platform.python_version(), "gpu": "none used", "kb": [], "volume": []}
def build(corpus, scale=1):
    raw = build_raw_condition(corpus, "auto"); out = list(raw)
    for k in range(1, scale):
        for r in raw:
            r2 = dict(r); r2["id"] = f"{r['id']}#{k}"; r2["description"] = r["description"] + f" variant{k}"; out.append(r2)
    return out
def pct(x, p): return float(np.percentile(x, p))
for corpus, scale in [("corpus_36", 1), ("corpus_200", 1), ("corpus_full", 1), ("corpus_full", 3), ("corpus_full", 7)]:
    raw = build(corpus, scale); tracemalloc.start()
    recs = make_records(raw, use_mitre_sigs=True); ix = KBIndex(recs, dks)
    cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    for name, fn in [("tfidf", lambda r: rank_tfidf(ix, r["queries"]["raw"])), ("bm25", lambda r: rank_bm25(ix, r["queries"]["raw"])),
                     ("dahr", lambda r: rank_dahr(ix, r["queries"]["raw"], r["alert"], cfg))]:
        lat = []
        for r in rows:
            t = time.perf_counter(); fn(r); lat.append((time.perf_counter() - t) * 1000)
        res["kb"].append({"records": len(recs), "method": name, "build_ms": ix.build_ms, "peak_index_MB": peak / 1e6, "p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "mean_ms": float(np.mean(lat))})
    print(len(recs), flush=True)
ix = make_index("corpus_full", "auto")
for vol in (100, 1000, 5000):
    rs = (rows * (vol // len(rows) + 1))[:vol]; t = time.perf_counter()
    for r in rs: rank_dahr(ix, r["queries"]["raw"], r["alert"], cfg)
    el = time.perf_counter() - t; res["volume"].append({"alerts": vol, "seconds": el, "alerts_per_s": vol / el})
res["max_rss_MB"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
save("efficiency.json", res); print(res["volume"], [ (k['records'],k['method'],round(k['mean_ms'],2)) for k in res['kb']])
