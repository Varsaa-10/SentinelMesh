"""M6: reproducible efficiency benchmark. CPU only. KB sizes above 706 are SYNTHETIC replicas (suffixed ids, perturbed text). Historical results_x/efficiency.json untouched."""
import os, platform, subprocess, sys, time, tracemalloc, resource, tempfile
from m1_common import *
from sentinelmesh_x.pipeline import SafePipeline
from sentinelmesh_x.safety import PolicyEngine, PolicyConfig, SafeExecutor
from sentinelmesh_x.audit import AuditLog
from sentinelmesh_x.calibration import Calibrator
OUT3 = ROOT / "results_x_v3"; S = alert_sets(); cfg = tuned_cfg(); rows = S["test"]; dks = detectors()
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
hw = {"cpu_model": sh("lscpu | grep 'Model name' | head -1 | cut -d: -f2").strip(), "logical_cores": os.cpu_count(), "mem_total_MB": int(sh("grep MemTotal /proc/meminfo | awk '{print $2}'")) // 1024,
      "os": platform.platform(), "python": platform.python_version(), "gpu": "none present / none used", "load_avg_at_start": os.getloadavg()}
# cold start: fresh interpreter, import + build 706-record index + first query
code = "import time,sys;t=time.perf_counter();sys.path.insert(0,'sentinelmesh_x/experiments');from m1_common import *;ix=make_index('corpus_full','auto');r=alert_sets()['test'][0];rank_dahr(ix,r['queries']['raw'],r['alert']);print(time.perf_counter()-t)"
cold = [float(sh(f"cd {ROOT} && python3 -c \"{code}\"").split()[-1]) for _ in range(3)]
def build(scale):
    raw = build_raw_condition("corpus_full", "auto"); out = list(raw)
    for k in range(1, scale):
        for r in raw: r2 = dict(r); r2["id"] = f"{r['id']}#{k}"; r2["description"] = r["description"] + f" variant{k}"; out.append(r2)
    return out
res = {"hardware": hw, "cold_start_s_fresh_process_706_records": cold, "kb": []}
for scale in (1, 2, 7, 14, 35):
    raw = build(scale); tracemalloc.start(); t = time.perf_counter(); recs = make_records(raw, use_mitre_sigs=True); ix = KBIndex(recs, dks); build_s = time.perf_counter() - t
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop(); n = len(recs); sub = rows if n <= 5000 else rows[:60]; reps = 5 if n <= 5000 else 3
    for name, fn in (("tfidf", lambda r: rank_tfidf(ix, r["queries"]["raw"])), ("bm25", lambda r: rank_bm25(ix, r["queries"]["raw"])), ("dahr", lambda r: rank_dahr(ix, r["queries"]["raw"], r["alert"], cfg))):
        for r in sub[:5]: fn(r)                                          # warm-up
        runs = []
        for _ in range(reps):
            lat = []; c0 = time.process_time(); w0 = time.perf_counter()
            for r in sub: t = time.perf_counter(); fn(r); lat.append((time.perf_counter() - t) * 1000)
            wall = time.perf_counter() - w0; runs.append({"p50": np.percentile(lat, 50), "p95": np.percentile(lat, 95), "p99": np.percentile(lat, 99), "throughput": len(sub) / wall, "cpu_util": (time.process_time() - c0) / wall})
        res["kb"].append({"records": n, "method": name, "index_build_s": build_s, "peak_index_MB_tracemalloc": peak / 1e6, "alerts_per_run": len(sub), "repetitions": reps,
                          **{k: {"mean": float(np.mean([x[k] for x in runs])), "std": float(np.std([x[k] for x in runs]))} for k in ("p50", "p95", "p99", "throughput", "cpu_util")}})
    print(n, "done", flush=True)
# full safe pipeline (retrieval x2 views + calibration + policy + audit write) at 706 records
ix = make_index("corpus_full", "auto"); cal = Calibrator().fit([[0.5] * 9, [0.9] * 9, [0.2] * 9, [0.8] * 9], [1, 1, 0, 1]); import random
gt = ground_truth(); SEV = {v["technique_id"]: v["severity"] for k, v in gt.items() if k != "S10"}
pl = SafePipeline(ix, cfg, cal, PolicyEngine(PolicyConfig(0.5)), AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl"), "kb", True, sorted(targets()), SEV, {"webapp": 3}, lambda a: build_query(a, "raw"))
for r in rows[:5]: pl.process(r["alert"], "w")
lat = []; t0 = time.perf_counter()
for i, r in enumerate(rows): t = time.perf_counter(); pl.process(r["alert"], f"e{i}"); lat.append((time.perf_counter() - t) * 1000)
res["safe_pipeline_706"] = {"p50_ms": float(np.percentile(lat, 50)), "p95_ms": float(np.percentile(lat, 95)), "p99_ms": float(np.percentile(lat, 99)), "alerts_per_s_single_thread": len(rows) / (time.perf_counter() - t0),
                            "note": "includes two retrievals, calibration, policy, simulated execution and a hash-chained audit append per alert; single process, no concurrency, no network ingestion"}
res["peak_rss_MB_process"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
res["integrity_verification_s"] = "see results_x_v3/m3_integrity_eval.json latency"
(OUT3 / "m6_efficiency.json").write_text(json.dumps(res, indent=1, default=str)); print({k: (round(v["p50"]["mean"], 2), round(v["p99"]["mean"], 2)) for k, v in [((x["records"], x["method"]), x) for x in res["kb"]]}); print(res["safe_pipeline_706"])
