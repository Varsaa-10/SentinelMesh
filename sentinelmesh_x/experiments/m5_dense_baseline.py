"""M5: pretrained dense / hybrid baselines. IMPLEMENTED BUT NOT RUN HERE: the all-MiniLM-L6-v2 ONNX export is not available offline and huggingface.co is unreachable.
Run on a machine with the model:  SENTINELMESH_MINILM_ONNX=/path/to/model python3 sentinelmesh_x/experiments/m5_dense_baseline.py
Uses the repo's existing ONNX embedder; Track B queries (event fields only) so the comparison is leak-free; same splits as M1."""
import os, json, sys
from m1_common import *
OUT3 = ROOT / "results_x_v3"
md = os.environ.get("SENTINELMESH_MINILM_ONNX", "models/all-MiniLM-L6-v2")
if not os.path.exists(os.path.join(md, "onnx", "model.onnx")):
    (OUT3 / "m5_dense_baseline.json").write_text(json.dumps({"status": "BLOCKED", "reason": f"no ONNX model at '{md}'; huggingface.co unreachable from the build environment (HTTP 000)", "what_to_do": "set SENTINELMESH_MINILM_ONNX and rerun", "simulated_results": None}, indent=1)); print("blocked"); sys.exit(0)
from embeddings import EMBEDDERS
S = alert_sets(); [attach_trackb(S[k]) for k in S]; test = S["test"]; raw = build_raw_condition("corpus_full", "mitre"); recs = make_records(raw); ids = [r.id for r in recs]
emb = EMBEDDERS["dense-minilm-onnx"](); D = emb.embed([r.text for r in recs]); ix = make_index_B("corpus_full"); res = {}
def rrf(rankings, k=60):
    s = np.zeros(len(ids))
    for sc in rankings: o = np.argsort(-sc); r = np.empty(len(sc)); r[o] = np.arange(1, len(sc) + 1); s += 1 / (k + r)
    return s
rows = {"dense": [], "hybrid_bm25_dense": []}
for r in test:
    q = r["qB"]; sc = (emb.embed([q]) @ D.T).ravel(); bm = ix.bm.scores(q)
    for name, s in (("dense", sc), ("hybrid_bm25_dense", rrf([bm, sc]))): rows[name].append(rank_of_truth([ids[i] for i in np.argsort(-s)], r["truth"], "corpus_full"))
res = {n: metrics_from_ranks(v, ["?"] * len(v), [r["truth"] for r in test]) for n, v in rows.items()}; (OUT3 / "m5_dense_baseline.json").write_text(json.dumps(res, indent=1)); print(res)
