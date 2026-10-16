"""eval/score_fresh_heldout.py -- per-alert retrieval on the ten test captures and the held-out capture.

For every knowledge base (lab-written; MITRE corpora with and without lab text), both retrievers and
three query forms, records each alert's predicted technique, tactic, tactic-layer similarity and confidence.
Usage: SENTINELMESH_ROOT=$PWD python3 eval/score_fresh_heldout.py OUT.json EMBEDDER
  EMBEDDER: tfidf-word (default), tfidf-char, dense-minilm-onnx, dense-minilm-onnx-chunked, hybrid-tfidf-dense"""
import json, os, sys
from pathlib import Path
ROOT = Path(os.environ["SENTINELMESH_ROOT"])
sys.path.insert(0, str(ROOT / "rag_engine" / "src")); sys.path.insert(0, str(ROOT))
from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import EMBEDDERS
from rag_engine import TwoLayerRAG
from flat_rag import FlatRAG
from eval.alert_query import QUERY_FORMS, build_query, load_alerts, select_alerts
from eval.kb_curation_ablation import CORPORA, VARIANTS, build_variant, lab_parts

FRESH = ["20261014T104641Z", "20261014T111618Z", "20261014T113310Z", "20261014T122816Z", "20261014T130955Z",
         "20261014T132438Z", "20261014T134019Z", "20261014T135319Z", "20261014T140601Z", "20261014T141640Z"]
HELD = "20261015T051907Z"
emb_name = sys.argv[2] if len(sys.argv) > 2 else "tfidf-word"

gt = json.loads((ROOT / "eval/ground_truth.json").read_text())["scenarios"]
targets = {v["technique_id"] for v in gt.values()}
rows, missing = [], {}
for run, d, setname in [(r, "runs", "fresh") for r in FRESH] + [(HELD, "runs_heldout", "heldout")]:
    sel, miss = select_alerts(load_alerts(ROOT / "eval" / d / run / "alerts.jsonl"), gt)
    missing[run] = miss
    for it in sel:
        rows.append({"set": setname, "run": run, "slot": it["slot"], "truth": it["ground_truth_technique"],
                     "alert": it["alert"], "q": {f: build_query(it["alert"], f) for f in QUERY_FORMS}})
print({s: sum(r["set"] == s for r in rows) for s in ("fresh", "heldout")}, missing[HELD])

techs, cves = load_kb_dir(str(ROOT / "kb_master/techniques"), str(ROOT / "kb_master/cves"))
cve_map = build_cve_lookup(cves)
lab = lab_parts(ROOT / "kb_master/techniques")
kbs = {("lab", 36, "lab"): techs}
for corpus in CORPORA:
    base = [json.loads(p.read_text()) for p in sorted((ROOT / "rag_engine/kb/corpora" / corpus).glob("*.json"))]
    for v, a in VARIANTS.items():
        kbs[(corpus, len(base), v)] = build_variant(base, lab, targets, **a)

out = {"embedder": emb_name, "missing": missing, "alerts": [{k: r[k] for k in ("set", "run", "slot", "truth")} for r in rows], "results": []}
for (corpus, n, v), recs in kbs.items():
    shared = EMBEDDERS[emb_name]() if emb_name.startswith("dense") else None
    tl = TwoLayerRAG(recs, shared or EMBEDDERS[emb_name](), cve_lookup=cve_map)
    fl = FlatRAG(recs, shared or EMBEDDERS[emb_name](), cve_lookup=cve_map)
    for form in QUERY_FORMS:
        preds = []
        for r in rows:
            kw = dict(container_id=r["alert"].get("service", ""), falco_rule=r["alert"].get("title", ""),
                      alert_source=(r["alert"].get("source") or "").replace("-", "_"))
            a = tl.query(alert_output_text=r["q"][form], **kw)
            b = fl.query(alert_output_text=r["q"][form], **kw)
            preds.append({"tl": a.predicted_technique, "tl_tactic": a.predicted_tactic,
                          "sim": a.evidence.get("layer1_similarity"), "fl": b.predicted_technique,
                          "fl_conf": round(float(b.confidence.score), 4), "tl_conf": round(float(a.confidence.score), 4)})
        out["results"].append({"corpus": corpus, "records": n, "variant": v, "form": form, "preds": preds})
    print(corpus, v, "done", flush=True)
Path(sys.argv[1]).write_text(json.dumps(out))
