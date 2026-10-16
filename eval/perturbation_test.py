"""
eval/perturbation_test.py -- does tactic-first accuracy on raw alerts depend on incidental field values?

Reference run 20261012T140201Z, the 14 selected alerts, lab-written corpus. In each of 300 trials
every IPv4 address is replaced with a random private address, and failure counts, response times,
durations, sizes, log timestamps and HTTP ports are redrawn. Words, field names and titles are kept.
Trial t uses random.Random(1000 + t), so the run is deterministic.
Usage: python3 eval/perturbation_test.py
"""
from __future__ import annotations

import json
import os
import random
import re
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(os.environ.get("SENTINELMESH_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup  # noqa: E402
from embeddings import EMBEDDERS  # noqa: E402
from rag_engine import TwoLayerRAG  # noqa: E402
from flat_rag import FlatRAG  # noqa: E402
from alert_normalizer import normalize_alert_text  # noqa: E402
from eval.alert_query import build_query, load_alerts, select_alerts  # noqa: E402

N = 300
REF = "20261012T140201Z"
IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def rand_ip(r):
    k = r.random()
    if k < .33:
        return f"10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    if k < .66:
        return f"172.{r.randint(16, 31)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    return f"192.168.{r.randint(0, 255)}.{r.randint(1, 254)}"


def perturb(t, r):
    t = IP.sub(lambda m: rand_ip(r), t)
    t = re.sub(r"failure_count=\d+", lambda m: f"failure_count={r.randint(5, 25)}", t)
    t = re.sub(r"time_ms=\d+", lambda m: f"time_ms={r.randint(3, 400)}", t)
    t = re.sub(r"duration=[\d.]+ms", lambda m: f"duration={r.uniform(3, 400):.6f}ms", t)
    t = re.sub(r"size=\d+", lambda m: f"size={r.randint(10, 5000)}", t)
    t = re.sub(r"t=\S+Z", lambda m: f"t=2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}T{r.randint(0, 23):02d}:"
               f"{r.randint(0, 59):02d}:{r.randint(0, 59):02d}.{r.randint(0, 999999999):09d}Z", t)
    t = re.sub(r":80 ", lambda m: f":{r.choice([80, 443, 8080])} ", t)
    return t


def main():
    gt = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    sel, _ = select_alerts(load_alerts(REPO_ROOT / "eval" / "runs" / REF / "alerts.jsonl"), gt)
    records, cves = load_kb_dir(str(REPO_ROOT / "kb_master" / "techniques"), str(REPO_ROOT / "kb_master" / "cves"))
    cm = build_cve_lookup(cves)
    res = {}
    for emb in ("tfidf-word", "tfidf-char"):
        engs = {"tactic_first": TwoLayerRAG(records, EMBEDDERS[emb](), cve_lookup=cm),
                "flat": FlatRAG(records, EMBEDDERS[emb](), cve_lookup=cm)}
        for form in ("raw", "title_raw", "rewrite"):
            accs = {k: [] for k in engs}
            diffs = []
            observed = {}
            for trial in range(-1, N):
                r = random.Random(1000 + trial)
                row = {}
                for en, e in engs.items():
                    c = 0
                    for it in sel:
                        a = it["alert"]
                        raw = build_query(a, "raw")
                        p = raw if trial < 0 else perturb(raw, r)
                        if form == "raw":
                            q = p
                        elif form == "title_raw":
                            q = f"{a.get('title', '').strip()}. {p}"
                        else:
                            q = normalize_alert_text({**a, "output": p})
                        pred = e.query(alert_output_text=q, container_id=a.get("service", ""), falco_rule=a.get("title", ""),
                                       alert_source=(a.get("source") or "").replace("-", "_")).predicted_technique
                        c += pred == it["ground_truth_technique"]
                    row[en] = c
                if trial < 0:
                    observed = row
                    continue
                for en in engs:
                    accs[en].append(row[en])
                diffs.append(row["flat"] - row["tactic_first"])
            key = f"{emb}__{form}"
            res[key] = {en: {"observed": observed[en], "mean": statistics.mean(v), "min": min(v), "max": max(v),
                             "all14_share": sum(x == len(sel) for x in v) / N} for en, v in accs.items()}
            res[key]["flat_ahead_share"] = sum(x > 0 for x in diffs) / N
            res[key]["tactic_first_ahead_share"] = sum(x < 0 for x in diffs) / N
            print(key, json.dumps(res[key]), flush=True)
    out = REPO_ROOT / "eval" / "perturbation_results.json"
    out.write_text(json.dumps({"run": REF, "alerts": len(sel), "trials": N, "results": res}, indent=2), encoding="utf-8")
    print("written", out)


if __name__ == "__main__":
    main()
