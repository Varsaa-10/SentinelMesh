"""
eval/held_out_variants.py — SentinelMesh Module W4: Evaluation on Held-Out Attack Variants.

Evaluates retrieval generalization when faced with attack variants that nobody hand-tuned
rules or titles for:
- S1 (SQLi): Time-based blind sleep payloads & stacked query injection
- S2 (Brute Force): Slow distributed password guessing across accounts
- S3 (Valid Accounts): Non-standard default maintenance accounts
- S4 (JWT): HS384 / key confusion bypass
- S5 (Remote Services): Direct psql socket connection from new subnet
- S6 (Indicator Removal): In-place log shredding / truncation
- S7 (Default Auth): Anonymous snapshot and telemetry API scraping
- S8 (Exfiltration): Python script / wget egress exfiltration
- S9 (Credential Dumping): SSH private key theft (/root/.ssh/id_rsa)

Outputs seen vs. held-out comparison across raw, title+raw, and rewrite representations.
"""

from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
sys.path.insert(0, str(REPO_ROOT))

from kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
from embeddings import EMBEDDERS
from rag_engine import TwoLayerRAG
from flat_rag import FlatRAG
from alert_normalizer import normalize_alert_text
from eval.stats_utils import wilson_score_interval, exact_mcnemar_test


HELD_OUT_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "ho_s1_blind",
        "scenario_id": "S1",
        "variant_desc": "Blind time-delay SQL injection payload",
        "title": "Application Log Suspicious Query",
        "rule": "N/A (log-tail detector)",
        "container_id": "sentinelmesh-webapp",
        "severity": 5,
        "source": "log_tail",
        "output": "login_attempt event_type, result=success, identifier=\"admin' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -\", client_ip=10.20.0.5, details.latency_ms=5012",
        "ground_truth_technique": "T1190",
        "ground_truth_tactic": "Initial Access",
    },
    {
        "alert_id": "ho_s2_slow_spray",
        "scenario_id": "S2",
        "variant_desc": "Low-and-slow distributed password spray",
        "title": "Failed Authentication Warning",
        "rule": "N/A (log-tail detector)",
        "container_id": "sentinelmesh-webapp",
        "severity": 3,
        "source": "log_tail",
        "output": "login_attempt event_type, result=failure, identifier=svc_backup, client_ip=192.168.50.14, failure_count=3, window_seconds=600",
        "ground_truth_technique": "T1110",
        "ground_truth_tactic": "Credential Access",
    },
    {
        "alert_id": "ho_s3_maintenance_acct",
        "scenario_id": "S3",
        "variant_desc": "Default database maintenance service account login",
        "title": "Service Account Access",
        "rule": "N/A (log-tail detector)",
        "container_id": "sentinelmesh-authservice",
        "severity": 4,
        "source": "log_tail",
        "output": "login_attempt event_type, result=success, identifier=postgres_backup, client_ip=10.20.0.2, details.user_id=99, details.role=db_admin, preseeded=true",
        "ground_truth_technique": "T1078",
        "ground_truth_tactic": "Initial Access",
    },
    {
        "alert_id": "ho_s4_hs384_confusion",
        "scenario_id": "S4",
        "variant_desc": "JWT algorithm confusion via HS384 / RSA public key",
        "title": "Token Verification Anomaly",
        "rule": "N/A (log-tail detector)",
        "container_id": "sentinelmesh-authservice",
        "severity": 5,
        "source": "log_tail",
        "output": "jwt_verification event_type, result=valid, identifier=admin, client_ip=10.20.0.8, details.header.alg=HS384, details.hmac_public_key_mismatch=true",
        "ground_truth_technique": "T1212",
        "ground_truth_tactic": "Credential Access",
    },
    {
        "alert_id": "ho_s5_direct_psql",
        "scenario_id": "S5",
        "variant_desc": "Direct libpq / psql socket connection",
        "title": "Falco Alert: Unauthorized Inbound TCP",
        "rule": "Disallowed Inbound TCP Connection",
        "container_id": "sentinelmesh-database",
        "severity": 4,
        "source": "falco",
        "output": "Notice Inbound connection to database service: proc=postgres, sport=49152, dport=5432, sip=192.168.50.88, client_driver=psql_libpq",
        "ground_truth_technique": "T1021",
        "ground_truth_tactic": "Lateral Movement",
    },
    {
        "alert_id": "ho_s6_shred_tamper",
        "scenario_id": "S6",
        "variant_desc": "Audit log shredding via shred utility",
        "title": "Falco Alert: Log Destruction",
        "rule": "Log Directory File Tampering",
        "container_id": "sentinelmesh-logcollector",
        "severity": 4,
        "source": "falco",
        "output": "Warning File modification in log dir: proc=shred, fd.name=/var/log/sentinelmesh/audit.log, flags=O_WRONLY|O_TRUNC",
        "ground_truth_technique": "T1070",
        "ground_truth_tactic": "Defense Evasion",
    },
    {
        "alert_id": "ho_s7_anon_snapshot",
        "scenario_id": "S7",
        "variant_desc": "Grafana anonymous snapshot export endpoint scrape",
        "title": "Dashboard Anonymous Access",
        "rule": "N/A (log-tail detector)",
        "container_id": "sentinelmesh-dashboard",
        "severity": 3,
        "source": "log_tail",
        "output": "HTTP GET /api/snapshots/internal_metrics returned status 200, user=anonymous, org_role=Viewer, anonymous_enabled=true",
        "ground_truth_technique": "T1078",
        "ground_truth_tactic": "Initial Access",
    },
    {
        "alert_id": "ho_s8_python_egress",
        "scenario_id": "S8",
        "variant_desc": "Exfiltration via Python urllib script",
        "title": "Falco Alert: Unexpected Egress",
        "rule": "Unexpected Outbound Network Connection",
        "container_id": "sentinelmesh-database",
        "severity": 5,
        "source": "falco",
        "output": "Critical Outbound network connection to unauthorized IP: proc=python3, cmd=python3 -c import urllib.request; urllib.request.urlopen, dip=198.51.100.22, dport=443",
        "ground_truth_technique": "T1041",
        "ground_truth_tactic": "Exfiltration",
    },
    {
        "alert_id": "ho_s9_ssh_key_theft",
        "scenario_id": "S9",
        "variant_desc": "SSH private key file read from host",
        "title": "Falco Alert: Credential Theft",
        "rule": "Sensitive Credential File Read",
        "container_id": "sentinelmesh-webapp",
        "severity": 5,
        "source": "falco",
        "output": "Critical Read of sensitive credential store: proc=tar, fd.name=/root/.ssh/id_rsa, container_id=sentinelmesh-webapp",
        "ground_truth_technique": "T1003.008",
        "ground_truth_tactic": "Credential Access",
    },
]


def evaluate_dataset(engine, alerts: List[Dict[str, Any]], query_form: str) -> Dict[str, Any]:
    correct = 0
    total = len(alerts)
    predictions = []
    latencies = []
    
    for a in alerts:
        if query_form == "raw":
            q_text = a["output"]
        elif query_form == "title_raw":
            q_text = f"{a.get('title', '')} {a['output']}".strip()
        elif query_form == "rewrite":
            q_text = normalize_alert_text(a)
        else:
            raise ValueError(f"Unknown query_form: {query_form}")
            
        res = engine.query(
            alert_output_text=q_text,
            container_id=a["container_id"],
            falco_rule=a.get("rule", ""),
            alert_source=a.get("source"),
        )
        is_corr = res.predicted_technique == a["ground_truth_technique"]
        if is_corr:
            correct += 1
        predictions.append(res.predicted_technique)
        latencies.append(res.latency_ms)
        
    acc, ci_low, ci_high = wilson_score_interval(correct, total)
    return {
        "accuracy": round(acc, 4),
        "ci_95": [round(ci_low, 4), round(ci_high, 4)],
        "correct": correct,
        "total": total,
        "predictions": predictions,
        "mean_latency_ms": round(float(sum(latencies) / len(latencies)), 2) if latencies else 0.0,
    }


def run_held_out_experiments(repo_root: Path) -> Dict[str, Any]:
    tech_dir = repo_root / "kb_master" / "techniques"
    cve_dir = repo_root / "kb_master" / "cves"
    records, cves = load_kb_dir(str(tech_dir), str(cve_dir))
    cve_map = build_cve_lookup(cves)
    
    # Load seen alerts from placeholder_alerts.json
    with open(repo_root / "rag_engine" / "data" / "placeholder_alerts.json") as f:
        seen_alerts = [a for a in json.load(f)["alerts"] if a["scenario_id"] != "S10"]
        
    held_out_alerts = HELD_OUT_ALERTS
    
    print(f"Loaded {len(seen_alerts)} seen alerts and {len(held_out_alerts)} held-out alerts.")
    
    query_forms = ["raw", "title_raw", "rewrite"]
    models = ["tfidf-word", "dense-minilm"]
    
    results = {}
    for model_name in models:
        two_layer = TwoLayerRAG(records, EMBEDDERS[model_name](), cve_lookup=cve_map)
        flat = FlatRAG(records, EMBEDDERS[model_name](), cve_lookup=cve_map)

        
        for qf in query_forms:
            k_seen_2l = f"seen__two_layer__{model_name}__{qf}"
            k_seen_flat = f"seen__flat__{model_name}__{qf}"
            k_ho_2l = f"held_out__two_layer__{model_name}__{qf}"
            k_ho_flat = f"held_out__flat__{model_name}__{qf}"
            
            results[k_seen_2l] = evaluate_dataset(two_layer, seen_alerts, qf)
            results[k_seen_flat] = evaluate_dataset(flat, seen_alerts, qf)
            results[k_ho_2l] = evaluate_dataset(two_layer, held_out_alerts, qf)
            results[k_ho_flat] = evaluate_dataset(flat, held_out_alerts, qf)

    # Save results
    out_path = repo_root / "eval" / "held_out_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"Held-out experiment results written to {out_path}")
    return results


if __name__ == "__main__":
    run_held_out_experiments(REPO_ROOT)
