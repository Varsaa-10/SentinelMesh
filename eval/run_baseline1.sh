#!/usr/bin/env bash
# run_baseline1.sh — Standardized runner for SentinelMesh Baseline 1 evaluation
# Ensures all detectors (including S7 Grafana detector) are explicitly included.

set -euo pipefail

PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

exec "${PYTHON}" eval/harness.py \
  --ground-truth eval/ground_truth.json \
  --falco-rules-dir detection/falco-rules \
  --falco-shim detection/falco-rules/falco_shim.py \
  --tailer detection/log-tail/tailer.py \
  --webapp-log /var/log/sentinelmesh/webapp.log \
  --auth-log /var/log/sentinelmesh/authservice.log \
  --grafana-detector detection/log-tail/scenario7_detector.py \
  --grafana-container sentinelmesh-dashboard \
  --auto-run-attacks \
  --attack-scripts-dir attack_scripts \
  "$@"
