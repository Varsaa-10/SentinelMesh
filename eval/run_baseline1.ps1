# run_baseline1.ps1 — Standardized PowerShell runner for SentinelMesh Baseline 1 evaluation
# Ensures all detectors (including S7 Grafana detector) are explicitly included.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

python eval/harness.py `
  --ground-truth eval/ground_truth.json `
  --falco-rules-dir detection/falco-rules `
  --falco-shim detection/falco-rules/falco_shim.py `
  --tailer detection/log-tail/tailer.py `
  --webapp-log /var/log/sentinelmesh/webapp.log `
  --auth-log /var/log/sentinelmesh/authservice.log `
  --grafana-detector detection/log-tail/scenario7_detector.py `
  --grafana-container sentinelmesh-dashboard `
  --auto-run-attacks `
  --attack-scripts-dir attack_scripts `
  $args
