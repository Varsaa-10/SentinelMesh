#!/usr/bin/env bash
# Regenerates every SentinelMesh-X result and figure (CPU only, ~40 min; exp2 dominates). Run from the repository root.
set -euo pipefail
export SENTINELMESH_ROOT=$PWD
pip install -r requirements-x.txt
python3 -m pytest -q   # full original + SentinelMesh-X suite; any failure stops the run (set -e)
mkdir -p results_x figures_x
for s in exp0_tune exp2_benchmark exp3_generalise_ablate exp5_calibration exp6_robustness exp8_e2e exp7_efficiency exp9_figures m1_nested_tuning m1_benchmark m1_calibration; do
  python3 sentinelmesh_x/experiments/$s.py
done
# --- M2-M7 (external data needs network access to github.com / codeload.github.com / raw.githubusercontent.com; see REPRODUCE.md)
for s in m2_safety_eval m3_integrity_eval m5_zero_shot m5_ablation_stats m6_adaptive m6_efficiency m4_make_annotation_packet; do
  python3 sentinelmesh_x/experiments/$s.py
done
# m4_external_eval needs /tmp/ext/sigma.tgz and /tmp/ext/atomic_index.yaml (download commands in REPRODUCE.md), then m5_external_stats
python3 sentinelmesh_x/experiments/m5_dense_baseline.py   # writes BLOCKED unless SENTINELMESH_MINILM_ONNX is set
python3 sentinelmesh_x/experiments/m7_build_tables_figures.py
python3 sentinelmesh_x/experiments/m7_run_manifest.py
