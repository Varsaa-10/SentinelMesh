# SentinelMesh-X supplementary information (index)
| Item | Content | Where |
|---|---|---|
| S1 | Full detector specifications | `S1_detector_specifications.md` |
| S2 | Dataset provenance and schema | below + `results_x_v3/RUN_MANIFEST.json`, `figures_x/table2_dataset.csv` |
| S3 | Annotation guidelines | `annotation/PROTOCOL.md` (NOT executed) |
| S4 | ATT&CK coverage | `results_x_v3/m4_external_eval.json` -> `coverage`; `figures_x/fig3_attack_coverage.png` |
| S5 | Hyper-parameter search | `S5_hyperparameter_search.md` |
| S6 | Full benchmark tables | `results_x_v2/detector_{aware,independent}_benchmark.json`, `tables_x/T1*` |
| S7 | Statistical analysis | `results_x/benchmark_stats.json` (pre-M1), `results_x_v2/detector_independent_benchmark.json` (paired_stats), `results_x_v3/m5_ablation_stats.json`, `m5_external_stats.json` |
| S8 | Calibration details | `results_x_v2/calibration_v2.json`, `tables_x/T3*` |
| S9 | Poisoning / robustness protocols | `results_x/robustness.json` (pre-M1, unchanged, integrity metric there must not be cited), `results_x_v3/m2_safety_eval.json`, `m3_integrity_eval.json`, `m6_adaptive_attacks.json` |
| S10 | Hardware / efficiency | `results_x_v3/m6_efficiency.json` (`hardware` block), historical `results_x/efficiency.json` |
| S11 | Failed experiments and limitations | `LIMITATIONS_AND_NEGATIVE_RESULTS.md` |
| S12 | Reproduction instructions | `REPRODUCE.md` (SentinelMesh-X section) |
## S2 Dataset provenance
Lab data: 10 test captures (5 Docker subnets, one lab design), 5 development captures, 1 held-out variant capture; 205 labelled alerts, all attacks, no benign traffic. Alert schema: `alert_spec.md` (7 keys). External: Sigma (Windows process_creation) and Atomic Red Team index, retrieved 2026-11-06; sha256 values in `results_x_v3/m4_external_eval.json` (`provenance`); not redistributed; re-download with the URLs given there.
