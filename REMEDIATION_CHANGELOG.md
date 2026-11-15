# Remediation changelog
## M1 — experimental validity (this release)
New files: `sentinelmesh_x/{track_b,tuning,calib_eval}.py`, `sentinelmesh_x/test_m1_validity.py`, `sentinelmesh_x/experiments/{m1_common,m1_nested_tuning,m1_benchmark,m1_calibration}.py`, `results_x_v2/*`, `docs/REMEDIATION_PLAN.md`, `figures_x/fig11_track_a_vs_b.png`.
Modified: `run_all_x.sh` (M1 stages added). Everything under `results_x/` is untouched (hashes in `results_x_v2/BASELINE_RESULT_HASHES.txt`).
### Before vs after
| Item | Before (pre-M1) | After (M1) |
|---|---|---|
| Retrieval claim | DAHR 100% = BM25 100% (queries contain detector wording) | Track A unchanged. Track B (no detector identity/wording, ATT&CK corpus only): DAHR, TF-IDF, BM25, RRF, FlatRAG, TwoLayerRAG all 0% P@1 on the 706- and 227-record corpora (14-24% on the 36-record corpus) |
| Leakage in query forms (140 test queries) | not measured | detector-authored phrase or annotation key in 50% of `raw`, 100% of `title_raw`, 14% of `rewrite`; 0 of 205 Track B queries |
| Tuning (dev MRR, mean of 5 held-out captures) | Track A 0.924 (shortlist saw held-out) | Track A nested 0.924 (identical; default weights 0.897). Track B: nested 0.065, old 0.066, default 0.064 |
| Calibration, Track A | Brier 0.235 -> 0.091, no CI | Brier 0.235 [0.231,0.239] -> 0.091 [0.083,0.101] (original-alert cluster bootstrap); slope 3.87 -> 1.29, intercept 1.97 -> 0.03 |

## M2-M7 (this release; M1 files and all historical results untouched, verified by hash)
New code: `sentinelmesh_x/{safety,integrity,audit,pipeline,external,annotation}.py`; tests `test_m2_safety.py`(20) `test_m3_integrity.py`(9) `test_m4_external.py`(3) `test_m4_annotation.py`(3) `test_m6_pipeline.py`(6); experiments `m2_safety_eval, m3_integrity_eval, m4_external_eval, m4_make_annotation_packet, m5_zero_shot, m5_ablation_stats, m5_external_stats, m5_dense_baseline, m6_adaptive, m6_efficiency, m7_build_tables_figures, m7_run_manifest`; results in `results_x_v3/`; tables `tables_x/`; figures 12-18.
Modified original-project files (behaviour unchanged): `detection/log-tail/test_detectors.py` (assertions), `graph/tests/test_graph_only.py` (close file), `backend/app.py` (Pydantic v2 `json_schema_extra`, `model_dump`), `docker-compose.yml` (ngrok opt-in profile), `run_all_x.sh`, `requirements-x.txt` (+`requirements-lock.txt`), `README.md`, `REPRODUCE.md`.
Test status: `pytest -q -W error` -> 146 passed, 3 skipped, also in a fresh venv. A clean-venv run caught an import-name collision in my own test (fixed).
Disclosed deviation: the M2 policy rule "assume worst plausible candidate severity when uncertain" was added after seeing test under-escalation of 14.7% (-> 4.5%).
