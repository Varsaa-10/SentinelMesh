# STATUS AFTER M2-M7 (supersedes earlier status where different)
Classes: **IT** implemented and tested | **NV** implemented, not independently validated | **EV** experimentally validated (lab only) | **BL** blocked | **NS** not started
| Item | Class | Evidence file |
|---|---|---|
| Track A/B, leakage audit, nested tuning, cluster-aware calibration (M1) | IT, EV (lab) | `results_x_v2/` |
| Safety-gated routing, abstention, field trust, sanitiser (M2) | IT; NV (simulation; revised once after seeing test results) | `results_x_v3/m2_safety_eval.json` |
| Signed manifests, rollback protection, tamper-evident audit log (M3) | IT, EV (12 attack classes) ; local-dev keys only | `m3_integrity_eval.json` |
| External validation Sigma x Atomic (M4) | EV (third-party rules/labels, not telemetry) | `m4_external_eval.json` |
| Independent annotation | BL (no annotators): protocol + packet + kappa tools IT | `annotation/` |
| Independent environment / benign data | BL | - |
| Pretrained dense / security-domain baselines (M5) | BL (code ready, not run); LSA non-pretrained EV | `m5_dense_baseline.json`, `m4_external_eval.json` |
| Zero-shot / unseen / abstention (M5) | EV (lab) | `m5_zero_shot.json` |
| Ablation + cluster-aware stats (M5) | EV (lab) | `m5_ablation_stats.json`, `m5_external_stats.json` |
| Adaptive attacks, audited pipeline, efficiency (M6) | IT, EV (lab) | `m6_*.json` |
| Safe-demo Docker profile, secret scan, image pinning | NS | - |
| Licence, authors/ORCID, Zenodo DOI, GPU benchmarks | NS / BL | - |
| Tables T1-T10 (CSV/MD/LaTeX), figures 1-18, supplement S1-S12 (S3 not executed) | IT | `tables_x/`, `figures_x/`, `docs/supplementary/` |

# CORRECTION (M1, supersedes parts of the table below)
* The Track A results below used queries that contain detector-authored wording; they are **detector-aware** results only. Under the detector-independent Track B every unsupervised retriever, including DAHR, scores 0% top-1 on the 706-record corpus (`results_x_v2/detector_independent_benchmark.json`). The statement "DAHR 100% vs BM25" must not be used as evidence of independent ATT&CK identification.
* The supervised classifier reaches 100% on Track B, but a classifier on field *names* alone already reaches 64% (majority 21%), so this reflects lab-specific schema memorisation, not generalisation.
* Nested tuning gave the same Track A result as the old procedure; the leakage in tuning did not change the numbers.
* Calibration improvement now has CIs (see `calibration_v2.json`) but is still measured on perturbations I generated from 140 lab alerts in 5 captures; Track B calibration is uninformative (accuracy 0.4%).
Status classes: Implemented and tested = Track B/leakage auditor, nested tuner, cluster-aware calibration evaluation. Experimentally validated = nothing beyond the lab. Blocked = dense/security-domain baselines, external data, independent annotators. Not started = M2-M7.

# SentinelMesh-X: status against `Varsha_ieee_access_enhance.docx`
Legend: DONE = implemented and run here; PARTIAL = implemented, but limited by the available data; PENDING = needs data/people/infrastructure not available.

| # | Item | Status | What exists | Main limitation |
|---|---|---|---|---|
| 1 | Multi-environment independent dataset | PENDING | env descriptors + subnet split (`sentinelmesh_x/data.py`) | all 5 "environments" are Docker subnets of one lab design on one host family; no benign capture |
| 2 | Large-scale attack coverage, expert-verified labels | PENDING | coverage heatmap (fig 3) | 8 techniques / 5 tactics; labels by the lab team |
| 3 | Automated detector-aware knowledge generation | PARTIAL | `knowledge_gen.py`, `falco_cond.py`; all 9 detectors parsed | compared only with the team's own annotation; idioms of this lab's detectors only; token overlap with expert text 20-35% |
| 4 | Novel hybrid retrieval + maths + complexity | DONE (method) | DAHR in `retrieval.py`, `docs/SENTINELMESH_X_METHODS.md` | hierarchy and adaptive weighting add nothing on this data |
| 5 | Comparative benchmarking | PARTIAL | 9 methods x 3 KBs x 3 query forms, clustered stats, Holm | dense / security-domain embeddings and published systems not re-run (models not downloadable); original dense results exist in `eval/results/` |
| 6 | Learned calibration + risk | PARTIAL | `calibration.py`, `results_x/calibration.json` (Brier 0.235 -> 0.091, ECE 0.224 -> 0.045) | derived severity/criticality only weakly agree with hand values (rho 0.40 / 0.53); routing still under-escalates |
| 7 | Cross-environment / zero-shot | PARTIAL | leave-one-subnet-out, leave-one-technique-out, held-out variants | zero-shot fails (DAHR ~12% P@1, supervised 0%); no truly unseen environments |
| 8 | Adaptive poisoning robustness | PARTIAL | `exp6_robustness.py`, `results_x/robustness.json` | attacker model is mine; integrity-check detection numbers in the JSON are unverified and should not be cited |
| 9 | End-to-end pipeline validation | DONE (on available data) | `exp8_e2e.py` (original vs X, 10 captures) | easy in-distribution alerts; routing result is optimistic |
| 10 | Ablation and sensitivity | DONE | 2^4 channel factorial, one-at-a-time sweeps | see 4 |
| 11 | Statistical analysis | DONE | cluster bootstrap, exact McNemar, Holm, effect sizes | dependence between alerts; few techniques |
| 12 | Efficiency | PARTIAL | latency, throughput, memory on CPU, synthetic KB scaling up to ~5k | no GPU; baselines are lexical only |
| 13 | Reproducibility | PARTIAL | `run_all_x.sh`, pinned `requirements-x.txt`, seeds, tests | no Zenodo DOI yet |
| 14-16,18 | Methodology / data / code availability / statistics reporting | PARTIAL | methods doc, DATA/CODE statements, CITATION.cff, .zenodo.json | drafts; authors/DOI to complete |
| 17 | Supplementary information | PENDING | raw result JSONs in `results_x/` | needs curation into a supplement |
Figures/tables 1-10: all generated in `figures_x/` (fig 2, 9 also as CSV). Fig 4 and 6 should be re-checked before use because several methods hit 100% on the in-distribution test set.

## Headline results (corpus_full, 140 test alerts, raw queries)
Registry lookup and a supervised classifier trained on dev both reach 100%, so the test set cannot separate good retrievers. DAHR 100% vs original FlatRAG 63% / TwoLayerRAG 53%; vs BM25 on the same generated knowledge no significant difference. Under perturbation field matching is the main contributor (MRR 0.80-1.00 vs 0.27 without generated knowledge). Adding ~25% decoy text to attacker-controlled fields flips up to 25% of DAHR answers; 80% field dropout drops accuracy to 46%.
