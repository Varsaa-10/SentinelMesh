# Reproducing the paper's tables and figures

Everything below runs on a laptop CPU. Nothing needs a GPU or network access once the
dense model files are on disk. Times are for a 2-core machine.

## 1. Environment

Tested with:

| Package | Version |
|---|---|
| Python | 3.13 |
| numpy | 2.5.3 |
| scikit-learn | 1.9.1 |
| scipy | 1.18.1 |
| matplotlib | 3.11.2 |
| PyYAML | 6.0.3 |
| onnxruntime | 1.29.0 (dense and hybrid runs only) |
| tokenizers | 0.23.3 (dense and hybrid runs only) |

```
pip install numpy scikit-learn scipy matplotlib pyyaml onnxruntime tokenizers
```

## 2. Data that the scripts read (all in this repository)

| What | Where | Version / check |
|---|---|---|
| Lab-written knowledge base | `kb_master/techniques`, `kb_master/cves` | 36 techniques, 16 CVEs |
| MITRE ATT&CK STIX bundle | `rag_engine/kb/attack_stix/enterprise-attack.json` | ATT&CK v20.0, sha256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352` |
| MITRE corpora (36 / 227 / 706 records) | `rag_engine/kb/corpora/corpus_36`, `corpus_200`, `corpus_full` | built by `rag_engine/src/build_attack_corpus.py` |
| Ground truth | `eval/ground_truth.json` | |
| Held-out ground truth and predictions | `eval/held_out_ground_truth.json` | written before the run |
| Development captures | `eval/runs/20260818T052007Z`, `20260818T052217Z_chaintagged`, `20261012T030225Z_chaintagged`, `20261012T031032Z_chaintagged`, `20261012T140201Z` (reference run) | `SHA256SUMS` in each folder |
| Test captures | `eval/runs/20261014T104641Z` ... `20261014T141640Z` (10 folders) | `SHA256SUMS` in each folder; check with `sha256sum -c` from the repo root |
| Held-out capture | `eval/runs_heldout/20261015T051907Z` | `SHA256SUMS` |
| Excluded runs and reasons | `eval/runs_excluded.txt`, `eval/runs_heldout_excluded.txt` | |

Alerts are lab-generated. The only addresses in them are private lab addresses and the public
addresses of the example website used by the exfiltration scenario.

## 3. Dense model

The dense runs use the ONNX export of `sentence-transformers/all-MiniLM-L6-v2` published as
`Xenova/all-MiniLM-L6-v2` (files `onnx/model.onnx`, `tokenizer.json`). Put the two files in one folder:

```
models/all-MiniLM-L6-v2/tokenizer.json
models/all-MiniLM-L6-v2/onnx/model.onnx
```

and set `export SENTINELMESH_MINILM_ONNX=models/all-MiniLM-L6-v2`.

Checks for the files we used: `model.onnx` is 90,387,606 bytes, sha256
`759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e`; `tokenizer.json` sha256
`da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0`. As a functional check, the cosine
of "A man is eating food." and "A man is eating a piece of bread." should be 0.755.

The PyTorch embedders `dense-minilm` and `dense-minilm-chunked` in `rag_engine/src/embeddings.py`
give the same vectors from the official `sentence-transformers` weights, if you prefer those.

## 4. Commands

Run from the repository root. Seeds are fixed in the scripts (bootstrap seed 20261016;
perturbation trial t uses `random.Random(1000 + t)`); every other step is deterministic.

```
export SENTINELMESH_ROOT=$PWD
mkdir -p eval/results figures

# per-alert retrieval on the 140 test alerts and 5 held-out alerts, every knowledge base,
# both retrievers, three query forms (about 25 min for TF-IDF; dense about 20 min; hybrid about 2 h)
python3 eval/score_fresh_heldout.py eval/results/scores_tfidf-word.json tfidf-word
python3 eval/score_fresh_heldout.py eval/results/scores_dense-chunked.json dense-minilm-onnx-chunked
python3 eval/score_fresh_heldout.py eval/results/scores_dense-cutoff.json dense-minilm-onnx
python3 eval/score_fresh_heldout.py eval/results/scores_hybrid.json hybrid-tfidf-dense

# Tables III-IV, the appendix heatmap and the held-out retrieval numbers
python3 eval/summarise_scores.py eval/results/scores_tfidf-word.json

# per-capture and clustered statistics (two-way bootstrap, sign tests, knowledge-base effects)
python3 eval/clustered_stats.py eval/results/scores_tfidf-word.json eval/results/stats_tfidf-word.json

# confidence calibration
python3 eval/confidence_calibration.py eval/results/scores_tfidf-word.json eval/results/calibration_tfidf-word.json

# perturbation test (Table V)
python3 eval/perturbation_test.py

# leave-one-run-out fallback threshold
python3 eval/fallback_threshold_heldout.py

# poisoning with denominators and defences (Tables VI-VII)
python3 eval/poisoning_v2.py --alerts fresh70

# full pipeline on all alerts of the ten test captures and the reference run, with the threshold sweep
python3 eval/pipeline_safety.py eval/results/pipeline_safety.json

# figures (paper versions without titles)
python3 eval/plot_paper_figures.py eval/results/scores_tfidf-word.json figures eval/results/stats_tfidf-word.json --paper
```

## 5. Where each table and figure comes from

| Paper item | Script | Output |
|---|---|---|
| Table III (MITRE text vs lab-written) | `score_fresh_heldout.py` + `summarise_scores.py` | `scores_tfidf-word.json` |
| Table IV (ablation), Fig. 2, appendix Fig. 5 | same, + `plot_paper_figures.py` | same |
| Table of sparse, dense and hybrid retrieval | `score_fresh_heldout.py` with each embedder | `scores_*.json` |
| Clustered intervals, sign tests | `clustered_stats.py` | `stats_*.json` |
| Fig. 3 (scaling), Fig. 4 (subnets) | `plot_paper_figures.py` | `figures/` |
| Table V (perturbation) | `perturbation_test.py` | `eval/perturbation_results.json` |
| Fallback threshold | `fallback_threshold_heldout.py` | `eval/fallback_threshold_heldout_results.json` |
| Poisoning and defences | `poisoning_v2.py` | `eval/poisoning_v2_results_fresh70.json` |
| Reference-run routing, pipeline over ten captures, threshold sweep | `pipeline_safety.py` | `pipeline_safety.json` |
| Confidence calibration | `confidence_calibration.py` | `calibration_*.json` |
| Held-out detection | `eval/runs_heldout/*/alerts.jsonl`, `eval/runs_heldout_excluded.txt` | |

## 6. Capturing new runs

`linux_run/set_subnet.sh A.B` moves the lab to subnet A.B.0.0/16. `linux_run/preflight.sh` and
`linux_run/check_run.py` check a host and a finished run. `docs/held_out_step6_README.md` gives the
held-out protocol. The runbook used for the test captures describes the steps in order.

## SentinelMesh-X reproduction (M1-M7)
Environment: Python 3.12. `python3 -m venv .venv && .venv/bin/pip install -r requirements-x.txt` (direct pins) or `-r requirements-lock.txt` (full transitive set from a clean venv). Verified: in a fresh venv the complete suite gives `146 passed, 3 skipped` with `pytest -q -W error`.
External data (M4), retrieved 2026-11-06, not redistributed:
```
mkdir -p /tmp/ext && cd /tmp/ext
curl -L https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master -o sigma.tgz
curl -L https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml -o atomic_index.yaml
```
These track `master`, so a later download will differ; compare with the sha256 in `results_x_v3/m4_external_eval.json` and expect different numbers if they do not match.
Order: `./run_all_x.sh` (then run `m4_external_eval.py` and `m5_external_stats.py` once the two files exist). Seeds are fixed (see `results_x_v3/RUN_MANIFEST.json`). Efficiency numbers depend on the machine; the manifest records hardware.
Result directories: `results_x/` (pre-M1, frozen), `results_x_v2/` (M1, frozen), `results_x_v3/` (M2-M7). `RUN_MANIFEST.json` verifies the frozen files are byte-identical to their recorded hashes (16 checked, 0 changed).
Not reproducible here: pretrained dense baselines (set `SENTINELMESH_MINILM_ONNX`), independent annotations, git commit ids of the external data.
