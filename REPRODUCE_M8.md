# M8: dense baselines, deduplicated external evaluation, clustered statistics

Copy `sentinelmesh_x/experiments/m8_*.py` and `results_x_v4/` into the repository root. Then run the steps below from the repository root, with the pinned environment from `requirements-x.txt` plus `tokenizers`.

## 1. Inputs

**Dense model.** The all-MiniLM-L6-v2 ONNX export used in the earlier study. If huggingface.co is reachable, download `Xenova/all-MiniLM-L6-v2` (`onnx/model.onnx`, `tokenizer.json`). Otherwise the npm package `@maycombhq/embed-model@2.0.0-beta.1` holds byte-identical copies:

```
npm pack @maycombhq/embed-model@2.0.0-beta.1 && tar -xzf maycombhq-embed-model-2.0.0-beta.1.tgz
mkdir -p models/all-MiniLM-L6-v2/onnx
cp package/model.onnx models/all-MiniLM-L6-v2/onnx/ && cp package/tokenizer.json models/all-MiniLM-L6-v2/
sha256sum models/all-MiniLM-L6-v2/onnx/model.onnx models/all-MiniLM-L6-v2/tokenizer.json
# expect 759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e and da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0
export SENTINELMESH_MINILM_ONNX=$PWD/models/all-MiniLM-L6-v2
```

`m8_dense_and_external.py` refuses to run if either checksum differs or if the model does not give a cosine of 0.755 on the model card's example sentences.

**Atomic Red Team index.** Commit `8ef16ded0f49d186d2b2bf60e0e8ad14f4dfac19`. Its `atomics/Indexes/index.yaml` is byte-identical to the file evaluated on 6 Nov 2026 (sha256 `86e8c1600920fc04c3e80ef51164b89604175fe609252e8bfe8a643af623616a`). Commit `edb5039` has the same file.

```
mkdir -p /tmp/ext
curl -L https://raw.githubusercontent.com/redcanaryco/atomic-red-team/8ef16ded0f49d186d2b2bf60e0e8ad14f4dfac19/atomics/Indexes/index.yaml -o /tmp/ext/atomic_index.yaml
```

**Sigma.** Commit `53423dac8742ef6a44fb73f23f049e84594a66ce`. The evaluated tarball cannot be recreated byte for byte, so `m8_verify_sigma_commit.py` checks the commit by result instead. It must give 995 parsed rules and 0 events whose prediction differs from `results_x_v3/m4_external_events.json`. All seven commits tested, from `52f81d6` (the last commit before 6 Nov 15:42 UTC) to `53b90df` (7 Nov 01:36 UTC), pass this check, because `rules/windows/process_creation` did not change between them.

## 2. Commands

```
export SENTINELMESH_ROOT=$PWD
git clone --filter=blob:none https://github.com/SigmaHQ/sigma.git && SIGMA_GIT=$PWD/sigma \
  python3 sentinelmesh_x/experiments/m8_verify_sigma_commit.py 53423dac8742ef6a44fb73f23f049e84594a66ce
python3 sentinelmesh_x/experiments/m8_external_clustered_stats.py results_x_v3/m4_external_events.json results_x_v4/m8_external_stats_as_published.json
python3 sentinelmesh_x/experiments/m8_external_clustered_stats.py results_x_v3/m4_external_events.json results_x_v4/m8_external_stats_dedup.json --dedup
cd sentinelmesh_x/experiments && python3 m8_dense_and_external.py && python3 m8_dense_cost.py   # m8_dense_cost reads /tmp/ext/cmds.json, see below
```

`m8_dense_cost.py` times 300 distinct Atomic command lines. They were drawn with `random.Random(0).shuffle(sorted(set(CommandLine)))[:300]` over the events from step 1.

## 3. What changed and why

- **Duplicate events.** `load_atomic_events` reads `index.yaml`, which lists each Atomic test once under every tactic of its technique. 1,225 of the 5,935 events were therefore exact copies (same event id, technique, image and command line). The manuscript now uses the 4,710 distinct events. Every estimate moves by at most 1.6 points, and no conclusion changes.
- **Table 3 statistics.** The clustered McNemar test (Durkalski et al.), the technique-level sign-flip permutation test and the technique-cluster bootstrap reported in Table 3 were not in the repository. `m8_external_clustered_stats.py` implements them. On the original 5,935 events it reproduces the published McNemar p-values exactly; the intervals and permutation p-values agree within Monte Carlo error.
- **Dense baselines (item 5).** Run on Track A (raw, title + raw, rewrite; detector-aware knowledge base), on Track B and on the deduplicated external events. The harness reproduces the published Track A lexical numbers (BM25 1.000, TF-IDF 0.929).
- **Poisoning results.** `results_x/robustness.json` reproduces exactly when `exp6_robustness.py` is rerun (all 372 values identical). The key `integrity_check_detection_rate` is not a measurement: it is 0 by construction for two of the three attacks and compares against the original record for the third. Do not cite it.
