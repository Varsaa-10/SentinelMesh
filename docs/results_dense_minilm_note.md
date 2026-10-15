# Dense-model KB-curation ablation (all-MiniLM-L6-v2)

- Script: eval/kb_curation_ablation.py, patched to accept --embedder, feed the
  chosen embedder to both engines, and write
  eval/kb_curation_ablation_results_<embedder>.json with an "embedder" field.
- Embedder: dense-minilm (sentence-transformers/all-MiniLM-L6-v2), CPU.
- Model commit hash: 1110a243fdf4706b3f48f1d95db1a4f5529b4d41
- Same frozen captures / RUNS list as the TF-IDF ablation.
- TF-IDF result: eval/kb_curation_ablation_results.json (copy: _tfidf-word.json)
- Dense result:  eval/kb_curation_ablation_results_dense-minilm.json
