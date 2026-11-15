**Channel ablation with two-way cluster bootstrap**

| variant | MRR | CI95_cluster | diff_vs_full | diff_CI95_cluster |
|---|---|---|---|---|
| full (tuned) | 0.937 | [0.889, 0.976] | 0.000 | [0, 0] |
| default weights | 0.897 | [0.825, 0.958] | -0.040 | [-0.078, -0.008] |
| - field matching | 0.824 | [0.688, 0.931] | -0.114 | [-0.211, -0.04] |
| - semantic TF-IDF | 0.940 | [0.893, 0.979] | 0.003 | [-0.005, 0.013] |
| - BM25 | 0.902 | [0.84, 0.955] | -0.035 | [-0.066, -0.009] |
| - hierarchy (already w_h=0 in tuned config) | 0.937 | [0.889, 0.976] | 0.000 | [0.0, 0.0] |
| - adaptive weights | 0.937 | [0.889, 0.976] | 0.000 | [0.0, 0.0] |
| - generated knowledge (MITRE-only KB) | 0.312 | [0.099, 0.562] | -0.625 | [-0.812, -0.395] |
