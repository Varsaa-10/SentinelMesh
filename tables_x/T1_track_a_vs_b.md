**Detector-aware (A) vs detector-independent (B) retrieval, 706 records, 140 test alerts**

| method | TrackA_P@1_raw | TrackB_P@1 | TrackB_CI95_cluster | TrackB_R@5 | TrackB_MRR |
|---|---|---|---|---|---|
| tfidf | 0.929 | 0.000 | [0.00,0.00] | 0.143 | 0.077 |
| bm25 | 1.000 | 0.000 | [0.00,0.00] | 0.143 | 0.079 |
| rrf | 1.000 | 0.000 | [0.00,0.00] | 0.143 | 0.078 |
| dahr | 1.000 | 0.000 | [0.00,0.00] | 0.143 | 0.083 |
| repo_flat | 0.629 | 0.000 | [0.00,0.00] | 0.000 | 0.025 |
| repo_two_layer | 0.529 | 0.000 | [0.00,0.00] | 0.000 | 0.010 |
| supervised | 1.000 | 1.000 | [1.00,1.00] | 1.000 | 1.000 |
