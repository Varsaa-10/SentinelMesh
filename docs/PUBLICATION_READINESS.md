# Publication-readiness assessment (honest)
**Not ready for a journal claiming independent ATT&CK identification. Potentially defensible, with substantial additional work, as a paper on detector-aware alert interpretation plus safe routing and KB integrity - but only if the narrower claim is made plainly.**
| Requirement | State |
|---|---|
| Claim supported by evidence | Only detector-aware, lab, in-distribution (Track A). Independent data (Sigma x Atomic) shows weak performance (precision 32.6% when a rule fires) |
| Independent environments / real telemetry / benign data | Absent |
| Independent annotation | Protocol and tooling only; no annotators |
| Baselines | TF-IDF, BM25, RRF, FlatRAG, TwoLayerRAG, supervised, non-pretrained LSA. Pretrained dense/security-domain and published ATT&CK mappers: blocked/not run |
| Statistics | Cluster-aware CIs and paired tests implemented; few distinct techniques (8 lab) limits power; event-level McNemar on external data is not cluster-aware (flagged) |
| Safety/trust/integrity | Implemented and tested in simulation; no real response path; no independent security review |
| Reproducibility | Clean-venv suite verified; seeds, hashes, manifest; external data tracks `master` |
| Release | No licence chosen, author list/ORCIDs missing, no DOI; nothing was published |
Recommended framing: (1) a negative/measurement result (detector wording leakage and the limits of detector-independent retrieval), (2) the inverted-confidence routing flaw and the fail-closed gate, (3) signed-KB integrity. Obtain independent annotations, a second environment and benign data before submitting.
