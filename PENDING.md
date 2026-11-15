# Pending work
1. Collect alerts from 3-5 independently configured environments (different OS/runtime/policies), including benign traffic and more ATT&CK techniques (items 1, 2, 7).
2. Independent annotators for ground truth and for the generated knowledge (items 2, 3).
3. Run dense, security-domain (e.g. SecBERT-style) and published ATT&CK mappers on the same splits (item 5); needs model downloads.
4. Evaluate zero-shot properly: the 8 covered techniques are all that detectors can verify; uncovered techniques need a different mechanism.
5. Re-verify the poisoning integrity-check numbers (`robustness.json`, key `integrity_check_detection_rate`) before use.
6. Harden against attacker-controlled fields (identifier/path text) and field loss; consider a field-trust model.
7. Complete the supplementary information, author metadata, Zenodo release and DOI (items 13-17).
8. Defensive note: the lab is deliberately vulnerable; do not expose it via the optional ngrok tunnel on a shared network.

## After M1
- Track B shows detector-independent identification does not work with MITRE text alone; decide whether the paper claims detector-aware interpretation only, or builds an independent method (needs external labelled data, M4/M5).
- Dense / security-domain baselines (blocked: model downloads).
- Track B calibration needs a model that is right more often than 0.4% of the time before it can be assessed.
- M2-M7 not started (safety-gated routing, field trust, cryptographic KB integrity, external data, annotators, supplements, release).

## After M2-M7
- Independent reviewers + annotation run (`annotation/PROTOCOL.md`); second independently configured environment; benign traffic.
- Run `m5_dense_baseline.py` where a MiniLM ONNX model is available; add a security-domain model and a published ATT&CK mapper.
- Safe-demonstration Docker profile (env-var secrets, password auth, pinned digests), secret scan, second-person security review.
- Decide licence, author list/ORCIDs; Zenodo release after the above. Do not claim independent ATT&CK identification.
- Re-evaluate the safety gate on scenarios whose oracle tier includes `auto` (none exist in the lab) and on held-out thresholds not revised after test inspection.
- Real response path was never built; safety claims are simulation-only.
