# Data Availability Statement (draft - complete only after annotation, DOI and licence decisions)
All alerts analysed are lab-generated attack alerts from the SentinelMesh Docker lab (no personal data). Captures, checksums
(`SHA256SUMS`), run manifests, ground truth and result files are in this repository (`eval/runs*`, `eval/ground_truth.json`,
`results_x/`). The MITRE ATT&CK STIX bundle (v20) is public (sha256 in `REPRODUCE.md`). Attack scripts are included because the
lab is deliberately vulnerable and must only be run on a machine you control.
**Not yet satisfied:** a DOI-minted deposit (Zenodo) and a multi-environment dataset (see PENDING.md).
External data (Sigma rules, Atomic Red Team index) are third-party, retrieved 2026-11-06, not redistributed; re-download commands and sha256 are in `REPRODUCE.md` and `results_x_v3/m4_external_eval.json`. Their licences were taken from repository documentation and were not machine-verified here; check them before release. No independent annotations exist. The annotation packet and team-label key are in `annotation/` (do not share the key with annotators).
