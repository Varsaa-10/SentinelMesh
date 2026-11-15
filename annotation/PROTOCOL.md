# Independent annotation protocol (STATUS: NOT EXECUTED - no independent reviewers were available)
Goal: obtain labels for lab alerts that do not come from the team that built the detectors.
1. Recruit 2-3 security practitioners with no involvement in SentinelMesh. Record experience level and conflicts of interest.
2. Give each reviewer `annotation_packet_blinded.csv` (60 alerts sampled with a fixed seed; event fields only; no detector titles, scenario ids, team labels or DAHR output) and the public ATT&CK matrix. Reviewers work independently and must not discuss items.
3. Per item they record: ATT&CK technique id (or `UNSURE`/`NONE`), the fields that support it, malicious/benign/uncertain, severity 1-5, and the escalation they would choose (auto/analyst/admin).
4. Agreement: Cohen's kappa per reviewer pair, Fleiss' kappa across reviewers, percent agreement, per-technique confusion; implemented in `sentinelmesh_x/annotation.py` (unit-tested against textbook values).
5. Disagreements are adjudicated in a documented session; keep every raw annotation and the adjudicated label with its provenance. `UNSURE` is never forced into a technique.
6. Only after annotation: compare with the team labels (`annotation/_answer_key_team_labels_DO_NOT_SHARE.csv`, sha256 recorded in the experiment log) and with system output.
Limitations to state in the paper: the packet contains only attacks (no benign alerts exist in the lab captures); 60 items is a pilot, not a validation set.
