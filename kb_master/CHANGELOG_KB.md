# KB Master — Change Log

All changes to `kb_master/` are documented here. This file is frozen under tag `kb-master-v1.0-frozen` and is never edited in place after Day 4.

---

## [v1.0.0-frozen] — 2026-08-21

### Day 1 — 2026-08-21
#### Added
- `schema.json` — locked dual-source technique + CVE record schema
- `README.md` — field guide, immutability policy, handoff instructions
- `validate_schema.py` — stdlib-only schema validator
- `FROZEN` — immutability sentinel file
- `phases/KB-P0_schema_design.md` — phase document

---

### Day 2 — 2026-08-21
#### Added
- `kb_master/techniques/T1190.json` — Exploit Public-Facing Application (S1, S10) — log_tail
- `kb_master/techniques/T1110.json` — Brute Force (S2) — log_tail
- `kb_master/techniques/T1078.json` — Valid Accounts (S3, S7, S10) — log_tail
- `kb_master/techniques/T1212.json` — Exploitation for Credential Access (S4, S10) — log_tail
- `kb_master/techniques/T1021.json` — Remote Services (S5) — falco
- `kb_master/techniques/T1070.json` — Indicator Removal (S6) — falco
- `kb_master/techniques/T1003.008.json` — OS Credential Dumping /etc/passwd (S9, S10) — falco
- `kb_master/techniques/T1041.json` — Exfiltration Over C2 Channel (S8, S10) — both
- `kb_master/cves/CVE-2022-29217.json` — PyJWT alg:none bypass (lab-planted, S4, S10)
- 28 distractor technique records across 10 ATT&CK tactics (T1566, T1133, T1195, T1555, T1552, T1528, T1539, T1550, T1563, T1534, T1080, T1036, T1027, T1562, T1553, T1048, T1029, T1053.003, T1136, T1098, T1082, T1083, T1087, T1059, T1068, T1485, T1499, T1003)
- 15 distractor CVE records (CVE-2021-44228, CVE-2021-45046, CVE-2022-0847, CVE-2021-4034, CVE-2021-3156, CVE-2021-22555, CVE-2022-22965, CVE-2021-41773, CVE-2021-26084, CVE-2020-11651, CVE-2019-11043, CVE-2020-15257, CVE-2019-14271, CVE-2020-14882, CVE-2018-11776)
- `phases/KB-P1_scenario_techniques.md` and `phases/KB-P2_distractors.md` — phase documents

**Totals after Day 2: 36 technique records + 16 CVE records — all pass validate_schema.py**

---

### Day 3 — 2026-08-21
#### Added
- `kb_master/benchmark_notes.md` — CTI-to-ATT&CK benchmark dataset identified: TRAM (MITRE CTID), Apache 2.0, https://github.com/center-for-threat-informed-defense/tram (ATT&CK v13, actively maintained). Actual comparison deferred to a later task per PRD.
- `phases/KB-P3_handoff.md` — handoff instructions for Person 2 (RAG engine) and Person 3 (poisoned-variant generation).

#### Fixed
- `benchmark_notes.md` — corrected TRAM URL from archived `mitre-attack/tram` to canonical `center-for-threat-informed-defense/tram` (verified live via Firecrawl).

---

### Day 4 — 2026-08-21
#### Freeze
- Final verification pass: `validate_schema.py` → `[OK] 36 technique record(s) validated` + `[OK] 16 CVE record(s) validated`
- Spot checks passed: T1190 (S1/S10), T1212+CVE-2022-29217 (S4/S10), TRAM benchmark URL
- `phases/KB-P4_freeze.md` — freeze phase document added
- `CHANGELOG_KB.md` finalized (this entry)
- Tagged: `kb-master-v1.0-frozen`

**The `kb_master/` directory is now frozen. Any future changes require a new versioned copy — no in-place edits.**

---

_This CHANGELOG is frozen. Do not edit._
