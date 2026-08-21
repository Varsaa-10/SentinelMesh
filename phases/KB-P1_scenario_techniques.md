# KB-P1 — Scenario-Critical Technique & CVE Population

**Status:** Complete  
**Days:** 1–2  
**Branch:** `feature/module-kb-master`

## Objective

Populate the 8 scenario-critical MITRE ATT&CK technique records (one per distinct technique ID used across S1–S10) and the 1 lab-planted CVE record. These are the KB records that directly underpin ground-truth evaluation — every record must be factually accurate.

## Technique Records Written

| File | Technique | Scenario Refs | Detection Source |
|---|---|---|---|
| `T1190.json` | Exploit Public-Facing Application | S1, S10 | `log_tail` only |
| `T1110.json` | Brute Force | S2 | `log_tail` only |
| `T1078.json` | Valid Accounts | S3, S7, S10 | `log_tail` only |
| `T1212.json` | Exploitation for Credential Access | S4, S10 | `log_tail` only |
| `T1021.json` | Remote Services | S5 | `falco` only |
| `T1070.json` | Indicator Removal | S6 | `falco` only |
| `T1003.008.json` | OS Credential Dumping: /etc/passwd | S9, S10 | `falco` only |
| `T1041.json` | Exfiltration Over C2 Channel | S8, S10 | **both** |

## CVE Records Written

| File | CVE | Lab Planted | Technique | Scenarios |
|---|---|---|---|---|
| `CVE-2022-29217.json` | PyJWT alg:none bypass | ✅ Yes | T1212 | S4, S10 |

## Design Notes

- **S3 and S7 share T1078** — both exploit "Valid Accounts" but via different vectors (default credentials vs. Grafana anonymous access). A single technique record covers both; `scenario_refs: ["S3", "S7", "S10"]` reflects this.
- **T1041 is dual-source** — Falco catches the outbound connection syscall (S8 standalone); in S10 chain context, log-tail alerts (S1/S3/S4) provide pre-exfiltration corroboration. The `log_tail` sub-key is populated with `chain_context` event type to enable cross-source reasoning by Person 2's RAG engine.
- **No CVEs for S1–S3, S5–S7** — these are CWE-referenced weaknesses (CWE-89, CWE-307, CWE-798, CWE-284, CWE-732) with no associated CVE ID. `related_cves: []` is the correct value per schema.

## Acceptance Criteria

- [x] All 8 technique records pass `validate_schema.py`
- [x] CVE-2022-29217 passes `validate_schema.py`
- [x] `is_scenario_critical: true` on all 8 technique records
- [x] Detection source routing matches `eval/ground_truth.json` exactly
- [x] Committed and pushed
