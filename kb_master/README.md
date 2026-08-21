# KB Master — Knowledge Base for SentinelMesh Threat-Intelligence/RAG Layer

## Overview

`kb_master/` is the **authoritative, read-only** knowledge base that every downstream component in the SentinelMesh Threat-Intelligence/RAG layer is built against. It contains:

- `techniques/` — MITRE ATT&CK technique records (8 scenario-critical + 20–40 distractors)
- `cves/` — CVE records (lab-planted + distractor entries)
- `schema.json` — Locked record structure (see below)
- `validate_schema.py` — Schema validator (run before every commit)
- `benchmark_notes.md` — Identified CTI-to-ATT&CK benchmark dataset (Day 4)
- `CHANGELOG_KB.md` — Weekly change log (frozen Day 5)
- `FROZEN` — Sentinel file marking this directory as immutable after freeze

**Person 2 (RAG engine)** and **Person 3 (poisoned-variant generation)** both build against this exact copy. Never modify it in place — see the immutability policy below.

---

## Field Reference

### Technique Record

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | ✅ | string | ATT&CK technique ID (e.g. `T1190`, `T1003.008`) |
| `tactic` | ✅ | string | ATT&CK tactic name |
| `technique_name` | ✅ | string | Official technique name |
| `description` | ✅ | string | Factually accurate description |
| `detection_signatures` | ✅ | object | Dual-source signature — see below |
| `related_cves` | ✅ | array | CVE IDs (empty `[]` if none) |
| `mitigation` | ✅ | string | ATT&CK/CIS mitigation guidance |
| `scenario_refs` | optional | array | SentinelMesh scenario IDs (empty for distractors) |
| `is_scenario_critical` | optional | boolean | `true` if used in S1–S10 |
| `sub_technique_of` | optional | string/null | Parent ID for sub-techniques |
| `platforms` | optional | array | Applicable platforms |
| `data_sources` | optional | array | ATT&CK data source components |

### CVE Record

| Field | Required | Type | Description |
|---|---|---|---|
| `cve_id` | ✅ | string | Official CVE ID |
| `description` | ✅ | string | Accurate description (matches NVD) |
| `cvss_score` | ✅ | number | CVSS v3.1 base score (0–10) |
| `affected_component` | ✅ | string | Software + version range |
| `related_technique_ids` | ✅ | array | ATT&CK IDs this CVE maps to |
| `lab_planted` | ✅ | boolean | `true` if intentionally planted in lab |
| `cwe_ids` | optional | array | Associated CWE IDs |
| `cvss_vector` | optional | string | CVSS v3.1 vector |
| `published_date` | optional | string | ISO 8601 publication date |
| `scenario_refs` | optional | array | SentinelMesh scenarios exercising this CVE |
| `patch_reference` | optional | string | Fix/upgrade reference |

---

## Dual-Source Detection Signatures

The `detection_signatures` field has two sub-keys: `log_tail` and `falco`. Routing is determined by the technique type, mirroring Week 1's two-source detection architecture:

| Source | Techniques | Reason |
|---|---|---|
| `log_tail` only | T1190, T1110, T1078, T1212 | SQL injection and credential-based — detected via app log events |
| `falco` only | T1021, T1070, T1003.008 | Lateral movement, privilege escalation — detected via syscall rules |
| **Both** | T1041 | Exfiltration appears in both Falco rules (S8) and the cross-source chain (S10) |

When a sub-key does not apply, set it to `null` (not absent — presence of both keys with `null` values is intentional and makes schema validation deterministic).

Person 2's confidence-scoring layer uses source-agreement between `log_tail` and `falco` as a genuine signal. This field design makes that possible without retrofitting.

---

## Immutability Policy

> **After Day 5 freeze (`git tag kb-master-v1.0-frozen`), this directory is NEVER edited in place.**

| Situation | Action |
|---|---|
| Typo or minor factual fix before freeze | Edit in place, commit with `fix:` prefix |
| Schema field addition/rename after freeze | Create `kb_master_v2/`, notify Person 2 and Person 3 directly |
| New technique or CVE record after freeze | New versioned copy or separate `kb_additions/` directory |
| Working/poisoned copy for RAG testing | Person 2/3 maintain their own copy — never modify this directory |

---

## Running the Schema Validator

```bash
python kb_master/validate_schema.py
```

Expected output:
```
[OK] <N> technique records validated
[OK] <M> CVE records validated
```

Run this before every commit that touches `kb_master/techniques/` or `kb_master/cves/`.

---

## Handoff Instructions

### For Person 2 (RAG Engine)
- Load records from `kb_master/techniques/*.json` and `kb_master/cves/*.json`
- The `detection_signatures` field is the primary grounding signal for confidence scoring
- Do not modify this directory — make a working copy for embedding/indexing

### For Person 3 (Poisoned-Variant Generation)
- The 8 `is_scenario_critical: true` technique records are the ground truth for correct technique attribution
- Poisoned variants should be created in a separate directory
- Reference `scenario_refs` to associate each technique with the correct scenario

---

## Directory Structure

```
kb_master/
├── FROZEN                  ← Immutability sentinel
├── README.md               ← This file
├── schema.json             ← Locked record schema (Day 1 deliverable)
├── validate_schema.py      ← Schema validator
├── benchmark_notes.md      ← CTI-to-ATT&CK benchmark dataset (Day 4)
├── CHANGELOG_KB.md         ← Weekly changes (frozen Day 5)
├── techniques/
│   ├── T1190.json          ← Exploit Public-Facing App (S1, S10) [scenario-critical]
│   ├── T1110.json          ← Brute Force (S2) [scenario-critical]
│   ├── T1078.json          ← Valid Accounts (S3, S7, S10) [scenario-critical]
│   ├── T1212.json          ← Exploitation for Credential Access (S4, S10) [scenario-critical]
│   ├── T1021.json          ← Remote Services (S5) [scenario-critical]
│   ├── T1070.json          ← Indicator Removal (S6) [scenario-critical]
│   ├── T1041.json          ← Exfiltration Over C2 Channel (S8, S10) [scenario-critical]
│   ├── T1003.008.json      ← OS Credential Dumping: /etc/passwd (S9, S10) [scenario-critical]
│   └── [20–40 distractor technique files]
└── cves/
    ├── CVE-2022-29217.json ← PyJWT alg confusion [lab-planted, S4/S10]
    └── [14–19 other CVE files]
```
