# KB-P3 — Handoff & Integration Support

**Status:** Complete  
**Days:** 3–4  
**Branch:** `feature/module-kb-master`

## Objective

Deliver the stable, populated KB to Person 2 (RAG engine) and Person 3 (poisoned-variant generation) by Day 3. Fix any schema mismatches that surface during integration. Identify the public CTI-to-ATT&CK benchmark dataset for future retrieval quality comparison.

## Handoff Instructions for Collaborators

### For Person 2 — RAG Engine

The KB is stable and ready for integration:

```bash
# Clone or pull the feature branch
git fetch origin
git checkout feature/module-kb-master

# Load technique records
ls kb_master/techniques/   # 36 JSON files (8 scenario-critical + 28 distractors)

# Load CVE records
ls kb_master/cves/         # 16 JSON files (1 lab-planted + 15 distractors)

# Validate before ingesting
python kb_master/validate_schema.py
```

**Key fields for RAG embedding:**
- `technique_name` + `description` → primary embedding corpus
- `detection_signatures` → confidence-scoring signal (source-agreement between `log_tail` and `falco`)
- `is_scenario_critical` → ground-truth label for retrieval accuracy scoring
- `scenario_refs` → maps retrieved techniques to scenario IDs for evaluation

**Important:** Do not modify `kb_master/` directly. Make a working copy for indexing/embedding. The master copy is read-only.

### For Person 3 — Poisoned-Variant Generation

Scenario-critical technique records (all 8 with `is_scenario_critical: true`) are the ground truth for correct technique attribution:

| Scenario | Technique ID | File |
|---|---|---|
| S1, S10 | T1190 | `kb_master/techniques/T1190.json` |
| S2 | T1110 | `kb_master/techniques/T1110.json` |
| S3, S7, S10 | T1078 | `kb_master/techniques/T1078.json` |
| S4, S10 | T1212 | `kb_master/techniques/T1212.json` |
| S5 | T1021 | `kb_master/techniques/T1021.json` |
| S6 | T1070 | `kb_master/techniques/T1070.json` |
| S8, S10 | T1041 | `kb_master/techniques/T1041.json` |
| S9, S10 | T1003.008 | `kb_master/techniques/T1003.008.json` |

Poisoned variants should be placed in a **separate directory** (e.g., `kb_poisoned/` or `kb_working_p3/`) — never inside `kb_master/`.

## Benchmark Dataset Identified

**Dataset:** TRAM (Threat Report ATT&CK Mapper) by MITRE ATT&CK  
**Repository:** https://github.com/mitre-attack/tram  
**License:** Apache 2.0 — confirmed free to use without registration  
**Format:** JSON with sentence-level ATT&CK technique labels  
**Technique ID format:** Standard `T####` — directly compatible with KB `id` field  

See `kb_master/benchmark_notes.md` for full format documentation and comparison methodology.

**Actual comparison:** Deferred to a later task per PRD scope.

## Schema Change Policy Reminder

The schema is frozen from Day 1. If Person 2 or Person 3 surface mismatches during integration:

1. **Minor missing field** (e.g., adding an optional field) → Create a new KB version; notify both before any edit
2. **Required field rename** → Same — new version, direct notice, no silent edits
3. **Factual correction to a record** (not a schema change) → Can be fixed in-place before Day 5 freeze with a commit note

## Acceptance Criteria

- [x] KB delivered to collaborators via `feature/module-kb-master` branch
- [x] Handoff instructions documented (this file + `kb_master/README.md`)
- [x] Benchmark dataset identified: TRAM (MITRE), format confirmed
- [x] `kb_master/benchmark_notes.md` written
- [x] `kb_master/CHANGELOG_KB.md` updated through Day 3
- [x] Committed and pushed
