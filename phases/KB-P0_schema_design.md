# KB-P0 — Schema Design & Day 1 Deliverable

**Status:** Complete  
**Day:** 1  
**Branch:** `feature/module-kb-master`

## Objective

Lock the KB schema and publish it to Person 2 (RAG engine) and Person 3 (poisoned-variant generation) before end of Day 1. Nothing downstream can start without this structure.

## Deliverables

| File | Purpose |
|---|---|
| `kb_master/schema.json` | Locked record schema — technique + CVE |
| `kb_master/README.md` | Immutability policy, handoff instructions, field guide |
| `kb_master/FROZEN` | Sentinel file — marks directory as read-only after freeze |
| `kb_master/validate_schema.py` | Schema checker — run before every commit |

## Schema Design Decisions

### Dual-Source Detection Signature

The `detection_signatures` field mirrors Week 1's two-source architecture:

| Rule | Source assignment |
|---|---|
| SQL injection, credential-based techniques (T1190, T1110, T1078, T1212) | `log_tail` only |
| Privilege escalation, lateral movement, credential dumping (T1021, T1070, T1003.008) | `falco` only |
| Exfiltration (T1041) and the multi-stage chain (S10) | both `log_tail` + `falco` |

This enables Person 2's confidence-scoring layer to use source-agreement as a genuine signal.

### Immutability Policy

After Day 5 freeze (`git tag kb-master-v1.0-frozen`):
- `kb_master/` is **never edited in place**
- Any change becomes a **new versioned copy** (e.g., `kb_master_v2/`)
- Breaking schema changes require direct notice to Person 2 and Person 3

## Acceptance Criteria

- [x] `schema.json` published with dual-source `detection_signatures` field
- [x] `README.md` documents all fields and immutability policy
- [x] `validate_schema.py` passes on empty `techniques/` and `cves/` directories
- [x] Committed and pushed on Day 1
