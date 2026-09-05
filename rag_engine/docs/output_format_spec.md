# RAG Output Format Specification (frozen)

**Owner:** Person 2 (Algorithms/Core Logic) — Week 2, Module B2
**Status:** Frozen for Week 3 consumption (Person 1 — attack graph; Person 2 — risk score)
**Freeze target:** Day 5, Week 2

This is the exact structure every RAG query returns. Week 3 code should be
written against this document, not against `rag_engine.py`'s internals.

## Top-level result object

```json
{
  "predicted_technique": "T1190",
  "predicted_technique_name": "Exploit Public-Facing Application",
  "predicted_tactic": "Initial Access",
  "matched_cves": ["CVE-2019-9193"],
  "confidence": { ... see below ... },
  "evidence": { ... see below ... },
  "engine": "two-layer",
  "embedder": "tfidf-word",
  "latency_ms": 0.945
}
```

| Field | Type | Notes |
|---|---|---|
| `predicted_technique` | string | ATT&CK technique ID, e.g. `"T1190"`. This is the field Week 3's graph nodes and risk score key off of. |
| `predicted_technique_name` | string | Human-readable name, for logs/UI only — never used as a join key. |
| `predicted_tactic` | string | The Layer-1 winning tactic. |
| `matched_cves` | array[string] | CVE IDs associated with the winning KB record. May be empty. |
| `confidence` | object | See below. |
| `evidence` | object | See below — this is the citation structure. |
| `engine` | string | `"two-layer"` or `"flat"`. Week 3 should consume `"two-layer"` output; `"flat"` exists only for the Week 2 comparison. |
| `embedder` | string | Which embedding backend produced this result (e.g. `"tfidf-word"`). |
| `latency_ms` | number | Wall-clock query latency in milliseconds. |

## `confidence` object

```json
{
  "confidence_score": 0.7359,
  "components": {
    "similarity": 0.74,
    "source_agreement": 1.0,
    "cross_document_agreement": 0.33,
    "retrieval_consistency": 0.61
  },
  "weights": {
    "similarity": 0.4,
    "source_agreement": 0.25,
    "cross_document_agreement": 0.2,
    "retrieval_consistency": 0.15
  }
}
```

- `confidence_score` is the single number Week 3's risk formula
  (`risk_score = retrieval_confidence × action_severity × asset_criticality`)
  should read. Range `[0, 1]`.
- `components` and `weights` are included for auditability/debugging and
  for Person 3's poison-detection thresholding (Week 3) — they should
  **not** be re-derived independently; read `confidence_score` directly
  unless you specifically need to inspect one component (e.g. a poisoned
  entry that has high similarity but low cross-document agreement).
- Definitions:
  - **similarity** — top-1 cosine similarity between the alert and the
    winning KB record.
  - **source_agreement** — whether the winning KB record's
    `detection_signatures` actually declares a signature for the source
    that produced this alert (`log_tail` or `falco`, per the alert's
    `source` field). `1.0` if the alert's source is the record's *only*
    declared source, `0.85` if the record is dual-source (e.g. T1041) and
    the alert's source is one of the two, `0.0` if the alert's source
    isn't declared at all for that record (e.g. a `falco`-origin alert
    matched to a `log_tail`-only technique — a real red flag even when
    text similarity is high), and `0.5` (neutral) if the alert's source is
    unknown. This is a KB-native signal, not a text-similarity one — see
    Person 1's handoff notes on `detection_signatures` dual-source
    routing.
  - **cross_document_agreement** — fraction of the top-k retrieved KB
    records (k=3) that share the winning record's tactic. High = several
    independent KB entries agree.
  - **retrieval_consistency** — normalized gap between the top-1 and
    top-2 similarity scores. High = the top result stands out clearly;
    low = the model was nearly torn between two candidates.

## `evidence` object (citation structure)

```json
{
  "falco_rule": "N/A (log-tail detector, not a Falco rule)",
  "container_id": "webapp-01",
  "attack_id": "T1190",
  "cve_ids": [],
  "kb_detector_ref": "detection/log-tail/scenario1_detector.py",
  "kb_falco_rule_name": null
}
```

Every field is required (use `null`/`[]`, never omit the key) so downstream
code can rely on the shape without existence-checking:

| Field | Type | Source |
|---|---|---|
| `falco_rule` | string | Passed through from the input alert (Week 1 alert-format spec). May legitimately be a non-Falco placeholder string for log-tail-origin alerts. |
| `container_id` | string | Passed through from the input alert. |
| `attack_id` | string | Same value as `predicted_technique` — duplicated here so `evidence` is self-contained for citation/logging purposes. |
| `cve_ids` | array[string] | Same value as `matched_cves`. |
| `kb_detector_ref` | string or null | The winning KB record's own `detection_signatures.log_tail.detector_ref`, when that record declares a log-tail signature. Null otherwise. |
| `kb_falco_rule_name` | string or null | The winning KB record's own `detection_signatures.falco.rule_name`, when that record declares a Falco signature. Null otherwise. |

`kb_detector_ref` / `kb_falco_rule_name` come from the **KB record's own
declared detection signature**, not from the input alert — they let a
downstream consumer check "does this technique's own KB entry agree this
should have been caught by a log-tail detector / this Falco rule", which
is exactly the source-agreement check `confidence.source_agreement` scores
numerically.

## Stability guarantees

- Field names and types above are frozen as of Day 5, Week 2. Any change
  requires a version bump and a heads-up to Person 1 and Person 3 before
  Week 3 starts.
- `predicted_technique` values are always ATT&CK technique IDs matching
  the KB record schema's `id` field (Person 1's `kb_master` schema) — no
  free-text technique names as the primary key, ever.

## Revision note (Day 3)

The `confidence` object gained a fourth component, `source_agreement`,
and `evidence` gained `kb_detector_ref` / `kb_falco_rule_name`, after
Person 1's real schema and handoff doc landed on Day 3 and explicitly
called out `detection_signatures` (dual-source: `log_tail` / `falco`) as
a confidence-scoring signal. This happened before the Day-5 freeze, so it
does not violate the stability guarantee above — it's the last schema
change expected before freeze.
