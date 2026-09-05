# Module B2 — Two-Layer RAG Engine (Person 2, Week 2)

## Status as of Day 5

Scoring against **real captured alert events** (harness.py run
`20260817T025000Z`) and **real KB records for all 8 scenario-critical
techniques + the lab-planted CVE**. This produced the most important
finding of the week — see `docs/embedding_comparison.md` for full detail:

**Raw structured alert fields (`event_type=login_attempt`,
`identifier=admin`) look nearly identical across different techniques and
badly hurt retrieval accuracy for both engines** (flat-RAG drops to 0.86,
two-layer to as low as 0.36). A rule-based normalization step
(`src/alert_normalizer.py`) that converts raw fields into short
natural-language text closes most of that gap: flat-RAG returns to a
clean 1.0 on both embedders, two-layer/word jumps from 0.36 to 0.93.
**Recommendation for Day 5's freeze: use word-level TF-IDF with
normalized alert text as the default.**

Two-layer's Layer-1 tactic-routing fragility (first found on placeholder
data, confirmed again here) persists across every configuration tested
except word+normalized — flag this as a known architectural limitation,
not something silently resolved.

## What's here

```
rag_engine/
  kb/kb_master_real/
    schema_reference.json         copy of Person 1's schema.json for reference
    techniques/*.json              36 files: 8 scenario-critical are REAL,
                                    28 distractors reconstructed from public data
    cves/*.json                    16 files: 1 lab-planted (CVE-2022-29217) is REAL,
                                    15 distractors reconstructed from public data
  data/ground_truth_reference.json Person 1/3's real ground_truth.json, saved verbatim
  data/placeholder_alerts.json     14 alerts (S1-S9 + S10's 5 stages); 13 are REAL
                                    captured events from harness.py run 20260817T025000Z,
                                    S7 (Grafana) still trigger-condition-derived
  data/eval_results.json           output of the last evaluate.py run (raw vs normalized x 2 embedders x 2 engines)
  scripts/generate_distractors.py  one-off generator for the reconstructed distractor records
  src/kb_loader.py                 KBRecord + CVERecord matching the real dual-source schema
  src/embeddings.py                2 swappable embedding backends
  src/confidence.py                similarity + source_agreement + cross-doc agreement + consistency
  src/alert_normalizer.py          rule-based raw-event -> natural-language normalizer (Day 5 fix)
  src/rag_engine.py                TwoLayerRAG (Layer 1 tactic -> Layer 2 technique/CVE)
  src/flat_rag.py                  FlatRAG comparison baseline
  src/evaluate.py                  runs both engines x both embedders x raw/normalized, scores accuracy+latency
  docs/output_format_spec.md       frozen output format spec (includes source_agreement)
  docs/embedding_comparison.md     Day-4/5 comparison: the raw-vs-normalized finding, final recommendation
```

## How to run

```bash
cd rag_engine/src
python3 evaluate.py
```

Requires `numpy` and `scikit-learn`. No network access needed at runtime.

## Do this next

1. **Decide whether `alert_normalizer.py`'s logic should move upstream**
   into the log-tail/Falco detectors (emit a human-readable summary at
   detection time) rather than living in the RAG layer — worth raising
   with Person 1 before Week 3 wiring starts.
2. **Get a run that includes S7 (Grafana)** — the only captured-alerts run
   available (`20260817T025000Z`) predates that scenario, so it's still
   trigger-condition-derived text, not a real capture.
3. **Get the more recent run** (`20260827T024810Z`, 19 alerts, 8/9 fired,
   one scenario didn't fire) if available — useful to see which scenario
   failed and whether the finding above still holds.
4. Real distractor files (27 techniques + 15 CVEs) are lower priority —
   already factually accurate stand-ins from public data.

## Definition of done — checked against the plan

- [x] Given any alert, the engine returns a technique + confidence score +
      cited evidence (`RAGResult` / see `output_format_spec.md`).
- [x] Flat-RAG and two-layer RAG have both been run against the same
      alerts, with accuracy/latency recorded (`docs/embedding_comparison.md`,
      `data/eval_results.json`).
- [x] The output format spec is a written document
      (`docs/output_format_spec.md`), not left implicit in code.
- [x] Scored against real ground-truth technique mappings for all 8
      scenario-critical techniques + the real lab-planted CVE.
- [x] Scored against real captured alert events (13 of 14; S7 pending a
      run that includes it).
- [ ] Full real KB (currently 9/52 files real: 8 techniques + 1 CVE;
      remaining 43 are reconstructed from public data).
