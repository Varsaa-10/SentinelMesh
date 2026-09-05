# Module B3 — Poisoned KB Variants & Detection (Person 3, Week 2)

## Objective (per the execution plan)

Build 5 distinct poisoned versions of the knowledge base and the logic to
measure how often poisoning is detected before it leads to an unsafe
recommendation.

## What's here

```
poisoning/
  generate_poisoned_variants.py   builds all 5 variants from kb_master_real/ (read-only)
  poison_detection.py             static KB scan + retrieval-time suspicion scoring
  evaluate_poisoning.py           runs both detection layers against all 5 variants
  poisoning_eval_results.json     output of the last evaluate_poisoning.py run
  variants/
    variant_1_mislabeled_cve/          full KB copy, CVE-2022-29217 relinked to wrong technique
    variant_2_fake_entry/              full KB copy + 1 fabricated technique record
    variant_3_near_duplicate/          full KB copy, T1110's description swapped for T1078's
    variant_4_adversarial_embedding/   full KB copy, T1566's description stuffed with T1190 vocabulary
    variant_5_stale_contradictory/     full KB copy, T1212's mitigation replaced with wrong guidance
```

**`kb_master_real/` is never modified.** Every variant is a full, separate
copy (261 files total: 5 × 52) built by `generate_poisoned_variants.py`,
which only *reads* the master. Verified by hash-checking the master's real
files before/after generation.

## The 5 poisoning types (as specified in the plan) and how each was built

| # | Type | What was actually done |
|---|---|---|
| 1 | Mislabeled technique-CVE mapping | `CVE-2022-29217.related_technique_ids` changed from `["T1212"]` to `["T1499"]` (unrelated tactic). T1212's own `related_cves` is left untouched, creating an asymmetric, one-way-broken link — the realistic signature of this kind of corruption. |
| 2 | Injected fake entry | A fabricated technique record, `T1337.007.json` ("Shared Memory Segment Injection"), added to the techniques directory. Not a real ATT&CK ID; designed to look plausible on casual inspection. |
| 3 | Semantic near-duplicate with wrong label | `T1110.json` (Brute Force) keeps its real `id`/`tactic`/`technique_name`, but its `description` is replaced with T1078's real description almost verbatim. |
| 4 | Adversarial embedding | `T1566.json` (Phishing) keeps its real metadata, but its `description` is stuffed with vocabulary lifted from T1190's real description (SQL injection / login endpoint terms), engineered to hijack TF-IDF-style retrieval for SQLi-related alerts. |
| 5 | Stale/contradictory entry | `T1212.json`'s `mitigation` field is replaced with guidance that actively contradicts the real CVE-2022-29217 fix (claims no patching is needed). All other fields — id, tactic, description — are left correct, so retrieval still finds this record correctly; only the payload is wrong. |

## Detection logic: two layers, honestly scoped to what each can catch

**Layer 1 — static KB integrity scan (`poison_detection.scan_kb`)**, no
retrieval needed:
- Bidirectional link check (technique ↔ CVE) — catches variant 1
- ATT&CK ID pattern + known-ID allowlist check — catches variant 2
- Keyword heuristic on mitigation text ("does not require patching," "low-risk," etc.) — catches variant 5
- Cross-record duplicate-description check (pairwise word-overlap between every technique's description) — catches variant 3

**Layer 2 — retrieval-time suspicion score (`poison_detection.score_retrieval_result`)**:
reuses B2's existing confidence components (similarity, source_agreement,
cross_document_agreement) already computed by `TwoLayerRAG`/`FlatRAG`.
Flags high similarity paired with low source agreement or low
cross-document corroboration — the signature of a record winning on text
similarity alone without independent support.

**This is reported as two separate layers on purpose, not merged into one
score.** They catch different things and neither one covers everything —
see results below.

## Results (real run, `evaluate_poisoning.py`)

| Variant | New static findings vs. clean baseline | Wrong recommendations caused | Caught (either layer)? |
|---|---|---|---|
| 1: mislabeled CVE | 2 | 1 (pre-existing S7 miss, not poison-caused) | **YES** — static link check |
| 2: fake entry | 1 | 1 (pre-existing S7 miss, not poison-caused) | **YES** — static ID check |
| 3: near-duplicate | 1 | 2 (1 poison-caused: S3 → T1110 instead of T1078) | **YES** — static duplicate-description check |
| 4: adversarial embedding | 0 | 0 (attack did not hijack any alert in this test set) | **NO** |
| 5: stale/contradictory | 1 | 1 (pre-existing S7 miss, not poison-caused) | **YES** — static keyword check |

Baseline (clean master KB) static scan returns 4 findings — all
pre-existing, legitimate scope-boundary notes (reconstructed distractor
CVEs referencing real ATT&CK techniques, e.g. T1611, T1210, that fall
outside this 36-record KB), not bugs. Every variant's count above is
**incremental** over that baseline, to avoid conflating background noise
with actual poison-detection signal.

## Honest findings, not a claimed clean sweep

- **4 of 5 variants are caught, all by the static layer, none by the
  retrieval-time layer.** The retrieval-time suspicion score
  (`score_retrieval_result`) flagged **zero** of the wrong recommendations
  actually observed in this run — every case where a poisoned KB produced
  a wrong technique still had internally consistent `detection_signatures`
  metadata (source_agreement stayed high), which is exactly what that
  heuristic checks. It's a real limitation of that specific signal, not
  fixed by tuning thresholds.
- **Variant 4 (adversarial embedding) is the one genuine miss.** With the
  Day-5-recommended config (word-TF-IDF + alert normalization), the
  attack didn't actually hijack any of the 9 real alerts tested — meaning
  either the attack as constructed is too weak against that specific
  embedder/normalization combination, or this alert set doesn't happen to
  probe it effectively. Worth testing with more alerts or a stronger
  adversarial construction before concluding this poisoning type is safe.
- **Most "wrong recommendations" observed are NOT caused by poisoning at
  all** — they're the same pre-existing S7 (Grafana) misroute already
  documented in `docs/embedding_comparison.md` (T1078 → T1110), which
  persists whether or not any poisoning is present. Only variant 3's S3
  case is a genuine poison-caused failure. Reporting raw "wrong
  recommendation count" without this distinction would overstate how much
  damage each poisoning type actually does.

## How to run

```bash
cd rag_engine/poisoning
python3 generate_poisoned_variants.py   # rebuilds all 5 variants from kb_master_real/
python3 evaluate_poisoning.py            # runs both detection layers, prints summary table
```

Both scripts only need `numpy`/`scikit-learn` (already required by
`rag_engine/src/`) and read `../kb/kb_master_real/` and
`../data/placeholder_alerts.json` — no new dependencies.

## Known gaps / next steps

1. **Variant 4 needs a stronger test** — either a larger/more diverse
   alert set, or a more aggressive adversarial construction, to determine
   whether it's genuinely hard to trigger or just undertested here.
2. **Retrieval-time detection needs a second signal** beyond
   source_agreement to catch variant-3-style attacks that preserve valid
   metadata — the static duplicate-description check covers this for now,
   but a retrieval-time equivalent (e.g., checking whether the top-1
   record's description is anomalously similar to a *different* KB
   entry's description) would close this gap without needing a separate
   offline scan.
3. Once Person 1's real distractor files replace the reconstructed ones,
   re-run `generate_poisoned_variants.py` and `evaluate_poisoning.py` —
   the baseline finding count and thresholds were tuned against the
   current reconstructed KB and should be re-verified.
