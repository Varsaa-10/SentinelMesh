# Results: knowledge-base curation, fallback threshold, poisoning (14 Oct 2026)

Three new scripts, run on the team's v3 code (STIX v20 corpora, cleaned capture set). All numbers are
TF-IDF word retrieval; the dense model was not run (not available in this environment).

Alert sets: `clean_60` = 60 alerts from 5 runs (faulty S8 slots removed); `oct12_14` = the 14 alerts
of run 20261012T140201Z. For the 227-record corpus, the parent T1003 counts as correct for T1003.008.

## 1. Which part of the lab-written knowledge base makes retrieval work

Script: `eval/kb_curation_ablation.py`, results: `eval/kb_curation_ablation_results.json`.

Start from MITRE text (citation markers removed), then add the lab-written fields back for the 8
answer techniques only. All other records stay MITRE text.

Correct out of 60 (two-layer / flat):

| Query form | Knowledge base | 36 records | 227 parents | 706 records |
|---|---|---|---|---|
| raw | MITRE text | 0 / 11 | 0 / 0 | 9 / 0 |
| raw | + lab detection text | 46 / 51 | 32 / 45 | 31 / 46 |
| raw | + lab description | 27 / 32 | 4 / 9 | 13 / 9 |
| raw | + detection + description | 46 / 46 | 37 / 45 | 33 / 43 |
| raw | + all lab fields | 46 / 60 | 37 / 51 | 36 / 51 |
| title + raw | MITRE text | 5 / 10 | 5 / 14 | 14 / 14 |
| title + raw | + lab detection text | 51 / 60 | 32 / 51 | 27 / 60 |
| title + raw | + all lab fields | 60 / 60 | 42 / 51 | 32 / 60 |
| rewrite | MITRE text | 23 / 28 | 18 / 19 | 5 / 14 |
| rewrite | + all lab fields | 60 / 60 | 37 / 51 | 32 / 55 |

Findings:

- The lab-written detection text is the piece that matters. Adding only that text to the 8 answer
  records lifts flat retrieval on raw alerts from 0 to 46 of 60 inside the full 706-record catalogue,
  and to 60 of 60 when the detector title is added. Lab descriptions alone help far less.
- With curated detection text, flat retrieval stays accurate at full ATT&CK scale. Tactic-first falls
  further behind as the corpus grows (title + raw at 706 records: 27 against 60).
- The 227-record corpus tops out at 51 of 60 because it has no T1003.008 record, so the lab detection
  text for credential-file reads has nowhere to go; all 9 misses are S9 slots.
- Removing MITRE citation markers moves only the near-zero MITRE baselines (for example 20 to 11 of 60,
  flat, raw, 36 records). It does not change any conclusion.
- Caveat: the lab detection text was written by the people who wrote the detectors. Held-out variants
  captured through the harness are needed before claiming this generalises.

## 2. Fallback threshold chosen without the test alerts

Script: `eval/fallback_threshold_heldout.py`, results: `eval/fallback_threshold_heldout_results.json`.

Leave-one-run-out on the 5 runs, lab-written corpus, grid 0.00 to 0.30:

| Query form | Threshold picked (every fold) | Held-out correct | Fallback rate | Two-layer alone | Flat |
|---|---|---|---|---|---|
| raw | 0.10 | 60 / 60 | 32% | 52 / 60 | 60 / 60 |
| title + raw | 0.00 (never falls back) | 60 / 60 | 0% | 60 / 60 | 60 / 60 |
| rewrite | 0.00 (never falls back) | 60 / 60 | 0% | 60 / 60 | 60 / 60 |

- Chosen this way, the fallback closes the raw-text gap, and the choice is stable across folds.
  The v3 value of 0.08 was tuned on the same alerts it was scored on and gave 55 of 60 clean alerts.
- The same 0.10 threshold falls back on 85%, 62% and 100% of raw queries on the MITRE corpora
  (36, 227, 706 records), so a threshold tuned on one knowledge base does not carry over to another.

## 3. Poisoning: one corruption per record, counted per alert

Script: `eval/poisoning_per_record.py`, results: `eval/poisoning_per_record_results.json`.

Lab-written corpus, the 9 standalone alerts of 12 Oct. Each corrupted copy differs from the clean
corpus in one record. Induced error = correct on the clean corpus, wrong on the corrupted one.

| Attack | Query form | Two-layer induced (alerts hit) | Flat induced (alerts hit) |
|---|---|---|---|
| Copied description (280 corpora) | raw | 25 / 2240 (3) | 4 / 2520 (1) |
| | title + raw | 12 / 2520 (2) | 0 / 2520 (0) |
| | rewrite | 70 / 2520 (5) | 13 / 2520 (2) |
| Tactic relabel (72 corpora) | raw | 23 / 576 (2) | 0 / 648 (0) |
| | title + raw | 3 / 648 (1) | 0 / 648 (0) |
| | rewrite | 14 / 648 (3) | 0 / 648 (0) |
| Targeted stuffing (315 pairs) | raw | 270 / 280 (8) | 301 / 315 (8) |
| | title + raw | 285 / 315 (9) | 262 / 315 (9) |
| | rewrite | 3 / 315 (2) | 2 / 315 (2) |

- Copied descriptions hurt tactic-first more than flat in all three query forms, and across more
  alerts. With only 9 distinct alerts, a per-alert test cannot reach significance (p = 0.25 to 0.5),
  so report the direction and counts, not p-values. The 3.8e-6 and 1.2e-10 values from v3 should not
  be used.
- Tactic relabelling affects only tactic-first, as expected, since flat retrieval ignores tactics.
- An attacker who copies an alert's own text into any one record wins against both retrievers about
  90 to 96% of the time on raw and title + raw queries. The rule-based rewrite resists it (about 1%)
  because it replaces the raw text the attacker copied. Tactic-first gives no protection here.

## Remaining limits

- Single-tactic indexing: the corpus builder files each MITRE technique under one tactic (for example
  T1078 under Stealth). The PRD default was every tactic; this affects only tactic-first numbers.
- MITRE detection text is stored under the Falco key for every record, so log-detector alerts get a
  zero source-agreement score on MITRE records. This affects confidence and routing, not ranking.
- Fresh captures, captured held-out variants and the dense model still need the team's machines.
