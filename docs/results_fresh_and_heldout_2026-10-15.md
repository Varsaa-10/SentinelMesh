# Fresh-capture and held-out scoring (15 Oct 2026)

Scored from the frozen runs in this zip. Nothing in kb_master/, the detectors,
the rewrite rules or the retrievers differs from the development captures
(only line endings changed).

## Test set: 10 fresh captures, 140 alerts

Subnets: 172.30, 172.18, 10.20, 10.40, 172.25 (two runs each). All checksums
verify, every run is CLEAN.

Lab-written corpus, tactic-first / flat:
- raw 114/140 / 140/140, title+raw 140/140 / 140/140, rewrite 140/140 / 140/140
- raw per subnet: 172.30 26/28, every other subnet 22/28. Tactic-first misses
  the brute-force alert everywhere and the token-forgery alerts everywhere
  except 172.30, as the development runs predicted (the "30" token).

MITRE text, flat, raw: 14/140 (36 records), 0 (227), 0 (706).
MITRE + lab detection text, flat, raw: 132, 115, 121. With title: 140, 120, 136.
Fallback threshold, leave-one-run-out over the 10 captures: 0.10 in every
fold for raw, 140/140, 29% fallback. 0.00 for title and rewrite.

## Held-out run 20261015T051907Z

Detected 5 of 9 (S1, S5, S6, S7, S9). Gaps S2, S3, S4, S8, as predicted.
S9 only fired after the planned tar read was replaced with cat (run
20261015T051212Z). The paper reports this.

Retrieval on the 5 alerts, lab corpus: raw 4/5 both retrievers, title 4/5,
rewrite 5/5. The miss is the UNION injection, answered with T1078.

eval/held_out_results.json scores nine hand-written alert texts, not the
captured alerts. Do not cite it in the paper.

## Dense model: the existing run is not usable

all-MiniLM-L6-v2 reads at most 256 word pieces. A record's text is
"name. description Signatures: ...", and MITRE descriptions of the answer
techniques run 155 to 236 words, so the detection text of 7 of the 8 answer
records is cut off before the model reads it. Tactic summaries are cut after
their first record. That is why two-layer scores 0 everywhere and why
+detection, +description and both give identical numbers in
kb_curation_ablation_results_dense-minilm.json.

Fix: rag_engine/src/embeddings.py now has `dense-minilm-chunked`, which reads
the whole text in overlapping 256-token windows and averages them. Re-run:

    python3 eval/kb_curation_ablation.py --embedder dense-minilm-chunked

The ablation script now scores four separate sets (oct12_14, clean_60,
fresh_140, heldout_5); the old version pooled the fresh captures into
clean_60. Send back eval/kb_curation_ablation_results_dense-minilm-chunked.json.
