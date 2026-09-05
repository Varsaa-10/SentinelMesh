# Embedding Model Comparison — Day 4-5 (Final)

Generated from `src/evaluate.py` against the **real 8 scenario-critical
technique records + the real lab-planted CVE**, plus 28 distractor
techniques + 15 distractor CVEs reconstructed from public ATT&CK/NVD data,
scored against **13 of 14 alerts using real captured events from
`harness.py` run `20260817T025000Z`** (S7/Grafana is still
trigger-condition-derived — that scenario didn't exist in that run yet).

## Headline finding: raw captured alert text breaks retrieval; normalizing it fixes most of that

| Engine | Embedder | Text | Accuracy | Mean latency (ms) |
|---|---|---|---|---|
| two-layer | tfidf-word | **raw** | 0.357 | 1.081 |
| flat | tfidf-word | **raw** | 1.000 | 0.971 |
| two-layer | tfidf-char | **raw** | 0.643 | 1.888 |
| flat | tfidf-char | **raw** | 0.857 | 2.289 |
| two-layer | tfidf-word | **normalized** | **0.929** | 0.954 |
| flat | tfidf-word | **normalized** | **1.000** | 0.870 |
| two-layer | tfidf-char | **normalized** | 0.714 | 1.547 |
| flat | tfidf-char | **normalized** | **1.000** | 1.964 |

**What "raw" text actually looks like**, from the real captured run:

```
login_attempt event_type, result=success, identifier="' OR '1'='1' -- ",
client_ip=172.18.0.1, details.authenticated_user_id=1, details.role=user
```

Compare S1 (SQLi), S2 (brute force), S3 (default creds), and S7 (Grafana)
— **all four emit the same `event_type=login_attempt` shape** and differ
only in field *values* (`identifier`, `result`), not vocabulary. TF-IDF
over raw field dumps like this has almost nothing to grab onto that
distinguishes "SQL injection" from "brute force" from "default
credentials" — the KB's natural-language descriptions use exactly those
phrases, but the raw alert never says them. That's why **even flat-RAG,
which has no tactic-routing failure mode at all, drops to 0.86 on raw text
with char-grams** — this isn't a two-layer-specific problem, it's a
vocabulary-gap problem between structured logs and natural-language KB
entries.

## The fix that was tested: `src/alert_normalizer.py`

A small rule-based normalizer translates recognizable raw field patterns
into short natural-language phrases before embedding — e.g. an
`identifier` containing SQL syntax becomes "authentication bypassed via
SQL injection syntax," a `jwt_verification` event with `algorithm=none`
becomes "signature verification bypassed... credential forgery." This is
deliberately simple and rule-based, not a learned model — it exists to
test the hypothesis, not to ship as-is. **Effect: two-layer/word jumps
from 0.36 to 0.93, flat/char reaches a clean 1.0, flat/word stays at
1.0.** The vocabulary gap was in fact the dominant problem.

**Reversal worth flagging:** on raw noisy text, char-grams outperformed
word-grams (0.643 vs 0.357 for two-layer) because sub-word matching
partially bridges structured-field noise. On clean normalized text, that
reverses — **word-grams outperform char-grams** (0.929 vs 0.714 for
two-layer), because char n-grams now pick up spurious substring overlap
between well-formed sentences that word-level matching wouldn't. Which
embedder "wins" depends entirely on how clean the input text is — not a
fixed property of the embedder itself.

## Remaining two-layer misses (normalized text)

- **two-layer/word:** only S7 (Grafana) misses, predicting T1110 instead
  of T1078 — and S7 is the one alert still using trigger-condition-derived
  text rather than a real capture, so this may resolve once real S7 data
  is available.
- **two-layer/char:** misses S1, S3, S10-stage-1, S10-stage-2 — all
  Layer-1 tactic-routing failures again, consistent with the Day-4 finding
  that two-layer's tactic gate is the fragile point regardless of exactly
  which embedder or text style is used.

## Recommendation for Day 5's freeze

**Use `tfidf-word` with alert-text normalization as the default
configuration**, for both engines — it's the only setting where flat-RAG
is perfect and two-layer is closest to it (0.929, one miss, on the one
scenario still lacking real data). Flag two-layer's Layer-1 fragility as
a known limitation in the Day-5 writeup rather than something silently
fixed, since it persisted across every text/embedder combination tested
except word+normalized.

## Why two offline TF-IDF variants instead of two "real" embedding models

This environment's network egress allowlist doesn't include model-hosting
domains (e.g. huggingface.co), so a hosted or downloaded neural embedding
model isn't reachable from here. `tfidf-word` and `tfidf-char` are both
implemented behind the same `BaseEmbedder` interface (`fit` / `embed` /
`similarity_matrix`) in `src/embeddings.py`, so swapping either one for a
real embedding API is a same-shape drop-in replacement, not a rewrite. A
real embedding model would likely handle the raw-vs-normalized gap better
than TF-IDF does on either side — worth testing once one is reachable.

## Remaining gaps before this is fully final

1. **S7 (Grafana) has no real capture** — the 20260817 run predates that
   scenario. Get a run that includes it.
2. **27 of 28 distractor techniques + 15 distractor CVEs are still
   reconstructed** from public data, not Person 1's actual files.
3. **The most recent run (`20260827T024810Z`, 19 alerts, 8/9 fired) hasn't
   been provided** — this data uses the older `20260817T025000Z` run
   (24 alerts, 8/8 fired). Worth getting the newer run specifically to see
   which scenario didn't fire and whether it changes anything above.
4. Decide whether `alert_normalizer.py`'s logic belongs in the RAG layer
   long-term, or should move upstream into the log-tail/Falco detectors
   themselves (emit a human-readable summary field at detection time,
   rather than reconstructing it downstream) — worth raising with Person 1.
