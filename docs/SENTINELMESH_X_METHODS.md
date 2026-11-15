# SentinelMesh-X methods (draft for the manuscript)
## Knowledge generation
Python detectors are analysed with `ast` (aliases of `event.get`, guard clauses returning None, `==`/`in` comparisons, compiled
regexes, loops over candidate fields, `len(window) >= THRESHOLD`, annotation keys); Falco conditions are parsed with a small
and/or/not/in/startswith/glob parser. Output: executable constraints, a standard description (event type, conditions, thresholds,
data source) and a record in the kb_master schema. Each detector is registered to an ATT&CK id by the operator (as Sigma tags do).
A small generic lexicon (IANA ports, sensitive paths, SQL tokens) is optional and ablated (`auto_lex`).
## DAHR scoring
score(a,d)= w_f s_fld + w_s s_sem + w_b s_bm25 + w_h s_hier, each channel max-normalised.
s_fld = max over d's signatures of (m - gamma(c - m))/t, with m,c,t = matched/checkable/total constraint weight, weights = IDF over the
constraint set (unknown fields are neutral, contradicted fields are penalised). Alert title and scenario are never read.
s_hier = 0.5*tactic evidence (mean of top-m semantic scores in the tactic) + 0.5*parent/sub-technique evidence.
Adaptive weights: w_f*(0.5+coverage), w_s*(0.5+in-vocabulary ratio), w_h*(0.5+1-margin). Weights/top_m tuned on the 60 development alerts under perturbation.
Complexity per query: sem/BM25 O(nnz(q)*posting length); field O(S*L) (independent of N); hierarchy O(N). Measured: 0.64 -> 3.1 ms at 706 records, 13.8 ms at 4,942 synthetic records, ~300 alerts/s, CPU only.
## Calibration
Logistic regression over 9 features (fused score, margin, field score, semantic score, field weight, OOV ratio, coverage, semantic margin, source agreement), trained on development predictions pooled over three knowledge conditions x four perturbations, tested on the 140 test alerts pooled the same way. Metrics: Brier, ECE (10 bins), reliability diagrams.
## Statistics
Two-way cluster bootstrap (captures x scenarios, 4,000 draws), exact McNemar, Cohen's h, Holm correction over 216 comparisons. Alerts within a capture/scenario are dependent; small CIs on 8 techniques should not be over-read.
