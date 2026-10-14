# SentinelMesh v3: Pre-Registered Statistical Analysis Plan (W9)

**Date Committed:** 2026-10-14  
**Authors:** SentinelMesh Research Team (@Jayasankar, Gowri, Varsaa, Sahasra)  
**Status:** Pre-registered before execution of W1–W4 upgrades  

---

## 1. Overview & Research Hypotheses

This document establishes the pre-registered protocol for SentinelMesh v3 experimental upgrades. 
The central research questions under evaluation are:
1. **Corpus Scale (W1):** Does hierarchical two-layer retrieval maintain its precision advantage or reverse performance relative to flat single-shot retrieval as corpus size scales from the 36-technique toy corpus to ~200 parent techniques and the full MITRE ATT&CK Enterprise catalogue (~600+ records)?
2. **Dense Embeddings vs Sparse Lexical (W2):** Does a modern dense sentence embedding model (e.g. `all-MiniLM-L6-v2`) eliminate the vocabulary gap observed in TF-IDF lexical matching on raw detector alerts?
3. **Variance Across Captures (W3):** Are accuracy and latency estimates robust across repeated network captures and Docker subnets?
4. **Generalization to Held-Out Variants (W4):** Do rewrite rules and detector titles overfit the 9 development scenarios, or do they generalize to held-out attack variants?
5. **Downstream Pipeline Impact (W5):** When retrieval fails on raw alerts, does feeding the retrieved tactic into risk assessment and action selection induce unsafe automated actions or out-of-scope executions?
6. **Tactic Fallback (W6):** Does low-confidence fallback (H-TechniqueRAG style) prevent catastrophic Layer 1 routing errors?
7. **Adversarial Poisoning at Scale (W7):** Do tactic summaries protect or concentrate susceptibility to poisoned knowledge-base entries under large-scale query loads?

---

## 2. Alert Selection Rule & Dataset Scope

To ensure non-cherry-picked evaluation across repeated runs:
- **Baseline Scenario Set:** Scenarios S1 through S9 (single attacks) and S10 (multi-stage attack chain spanning S1 -> S3 -> S4 -> S9 -> S8).
- **Inclusion Criteria:** An alert is included in the evaluation benchmark if:
  1. It originates from Falco syscall rules or the log-tail detectors mapped to S1–S10.
  2. It contains a valid target container ID mapped to the lab docker network.
  3. Ground truth technique mapping exists in `eval/ground_truth.json`.
- **Query Representations:** Each alert is tested under three standardized forms:
  1. `raw`: The raw detector output text exactly as emitted by Falco / log-tail detector.
  2. `title_raw`: Detector rule name / title concatenated with the raw alert output.
  3. `rewrite` (`normalized`): Alert output pre-processed through the frozen `rag_engine/src/alert_normalizer.py` rule set.
- **Repeated Runs (W3):** Across at least 10 independent captures with rotated Docker subnets (e.g. `172.18`, `172.30`, `10.20`, `192.168.50`), yielding $\ge 140$ evaluated alerts.

---

## 3. Metrics & Statistical Procedures

### 3.1 Binomial Accuracies & Error Rates
For technique retrieval accuracy, tactic accuracy, and induced poisoning rates:
- **Point Estimate:** $\hat{p} = \frac{k}{n}$
- **Confidence Interval:** 95% Wilson Score Interval with continuity correction:
  $$\tilde{p} = \frac{k + \frac{z^2}{2}}{n + z^2}, \quad \text{CI} = \tilde{p} \pm \frac{z}{1 + \frac{z^2}{n}}\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}$$
  where $z = 1.95996$.

### 3.2 Paired Retriever Comparisons
To compare two retrieval engines evaluated on identical alert sets:
- **Primary Test:** Exact two-tailed McNemar Test using the binomial distribution:
  Given discordant pairs $b$ (Model A correct, Model B wrong) and $c$ (Model A wrong, Model B correct), under $H_0: p = 0.5$:
  $$\text{p-value} = 2 \sum_{i=0}^{\min(b, c)} \binom{b+c}{i} 0.5^{b+c}$$
- **Significance Level:** $\alpha = 0.05$. Significant if $p < 0.05$.

### 3.3 Variance Across Captures & Latency Distributions
- **Bootstrap Resampling:** 10,000 bootstrap iterations to calculate mean and 95% bootstrap percentile intervals across independent capture sessions.
- **Latency Reporting:** Mean latency and 95th percentile (p95) in milliseconds.

### 3.4 Downstream Decision Drift (W5)
- **Tactic Drift Rate:** Proportion of alerts where retrieved tactic $\ne$ ground-truth tactic.
- **Action Shift Rate:** Proportion of alerts where selected remediation changes due to retrieval error.
- **Unsafe Escalation Count:** Number of erroneous retrievals resulting in `kill_container` or `isolate_network` routed to `auto` (must remain strictly 0).

---

## 4. Falsification Criteria (What Would Count Against the Paper's Claim)

The paper's claim is that:
1. *On raw alerts, sparse tactic-first retrieval is vulnerable to stray tokens that misdirect Layer 1, but detector titles and normalization repair this.*
2. *Tactic summaries can spread poisoned knowledge entries across techniques within a tactic.*

**Results that would refute or qualify these claims:**
- **Refutation 1:** If dense embedding models (e.g. `all-MiniLM-L6-v2`) achieve $\ge 90\%$ accuracy on `raw` alerts across both flat and two-layer architectures, showing that the lexical gap was purely a sparse artifact.
- **Refutation 2:** If Two-Layer retrieval significantly outperforms Flat retrieval ($p < 0.05$, McNemar) on raw alerts at full ATT&CK scale ($\sim 600$ records), showing that hierarchy overcomes vocabulary noise when candidate space is large.
- **Refutation 3:** If the poisoned record only affects queries matching its exact vocabulary and fails to bleed into sibling techniques under tactic-first search.

If any of these refutations occur, the paper will transparently report the empirical boundary conditions and crossover points as its scientific contribution.
