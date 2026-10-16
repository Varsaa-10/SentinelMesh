# Response to the IEEE Access revision list (16 Oct 2026)

Status: **done** = addressed in the manuscript and code; **partly** = addressed as far as the
existing data allows, with the remaining work listed; **team** = needs new lab runs or author input.

| # | Requirement | Status | What changed |
|---|---|---|---|
| 1 | Results and table consistency | done | Every table, figure and number in the text was recomputed from the result files by the scripts listed in `REPRODUCE.md`, then checked by an independent pass against those files. Thirteen small discrepancies and several over-strong sentences were corrected (e.g. per-capture vs per-subnet counts, 280 = 8 x 35 copied-description corpora, confidence 0.59 vs 0.62, the Defense Evasion / Stealth naming, the S8 variant's container). The perturbation table was regenerated from repository code (identical values) and now shows both directions. |
| 2 | Statistical validity | done | New Statistics paragraph and `eval/clustered_stats.py`: per-capture accuracy (mean, min, max), a two-way cluster bootstrap over captures and scenarios (10,000 resamples, seed 20261016), exact sign tests over captures and over subnets, and paired intervals for knowledge-base effects. Wilson intervals were removed from the figures. The text now says that the subnet is the more honest independent unit and that five units cannot give p < 0.0625. |
| 3 | Held-out attack evaluation | partly / team | Detection gaps and retrieval errors are now reported in separate columns. More variants across subnets and captures need new runs: rerun `attack_scripts_heldout/` on each of the five subnets, two captures each, using the planned S9 method (`tar`), and send the frozen run folders. |
| 4 | Retrieval baseline comparison | done | New Section "Sparse, dense and hybrid vectors" and Table: TF-IDF, all-MiniLM-L6-v2 cut off at 256 tokens (reproduces the earlier failure), all-MiniLM-L6-v2 reading whole records in windows (truncation fixed), and an equal-weight hybrid, all on the same alerts, queries and knowledge bases. Finding: MITRE text fails for every vector; detection text mainly helps lexical matching; tactic-first is ahead in a few dense/hybrid settings, all with low accuracy. |
| 5 | Risk score validation | done | Confidence components and weights explained (hand-set, not fitted, not a probability). Calibration over 114 settings (AUROC 0.79 / 0.78, ECE 0.07 / 0.23). Threshold sweep over 24 pairs (auto 0.30-0.50, analyst 0.50-0.70). |
| 6 | Response safety evaluation | done | Pipeline repeated on all 186 alerts of the ten test captures, four retrieval settings. Under-, over-response and unsafe automatic actions counted, including the 20 brute-force under-responses that the gate lets run automatically under every threshold pair, and the side effects of changing thresholds (8 over-responses; 10 automatic network isolations at high automatic thresholds). |
| 7 | Poisoning robustness | done | Repeated on 70 alerts (five captures, one per subnet) with clean baselines and explicit denominators. Three defences that need no trusted copy (duplicate text, alert-like text, upstream tactic check) flag every corrupted copy; false alarms on clean corpora reported. Record versioning discussed as the baseline control. |
| 8 | Reproducibility | done | `REPRODUCE.md`: software versions, data and corpus versions with checksums, dense model files with checksums, seeds, one command per table and figure. All analysis scripts and result files are in `eval/` and `eval/results/`. |
| 9 | External validation | partly | No external labelled runtime-alert collection was available. The limitation is stated plainly, claims are scoped to the lab, and a Discussion subsection separates report-level threat intelligence from runtime alerts. A second environment would need new captures. |
| 10 | RQ count | done | "five questions" -> "six questions". |
| 11 | Held-out S9 protocol | done | The planned `tar` read is the primary outcome (gap); the `cat` read is reported separately as a secondary test. Detection with planned methods: 4 of 9. |
| 12 | Claim qualification | done | Abstract, introduction, discussion, limitations and conclusion scoped to "the evaluated lab and configurations"; "never" claims restricted to word-level TF-IDF; "generally" where a pattern has exceptions. |
| 13 | References | done | All 36 entries checked against publisher, ACL Anthology, arXiv, Crossref and OpenAlex records; venues, years, pages and DOIs corrected (e.g. TechniqueRAG now ACL Findings 2025, ARTEMIS now ICLR 2026, gao2026 is the AAAI Summer Symposium). Added verified references for Sentence-BERT, MiniLM, BM25, DPR, sparse/dense retrieval, BEIR, calibration and the pigeonhole bootstrap. |
| 14 | Tables, figures, presentation | done / team | Tables re-laid out (pipeline table split into rows, perturbation table with both directions, new defence and vector tables), captions state the interval method, figures regenerated. An IEEE Access version of the manuscript is included; it was built with a public copy of the IEEE Access class, so before submission paste the source into the current official template from the IEEE Author Center, and add the corresponding author's e-mail and the author biographies with photographs. |

## Edits from the team's PDF that were kept

- Author order: Sahasra A, Gowri Ajith, Varsaa H, Dr. Deepa Nivethika S.
- Sentence "Code, captures and corpora are released." removed from the abstract.
- "where c is the confidence in the retrieval, s the severity of the scenario ..."
- Semicolons removed. Where the PDF had replaced a semicolon with a comma between two full sentences, the sentences were split instead.

## Edits from the team's PDF that were not kept

- The PDF dropped the Acknowledgment, Author Contributions, Ethics, Funding, Conflict of Interest, AI-use and Data Availability statements. IEEE requires the AI-use disclosure (now in the Acknowledgment), and the project's checklist requires the others, so they are back. In the IEEE Access version the funding statement is in the title footnote, as Access asks. Delete any you do not want.

## Needs the team

1. Held-out variants on five subnets x two captures, with the planned S9 method.
2. Corresponding author name and e-mail; author biographies and photographs (IEEE Access).
3. Confirm the author contributions sentence for Dr. Deepa Nivethika S ("supervised the work").
4. If possible, runtime alerts from a second environment for external validation.
