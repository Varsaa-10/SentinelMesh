# SentinelMesh: Final Evaluation Results

Run date: 2026-10-12. Source alerts: `eval/runs/20261012T140201Z/alerts.jsonl`
(18 alerts, 5 tagged as the S10 chain by the harness). Results:
`eval/runs/20261012T140420Z_FINAL/final_evaluation_results.json`.
Reproduce: `python3 eval/final_evaluation.py --alerts eval/runs/20261012T140201Z/alerts.jsonl`

## Read this first: what is and is not measured

| Item | Status |
|---|---|
| Baselines 1-4, graph reconstruction, routing | Computed from the real lab alert capture |
| Baseline 5 (autonomous agent) | **Simulated stand-in.** Its 44.4% unsafe rate is a property of the simulation and alert set, not a measurement |
| Reviewer in the adaptation experiment | **Simulated.** The "unsafe auto action" drop shows the loop reacting to simulated rejections, not a safety gain |
| Technique retrieval accuracy | 100% uses *normalized* alert text built by hand-written keyword rules (`rag_engine/src/alert_normalizer.py`) written with knowledge of the scenarios. Raw-text accuracy is lower, shown below |
| Routing thresholds (0.40 / 0.60) | Policy choices fitted to this lab's score range (0.34-0.67), not learned |

## Results

### Baseline 1: Falco only
9/9 single scenarios detected; the S10 chain fired all stages
(`BASELINE_1_FROZEN_linux.json`). The older August file (8/8, no S7) is archived
as superseded in `eval/archive/` and must not be quoted.

### Baseline 2: retrieval (technique mapping), 14 alerts
| Query text | Two-layer | Flat |
|---|---|---|
| Normalized (used by the system) | 14/14 (100%) | 14/14 (100%) |
| Raw alert text | 10/14 (71.4%) | 12/14 (85.7%) |

On raw text the two-layer retriever mis-maps S2 (T1078, truth T1110), S4 (T1078,
truth T1212) and S9 (T1082, truth T1003.008). Normalization removes those errors.
Mean latency is about 1.4 ms (normalized, two-layer).

### Baseline 3: graph only
22 nodes, 12 edges, **10 attack paths**: one per scenario S1-S9, plus S10, which is
reconstructed from alerts tagged `chain_id="S10"` as S1 -> S3 -> S4 -> S9 -> S8
(T1190, T1078, T1212, T1003.008, T1041).

### Baseline 4: full system (RAG + graph + tiered approval), 18 alerts
Routing: **3 auto, 11 analyst, 4 admin.** Out-of-scope action blocked: yes.

| Scenario | Technique | Risk score | Action | Route |
|---|---|---|---|---|
| S1 | T1190 | 0.416 | log_only | analyst |
| S2 | T1110 | 0.349 | kill_container | analyst |
| S3 | T1078 | 0.541 | log_only | analyst |
| S4 | T1212 | 0.669 | revoke_token / kill_container (chain) | admin |
| S5 | T1021 | 0.535 | isolate_network | analyst |
| S6 | T1070 | 0.336 | log_only | auto |
| S7 | T1078 | 0.355 | log_only | auto |
| S8 | T1041 | 0.477 | kill_container | analyst |
| S9 | T1003.008 | 0.616 | revoke_token / kill_container (chain) | admin |

`kill_container` is never auto-executed. Alerts in the S10 chain are scored with the
chain's path length (5), which escalates S4 and S9 to `kill_container`.

### Baseline 5: autonomous agent (SIMULATED)
No RAG, no approval gate; all 18 decisions auto-executed; 8 judged unsafe (44.4%).
Simulated agent, so this is illustrative only. The rate moved from 31.6% to 44.4%
when the alert set changed, which shows how sensitive it is to the stand-in.

### Ablations
- **No RAG grounding:** falls back to graph-only (Baseline 3).
- **No graph reconstruction (path length forced to 1):** routing distribution is
  unchanged (3/11/4). Graph escalation changes the selected action for chain alerts
  but did not change the routing tier on this alert set.
- **No tiered approval:** all 18 would auto-execute; the ablation flags 16 as
  would-be-unsafe (severity >= 4) versus 3 auto-routed in the full system. Those 3 are
  `log_only` actions, so the severity-based flag overstates their risk.

### Adaptation experiment (SIMULATED reviewer)
| | First iteration | Last iteration |
|---|---|---|
| Unnecessary approvals | 7 | 7 |
| Unsafe auto actions (auto-routed and rejected) | 2 | 0 |
| Mean response time (s) | 84.0 | 41.9 |

Threshold convergence score 0.024. The unsafe-action drop and the response-time
gain come from the loop tightening thresholds after simulated rejections.
Unnecessary approvals did not improve.

### Poisoning runs
Five variants loaded (mislabeled CVE, fake entry, near-duplicate, adversarial
embedding, stale/contradictory); results are in `rag_engine/poisoning/`.

## Known limitations
1. Normalization rules are hand-written; a different alert set may not be covered.
2. Severity and asset criticality are per-scenario constants from `ground_truth.json`,
   so risk scores vary mostly with retrieval confidence.
3. The routing thresholds were fitted to this scenario set.
4. The Baseline 5 agent and the adaptation reviewer are simulated.
5. The graph ablation shows no routing difference on this alert set.
6. One lab capture of 18 alerts; no repeated captures, so no variance estimate.
