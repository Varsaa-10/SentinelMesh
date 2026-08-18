# SentinelMesh

> A human-supervised, graph-augmented multi-agent framework for explainable container threat investigation via hierarchical RAG over MITRE ATT&CK.
>
> *(Working title carried over from the project proposal — rename freely before submission.)*

---

## Overview

Container and Kubernetes environments generate high-volume runtime telemetry, but existing monitoring stacks stop at raw alert generation: no attack-technique context, no reconstructed attack path, and no proposed remediation. Separately, RAG-grounded threat intelligence over MITRE ATT&CK has only ever been evaluated against static CTI text, never against a live running system, and is itself vulnerable to knowledge-base poisoning — a risk left unaddressed in prior work. Agentic incident-response systems, meanwhile, are either fully autonomous (inheriting the hallucination and unsafe-action risks documented in the literature) or scoped to enterprise SOC scale rather than a reproducible lab.

This project builds a small, reproducible Docker lab monitored by Falco/eBPF, feeding a pipeline that detects attacks, retrieves grounded MITRE ATT&CK context through a two-layer hierarchical RAG engine, reconstructs the attack as a graph rather than a flat timeline, and routes a risk-scored response through a tiered human-approval gate — with every stage measured, not assumed.

## What's unique

1. **Hierarchical RAG evaluated as a retrieval algorithm, not just used as a component.** Tactic-first, then technique-scoped retrieval, benchmarked against flat RAG and a graph-only baseline on live telemetry rather than static CTI text.
2. **A risk-scored, tiered approval policy that is itself the object of study.** Routing depends on retrieval confidence × action severity × asset criticality, and is measured for agreement rate, override rate, and approval latency — directly answering a documented gap where runtime approval is widely deployed in production but rarely evaluated in research.
3. **Poisoning resilience treated as a measured security property.** The RAG-backed knowledge base is tested against five distinct corruption types, reporting both unsafe-action rate and poison-detection rate rather than treating the knowledge base as a trusted black box.
4. **A feedback loop that adapts to human decisions.** Confidence weights and routing thresholds update based on accumulated analyst approve/reject/modify decisions across repeated evaluation runs, measured via reduction in unnecessary approvals, reduction in unsafe automated actions, MTTR improvement, and threshold convergence.

## Architecture

```
Docker lab (5 services)
        │
        ▼
   Monitor  ──────────────  Falco / eBPF runtime telemetry
        │
        ▼
   Detect  ───────────────  Falco rules → raw alert
        │
        ▼
   Threat-Intel / RAG  ───  Layer 1: tactic routing
        │                   Layer 2: technique retrieval + reranking
        │                   confidence score + evidence citation
        │                   (poisoning-detection check on retrieved chunks)
        ▼
   Investigation + Attack Graph
        │                   ATT&CK adjacency · CVE chains
        │                   process lineage · network flow
        ▼
   Risk-Scored Response  ── confidence × severity × asset criticality
        │
        ├── Low risk    → automatic execution, logged
        ├── Medium risk → analyst confirmation
        └── High risk   → administrator confirmation
```

Every decision made by a human at the approval stage feeds back into the confidence-weighting and routing-threshold logic for subsequent runs.

## Tech stack

| Layer | Tools |
|---|---|
| Container lab | Docker, Docker Compose |
| Runtime monitoring | Falco (v0.43+, modern eBPF driver), Falcosidekick |
| Attack simulation | Hydra, kube-hunter, kube-bench, Trivy/Grype, custom Python/Bash scripts, Atomic Red Team (where applicable) |
| Backend | Python 3.11+, FastAPI, Pydantic, SQLAlchemy/SQLModel |
| Database | PostgreSQL (+ pgvector for the knowledge base embeddings) |
| Graph layer | NetworkX |
| LLM reasoning | Claude / GPT-4-class via API, structured tool calling |
| Frontend | React + TypeScript (Vite), WebSocket live updates |
| Knowledge base sources | MITRE ATT&CK for Containers (STIX 2.1, `attack-stix-data`), NVD CVE API |

## Repository structure

```
.
├── docker-compose.yml
├── services/                  # the 5 lab services, each with one planted vulnerability
│   ├── web-app/
│   ├── auth/
│   ├── database/
│   ├── log-collector/
│   └── dashboard/
├── detection/
│   ├── falco-rules/           # one rule per scenario
│   └── attack-scripts/        # 8 single-technique + 1 multi-stage chain
├── knowledge-base/
│   ├── kb_master/              # frozen ATT&CK + CVE records (never edited in place)
│   └── poisoned-variants/      # 5 corruption-type copies
├── rag-engine/                 # two-layer hierarchical retrieval + confidence scoring
├── graph/                      # attack-graph construction + graph-only baseline
├── response/                   # risk scoring, action executor, allowlist/kill-switch
├── evaluation/
│   ├── ground_truth.json
│   ├── baselines/               # Falco-only, flat-RAG, graph-only, full system, autonomous-agent
│   ├── ablation/
│   ├── poisoning-runs/
│   └── results/                 # timestamped run folders
├── backend/                     # FastAPI app, WebSocket, decision logging
├── frontend/                    # React dashboard + approval queue
└── scripts/
    └── reset_lab.sh
```

## Getting started

**Prerequisites:** Docker and Docker Compose. Falco requires a real Linux kernel (native Linux, a Linux VM, or a Linux VPS — it does not work through Docker Desktop's virtualization on Mac, and is unreliable on Windows/WSL2).

```bash
git clone <repo-url>
cd <repo>
docker compose up -d
./scripts/reset_lab.sh          # returns the lab to a clean state
```

No manual configuration steps should be required after `docker compose up` — if any are, that's a bug in the lab, not an expected setup step.

## Attack scenarios

Nine scripted scenarios (8 single-technique + 1 multi-stage chain), each mapped to a specific MITRE ATT&CK technique and a planted vulnerability in one of the five lab services. Full mapping lives in `evaluation/ground_truth.json`.

## Evaluation

**Baselines:**
1. Falco-only (raw alerts, no RAG/graph)
2. Falco + flat RAG (single-stage retrieval)
3. Falco + graph-only (attack-graph reconstruction, no RAG grounding)
4. Full system
5. Fully-autonomous LLM agent (tool access, no RAG grounding, no approval gate) — isolates the value of the approval gate specifically

**Metrics:** retrieval accuracy, investigation completeness, MTTD/MTTR, false-positive rate, analyst workload, human agreement/override rate and approval latency, unsafe-action rate, poison-detection rate, and the four feedback-loop adaptation metrics (approval reduction, unsafe-action reduction, MTTR improvement, threshold convergence).

**Ablation:** RAG, graph, and tiered-approval are each removed individually to isolate their marginal contribution.

Results are written to timestamped run folders under `evaluation/results/` and validated with a reproducibility check on a fresh clone before being reported.

## Team & execution plan

Built by a 3-person team over 3 weeks, one module per week, with each person holding a consistent role (Systems/Infra, Algorithms/Core Logic, Evaluation/Safety) across all three modules. See `docs/three_week_execution_plan.md` for the full day-by-day breakdown, shared interface contracts, and per-person deliverables.

| Week | Module | Focus |
|---|---|---|
| 1 | Lab Infrastructure & Detection | Docker lab, Falco rules, attack scripts, ground truth, Baseline 1 |
| 2 | Threat-Intel RAG & Knowledge Base | Curated KB, two-layer RAG engine, flat-RAG baseline, poisoned KB variants |
| 3 | Attack-Graph, Response & Evaluation | Graph reconstruction, risk-scored response, feedback loop, autonomous baseline, full evaluation |

## Related work

A curated literature review of 41 papers spanning container security, agentic AI in cybersecurity, RAG-grounded threat intelligence, and human-AI approval studies is maintained separately (see `docs/literature_review.xlsx`).

## Status

Research prototype under active development. Not intended for use against production systems — the lab is isolated, has zero internet-facing ports, and the action executor is restricted to a hard-coded allowlist scoped to the lab's own Docker network.

## License

*(Add license before publishing — MIT or Apache 2.0 are common choices for research-artifact repos.)*