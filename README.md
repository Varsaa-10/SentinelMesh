# SentinelMesh

SentinelMesh is a small Docker lab for studying how runtime security alerts from containers can be explained and acted on. Five containers carry seven planted weaknesses. Scripted attacks exploit them and two kinds of detector raise alerts. A pipeline then maps each alert to a MITRE ATT&CK technique, links the alerts into an attack graph, and proposes a response that either runs automatically or waits for a person, depending on a risk score.

The repository also holds the captures, knowledge bases and analysis scripts behind the paper below.

> The lab services are deliberately vulnerable. Run them only on a machine you control. See [Safety](#safety).

## Paper

**SentinelMesh: Detector-Aware Knowledge Makes ATT&CK Retrieval Work on Container Runtime Alerts**
Sahasra A, Gowri Ajith, Varsaa H, Dr. Deepa Nivethika S. School of Computer Science and Engineering, Vellore Institute of Technology, Chennai.

Main findings, for the evaluated lab and configurations (140 labelled test alerts from ten captures on five Docker subnets):

- With MITRE's own text as the knowledge base, retrieval fails on raw alerts with sparse, dense and hybrid vectors. Flat TF-IDF search finds 14 of 140 techniques among 36 records and none among 706.
- Adding detection text written for the lab's detectors to the eight relevant records lifts flat TF-IDF search to 121 of 140 inside the full 706-record catalogue.
- With that text and word-level TF-IDF, choosing a tactic first never beats flat search, and on raw alerts its accuracy depends on the Docker subnet.
- A retrieval error turned every brute-force alert into an automatic log entry under every routing threshold tested.
- The frozen detectors missed five of nine attack variants written after the system was frozen.

## How the pipeline works

```
attack scripts -> lab -> detectors -> query text -> retrieval -> attack graph -> risk score and routing
```

1. **Lab.** A Flask web app, a Flask authentication service using PyJWT, PostgreSQL 15, a Fluentd log collector and Grafana, on one Docker bridge network (172.30.0.0/16 by default).
2. **Attacks.** Ten scripts in `attack_scripts/`. S1 to S9 each use one technique. S10 chains S1, S3, S4, S9 and S8.
3. **Detection.** Four Falco rules watch kernel events (S5, S6, S8, S9). Five Python detectors read the services' JSON logs (S1 to S4, S7). Both write the same seven-field alert format, described in `alert_spec.md`.
4. **Query text.** Each alert is turned into one of three queries: the raw alert, the detector's title followed by the raw alert, or a rule-based rewrite into an English sentence.
5. **Retrieval.** Two retrievers search a knowledge base of ATT&CK technique records. *Tactic-first* picks the closest tactic, then ranks only that tactic's techniques. *Flat* ranks all techniques. TF-IDF is the default. A dense model (all-MiniLM-L6-v2) and an equal-weight TF-IDF/dense hybrid are also available. Each answer gets a confidence score between 0 and 1.
6. **Attack graph.** Each alert adds nodes for its container, process, network endpoint, technique and CVE, joined by four edge rules. This gives one path per scenario plus a path for the S10 chain.
7. **Risk and routing.** Risk is confidence x severity x asset criticality / 25. Below 0.40 the proposed action runs automatically, from 0.40 up to 0.60 it goes to an analyst, and from 0.60 up it goes to an administrator. Container termination never runs automatically. The executor accepts only four actions (log, isolate network, revoke token, terminate container) and only against lab containers.

| ID | Attack | Weakness | Technique | Detector |
|---|---|---|---|---|
| S1 | SQL injection login | CWE-89 | T1190 | log |
| S2 | Password guessing | CWE-307 | T1110 | log |
| S3 | Default admin login | CWE-798 | T1078 | log |
| S4 | JWT `alg=none` forgery | CVE-2022-29217 | T1212 | log |
| S5 | Direct database access | CWE-284 | T1021 | Falco |
| S6 | Log file tampering | CWE-732 | T1070 | Falco |
| S7 | Grafana default or anonymous access | CWE-306 | T1078 | log |
| S8 | Outbound exfiltration | post-exploit | T1041 | Falco |
| S9 | `/etc/shadow` read | post-exploit | T1003.008 | Falco |
| S10 | Chain S1, S3, S4, S9, S8 | several | 5 stages | both |

The full mapping, with tactics, target containers, severity and asset criticality, is in `eval/ground_truth.json`.

## Repository layout

```
docker-compose.yml        the five lab services (plus an optional tunnel profile, see Safety)
services/                 Dockerfiles and code for the lab services
attack_scripts/           S1 to S9 and the S10 chain
attack_scripts_heldout/   one variant of each of S1 to S9, written after the system was frozen
detection/falco-rules/    Falco rules and the adapter that converts Falco output to the alert format
detection/log-tail/       log detectors for S1 to S4 and S7, and the tailer that runs them
kb_master/                lab-written knowledge base: 36 technique and 16 CVE records, schema, validator
rag_engine/               retrievers, embedders, confidence score, alert rewrite rules
rag_engine/kb/            MITRE ATT&CK STIX bundle (version 20) and the corpora built from it
rag_engine/poisoning/     corrupted knowledge-base copies and the integrity scan
graph/                    attack-graph construction, graph-only baseline, tests
response/                 risk scoring, routing and the action allowlist
backend/                  FastAPI service behind the analyst dashboard
frontend/                 React dashboard (built copy in frontend/dist)
eval/                     capture harness, ground truth, analysis scripts
eval/runs/                development and test captures
eval/runs_heldout/        held-out variant capture
eval/results/             result files behind the paper's tables and figures
linux_run/                scripts for capturing runs on a Linux host
docs/                     vulnerability notes, smoke tests, analysis plan, held-out protocol
REPRODUCE.md              how to regenerate every table and figure in the paper
```

## Requirements

- Falco needs a real Linux kernel, so captures need a Linux machine or a Linux VM. Falco does not work through Docker Desktop on macOS and is unreliable on WSL2. The paper's captures used two Linux hosts (kernels 6.14 and 6.12, Docker 29.7.1 and 28.5.2, Falco 0.44.1 and 0.45.0).
- Docker with Docker Compose.
- Python 3.11 or newer. The analysis was tested with Python 3.13; exact package versions are in `REPRODUCE.md`.
- Node.js, only if you want to rebuild the dashboard.

## Getting started

### Start the lab

```bash
docker compose up -d
```

`./reset_lab.sh` (or `reset_lab.ps1` on Windows) tears everything down, rebuilds the images without cache and starts the lab again. The services listen on 127.0.0.1 only: web app 5000, authentication service 5001, PostgreSQL 5432, Fluentd 24224, Grafana 3000.

### Run the tests

```bash
pip install -r requirements.txt
python3 -m pytest graph/tests detection/log-tail/test_detectors.py backend/test_backend.py
python3 kb_master/validate_schema.py
```

These do not need the lab to be running.

### Open the dashboard

```bash
pip install -r requirements.txt -r backend/requirements.txt
cd backend
python3 app.py
```

Then open http://127.0.0.1:8000/dashboard. At startup the backend loads the alerts of the reference capture (`eval/runs/20261012T140201Z`), so the dashboard has data without a running lab. Triggering attacks from the dashboard needs the lab.

To work on the dashboard itself, run `npm install` and `npm run dev` in `frontend/`. The dev server uses port 3000, which Grafana also uses, so run `npm run dev -- --port 5173` while the lab is up. `npm run build` updates `frontend/dist`.

## Capturing a run

On the Linux host, with the lab running:

```bash
sudo ./linux_run/preflight.sh
sudo ./linux_run/run_linux_baseline.sh --reset
```

`preflight.sh` checks the host tools, compiles the Falco rules, and checks container addresses, log paths and Grafana settings. `run_linux_baseline.sh` resets the lab, starts Falco and the log detectors, runs all ten attack scripts and writes a new folder under `eval/runs/`. The folder holds the alerts, a manifest (Git commit, hashes of rule files, attack scripts and container images) and a check report, `run_report.txt`. Read the report before using a run.

To move the lab to another subnet, for example 10.20.0.0/16:

```bash
./linux_run/set_subnet.sh 10.20
```

The script rewrites the five files that contain the lab address and refuses to finish if an old address remains. The protocol for the held-out variants is in `docs/held_out_step6_README.md`.

## Reproducing the paper

`REPRODUCE.md` lists the software versions, the data with checksums, the dense model files, the fixed seeds, and one command for each table and figure. Everything runs on a laptop CPU.

The captures used in the paper:

| Set | Location |
|---|---|
| Development (5 runs, 18 August and 12 October 2026) | `eval/runs/20260818T052007Z`, `20260818T052217Z_chaintagged`, `20261012T030225Z_chaintagged`, `20261012T031032Z_chaintagged`, `20261012T140201Z` (reference run) |
| Test (10 runs, 14 October 2026, two on each of five subnets) | `eval/runs/20261014T*` |
| Held-out variants | `eval/runs_heldout/20261015T051907Z` |
| Excluded runs, with reasons | `eval/runs_excluded.txt`, `eval/runs_heldout_excluded.txt` |

The `_chaintagged` folders are copies of the raw captures with the S10 chain tag added; the raw captures sit next to them. `eval/runs/20260817T025000Z` and `eval/runs/20260827T024810Z` are earlier captures cited in `rag_engine/README.md` and are not used in the paper.

The code also includes a simulated reviewer (`eval/feedback_loop.py`) and a simulated autonomous agent (`eval/autonomous_baseline.py`). The paper reports no results from either.

## Safety

- The services are deliberately vulnerable: SQL injection, no login rate limit, default passwords, a PyJWT release affected by CVE-2022-29217, a database that trusts every host on its network, a world-writable log directory and anonymous Grafana access. `docs/vulnerabilities/` describes each one.
- All host ports bind to 127.0.0.1. The lab network allows outbound traffic, because S8 sends one HTTP request to example.com.
- The `tunnel` profile in `docker-compose.yml` (nginx plus ngrok) makes the services reachable from the internet. It starts only with `docker compose --profile tunnel up` and needs an ngrok token in `.env`. Do not use it while running attacks or on a network you do not control.
- The response executor accepts only the four allowed actions and only against lab containers.

## More documentation

| File | Contents |
|---|---|
| `alert_spec.md` | the shared alert format |
| `docs/vulnerabilities/` | each planted weakness, per service |
| `docs/scenario_mapping.md` | scenario table (`eval/ground_truth.json` is the authoritative copy) |
| `docs/evidence/` | notes from the early exploit tests of S1, S5, S6 and S8 |
| `docs/smoke-test-results.md` | manual exploit checks for each weakness |
| `docs/analysis_plan_v3.md` | the analysis plan fixed before the test captures |
| `docs/held_out_step6_README.md` | protocol for the held-out variants |
| `kb_master/README.md` | knowledge-base record format and freeze policy |
| `rag_engine/README.md` | retrieval engine notes |
| `graph/docs/graph_output_spec.md` | attack-graph output format |
| `CHANGELOG.md` | changes to the lab infrastructure |

## Authors

Gowri Ajith built the Docker lab and its planted weaknesses, curated the knowledge base and its schema, and implemented attack-graph reconstruction. Varsaa H wrote the detection rules and attack scripts, built the two retrievers and the confidence score, and implemented risk scoring and tiered approval. Sahasra A wrote the ground truth and lab reset tooling, ran the detection-only baseline, built the corrupted corpora and the integrity scan, and ran the final evaluation. Dr. Deepa Nivethika S supervised the work.

## License

No license has been chosen yet.