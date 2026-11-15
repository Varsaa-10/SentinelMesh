# SentinelMesh: plan for the second data collection (environments, techniques, benign traffic)

Status: frozen. Prerequisite (section 1) done in commit 76efd0d: all 19 stock rules parse, the 9 lab detectors' generated knowledge is byte-identical, and pytest passes on Linux (149 passed, 3 skipped).
Code state at drafting: commit `f82808c` (main).

## 0. Rules for this round

1. **Freeze first.** After the tag `freeze-before-env2`, no change to:
   - detector rules
   - generated knowledge or the knowledge generator
   - DAHR weights
   - the calibrator or the abstention threshold
   - gate rules or routing thresholds
   - query builders or ground-truth entries
2. **Log any unavoidable change.** Record it in section 9 with the date, the reason and the captures it affects. Report results with and without it.
3. **Use the existing development data only.** Development data is the existing development captures and nothing else. All new captures are test data.
4. **Keep the labs isolated.** Every lab runs on a host-only or internal network in a VM that can be thrown away. No port forwarding and no tunnel.

## 1. Prerequisite (before the freeze): read Falco's stock rules

On 15 Nov 2026, `falco_cond.parse_condition` could not parse any of the 19 stock rules in section 3. With macros expanded by hand, 7 of 19 parsed. The parser has to be extended to handle:
- macro references, including bare boolean macros such as `spawned_process` and `container`
- indexed fields such as `proc.aname[2]`
- unquoted list items containing brackets or colons, such as `runc:[0:PARENT]`
- the operators the stock rules use that it does not yet support

**Acceptance:**
- all 19 rules in section 3 parse
- the existing 9 lab detectors give byte-identical generated knowledge
- `python3 -m pytest -q` passes on Linux

Commit this before the freeze.

Rules that still cannot be parsed after this work stay in the study as detectors. They get no generated knowledge, and the paper reports them as not covered.

## 2. Environments

| Id | Host | Container runtime | Configuration differences | Captures |
|---|---|---|---|---|
| E1 | Existing lab setup (Ubuntu VM, Docker) | Docker | none (reference) | 6 attack + 2 benign-only |
| E2 | Ubuntu 24.04 VM | Docker (latest stable) | new passwords, ports, log paths and container names | 6 attack + 2 benign-only |
| E3 | Fedora VM | Podman with podman-compose (fallback: k3s with containerd, Falco as DaemonSet) | as E2, plus rootless containers | 6 attack + 2 benign-only |

- Attack captures use three subnets per environment, two captures each (`linux_run/set_subnet.sh`).
- Each benign-only capture runs at least 1 hour.
- Record kernel, runtime and Falco versions in every `run_manifest.txt`, and keep SHA-256 checksums for every capture.

## 3. Attack scenarios

**Detectors:** Falco default rules from `falcosecurity/rules` at commit `e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428` (files `falco_rules.yaml`, `falco-incubating_rules.yaml`, `falco-sandbox_rules.yaml`). Load all three files.

**Ground truth:** the ATT&CK technique is the tag the Falco maintainers attached to the rule. The team does not assign it. Where that tag differs from what ATT&CK's own definitions suggest, the case is listed in section 4 and given to the annotators.

**Severity (1–5):** set below, before any run.

**Asset criticality:** taken from the existing ground truth:
- webapp 4
- authservice 5
- database 5
- logcollector 3
- dashboard 3

S1–S10 are unchanged and run in every environment.

| Id | Attack action (inside the target container) | Falco rule (file) | Technique (Falco tag) | Target | Sev | Crit | Expected route |
|---|---|---|---|---|---|---|---|
| S11 | Interactive shell via `docker exec -it ... sh` | Terminal shell in container (stable) | T1059 | webapp | 3 | 4 | analyst |
| S12 | `grep -r "BEGIN RSA PRIVATE" /` and `find / -name id_rsa` | Search Private Keys or Passwords (stable) | T1552.001 | webapp | 4 | 4 | admin |
| S13 | Run a binary from a memfd (Python `os.memfd_create` + exec) | Fileless execution via memfd_create (stable) | T1620 | webapp | 4 | 4 | admin |
| S14 | `gdb -p` / `strace -p` attach to the service process | PTRACE attached to process (stable) | T1055.008 | authservice | 5 | 5 | admin |
| S15 | Open a raw packet socket (`tcpdump -i eth0 -c 5`) | Packet socket created in container (stable) | T1557.002 | logcollector | 3 | 3 | auto |
| S16 | `shred`/`rm -rf` on a copy of the data directory | Remove Bulk Data from Disk (stable) | T1485 | database | 5 | 5 | admin |
| S17 | Copy a script to `/dev/shm` and execute it | Execution from /dev/shm (stable) | T1059.004 | dashboard | 3 | 3 | auto |
| S18 | Add a crontab entry | Schedule Cron Jobs (incubating) | T1053.003 | webapp | 4 | 4 | admin |
| S19 | Append a line to `~/.bashrc` | Modify Shell Configuration File (incubating) | T1546.004 | authservice | 4 | 5 | admin |
| S20 | `useradd` a new account | User mgmt binaries (incubating) | T1098 | database | 4 | 5 | admin |
| S21 | `chmod u+s` on a copied binary | Set Setuid or Setgid bit (incubating) | T1548.001 | webapp | 4 | 4 | admin |
| S22 | `scp` a file to another lab container | Launch Remote File Copy Tools in Container (incubating) | T1020 | database | 5 | 5 | admin |
| S23 | Append a key to `~/.ssh/authorized_keys` | Adding ssh keys to authorized_keys (incubating) | T1098.004 | webapp | 4 | 4 | admin |
| S24 | `cat /proc/1/environ` | Read environment variable from /proc files (incubating) | T1083 | logcollector | 2 | 3 | auto |
| S25 | `nmap` scan of the lab subnet | Launch Suspicious Network Tool in Container (incubating) | T1059 | dashboard | 2 | 3 | auto |
| S26 | Create a hidden directory and file | Create Hidden Files or Directories (sandbox) | T1564.001 | logcollector | 3 | 3 | auto |
| S27 | `echo ... \| base64 -d \| sh` | Decoding Payload in Container (sandbox) | T1132 | webapp | 4 | 4 | admin |
| S28 | `rm ~/.bash_history` | Delete or rename shell history (incubating) | T1070 | authservice | 3 | 5 | admin |
| S29 | `mount` inside a privileged debug container (disposable VM only) | Mount Launched in Privileged Container (incubating) | T1611 | debug (privileged) | 5 | 3 | admin |

- **Expected route** is the impact tier at full confidence, using risk = severity × criticality / 25: automatic below 0.40, analyst below 0.60, administrator otherwise.
- **S15, S17, S24, S25 and S26** are the scenarios where automatic action is the correct route. They test the gate's known gap.
- **S28 tests detector independence:** it is a second, independently written detector for a technique the lab already covers (T1070).
- **Counts:** the study goes from 8 to 25 techniques, and from 5 to 11 tactics.
- **Before the freeze:** for every scenario, write in `ground_truth.json` whether you expect an alert (yes/no) and why. These predictions are scored after the run.

## 4. Known ambiguous labels (given to annotators, reported in the paper)

- **S15:** a raw packet socket is tagged ARP cache poisoning (T1557.002); capturing packets fits Network Sniffing (T1040).
- **S24:** reading `/proc/*/environ` is tagged File and Directory Discovery (T1083); credential access (T1552) also fits.
- **S25:** running `nmap` is tagged Command and Scripting Interpreter (T1059); Network Service Discovery (T1046) fits better.
- **S27:** decoding a payload is tagged Data Encoding (T1132); Deobfuscate/Decode Files (T1140) also fits.
- **S20:** `useradd` is tagged Account Manipulation (T1098); Create Account (T1136.001) also fits.
- **Existing cases:** listed in Supplementary Table S6 of the manuscript.

## 5. Benign workload

`benign_workload.sh` runs during every attack capture. In benign-only captures it runs alone.

**Activities:**
- correct logins
- single mistyped passwords, at most one per account per minute
- normal Grafana dashboard views
- a `pg_dump` backup from an authorised container
- log rotation
- an administrator reading configuration files
- package index updates
- `docker exec` for routine checks
- outbound HTTPS to common sites

**Scoring:**
- Every alert in a benign-only capture is a false positive.
- Alerts during attack captures that match no scenario script are counted separately.

## 6. Independent labelling

Follow `annotation/PROTOCOL.md`:
- 2–3 annotators who took no part in the project
- a new blinded packet that includes alerts from E2, E3 and the benign captures
- agreement computed by `sentinelmesh_x/annotation.py`

For item 3, the same annotators write the field rules they would expect for 4 detectors: S2, S9, S12 and S18.

## 7. Analyses (fixed now)

| Id | Outcome | Unit and clustering |
|---|---|---|
| P1 | Detection rate per scenario and environment, and agreement with the predicted yes/no | captures |
| P2 | False alarms per hour of benign activity, per rule and environment, and the share the gate routes to automatic action | captures |
| P3 | Track A and Track B P@1, R@5, MRR, nDCG@5 per environment, and leave-one-environment-out | two-way cluster bootstrap over environment and scenario |
| P4 | Leave-one-technique-out over all 25 techniques | technique clusters |
| P5 | Gate: under-escalation, over-escalation, automatic action on a wrong prediction, and automatic action where correct (S15, S17, S24, S25, S26), with τ = 0.9 and thresholds 0.40/0.60 fixed | scenario clusters |
| P6 | Calibration (Brier, 10-bin ECE) of the frozen calibrator on new data | original-alert clusters |
| P7 | Annotator agreement (Cohen's and Fleiss' kappa), and agreement with Falco tags and with system output | alerts |

Statistical conventions for all analyses:
- tests are two-sided at α = 0.05
- Holm correction within each outcome family
- exact p-values and 95% intervals
- seeds fixed in the scripts

## 8. Predictions (recorded before any run)

1. Track B top-1 stays below 5% in every environment.
2. Detector-aware retrieval stays above 90% top-1 for scenarios whose rule parses, and is lower for rules without generated knowledge.
3. The shell, package-management and network-tool rules raise false alarms during the benign workload.
4. With τ = 0.9, the gate routes few of S15, S17, S24, S25 and S26 to automatic action, so it over-escalates there.
5. Detection is the same across subnets within an environment, and may differ between E1, E2 and E3 for the Podman and k3s setups.

## 9. Change log after the freeze

| Date | Change | Reason | Captures affected |
|---|---|---|---|
| 2026-11-15 | Added `S11`–`S29` entries to `eval/ground_truth.json` (`falco-stock` source, rule metadata, pre-run `expected_alert` predictions and reasons; `S1`–`S10` unchanged) | implements plan section 3/5; no capture taken yet | all new ENV2 captures (none taken yet) |
| 2026-11-15 | Added `attack_scripts/scenario11_*.sh`–`scenario29_*.sh`, updated service Dockerfiles (`cron`, `postgresql-client` on `webapp`; `gdb`, `strace` on `authservice`; `tcpdump` on `logcollector`; `coreutils`, `openssh-client`, `shadow` on `database`; `nmap` on `dashboard`), updated `docker-compose.yml`, and added `docker-compose.debug.yml` for `--privileged-debug` `S29` | implements plan section 3/5; no capture taken yet | all new ENV2 captures (none taken yet) |
| 2026-11-15 | Added `linux_run/benign_workload.sh --duration MINUTES` covering all section 5 benign activities | implements plan section 3/5; no capture taken yet | all new ENV2 captures and benign-only captures (none taken yet) |
| 2026-11-15 | Updated `eval/harness.py` (`--include-stock-falco`, `S11`–`S28` + gated `S29 --privileged-debug`, per-scenario UTC windows, `--benign-minutes N`, `--benign-only`) and `detection/falco-rules/falco_shim.py` (empty `scenario` plus `falco_tags` on non-`sN` rules; lab rules unchanged) | implements plan section 3/5; no capture taken yet | all new ENV2 captures (none taken yet) |
| 2026-11-15 | Analysis clarification (`eval/attribute.py`): an alert belongs to scenario `X` iff its timestamp falls in `X`'s recorded window and its container matches `X`'s target (otherwise `"unattributed"`); attributed alerts take `X`'s ground-truth technique from `eval/ground_truth.json` while keeping Falco tags separately for comparison; every alert in a benign-only capture is a false positive | implements plan section 3/5; no capture taken yet | all new ENV2 analysis runs (none taken yet) |
| 2026-11-15 | Added benign action log (`$OUT/benign_actions.jsonl` written by `linux_run/benign_workload.sh` with `OUT` passed from `eval/harness.py`) recording `start`, `end`, `container` (or `host`), and `action` per benign action | analysis clarification / reproducibility; no capture taken yet | all new ENV2 and benign captures (none taken yet) |
| 2026-11-15 | Updated `eval/attribute.py` and `eval/harness.py` for benign overlap attribution (`attribution="ambiguous"` within ±2 s of a matching benign action inside a scenario window keeping both candidate labels; `attribution="benign"` false positive outside scenario windows) and dual reporting (ambiguous excluded vs counted as attack) | analysis clarification / reproducibility; no capture taken yet | all new ENV2 analysis runs (none taken yet) |
| 2026-11-15 | Pinned base image digests across `services/{webapp,authservice,logcollector,database,dashboard}/Dockerfile` (`python:3.11-slim@sha256:07d4824...`, `fluentd:v1.16-1@sha256:1ad8ae3...`, `postgres:15-alpine@sha256:23799e5...`, `grafana/grafana:13.3.1@sha256:0615ec4...`) and `docker-compose.debug.yml` (`alpine:3.19@sha256:6baf435...`); updated `eval/harness.py` to write running container image digests to `run_manifest.txt`, and fixed `docker-compose.yml` header comment (`127.0.0.1`) | analysis clarification / reproducibility; no capture taken yet | all new ENV2 builds and captures (none taken yet) |
