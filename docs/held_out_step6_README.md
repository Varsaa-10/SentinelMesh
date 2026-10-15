# Step 6 — Held-out variant runs

Purpose: test whether detection and retrieval still work on attack variants
the knowledge base, rewrite rules and detectors were not written for. Each
variant keeps the same planted weakness and target container as its base
scenario and changes only the method.

## The frozen rule

Do not change `kb_master/`, the rewrite rules, or the detectors while running
these. If a variant is not detected, that is a result (a detection gap), not
something to fix. Changing a detector after seeing a variant result
invalidates the test.

## What is here

- `attack_scripts_heldout/` — nine variant scripts, same filenames as
  `attack_scripts/`, so the harness picks them up unchanged. No chain (S10).
- `eval/held_out_ground_truth.json` — per variant: scenario, expected
  technique, and the predicted frozen-detector outcome (fires or gap),
  written before running.

## Predicted outcome against the frozen detectors

| Scenario | Variant | Expected |
|---|---|---|
| S1 | UNION injection (vs `OR 1=1`) | fires |
| S2 | spray across 6 accounts, 1 try each | gap |
| S3 | login as seeded `testuser` | gap |
| S4 | forged HS384 token (vs `alg:none`) | gap |
| S5 | DB connection from a different client | fires |
| S6 | in-place truncate/shred of a log | fires |
| S7 | anonymous scrape of `/api/search` | fires |
| S8 | egress from the database container | gap |
| S9 | read `/root/.ssh/id_rsa` via tar | fires |

Five generalize (the detector still catches them), four are gaps.

## Lab adaptations from the W4 designs

- S1: UNION injection, not a MySQL `SLEEP()` blind payload. The lab DB is
  PostgreSQL, where `SLEEP()` errors and logs `result=failure`, which the S1
  detector ignores. UNION returns a row, so `result=success`.
- S3: the seeded `testuser/testpass` account, not W4's `postgres_backup`.
  The lab only seeds `admin` and `testuser` (`services/database/init.sql`).
- S4: HS384 signed with the lab's hardcoded secret. Models an attacker who
  recovered the secret; produces a valid non-`none` verification.
- S8: egress from the database container, which the S8 rule does not watch.
- S9: a decoy `/root/.ssh/id_rsa` is planted first, so there is a real file
  to steal.

## Running

Bring the lab up on a clean subnet first, the same as the main captures.
Then, with Falco and the log-tail tailer running:

    sudo ./linux_run/preflight.sh && source linux_run/.paths.env
    sudo python3 eval/harness.py \
      --ground-truth eval/ground_truth.json \
      --falco-rules-dir detection/falco-rules \
      --falco-shim detection/falco-rules/falco_shim.py \
      --tailer detection/log-tail/tailer.py \
      --webapp-log "$WEBAPP_LOG" --auth-log "$AUTH_LOG" \
      --grafana-detector detection/log-tail/scenario7_detector.py \
      --grafana-container sentinelmesh-dashboard \
      --auto-run-attacks --attack-scripts-dir attack_scripts_heldout \
      --run-dir eval/runs_heldout

## Scoring

- A variant the detectors do not fire on is a detection gap. Record it; do
  not edit a detector to catch it.
- Variants that fire are scored with the same selection rule and query forms
  as the main runs.
- Compare the actual fires/gaps against the predicted column above. A
  mismatch is worth noting (for example, if S5's allowlist IPs were stale).

## Freezing

Freeze each held-out run folder the same way as the main captures:

    RUN=eval/runs_heldout/<timestamp>
    sha256sum $RUN/*.jsonl $RUN/run_manifest.txt $RUN/run_report.txt > $RUN/SHA256SUMS
    chmod -R a-w $RUN
    git add $RUN eval/held_out_ground_truth.json
    git commit -m "Held-out variant run <timestamp>"
