#!/usr/bin/env bash
# Usage:  sudo ./linux_run/run_linux_baseline.sh [--reset]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

if [ "${1:-}" = "--reset" ]; then
  echo ">> resetting lab"
  ./reset_lab.sh
  echo ">> waiting 30s for healthchecks + Grafana startup"; sleep 30
fi

"$HERE/preflight.sh"
source "$HERE/.paths.env"
touch "$WEBAPP_LOG" "$AUTH_LOG"

BEFORE="$(ls -1 eval/runs 2>/dev/null | sort | tail -n1 || true)"
PY="$(command -v python3)"
echo ">> starting harness"
"$PY" eval/harness.py \
  --ground-truth eval/ground_truth.json \
  --falco-rules-dir detection/falco-rules \
  --falco-shim detection/falco-rules/falco_shim.py \
  --tailer detection/log-tail/tailer.py \
  --webapp-log "$WEBAPP_LOG" \
  --auth-log "$AUTH_LOG" \
  --grafana-detector detection/log-tail/scenario7_detector.py \
  --grafana-container sentinelmesh-dashboard \
  --auto-run-attacks \
  --attack-scripts-dir attack_scripts \
  --chain-script scenario10_chain.sh \
  --run-dir eval/runs || echo "!! harness exited non-zero — continuing to report"

RUN="$(ls -1d eval/runs/2* | sort | tail -n1)"
[ "$(basename "$RUN")" != "$BEFORE" ] || { echo "no new run folder was created"; exit 1; }

{
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "host: $(uname -srm)"
  echo "falco: $(falco --version | head -n1)"
  echo "docker: $(docker --version)"
  echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo n/a)"
  sha256sum detection/falco-rules/*.yaml eval/ground_truth.json attack_scripts/* docker-compose.yml
  for c in $(docker ps --format '{{.Names}}' | grep '^sentinelmesh-'); do
    echo "$c $(docker inspect -f '{{.Config.Image}} {{.Image}}' "$c")"
  done
  docker compose ps
} > "$RUN/run_manifest.txt" 2>&1 || true

"$PY" "$HERE/check_run.py" "$RUN" | tee "$RUN/run_report.txt" || true
echo; echo "Run folder: $RUN"
echo "Review run_report.txt BEFORE freezing."
