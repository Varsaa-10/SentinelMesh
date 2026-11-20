#!/usr/bin/env bash
# Usage:  sudo [RUN_DIR=eval/runs] ./linux_run/run_linux_baseline.sh [--reset] [harness args...]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
# shellcheck source=./lab_env.sh
. "$HERE/lab_env.sh"

if [ "${1:-}" = "--reset" ]; then
  echo ">> resetting lab"
  ./reset_lab.sh
  echo ">> waiting up to 180s for webapp /health, authservice /health, and Grafana /api/health..."
  WEBAPP_HEALTH_URL="${WEBAPP_URL}/health"
  AUTHSERVICE_HEALTH_URL="${AUTHSERVICE_URL}/health"
  GRAFANA_HEALTH_URL="${GRAFANA_URL}/api/health"
  waited=0
  while true; do
    webapp_ok=0
    auth_ok=0
    grafana_ok=0
    curl -sf -m 2 "$WEBAPP_HEALTH_URL" >/dev/null 2>&1 && webapp_ok=1 || true
    curl -sf -m 2 "$AUTHSERVICE_HEALTH_URL" >/dev/null 2>&1 && auth_ok=1 || true
    curl -sf -m 2 -o /dev/null "$GRAFANA_HEALTH_URL" >/dev/null 2>&1 && grafana_ok=1 || true
    if [ "$webapp_ok" -eq 1 ] && [ "$auth_ok" -eq 1 ] && [ "$grafana_ok" -eq 1 ]; then
      echo ">> all services healthy after ${waited}s"
      break
    fi
    if [ "$waited" -ge 180 ]; then
      down=""
      [ "$webapp_ok" -eq 0 ] && down="$down webapp($WEBAPP_HEALTH_URL)"
      [ "$auth_ok" -eq 0 ] && down="$down authservice($AUTHSERVICE_HEALTH_URL)"
      [ "$grafana_ok" -eq 0 ] && down="$down grafana($GRAFANA_HEALTH_URL)"
      echo "ERROR: timed out after 180s waiting for service health; still down:${down}" >&2
      exit 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
  shift
fi

"$HERE/preflight.sh"
source "$HERE/.paths.env"
touch "$WEBAPP_LOG" "$AUTH_LOG"

RUN_DIR="${RUN_DIR:-eval/runs}"
RUN_DIR="${RUN_DIR%/}"
BEFORE="$(ls -1 "$RUN_DIR" 2>/dev/null | sort | tail -n1 || true)"
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
  --grafana-container "$DASHBOARD_CONTAINER" \
  --auto-run-attacks \
  --attack-scripts-dir attack_scripts \
  --chain-script scenario10_chain.sh \
  --run-dir "$RUN_DIR" \
  "$@" || echo "!! harness exited non-zero — continuing to report"

RUN="$(ls -1d "$RUN_DIR"/2* | sort | tail -n1)"
[ "$(basename "$RUN")" != "$BEFORE" ] || { echo "no new run folder was created"; exit 1; }

{
  echo "env_id: ${ENV_ID}"
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "host: $(uname -srm)"
  echo "falco: $(falco --version | head -n1)"
  echo "docker: $(docker --version)"
  echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo n/a)"
  sha256sum detection/falco-rules/*.yaml detection/falco-stock/*.yaml linux_run/benign_workload.sh eval/attribute.py eval/ground_truth.json attack_scripts/* docker-compose.yml env/*.env
  for c in $(docker ps --format '{{.Names}}' | grep "^${CONTAINER_PREFIX}-"); do
    echo "$c $(docker inspect -f '{{.Config.Image}} {{.Image}}' "$c")"
  done
  docker compose ps
} >> "$RUN/run_manifest.txt" 2>&1 || true

"$PY" "$HERE/check_run.py" "$RUN" | tee "$RUN/run_report.txt" || true
echo; echo "Run folder: $RUN"
echo "Review run_report.txt BEFORE freezing."
