#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 7 - Credential Access"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" cat /etc/shadow >/dev/null 2>&1 || docker exec "$WEBAPP_CONTAINER" cat /etc/shadow >/dev/null

echo
echo "[✓] Sensitive file accessed."
