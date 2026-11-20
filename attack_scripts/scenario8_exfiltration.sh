#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 8 - Data Exfiltration"
echo "========================================="

docker exec "$WEBAPP_CONTAINER" \
    curl -s http://example.com >/dev/null

echo
echo "[✓] Outbound request sent."
