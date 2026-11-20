#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 15 - Packet Socket Created in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -u 0 "$LOGCOLLECTOR_CONTAINER" timeout 5 tcpdump -i eth0 -c 5 >/dev/null 2>&1 || true

echo
echo "[✓] Packet capture simulation complete."
