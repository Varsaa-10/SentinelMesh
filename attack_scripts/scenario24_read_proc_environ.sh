#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 24 - Read Environment Variable from /proc Files"
echo "========================================="

PROC_USER="$(docker inspect -f '{{.Config.User}}' "$LOGCOLLECTOR_CONTAINER" 2>/dev/null | tr -d '[:space:]' || true)"
if [ -n "$PROC_USER" ]; then
    MSYS_NO_PATHCONV=1 docker exec -u "$PROC_USER" "$LOGCOLLECTOR_CONTAINER" cat /proc/1/environ >/dev/null
else
    MSYS_NO_PATHCONV=1 docker exec "$LOGCOLLECTOR_CONTAINER" cat /proc/1/environ >/dev/null
fi

echo
echo "[✓] /proc/1/environ read complete."
