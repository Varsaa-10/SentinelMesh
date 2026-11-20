#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 22 - Launch Remote File Copy Tools in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -e MARKER="${CONTAINER_PREFIX}-s22" "$DATABASE_CONTAINER" sh -c '
PAYLOAD="/tmp/s22_payload.txt"
rm -f "$PAYLOAD"
trap "rm -f \"$PAYLOAD\"" EXIT
echo "$MARKER" > "$PAYLOAD"
scp -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=2 "$PAYLOAD" root@webapp:/tmp/s22_payload.txt >/dev/null 2>&1 || true
rm -f "$PAYLOAD"
'
MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" rm -f /tmp/s22_payload.txt >/dev/null 2>&1 || true

echo
echo "[✓] Remote file copy simulation complete."
