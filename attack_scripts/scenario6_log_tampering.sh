#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 6 - Log Tampering"
echo "========================================="

docker exec "$LOGCOLLECTOR_CONTAINER" \
    sh -c "echo 'ATTACK' > '${LOG_DIR}/test.log'"

echo
echo "[✓] Log file modified."
