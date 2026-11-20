#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 20 - User Management Binaries (useradd)"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$DATABASE_CONTAINER" sh -c '
cleanup() { userdel sm_s20_tmp 2>/dev/null || true; }
trap cleanup EXIT
cleanup
useradd -M -s /bin/sh sm_s20_tmp
'

echo
echo "[✓] User management simulation complete."
