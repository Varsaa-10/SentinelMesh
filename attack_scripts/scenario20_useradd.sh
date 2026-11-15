#!/bin/bash

echo "========================================="
echo "Scenario 20 - User Management Binaries (useradd)"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-database sh -c '
cleanup() { userdel sm_s20_tmp 2>/dev/null || true; }
trap cleanup EXIT
cleanup
useradd -M -s /bin/sh sm_s20_tmp
'

echo
echo "[✓] User management simulation complete."
