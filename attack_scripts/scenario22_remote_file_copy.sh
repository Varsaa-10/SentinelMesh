#!/bin/bash

echo "========================================="
echo "Scenario 22 - Launch Remote File Copy Tools in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-database sh -c '
PAYLOAD="/tmp/s22_payload.txt"
rm -f "$PAYLOAD"
trap "rm -f \"$PAYLOAD\"" EXIT
echo "sentinelmesh-s22" > "$PAYLOAD"
scp -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=2 "$PAYLOAD" root@webapp:/tmp/s22_payload.txt >/dev/null 2>&1 || true
rm -f "$PAYLOAD"
'
MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp rm -f /tmp/s22_payload.txt >/dev/null 2>&1 || true

echo
echo "[✓] Remote file copy simulation complete."
