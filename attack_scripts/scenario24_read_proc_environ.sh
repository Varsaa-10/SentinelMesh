#!/bin/bash

echo "========================================="
echo "Scenario 24 - Read Environment Variable from /proc Files"
echo "========================================="

PROC_USER="$(docker inspect -f '{{.Config.User}}' sentinelmesh-logcollector 2>/dev/null | tr -d '[:space:]' || true)"
if [ -n "$PROC_USER" ]; then
    MSYS_NO_PATHCONV=1 docker exec -u "$PROC_USER" sentinelmesh-logcollector cat /proc/1/environ >/dev/null
else
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-logcollector cat /proc/1/environ >/dev/null
fi

echo
echo "[✓] /proc/1/environ read complete."
