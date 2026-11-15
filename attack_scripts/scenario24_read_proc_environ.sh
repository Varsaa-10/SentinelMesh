#!/bin/bash

echo "========================================="
echo "Scenario 24 - Read Environment Variable from /proc Files"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -u 0 sentinelmesh-logcollector cat /proc/1/environ >/dev/null

echo
echo "[✓] /proc/1/environ read complete."
