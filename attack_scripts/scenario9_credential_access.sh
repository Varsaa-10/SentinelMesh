#!/bin/bash

echo "========================================="
echo "Scenario 7 - Credential Access"
echo "========================================="

docker exec sentinelmesh-webapp \
    cat /etc/shadow >/dev/null

echo
echo "[✓] Sensitive file accessed."
