#!/bin/bash

echo "========================================="
echo "Scenario 7 - Credential Access"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp cat /etc/shadow >/dev/null 2>&1 || docker exec sentinelmesh-webapp cat /etc/shadow >/dev/null

echo
echo "[✓] Sensitive file accessed."
