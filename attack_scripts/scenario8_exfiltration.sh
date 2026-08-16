#!/bin/bash

echo "========================================="
echo "Scenario 8 - Data Exfiltration"
echo "========================================="

docker exec sentinelmesh-webapp \
    curl -s http://example.com >/dev/null

echo
echo "[✓] Outbound request sent."
