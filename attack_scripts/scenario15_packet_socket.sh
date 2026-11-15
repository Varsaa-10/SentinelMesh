#!/bin/bash

echo "========================================="
echo "Scenario 15 - Packet Socket Created in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -u 0 sentinelmesh-logcollector timeout 5 tcpdump -i eth0 -c 5 >/dev/null 2>&1 || true

echo
echo "[✓] Packet capture simulation complete."
