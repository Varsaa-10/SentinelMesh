#!/bin/bash

echo "========================================="
echo "Scenario 6 - Log Tampering"
echo "========================================="

docker exec sentinelmesh-logcollector \
    sh -c 'echo "ATTACK" > /var/log/sentinelmesh/test.log'

echo
echo "[✓] Log file modified."
