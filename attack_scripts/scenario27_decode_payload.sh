#!/bin/bash

echo "========================================="
echo "Scenario 27 - Decoding Payload in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp sh -c 'echo "ZWNobyBzMjcK" | base64 -d | sh >/dev/null'

echo
echo "[✓] Base64 payload decoding complete."
