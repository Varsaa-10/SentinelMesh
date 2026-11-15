#!/bin/bash

echo "========================================="
echo "Scenario 12 - Search Private Keys or Passwords"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp timeout 4 grep -r "BEGIN RSA PRIVATE" / </dev/null >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp timeout 6 find / -name id_rsa </dev/null >/dev/null 2>&1 || true

echo
echo "[✓] Private key and password search complete."
