#!/bin/bash

echo "========================================="
echo "SentinelMesh Scenario 10"
echo "Complete Attack Chain"
echo "========================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo "[1/5] SQL Injection"
bash "$SCRIPT_DIR/scenario1_sqli.sh"

sleep 2

echo
echo "[2/5] Default Credentials"
bash "$SCRIPT_DIR/scenario3_default_credentials.sh"

sleep 2

echo
echo "[3/5] JWT Algorithm Confusion"
python3 "$SCRIPT_DIR/scenario4_jwt_confusion.py"

sleep 2

echo
echo "[4/5] Credential Access"
bash "$SCRIPT_DIR/scenario9_credential_access.sh"

sleep 2

echo
echo "[5/5] Data Exfiltration"
bash "$SCRIPT_DIR/scenario8_exfiltration.sh"

echo
echo "========================================="
echo "Attack chain completed successfully."
echo "========================================="
