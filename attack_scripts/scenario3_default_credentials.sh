#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 3 - Default Credentials"
echo "========================================="

curl -s -X POST "${AUTHSERVICE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\":\"${AUTH_DEFAULT_USER}\",
        \"password\":\"${AUTH_DEFAULT_PASS}\"
    }"

echo
echo "[✓] Default credential login attempted."
