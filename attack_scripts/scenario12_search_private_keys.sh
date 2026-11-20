#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 12 - Search Private Keys or Passwords"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" timeout 4 grep -r "BEGIN RSA PRIVATE" / </dev/null >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" timeout 6 find / -name id_rsa </dev/null >/dev/null 2>&1 || true

echo
echo "[✓] Private key and password search complete."
