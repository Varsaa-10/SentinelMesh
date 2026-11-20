#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 7 - Grafana Default Credentials & Anonymous Access"
echo "========================================="

echo
echo "[1/2] Default credential login (${GRAFANA_ADMIN_USER}/${GRAFANA_ADMIN_PASS})..."
LOGIN_RESPONSE=$(curl -s -c /tmp/grafana_cookies.txt -X POST "${GRAFANA_URL}/login" \
    -H "Content-Type: application/json" \
    -d "{\"user\":\"${GRAFANA_ADMIN_USER}\",\"password\":\"${GRAFANA_ADMIN_PASS}\"}")
echo "Response: ${LOGIN_RESPONSE}"

echo
echo "[2/2] Anonymous dashboard access (no credentials, no session)..."
ANON_RESPONSE=$(curl -s -o /dev/null -w "HTTP %{http_code}" "${GRAFANA_URL}/api/search?type=dash-db")
echo "Response: ${ANON_RESPONSE}"

echo
echo "[✓] Grafana default-credential and anonymous-access checks sent."
