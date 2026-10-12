#!/bin/bash
echo "========================================="
echo "Scenario 7 - Grafana Default Credentials & Anonymous Access"
echo "========================================="

GRAFANA_URL="http://localhost:3000"

echo
echo "[1/2] Default credential login (admin/admin)..."
LOGIN_RESPONSE=$(curl -s -c /tmp/grafana_cookies.txt -X POST "${GRAFANA_URL}/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin","password":"admin"}')
echo "Response: ${LOGIN_RESPONSE}"

echo
echo "[2/2] Anonymous dashboard access (no credentials, no session)..."
ANON_RESPONSE=$(curl -s -o /dev/null -w "HTTP %{http_code}" "${GRAFANA_URL}/api/dashboards/home")
echo "Response: ${ANON_RESPONSE}"

echo
echo "[✓] Grafana default-credential and anonymous-access checks sent."
