#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 25 - Launch Suspicious Network Tool in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$DASHBOARD_CONTAINER" sh -c '
set -- $(hostname -i)
IP="$1"
IFS=. read -r o1 o2 _ <<EOF
$IP
EOF
TARGETS="${o1}.${o2}.0.2-6"
nmap -sT -Pn -T4 --max-retries 1 -p 5000,5001,5432,3000,24224 "$TARGETS" >/dev/null 2>&1 || true
'

echo
echo "[✓] Network tool scan complete."
