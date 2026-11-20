#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 18 - Schedule Cron Jobs"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -e MARKER="${CONTAINER_PREFIX}-s18" "$WEBAPP_CONTAINER" sh -c '
HAD_CRON=0
BACKUP="/tmp/s18_cron_backup"
rm -f "$BACKUP"
if crontab -l > "$BACKUP" 2>/dev/null; then
    HAD_CRON=1
fi
cleanup() {
    if [ "$HAD_CRON" -eq 1 ] && [ -f "$BACKUP" ]; then
        grep -v "$MARKER" "$BACKUP" | crontab - 2>/dev/null || true
    else
        crontab -r 2>/dev/null || true
    fi
    rm -f "$BACKUP"
}
trap cleanup EXIT
(grep -v "$MARKER" "$BACKUP" 2>/dev/null || true; echo "* * * * * true # $MARKER") | crontab -
crontab -l >/dev/null 2>&1 || true
'

echo
echo "[✓] Scheduled cron job simulation complete."
