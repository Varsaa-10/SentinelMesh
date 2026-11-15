#!/bin/bash

echo "========================================="
echo "Scenario 18 - Schedule Cron Jobs"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp sh -c '
HAD_CRON=0
BACKUP="/tmp/s18_cron_backup"
rm -f "$BACKUP"
if crontab -l > "$BACKUP" 2>/dev/null; then
    HAD_CRON=1
fi
cleanup() {
    if [ "$HAD_CRON" -eq 1 ] && [ -f "$BACKUP" ]; then
        grep -v "sentinelmesh-s18" "$BACKUP" | crontab - 2>/dev/null || true
    else
        crontab -r 2>/dev/null || true
    fi
    rm -f "$BACKUP"
}
trap cleanup EXIT
(grep -v "sentinelmesh-s18" "$BACKUP" 2>/dev/null || true; echo "* * * * * true # sentinelmesh-s18") | crontab -
crontab -l >/dev/null 2>&1 || true
'

echo
echo "[✓] Scheduled cron job simulation complete."
