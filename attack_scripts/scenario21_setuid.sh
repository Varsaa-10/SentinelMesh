#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 21 - Set Setuid or Setgid Bit"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" sh -c '
TARGET="/tmp/s21_sleep_copy"
rm -f "$TARGET"
trap "rm -f \"$TARGET\"" EXIT
cp /bin/sleep "$TARGET"
chmod u+s "$TARGET"
rm -f "$TARGET"
'

echo
echo "[✓] Setuid bit modification complete."
