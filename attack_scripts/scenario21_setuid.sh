#!/bin/bash

echo "========================================="
echo "Scenario 21 - Set Setuid or Setgid Bit"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp sh -c '
TARGET="/tmp/s21_sleep_copy"
rm -f "$TARGET"
trap "rm -f \"$TARGET\"" EXIT
cp /bin/sleep "$TARGET"
chmod u+s "$TARGET"
rm -f "$TARGET"
'

echo
echo "[✓] Setuid bit modification complete."
