#!/bin/bash

echo "========================================="
echo "Scenario 17 - Execution from /dev/shm"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-dashboard sh -c '
SCRIPT="/dev/shm/s17_script.sh"
rm -f "$SCRIPT"
trap "rm -f \"$SCRIPT\"" EXIT
printf "#!/bin/sh\necho s17 >/dev/null\n" > "$SCRIPT"
chmod +x "$SCRIPT"
"$SCRIPT"
sh "$SCRIPT"
rm -f "$SCRIPT"
'

echo
echo "[✓] Execution from /dev/shm complete."
