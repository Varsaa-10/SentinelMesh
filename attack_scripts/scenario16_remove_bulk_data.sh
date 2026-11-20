#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 16 - Remove Bulk Data from Disk"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$DATABASE_CONTAINER" sh -c '
set -e
DEST="/tmp/s16_data_copy"
rm -rf "$DEST"
trap "rm -rf \"$DEST\"" EXIT
mkdir -p "$DEST"
cp -a /var/lib/postgresql/data/global "$DEST/global"
count=0
for f in "$DEST"/global/*; do
    [ -f "$f" ] || continue
    shred -u "$f"
    count=$((count + 1))
    [ "$count" -ge 5 ] && break
done
rm -rf "$DEST"
'

echo
echo "[✓] Bulk data removal simulation complete."
