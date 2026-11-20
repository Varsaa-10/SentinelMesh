#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 26 - Create Hidden Files or Directories"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$LOGCOLLECTOR_CONTAINER" sh -c '
HDIR="/tmp/.s26_hidden_dir"
rm -rf "$HDIR"
trap "rm -rf \"$HDIR\"" EXIT
mkdir -p "$HDIR"
echo "s26" > "$HDIR/.s26_hidden_file"
rm -rf "$HDIR"
'

echo
echo "[✓] Hidden directory and file simulation complete."
