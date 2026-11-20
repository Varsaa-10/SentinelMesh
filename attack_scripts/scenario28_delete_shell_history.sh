#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 28 - Delete or Rename Shell History"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -e MARKER="${CONTAINER_PREFIX}-s28" "$AUTHSERVICE_CONTAINER" sh -c '
HIST="/root/.bash_history"
BAK="/tmp/.s28_bash_history.bak"
rm -f "$BAK"
HAD_HIST=0
if [ -f "$HIST" ]; then
    HAD_HIST=1
    cp -p "$HIST" "$BAK"
else
    echo "# $MARKER" > "$HIST"
fi
cleanup() {
    if [ "$HAD_HIST" -eq 1 ] && [ -f "$BAK" ]; then
        mv -f "$BAK" "$HIST"
    fi
    rm -f "$BAK"
}
trap cleanup EXIT
rm -f "$HIST"
'

echo
echo "[✓] Shell history deletion complete."
