#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 27 - Decoding Payload in Container"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" sh -c 'echo "ZWNobyBzMjcK" | base64 -d | sh >/dev/null'

echo
echo "[✓] Base64 payload decoding complete."
