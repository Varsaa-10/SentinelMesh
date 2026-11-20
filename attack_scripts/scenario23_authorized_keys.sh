#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 23 - Adding SSH Keys to authorized_keys"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -e MARKER="${CONTAINER_PREFIX}-s23" "$WEBAPP_CONTAINER" sh -c '
SSH_DIR="/root/.ssh"
AK="$SSH_DIR/authorized_keys"
HAD_DIR=0
HAD_AK=0
[ -d "$SSH_DIR" ] && HAD_DIR=1
[ -f "$AK" ] && HAD_AK=1
cleanup() {
    if [ "$HAD_AK" -eq 1 ] && [ -f "$AK" ]; then
        (grep -v "$MARKER" "$AK" || true) > "${AK}.tmp" && mv "${AK}.tmp" "$AK"
    else
        rm -f "$AK" "${AK}.tmp"
        if [ "$HAD_DIR" -eq 0 ]; then
            rmdir "$SSH_DIR" 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISentinelMeshS23DummyKey $MARKER" >> "$AK"
'

echo
echo "[✓] authorized_keys modification complete."
