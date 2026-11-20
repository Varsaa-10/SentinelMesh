#!/bin/bash

echo "========================================="
echo "Scenario 29 - Mount Launched in Privileged Container"
echo "========================================="

if [ "${1:-}" != "--privileged-debug" ]; then
    echo "Refusing to run S29 without --privileged-debug (disposable VM only)." >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$REPO_ROOT/linux_run/lab_env.sh"
STARTED_BY_SCRIPT=0

cleanup_container() {
    if [ "$STARTED_BY_SCRIPT" -eq 1 ]; then
        docker compose -f "$REPO_ROOT/docker-compose.debug.yml" down >/dev/null 2>&1 || true
    fi
}
trap cleanup_container EXIT

if ! docker inspect -f '{{.State.Running}}' "$DEBUG_CONTAINER" 2>/dev/null | grep -qx true; then
    docker compose -f "$REPO_ROOT/docker-compose.debug.yml" up -d >/dev/null
    STARTED_BY_SCRIPT=1
fi

if ! docker inspect -f '{{.HostConfig.Privileged}}' "$DEBUG_CONTAINER" 2>/dev/null | grep -qx true; then
    echo "$DEBUG_CONTAINER is not running in privileged mode." >&2
    exit 1
fi

MSYS_NO_PATHCONV=1 docker exec "$DEBUG_CONTAINER" sh -c '
MNT="/tmp/s29_mnt"
cleanup() {
    umount "$MNT" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$MNT"
mount -t tmpfs -o size=1M tmpfs "$MNT"
cleanup
'

echo
echo "[✓] Privileged container mount simulation complete."
