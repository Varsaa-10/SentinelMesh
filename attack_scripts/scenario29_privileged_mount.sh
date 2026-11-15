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
STARTED_BY_SCRIPT=0

cleanup_container() {
    if [ "$STARTED_BY_SCRIPT" -eq 1 ]; then
        docker compose -f "$REPO_ROOT/docker-compose.debug.yml" down >/dev/null 2>&1 || true
    fi
}
trap cleanup_container EXIT

if ! docker inspect -f '{{.State.Running}}' sentinelmesh-debug 2>/dev/null | grep -qx true; then
    docker compose -f "$REPO_ROOT/docker-compose.debug.yml" up -d >/dev/null
    STARTED_BY_SCRIPT=1
fi

if ! docker inspect -f '{{.HostConfig.Privileged}}' sentinelmesh-debug 2>/dev/null | grep -qx true; then
    echo "sentinelmesh-debug is not running in privileged mode." >&2
    exit 1
fi

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-debug sh -c '
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
