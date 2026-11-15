#!/bin/bash

echo "========================================="
echo "Scenario 23 - Adding SSH Keys to authorized_keys"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp sh -c '
SSH_DIR="/root/.ssh"
AK="$SSH_DIR/authorized_keys"
HAD_DIR=0
HAD_AK=0
[ -d "$SSH_DIR" ] && HAD_DIR=1
[ -f "$AK" ] && HAD_AK=1
cleanup() {
    if [ "$HAD_AK" -eq 1 ] && [ -f "$AK" ]; then
        (grep -v "sentinelmesh-s23" "$AK" || true) > "${AK}.tmp" && mv "${AK}.tmp" "$AK"
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
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISentinelMeshS23DummyKey sentinelmesh-s23" >> "$AK"
'

echo
echo "[✓] authorized_keys modification complete."
