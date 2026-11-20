#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 5 - Unauthorized DB Connection"
echo "========================================="

NET_NAME=$(docker network ls --filter name="${LAB_NET_NAME}" -q | head -n1)
if [ -z "$NET_NAME" ]; then
    NET_NAME="${LAB_NET_NAME}"
fi

docker run --rm \
    --network "$NET_NAME" \
    postgres:15-alpine \
    psql \
        -h "$DATABASE_CONTAINER" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        -c "\dt"

echo
echo "[✓] Connection attempt completed."
