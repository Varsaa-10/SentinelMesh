#!/bin/bash

echo "========================================="
echo "Scenario 5 - Unauthorized DB Connection"
echo "========================================="

NET_NAME=$(docker network ls --filter name=sentinelmesh_net -q | head -n1)
if [ -z "$NET_NAME" ]; then
    NET_NAME="sentinelmesh_net"
fi

docker run --rm \
    --network "$NET_NAME" \
    postgres:15-alpine \
    psql \
        -h sentinelmesh-database \
        -U postgres \
        -d sentinelmesh \
        -c "\dt"

echo
echo "[✓] Connection attempt completed."
