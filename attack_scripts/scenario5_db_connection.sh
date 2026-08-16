#!/bin/bash

echo "========================================="
echo "Scenario 5 - Unauthorized DB Connection"
echo "========================================="

docker run --rm \
    --network sentinelmesh_sentinelmesh_net \
    postgres:15-alpine \
    psql \
        -h sentinelmesh-database \
        -U postgres \
        -d sentinelmesh \
        -c "\dt"

echo
echo "[✓] Connection attempt completed."
