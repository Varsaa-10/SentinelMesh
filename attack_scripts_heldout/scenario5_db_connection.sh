#!/bin/bash
# Held-out variant of S5 (Unauthorized Database Connection, T1021).
# Original: psql from an ephemeral postgres:15-alpine container running \dt.
# Variant : a connection from an ephemeral client that is still not in the
# allowlist (.4 webapp, .5 authservice), using a different client image and a
# different query. The Falco rule flags any inbound accept on
# database:5432 from a non-allowlisted source, so this fires - the rule
# generalizes across clients. Same permissive pg_hba.conf (trust) weakness.
# Expected: detection FIRES.
echo "========================================="
echo "S5 held-out variant - DB connection from a different ephemeral client"
echo "========================================="
NET_NAME=$(docker network ls --filter name=sentinelmesh_net -q | head -n1)
[ -z "$NET_NAME" ] && NET_NAME="sentinelmesh_net"
docker run --rm --network "$NET_NAME" postgres:16-alpine \
    psql -h sentinelmesh-database -U postgres -d sentinelmesh \
         -c "SELECT usename FROM pg_user;" 2>/dev/null
echo
echo "[done] Unauthorized DB connection attempted (different client/query)."
