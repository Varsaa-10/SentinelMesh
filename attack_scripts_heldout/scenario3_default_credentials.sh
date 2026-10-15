#!/bin/bash
# Held-out variant of S3 (Default Credential Login, T1078).
# Original: admin / admin123 (the account the detector knows about).
# Variant : testuser / testpass - the OTHER account seeded into the lab DB
# (services/database/init.sql). It is a real pre-seeded weak account, so the
# login SUCCEEDS, but the S3 detector only flags username=admin, so it does
# not fire. Same default-credential weakness, a seeded account the detector
# was not written for. (W4 named a 'postgres_backup' account; the lab only
# seeds admin and testuser, so testuser is the runnable stand-in.)
# Expected: detection GAP.
echo "========================================="
echo "S3 held-out variant - second seeded default account"
echo "========================================="
curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"testpass"}'
echo
echo "[done] testuser default-credential login attempted."
