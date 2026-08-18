#!/bin/bash

echo "========================================="
echo "Scenario 3 - Default Credentials"
echo "========================================="

curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{
        "username":"admin",
        "password":"admin123"
    }'

echo
echo "[✓] Default credential login attempted."
