#!/bin/bash

echo "========================================="
echo "Scenario 2 - Brute Force Login"
echo "========================================="

for i in {1..6}
do
    echo "Attempt $i"

    curl -s -X POST http://localhost:5000/login \
        -H "Content-Type: application/json" \
        -d '{
            "username":"admin",
            "password":"wrongpassword"
        }' >/dev/null

    sleep 1
done

echo
echo "[✓] Brute-force simulation complete."
