#!/bin/bash
# Held-out variant of S6 (Log Directory Tampering, T1070).
# Original: echo "ATTACK" > /var/log/sentinelmesh/test.log (append/create).
# Variant : destroy a log in place by truncating it to zero. The Falco rule
# flags any open-for-write in /var/log/sentinelmesh/ in the logcollector,
# regardless of process, so this fires. Same world-writable log-dir weakness.
# Expected: detection FIRES.
echo "========================================="
echo "S6 held-out variant - in-place log truncation"
echo "========================================="
docker exec sentinelmesh-logcollector sh -c ': > /var/log/sentinelmesh/audit.log'
echo
echo "[done] Log file truncated in place."
