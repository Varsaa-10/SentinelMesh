#!/bin/bash
# Held-out variant of S7 (Grafana Default Creds / Anonymous Access, T1078).
# Original: anonymous GET /api/dashboards/home.
# Variant : anonymous scrape of a DIFFERENT API path (/api/search). The S7
# detector flags any GET to /api/* or /d/* returning 200 with no
# authenticated identity, so this fires - the detector generalizes across
# anonymous API paths. Same anonymous-access weakness
# (GF_AUTH_ANONYMOUS_ENABLED=true), a different endpoint.
# Expected: detection FIRES.
echo "========================================="
echo "S7 held-out variant - anonymous scrape of a different API path"
echo "========================================="
GRAFANA_URL="http://localhost:3000"
echo "[1/1] Anonymous GET /api/search ..."
curl -s -o /dev/null -w "HTTP %{http_code}\n" "${GRAFANA_URL}/api/search?query=&limit=50"
echo
echo "[done] Anonymous API scrape sent."
