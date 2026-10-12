#!/usr/bin/env bash
# preflight.sh — checks everything the Linux Baseline 1 run depends on, BEFORE
# you fire any attacks. Run:  sudo ./linux_run/preflight.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RULES="$ROOT/detection/falco-rules"
FAIL=0
ok()   { echo "  [ok]   $*"; }
warn() { echo "  [WARN] $*"; }
bad()  { echo "  [FAIL] $*"; FAIL=1; }

echo "== 1. Host tooling"
[ "$(id -u)" -eq 0 ] && ok "running as root" || bad "not root — re-run with sudo"
for t in docker falco stdbuf python3 curl; do
  command -v "$t" >/dev/null && ok "$t found" || bad "$t missing"
done
echo "         falco: $(falco --version 2>/dev/null | head -n1)"
pgrep -x falco >/dev/null && bad "a falco process is already running — stop it" || ok "no stray falco process"

echo "== 2. Falco rule files compile"
for f in "$RULES"/s0*.yaml; do
  if falco -V "$f" >/tmp/falco_validate.out 2>&1; then ok "$(basename "$f")"
  else bad "$(basename "$f") failed validation:"; sed 's/^/           /' /tmp/falco_validate.out | head -15; fi
done

echo "== 3. Lab containers and static IPs"
declare -A WANT=( [sentinelmesh-database]=172.30.0.2 [sentinelmesh-logcollector]=172.30.0.3
                  [sentinelmesh-webapp]=172.30.0.4 [sentinelmesh-authservice]=172.30.0.5
                  [sentinelmesh-dashboard]=172.30.0.6 )
for c in "${!WANT[@]}"; do
  got="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$c" 2>/dev/null | awk '{print $1}')"
  [ -z "$got" ] && { bad "$c not running"; continue; }
  [ "$got" = "${WANT[$c]}" ] && ok "$c = $got" || bad "$c has $got, expected ${WANT[$c]}"
done
SUBNET="$(docker network inspect sentinelmesh_net -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
[ "$SUBNET" = "172.30.0.0/16" ] && ok "network subnet $SUBNET" || bad "network subnet is '$SUBNET', expected 172.30.0.0/16"

echo "== 4. Rule IP lists match the live lab"
grep -q '"172.30.0.4", "172.30.0.5"' "$RULES/s05_db_access.yaml" \
  && ok "s05 allowlist = webapp .4 + authservice .5" || bad "s05 allowlist does not match webapp/authservice IPs"
if grep -q "sentinelmesh_internal_ips" "$RULES/s08_exfiltration.yaml"; then ok "s08 excludes the 172.30.0.0/16 lab subnet"
else bad "s08 still excludes the OLD subnets — patch detection/falco-rules/s08_exfiltration.yaml"; fi

echo "== 5. Log paths the tailer will read"
LOGDIR="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/log/sentinelmesh"}}{{.Source}}{{end}}{{end}}' sentinelmesh-webapp 2>/dev/null)"
if [ -z "$LOGDIR" ] || [ ! -d "$LOGDIR" ]; then bad "cannot resolve the log_data volume on the host"
else
  ok "log volume on host: $LOGDIR"
  for n in webapp_events.log auth_events.log; do
    [ -f "$LOGDIR/$n" ] && ok "$n exists" || warn "$n not created yet (wrapper pre-touches it)"
  done
  printf 'WEBAPP_LOG=%s/webapp_events.log\nAUTH_LOG=%s/auth_events.log\n' "$LOGDIR" "$LOGDIR" > "$HERE/.paths.env"
fi

echo "== 6. Grafana logging env"
GENV="$(docker exec sentinelmesh-dashboard env 2>/dev/null)"
for v in GF_LOG_LEVEL=debug GF_LOG_MODE=console GF_SERVER_ROUTER_LOGGING=true; do
  echo "$GENV" | grep -qx "$v" && ok "$v" || bad "$v missing on sentinelmesh-dashboard"
done

echo "== 7. Health"
curl -sf http://127.0.0.1:5000/health >/dev/null && ok "webapp /health" || bad "webapp /health"
curl -sf http://127.0.0.1:5001/health >/dev/null && ok "authservice /health" || bad "authservice /health"
curl -sf -o /dev/null http://127.0.0.1:3000/api/health && ok "grafana /api/health" || bad "grafana /api/health"

echo
[ $FAIL -eq 0 ] && echo "PREFLIGHT PASSED" || echo "PREFLIGHT FAILED — fix the [FAIL] lines."
exit $FAIL
