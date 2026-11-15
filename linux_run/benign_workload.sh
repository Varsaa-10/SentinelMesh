#!/usr/bin/env bash
# benign_workload.sh — Realistic benign traffic & administrative operations
# for SentinelMesh ENV2 captures (docs/PLAN_ENV2.md Section 5).
#
# Usage:
#   ./linux_run/benign_workload.sh --duration MINUTES
set -u

DURATION_MINUTES=""
WEBAPP_URL="${WEBAPP_URL:-http://127.0.0.1:5000}"
AUTHSERVICE_URL="${AUTHSERVICE_URL:-http://127.0.0.1:5001}"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --duration)
            DURATION_MINUTES="${2:-}"
            shift 2
            ;;
        --duration=*)
            DURATION_MINUTES="${1#--duration=}"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 --duration MINUTES"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 --duration MINUTES" >&2
            exit 2
            ;;
    esac
done

if [ -z "$DURATION_MINUTES" ] || ! [[ "$DURATION_MINUTES" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "ERROR: --duration MINUTES (positive number) is required." >&2
    exit 2
fi

DURATION_SECONDS=$(awk -v m="$DURATION_MINUTES" 'BEGIN { s = int(m * 60 + 0.5); if (s < 1) s = 1; print s }')

RUNNING=1
trap 'RUNNING=0' TERM INT

now_epoch() {
    date +%s
}

log_msg() {
    echo "[benign $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

do_correct_logins() {
    curl -sf -m 5 -X POST "${WEBAPP_URL}/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"testpass"}' >/dev/null 2>&1 || true
    curl -sf -m 5 -X POST "${AUTHSERVICE_URL}/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"testpass"}' >/dev/null 2>&1 || true
}

# Distinct accounts for single typos; per-account cooldown >= 65s guarantees <= 1 typo/account/min
TYPO_ACCOUNTS=("alice_benign" "bob_benign" "carol_benign" "dave_benign")
declare -A LAST_TYPO_EPOCH=()
TYPO_IDX=0

do_single_typo() {
    local now acct last
    now=$(now_epoch)
    acct="${TYPO_ACCOUNTS[$((TYPO_IDX % ${#TYPO_ACCOUNTS[@]}))]}"
    TYPO_IDX=$((TYPO_IDX + 1))
    last="${LAST_TYPO_EPOCH[$acct]:-0}"
    if [ $((now - last)) -lt 65 ]; then
        return 0
    fi
    LAST_TYPO_EPOCH["$acct"]="$now"
    curl -s -m 5 -X POST "${WEBAPP_URL}/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${acct}\",\"password\":\"wrongpass_typo\"}" >/dev/null 2>&1 || true
}

do_grafana_view() {
    curl -sf -m 5 -u admin:admin "${GRAFANA_URL}/api/dashboards/home" >/dev/null 2>&1 || true
    curl -sf -m 5 -u admin:admin "${GRAFANA_URL}/api/search?limit=10" >/dev/null 2>&1 || true
}

do_pg_dump() {
    MSYS_NO_PATHCONV=1 docker exec -e PGPASSWORD=postgres sentinelmesh-webapp \
        sh -c 'pg_dump -h database -U postgres -d sentinelmesh -f /tmp/benign_pg_backup.sql >/dev/null 2>&1 && rm -f /tmp/benign_pg_backup.sql' \
        >/dev/null 2>&1 || true
}

do_log_rotation() {
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp \
        sh -c 'touch /tmp/benign_app.log && cp -f /tmp/benign_app.log /tmp/benign_app.log.1 && : > /tmp/benign_app.log && rm -f /tmp/benign_app.log /tmp/benign_app.log.1' \
        >/dev/null 2>&1 || true
}

do_read_configs() {
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp cat /app/requirements.txt >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-authservice cat /etc/hosts >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-database cat /etc/pg_hba_override/pg_hba.conf >/dev/null 2>&1 || true
}

do_pkg_index_update() {
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-database apk update >/dev/null 2>&1 || true
}

do_routine_docker_exec() {
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-webapp python --version >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-database pg_isready -U postgres >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker exec sentinelmesh-logcollector fluentd --version >/dev/null 2>&1 || true
}

HTTPS_SITES=("https://example.com" "https://www.wikipedia.org" "https://pypi.org")
HTTPS_IDX=0

do_outbound_https() {
    local url
    url="${HTTPS_SITES[$((HTTPS_IDX % ${#HTTPS_SITES[@]}))]}"
    HTTPS_IDX=$((HTTPS_IDX + 1))
    curl -sS -m 5 -o /dev/null "$url" >/dev/null 2>&1 || true
}

START_EPOCH=$(now_epoch)
END_EPOCH=$((START_EPOCH + DURATION_SECONDS))

LAST_LOGIN=0
LAST_TYPO=0
LAST_GRAFANA=0
LAST_PGDUMP=0
LAST_LOGROT=0
LAST_CONFIG=0
LAST_PKG=0
LAST_EXEC=0
LAST_HTTPS=0

log_msg "starting benign workload for ${DURATION_MINUTES} minute(s) (${DURATION_SECONDS}s)"

while [ "$RUNNING" -eq 1 ]; do
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_LOGIN)) -ge 20 ]; then
        do_correct_logins
        LAST_LOGIN=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_TYPO)) -ge 20 ]; then
        do_single_typo
        LAST_TYPO=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_GRAFANA)) -ge 25 ]; then
        do_grafana_view
        LAST_GRAFANA=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_EXEC)) -ge 20 ]; then
        do_routine_docker_exec
        LAST_EXEC=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_HTTPS)) -ge 30 ]; then
        do_outbound_https
        LAST_HTTPS=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_CONFIG)) -ge 45 ]; then
        do_read_configs
        LAST_CONFIG=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_PGDUMP)) -ge 60 ]; then
        do_pg_dump
        LAST_PGDUMP=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_LOGROT)) -ge 60 ]; then
        do_log_rotation
        LAST_LOGROT=$NOW
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_PKG)) -ge 120 ]; then
        do_pkg_index_update
        LAST_PKG=$NOW
    fi

    sleep 1
done

log_msg "benign workload finished"
