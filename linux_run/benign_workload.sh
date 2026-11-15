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

OUT="${OUT:-.}"
mkdir -p "$OUT"
BENIGN_ACTIONS_LOG="${OUT}/benign_actions.jsonl"

RUNNING=1
trap 'RUNNING=0' TERM INT

now_epoch() {
    date +%s
}

now_iso_utc() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

log_msg() {
    echo "[benign $(now_iso_utc)] $*"
}

log_action() {
    local container="$1"
    local action="$2"
    local start_ts="$3"
    local end_ts="$4"
    printf '{"start":"%s","end":"%s","container":"%s","action":"%s"}\n' \
        "$start_ts" "$end_ts" "$container" "$action" >> "$BENIGN_ACTIONS_LOG"
}

run_docker_exec_logged() {
    local container="$1"
    local action="$2"
    shift 2
    local start_ts end_ts
    start_ts=$(now_iso_utc)
    MSYS_NO_PATHCONV=1 docker exec "$container" "$@" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "$container" "$action" "$start_ts" "$end_ts"
}

GRAFANA_VIEWER_USER="benign_viewer"
GRAFANA_VIEWER_PASS=""

generate_strong_password() {
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null \
        || od -An -N18 -tx1 /dev/urandom | tr -d ' \n'
}

setup_grafana_viewer() {
    local lookup uid created
    GRAFANA_VIEWER_PASS=$(generate_strong_password)
    lookup=$(curl -sf -m 5 -u admin:admin \
        "${GRAFANA_URL}/api/users/lookup?loginOrEmail=${GRAFANA_VIEWER_USER}" 2>/dev/null || true)
    uid=$(echo "$lookup" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)
    if [ -z "$uid" ]; then
        created=$(curl -sf -m 5 -u admin:admin -X POST "${GRAFANA_URL}/api/admin/users" \
            -H "Content-Type: application/json" \
            -d "{\"name\":\"Benign Viewer\",\"email\":\"${GRAFANA_VIEWER_USER}@sentinelmesh.local\",\"login\":\"${GRAFANA_VIEWER_USER}\",\"password\":\"${GRAFANA_VIEWER_PASS}\"}" \
            2>/dev/null || true)
        uid=$(echo "$created" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)
    else
        curl -sf -m 5 -u admin:admin -X PUT "${GRAFANA_URL}/api/admin/users/${uid}/password" \
            -H "Content-Type: application/json" \
            -d "{\"password\":\"${GRAFANA_VIEWER_PASS}\"}" >/dev/null 2>&1 || true
    fi
    if [ -n "$uid" ]; then
        curl -sf -m 5 -u admin:admin -X PATCH "${GRAFANA_URL}/api/orgs/1/users/${uid}" \
            -H "Content-Type: application/json" \
            -d '{"role":"Viewer"}' >/dev/null 2>&1 || true
    fi
}

do_correct_logins() {
    local start_ts end_ts
    start_ts=$(now_iso_utc)
    curl -sf -m 5 -X POST "${WEBAPP_URL}/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"testpass"}' >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "sentinelmesh-webapp" "correct_login" "$start_ts" "$end_ts"

    start_ts=$(now_iso_utc)
    curl -sf -m 5 -X POST "${AUTHSERVICE_URL}/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"testpass"}' >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "sentinelmesh-authservice" "correct_login" "$start_ts" "$end_ts"
}

# Distinct accounts for single typos; per-account cooldown >= 65s guarantees <= 1 typo/account/min
TYPO_ACCOUNTS=("alice_benign" "bob_benign" "carol_benign" "dave_benign")
declare -A LAST_TYPO_EPOCH=()
TYPO_IDX=0

do_single_typo() {
    local now acct last start_ts end_ts
    now=$(now_epoch)
    acct="${TYPO_ACCOUNTS[$((TYPO_IDX % ${#TYPO_ACCOUNTS[@]}))]}"
    TYPO_IDX=$((TYPO_IDX + 1))
    last="${LAST_TYPO_EPOCH[$acct]:-0}"
    if [ $((now - last)) -lt 65 ]; then
        return 0
    fi
    LAST_TYPO_EPOCH["$acct"]="$now"
    start_ts=$(now_iso_utc)
    curl -s -m 5 -X POST "${WEBAPP_URL}/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${acct}\",\"password\":\"wrongpass_typo\"}" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "sentinelmesh-webapp" "single_typo" "$start_ts" "$end_ts"
}

do_grafana_view() {
    local start_ts end_ts
    start_ts=$(now_iso_utc)
    curl -sf -m 5 -u "${GRAFANA_VIEWER_USER}:${GRAFANA_VIEWER_PASS}" "${GRAFANA_URL}/api/dashboards/home" >/dev/null 2>&1 || true
    curl -sf -m 5 -u "${GRAFANA_VIEWER_USER}:${GRAFANA_VIEWER_PASS}" "${GRAFANA_URL}/api/search?limit=10" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "sentinelmesh-dashboard" "grafana_view" "$start_ts" "$end_ts"
}

do_pg_dump() {
    local start_ts end_ts
    start_ts=$(now_iso_utc)
    MSYS_NO_PATHCONV=1 docker exec -e PGPASSWORD=postgres sentinelmesh-webapp \
        sh -c 'pg_dump -h database -U postgres -d sentinelmesh -f /tmp/benign_pg_backup.sql >/dev/null 2>&1 && rm -f /tmp/benign_pg_backup.sql' \
        >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "sentinelmesh-webapp" "pg_dump" "$start_ts" "$end_ts"
}

do_log_rotation() {
    run_docker_exec_logged "sentinelmesh-webapp" "log_rotation" \
        sh -c 'touch /tmp/benign_app.log && cp -f /tmp/benign_app.log /tmp/benign_app.log.1 && : > /tmp/benign_app.log && rm -f /tmp/benign_app.log /tmp/benign_app.log.1'
}

do_read_configs() {
    run_docker_exec_logged "sentinelmesh-webapp" "read_configs" cat /app/requirements.txt
    run_docker_exec_logged "sentinelmesh-authservice" "read_configs" cat /etc/hosts
    run_docker_exec_logged "sentinelmesh-database" "read_configs" cat /etc/pg_hba_override/pg_hba.conf
}

do_pkg_index_update() {
    run_docker_exec_logged "sentinelmesh-database" "pkg_index_update" apk update
}

do_routine_docker_exec() {
    run_docker_exec_logged "sentinelmesh-webapp" "routine_docker_exec" python --version
    run_docker_exec_logged "sentinelmesh-database" "routine_docker_exec" pg_isready -U postgres
    run_docker_exec_logged "sentinelmesh-logcollector" "routine_docker_exec" fluentd --version
}

HTTPS_SITES=("https://example.com" "https://www.wikipedia.org" "https://pypi.org")
HTTPS_IDX=0

do_outbound_https() {
    local url start_ts end_ts
    url="${HTTPS_SITES[$((HTTPS_IDX % ${#HTTPS_SITES[@]}))]}"
    HTTPS_IDX=$((HTTPS_IDX + 1))
    start_ts=$(now_iso_utc)
    curl -sS -m 5 -o /dev/null "$url" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    log_action "host" "outbound_https" "$start_ts" "$end_ts"
}

setup_grafana_viewer

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
