#!/usr/bin/env bash
# benign_workload.sh — Realistic benign traffic & administrative operations
# for SentinelMesh ENV2 captures (docs/PLAN_ENV2.md Section 5).
#
# Usage:
#   ./linux_run/benign_workload.sh --duration MINUTES
set -u

_BENIGN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lab_env.sh
. "$_BENIGN_DIR/lab_env.sh"

DURATION_MINUTES=""

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
SM_ATTACK_LOCK="${SM_ATTACK_LOCK:-}"
SM_BENIGN_BUSY="${SM_BENIGN_BUSY:-}"
if [ -n "$SM_ATTACK_LOCK" ] && [ -z "$SM_BENIGN_BUSY" ]; then
    SM_BENIGN_BUSY="${SM_ATTACK_LOCK}.busy"
fi

RUNNING=1
cleanup_busy() {
    if [ -n "${SM_BENIGN_BUSY:-}" ]; then
        rm -f "$SM_BENIGN_BUSY"
    fi
}
trap 'RUNNING=0; cleanup_busy' TERM INT
trap 'cleanup_busy' EXIT

BENIGN_ACTION_TIMEOUT="${BENIGN_ACTION_TIMEOUT:-90}"
LAST_TIMED_OUT=false

# run_limited CMD...: run CMD under `timeout`; sets LAST_TIMED_OUT (exit 124).
run_limited() {
    local rc=0
    timeout "$BENIGN_ACTION_TIMEOUT" "$@" || rc=$?
    if [ "$rc" -eq 124 ]; then
        LAST_TIMED_OUT=true
    fi
    return 0
}

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
    if [ "$LAST_TIMED_OUT" = true ]; then
        printf '{"start":"%s","end":"%s","container":"%s","action":"%s","timed_out":true}\n' \
            "$start_ts" "$end_ts" "$container" "$action" >> "$BENIGN_ACTIONS_LOG"
        LAST_TIMED_OUT=false
    else
        printf '{"start":"%s","end":"%s","container":"%s","action":"%s"}\n' \
            "$start_ts" "$end_ts" "$container" "$action" >> "$BENIGN_ACTIONS_LOG"
    fi
}

wait_for_attack_lock() {
    [ -n "$SM_ATTACK_LOCK" ] || return 0
    if [ -e "$SM_ATTACK_LOCK" ]; then
        local pause_ts resume_ts
        pause_ts=$(now_iso_utc)
        log_action "" "pause" "$pause_ts" "$pause_ts"
        while [ "$RUNNING" -eq 1 ] && [ -e "$SM_ATTACK_LOCK" ]; do
            if [ -n "${END_EPOCH:-}" ] && [ "$(now_epoch)" -ge "$END_EPOCH" ]; then
                break
            fi
            sleep 0.2
        done
        resume_ts=$(now_iso_utc)
        log_action "" "resume" "$resume_ts" "$resume_ts"
    fi
}

begin_benign_action() {
    wait_for_attack_lock
    [ "$RUNNING" -eq 1 ] || return 1
    if [ -n "${END_EPOCH:-}" ] && [ "$(now_epoch)" -ge "$END_EPOCH" ]; then
        return 1
    fi
    if [ -n "$SM_BENIGN_BUSY" ]; then
        : > "$SM_BENIGN_BUSY"
    fi
    if [ -n "$SM_ATTACK_LOCK" ] && [ -e "$SM_ATTACK_LOCK" ]; then
        cleanup_busy
        wait_for_attack_lock
        [ "$RUNNING" -eq 1 ] || return 1
        if [ -n "${END_EPOCH:-}" ] && [ "$(now_epoch)" -ge "$END_EPOCH" ]; then
            return 1
        fi
        if [ -n "$SM_BENIGN_BUSY" ]; then
            : > "$SM_BENIGN_BUSY"
        fi
    fi
    return 0
}

end_benign_action() {
    cleanup_busy
}

run_docker_exec_logged() {
    local container="$1"
    local action="$2"
    shift 2
    begin_benign_action || return 0
    local start_ts end_ts
    start_ts=$(now_iso_utc)
    MSYS_NO_PATHCONV=1 run_limited docker exec "$container" "$@" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$container" "$action" "$start_ts" "$end_ts"
}

GRAFANA_VIEWER_USER="benign_viewer"
GRAFANA_VIEWER_PASS=""

generate_strong_password() {
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null \
        || od -An -N18 -tx1 /dev/urandom | tr -d ' \n'
}

setup_grafana_viewer() {
    local lookup uid created start_ts end_ts admin_auth
    GRAFANA_VIEWER_PASS=$(generate_strong_password)
    admin_auth="${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASS}"

    begin_benign_action || return 0
    start_ts=$(now_iso_utc)
    lookup=$(timeout "$BENIGN_ACTION_TIMEOUT" curl -sf -m 5 -u "$admin_auth" \
        "${GRAFANA_URL}/api/users/lookup?loginOrEmail=${GRAFANA_VIEWER_USER}" 2>/dev/null || true)
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$DASHBOARD_CONTAINER" "grafana_setup" "$start_ts" "$end_ts"

    uid=$(echo "$lookup" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)
    if [ -z "$uid" ]; then
        begin_benign_action || return 0
        start_ts=$(now_iso_utc)
        created=$(timeout "$BENIGN_ACTION_TIMEOUT" curl -sf -m 5 -u "$admin_auth" -X POST "${GRAFANA_URL}/api/admin/users" \
            -H "Content-Type: application/json" \
            -d "{\"name\":\"Benign Viewer\",\"email\":\"${GRAFANA_VIEWER_USER}@${CONTAINER_PREFIX}.local\",\"login\":\"${GRAFANA_VIEWER_USER}\",\"password\":\"${GRAFANA_VIEWER_PASS}\"}" \
            2>/dev/null || true)
        end_ts=$(now_iso_utc)
        end_benign_action
        log_action "$DASHBOARD_CONTAINER" "grafana_setup" "$start_ts" "$end_ts"
        uid=$(echo "$created" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)
    else
        begin_benign_action || return 0
        start_ts=$(now_iso_utc)
        run_limited curl -sf -m 5 -u "$admin_auth" -X PUT "${GRAFANA_URL}/api/admin/users/${uid}/password" \
            -H "Content-Type: application/json" \
            -d "{\"password\":\"${GRAFANA_VIEWER_PASS}\"}" >/dev/null 2>&1 || true
        end_ts=$(now_iso_utc)
        end_benign_action
        log_action "$DASHBOARD_CONTAINER" "grafana_setup" "$start_ts" "$end_ts"
    fi
    if [ -n "$uid" ]; then
        begin_benign_action || return 0
        start_ts=$(now_iso_utc)
        run_limited curl -sf -m 5 -u "$admin_auth" -X PATCH "${GRAFANA_URL}/api/orgs/1/users/${uid}" \
            -H "Content-Type: application/json" \
            -d '{"role":"Viewer"}' >/dev/null 2>&1 || true
        end_ts=$(now_iso_utc)
        end_benign_action
        log_action "$DASHBOARD_CONTAINER" "grafana_setup" "$start_ts" "$end_ts"
    fi
}

do_correct_logins() {
    local start_ts end_ts creds
    creds="{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}"
    begin_benign_action || return 0
    start_ts=$(now_iso_utc)
    run_limited curl -sf -m 5 -X POST "${WEBAPP_URL}/login" \
        -H "Content-Type: application/json" \
        -d "$creds" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$WEBAPP_CONTAINER" "correct_login" "$start_ts" "$end_ts"

    begin_benign_action || return 0
    start_ts=$(now_iso_utc)
    run_limited curl -sf -m 5 -X POST "${AUTHSERVICE_URL}/auth/login" \
        -H "Content-Type: application/json" \
        -d "$creds" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$AUTHSERVICE_CONTAINER" "correct_login" "$start_ts" "$end_ts"
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
    begin_benign_action || return 0
    LAST_TYPO_EPOCH["$acct"]="$(now_epoch)"
    start_ts=$(now_iso_utc)
    run_limited curl -s -m 5 -X POST "${WEBAPP_URL}/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${acct}\",\"password\":\"wrongpass_typo\"}" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$WEBAPP_CONTAINER" "single_typo" "$start_ts" "$end_ts"
}

do_grafana_view() {
    local start_ts end_ts
    begin_benign_action || return 0
    start_ts=$(now_iso_utc)
    run_limited curl -sf -m 5 -u "${GRAFANA_VIEWER_USER}:${GRAFANA_VIEWER_PASS}" "${GRAFANA_URL}/api/dashboards/home" >/dev/null 2>&1 || true
    run_limited curl -sf -m 5 -u "${GRAFANA_VIEWER_USER}:${GRAFANA_VIEWER_PASS}" "${GRAFANA_URL}/api/search?limit=10" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$DASHBOARD_CONTAINER" "grafana_view" "$start_ts" "$end_ts"
}

do_pg_dump() {
    local start_ts end_ts
    begin_benign_action || return 0
    start_ts=$(now_iso_utc)
    MSYS_NO_PATHCONV=1 run_limited docker exec -e PGPASSWORD="$DB_PASS" "$WEBAPP_CONTAINER" \
        sh -c "pg_dump -h database -U \"$DB_USER\" -d \"$DB_NAME\" -f /tmp/benign_pg_backup.sql >/dev/null 2>&1 && rm -f /tmp/benign_pg_backup.sql" \
        >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "$WEBAPP_CONTAINER" "pg_dump" "$start_ts" "$end_ts"
}

do_log_rotation() {
    run_docker_exec_logged "$WEBAPP_CONTAINER" "log_rotation" \
        sh -c 'touch /tmp/benign_app.log && cp -f /tmp/benign_app.log /tmp/benign_app.log.1 && : > /tmp/benign_app.log && rm -f /tmp/benign_app.log /tmp/benign_app.log.1'
}

do_read_configs() {
    run_docker_exec_logged "$WEBAPP_CONTAINER" "read_configs" cat /app/requirements.txt
    run_docker_exec_logged "$AUTHSERVICE_CONTAINER" "read_configs" cat /etc/hosts
    run_docker_exec_logged "$DATABASE_CONTAINER" "read_configs" cat /etc/pg_hba_override/pg_hba.conf
}

do_pkg_index_update() {
    run_docker_exec_logged "$DATABASE_CONTAINER" "pkg_index_update" apk update
}

do_routine_docker_exec() {
    run_docker_exec_logged "$WEBAPP_CONTAINER" "routine_docker_exec" python --version
    run_docker_exec_logged "$DATABASE_CONTAINER" "routine_docker_exec" pg_isready -U "$DB_USER" -d "$DB_NAME"
    run_docker_exec_logged "$LOGCOLLECTOR_CONTAINER" "routine_docker_exec" fluentd --version
}

HTTPS_SITES=("https://example.com" "https://www.wikipedia.org" "https://pypi.org")
HTTPS_IDX=0

do_outbound_https() {
    local url start_ts end_ts
    url="${HTTPS_SITES[$((HTTPS_IDX % ${#HTTPS_SITES[@]}))]}"
    HTTPS_IDX=$((HTTPS_IDX + 1))
    begin_benign_action || return 0
    start_ts=$(now_iso_utc)
    run_limited curl -sS -m 5 -o /dev/null "$url" >/dev/null 2>&1 || true
    end_ts=$(now_iso_utc)
    end_benign_action
    log_action "host" "outbound_https" "$start_ts" "$end_ts"
}

START_EPOCH=$(now_epoch)
END_EPOCH=$((START_EPOCH + DURATION_SECONDS))

setup_grafana_viewer

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
    wait_for_attack_lock
    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_LOGIN)) -ge 20 ]; then
        do_correct_logins
        LAST_LOGIN=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_TYPO)) -ge 20 ]; then
        do_single_typo
        LAST_TYPO=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_GRAFANA)) -ge 25 ]; then
        do_grafana_view
        LAST_GRAFANA=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_EXEC)) -ge 20 ]; then
        do_routine_docker_exec
        LAST_EXEC=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_HTTPS)) -ge 30 ]; then
        do_outbound_https
        LAST_HTTPS=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_CONFIG)) -ge 45 ]; then
        do_read_configs
        LAST_CONFIG=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_PGDUMP)) -ge 60 ]; then
        do_pg_dump
        LAST_PGDUMP=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_LOGROT)) -ge 60 ]; then
        do_log_rotation
        LAST_LOGROT=$(now_epoch)
    fi

    [ "$RUNNING" -eq 1 ] || break
    NOW=$(now_epoch)
    [ "$NOW" -ge "$END_EPOCH" ] && break

    if [ $((NOW - LAST_PKG)) -ge 120 ]; then
        do_pkg_index_update
        LAST_PKG=$(now_epoch)
    fi

    sleep 1
done

log_msg "benign workload finished"
