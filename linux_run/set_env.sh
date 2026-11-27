#!/usr/bin/env bash
# set_env.sh — switch active lab environment profile (e.g. E1 or E2).
#
# Usage:  ./linux_run/set_env.sh <E1|E2>
#
# Writes repo-root .env from env/<PROFILE>.env and rewrites deployment values
# (container names, network name, host ports, log directory, and rotated DB /
# app credentials) across compose, Falco lab rules, tailer defaults, preflight,
# check_run, and service configs. Refuses to succeed if any old value remains.
# Leaves the current subnet untouched and commutes cleanly with set_subnet.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "usage: $0 <E1|E2>" >&2
  exit 2
fi

NEW_ENV_FILE="env/${TARGET}.env"
if [ ! -f "$NEW_ENV_FILE" ]; then
  echo "ERROR: unknown environment profile '$TARGET' (missing $NEW_ENV_FILE)" >&2
  exit 2
fi

load_env_map() {
  local file="$1"
  local prefix="$2"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in
      ""|\#*) continue ;;
    esac
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      printf -v "${prefix}_${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
    fi
  done < "$file"
}

detect_current_profile() {
  local cur_prefix
  cur_prefix="$(grep -oE 'container_name:[[:space:]]*[A-Za-z0-9_]+-webapp' docker-compose.yml | head -1 | sed -E 's/^container_name:[[:space:]]*//; s/-webapp$//' || true)"
  if [ -z "$cur_prefix" ]; then
    echo "ERROR: could not detect current container prefix from docker-compose.yml" >&2
    exit 1
  fi
  for f in env/*.env; do
    [ -f "$f" ] || continue
    local p
    p="$(grep -E '^CONTAINER_PREFIX=' "$f" | head -1 | cut -d= -f2- | tr -d '\r')"
    if [ "$p" = "$cur_prefix" ]; then
      basename "$f" .env
      return 0
    fi
  done
  echo "ERROR: current prefix '$cur_prefix' in docker-compose.yml does not match any env/*.env profile" >&2
  exit 1
}

CUR="$(detect_current_profile)"
OLD_ENV_FILE="env/${CUR}.env"

load_env_map "$OLD_ENV_FILE" OLD
load_env_map "$NEW_ENV_FILE" NEW

MANAGED_FILES=(
  "docker-compose.yml"
  "docker-compose.debug.yml"
  "detection/falco-rules/s05_db_access.yaml"
  "detection/falco-rules/s06_log_tamper.yaml"
  "detection/falco-rules/s08_exfiltration.yaml"
  "detection/falco-rules/s09_credential_access.yaml"
  "detection/log-tail/tailer.py"
  "linux_run/preflight.sh"
  "linux_run/check_run.py"
  "services/logcollector/Dockerfile"
  "services/logcollector/fluent.conf"
  "services/database/init.sql"
  "services/dashboard/provisioning/datasources.yml"
)

for f in "${MANAGED_FILES[@]}"; do
  [ -f "$f" ] || { echo "ERROR: missing file $f" >&2; exit 1; }
done

# Always refresh root .env (gitignored compose env file) with LF endings
tr -d '\r' < "$NEW_ENV_FILE" > .env
chmod --reference="$NEW_ENV_FILE" .env 2>/dev/null || chmod 0644 .env

escape_ere() {
  printf '%s' "$1" | sed -E 's/[][(){}.^$+*?|\\#]/\\&/g'
}

escape_sed_rep() {
  printf '%s' "$1" | sed -E 's/[&|\\#]/\\&/g'
}

replace_preserving_mode() {
  local src="$1"
  local dst="$2"
  if chmod --reference="$dst" "$src" 2>/dev/null; then
    mv "$src" "$dst"
  else
    cat "$src" > "$dst"
    rm -f "$src"
  fi
}

rewrite_file() {
  local file="$1"
  shift
  local tmp
  tmp="$(mktemp)"
  sed -E "$@" "$file" | tr -d '\r' > "$tmp"
  replace_preserving_mode "$tmp" "$file"
}

if [ "$CUR" = "$TARGET" ]; then
  # Confirm no leftover deployment values from another profile exist
  OTHER_LEFTOVER=0
  for other in env/*.env; do
    [ -f "$other" ] || continue
    [ "$other" = "$NEW_ENV_FILE" ] && continue
    load_env_map "$other" CHK
    chk_pref_re="$(escape_ere "$CHK_CONTAINER_PREFIX")"
    chk_net_re="$(escape_ere "$CHK_LAB_NET_NAME")"
    chk_log_re="$(escape_ere "$CHK_LOG_DIR")"
    for f in "${MANAGED_FILES[@]}"; do
      if [ "$CHK_CONTAINER_PREFIX" != "$NEW_CONTAINER_PREFIX" ] && \
         grep -qE "(${chk_pref_re}-(webapp|authservice|database|logcollector|dashboard|proxy|ngrok|debug)|startswith \"${chk_pref_re}-\")" "$f"; then
        echo "LEFTOVER prefix from $other in $f" >&2
        OTHER_LEFTOVER=1
      fi
      if [ "$CHK_LAB_NET_NAME" != "$NEW_LAB_NET_NAME" ] && grep -qE "\b${chk_net_re}\b" "$f"; then
        echo "LEFTOVER network from $other in $f" >&2
        OTHER_LEFTOVER=1
      fi
      if [ "$CHK_LOG_DIR" != "$NEW_LOG_DIR" ] && grep -qF "$CHK_LOG_DIR" "$f"; then
        echo "LEFTOVER log dir from $other in $f" >&2
        OTHER_LEFTOVER=1
      fi
    done
  done
  [ "$OTHER_LEFTOVER" -eq 0 ] || exit 1
  echo "Environment already set to $TARGET (.env refreshed)."
  exit 0
fi

echo "Switching environment profile: $CUR -> $TARGET"

OLD_PREF_RE="$(escape_ere "$OLD_CONTAINER_PREFIX")"
OLD_NET_RE="$(escape_ere "$OLD_LAB_NET_NAME")"
OLD_LOG_RE="$(escape_ere "$OLD_LOG_DIR")"
OLD_DB_RE="$(escape_ere "$OLD_DB_NAME")"
OLD_USER_RE="$(escape_ere "$OLD_DB_USER")"
OLD_PASS_RE="$(escape_ere "$OLD_DB_PASS")"
OLD_TUSER_RE="$(escape_ere "$OLD_TEST_USER")"
OLD_TPASS_RE="$(escape_ere "$OLD_TEST_PASS")"

NEW_PREF_S="$(escape_sed_rep "$NEW_CONTAINER_PREFIX")"
NEW_NET_S="$(escape_sed_rep "$NEW_LAB_NET_NAME")"
NEW_LOG_S="$(escape_sed_rep "$NEW_LOG_DIR")"
NEW_DB_S="$(escape_sed_rep "$NEW_DB_NAME")"
NEW_USER_S="$(escape_sed_rep "$NEW_DB_USER")"
NEW_PASS_S="$(escape_sed_rep "$NEW_DB_PASS")"
NEW_TUSER_S="$(escape_sed_rep "$NEW_TEST_USER")"
NEW_TPASS_S="$(escape_sed_rep "$NEW_TEST_PASS")"

# 1. docker-compose.yml (keep subnet untouched; inject/remove LOG_DIR & JWT_SECRET for non-E1 vs E1)
rewrite_file "docker-compose.yml" \
  -e "s#${OLD_PREF_RE}-(webapp|authservice|database|logcollector|dashboard|proxy|ngrok)#${NEW_PREF_S}-\\1#g" \
  -e "s#\b${OLD_NET_RE}\b#${NEW_NET_S}#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_WEBAPP_PORT}:5000#127.0.0.1:${NEW_WEBAPP_PORT}:5000#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_AUTHSERVICE_PORT}:5001#127.0.0.1:${NEW_AUTHSERVICE_PORT}:5001#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_POSTGRES_PORT}:5432#127.0.0.1:${NEW_POSTGRES_PORT}:5432#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_GRAFANA_PORT}:3000#127.0.0.1:${NEW_GRAFANA_PORT}:3000#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_FLUENTD_PORT}:24224#127.0.0.1:${NEW_FLUENTD_PORT}:24224#g" \
  -e "s#log_data:${OLD_LOG_RE}#log_data:${NEW_LOG_S}#g" \
  -e "s#DB_NAME=${OLD_DB_RE}\b#DB_NAME=${NEW_DB_S}#g" \
  -e "s#POSTGRES_DB=${OLD_DB_RE}\b#POSTGRES_DB=${NEW_DB_S}#g" \
  -e "s#pg_isready -U ${OLD_USER_RE} -d ${OLD_DB_RE}#pg_isready -U ${NEW_USER_S} -d ${NEW_DB_S}#g" \
  -e "s#DB_PASS=${OLD_PASS_RE}\b#DB_PASS=${NEW_PASS_S}#g" \
  -e "s#POSTGRES_PASSWORD=${OLD_PASS_RE}\b#POSTGRES_PASSWORD=${NEW_PASS_S}#g"

# Strip any previous injected LOG_DIR / JWT_SECRET lines; re-insert when TARGET != E1
tmp_dc="$(mktemp)"
awk -v target="$TARGET" -v log_dir="$NEW_LOG_DIR" -v jwt_sec="$NEW_JWT_SECRET" '
  /^[[:space:]]*- (LOG_DIR|JWT_SECRET)=/ { next }
  /^[[:space:]]*webapp:[[:space:]]*$/ { svc="webapp" }
  /^[[:space:]]*authservice:[[:space:]]*$/ { svc="authservice" }
  /^[[:space:]]*database:[[:space:]]*$/ { svc="database" }
  /^[[:space:]]*logcollector:[[:space:]]*$/ { svc="logcollector" }
  /^[[:space:]]*dashboard:[[:space:]]*$/ { svc="dashboard" }
  {
    print
    if (target != "E1" && /^[[:space:]]*- DB_PASS=/) {
      if (svc == "webapp") {
        print "      - LOG_DIR=" log_dir
      } else if (svc == "authservice") {
        print "      - LOG_DIR=" log_dir
        print "      - JWT_SECRET=" jwt_sec
      }
    }
  }
' docker-compose.yml | tr -d '\r' > "$tmp_dc"
replace_preserving_mode "$tmp_dc" "docker-compose.yml"

# 2. docker-compose.debug.yml
rewrite_file "docker-compose.debug.yml" \
  -e "s#${OLD_PREF_RE}-debug#${NEW_PREF_S}-debug#g" \
  -e "s#\b${OLD_NET_RE}\b#${NEW_NET_S}#g"

# 3. Falco lab rules (preserve list names, tags, rule names, and current subnet IPs)
rewrite_file "detection/falco-rules/s05_db_access.yaml" \
  -e "s#${OLD_PREF_RE}-(webapp|authservice|database|logcollector|dashboard)#${NEW_PREF_S}-\\1#g"

rewrite_file "detection/falco-rules/s06_log_tamper.yaml" \
  -e "s#${OLD_PREF_RE}-logcollector#${NEW_PREF_S}-logcollector#g" \
  -e "s#${OLD_LOG_RE}/#${NEW_LOG_S}/#g"

rewrite_file "detection/falco-rules/s08_exfiltration.yaml" \
  -e "s#${OLD_PREF_RE}-(webapp|authservice)#${NEW_PREF_S}-\\1#g"

rewrite_file "detection/falco-rules/s09_credential_access.yaml" \
  -e "s#startswith \"${OLD_PREF_RE}-\"#startswith \"${NEW_PREF_S}-\"#g"

# 4. tailer.py defaults
rewrite_file "detection/log-tail/tailer.py" \
  -e "s#${OLD_LOG_RE}/#${NEW_LOG_S}/#g"

# 5. preflight.sh (keep subnet IPs and sentinelmesh_internal_ips list name untouched)
rewrite_file "linux_run/preflight.sh" \
  -e "s#${OLD_PREF_RE}-(webapp|authservice|database|logcollector|dashboard)#${NEW_PREF_S}-\\1#g" \
  -e "s#\b${OLD_NET_RE}\b#${NEW_NET_S}#g" \
  -e "s#${OLD_LOG_RE}#${NEW_LOG_S}#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_WEBAPP_PORT}/health#127.0.0.1:${NEW_WEBAPP_PORT}/health#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_AUTHSERVICE_PORT}/health#127.0.0.1:${NEW_AUTHSERVICE_PORT}/health#g" \
  -e "s#127\\.0\\.0\\.1:${OLD_GRAFANA_PORT}/api/health#127.0.0.1:${NEW_GRAFANA_PORT}/api/health#g"

# 6. check_run.py (rewrite any non-subnet prefix/path/net references while preserving LAB_STATIC)
rewrite_file "linux_run/check_run.py" \
  -e "s#${OLD_PREF_RE}-(webapp|authservice|database|logcollector|dashboard)#${NEW_PREF_S}-\\1#g" \
  -e "s#\b${OLD_NET_RE}\b#${NEW_NET_S}#g" \
  -e "s#${OLD_LOG_RE}#${NEW_LOG_S}#g"

# 7. Container internal build/provisioning/seed files
rewrite_file "services/logcollector/Dockerfile" \
  -e "s#${OLD_LOG_RE}#${NEW_LOG_S}#g"

rewrite_file "services/logcollector/fluent.conf" \
  -e "s#${OLD_LOG_RE}#${NEW_LOG_S}#g"

rewrite_file "services/database/init.sql" \
  -e "s#'${OLD_TUSER_RE}', '${OLD_TPASS_RE}'#'${NEW_TUSER_S}', '${NEW_TPASS_S}'#g"

rewrite_file "services/dashboard/provisioning/datasources.yml" \
  -e "s#database:[[:space:]]*${OLD_DB_RE}\b#database: ${NEW_DB_S}#g" \
  -e "s#password:[[:space:]]*${OLD_PASS_RE}\b#password: ${NEW_PASS_S}#g"

# --- Verify: refuse to finish if any old deployment value remains ---
LEFT=0
check_none_grep() {
  local desc="$1"
  local pattern="$2"
  shift 2
  for f in "$@"; do
    if grep -qE "$pattern" "$f"; then
      echo "LEFTOVER ${desc} in ${f}:" >&2
      grep -nE "$pattern" "$f" >&2
      LEFT=1
    fi
  done
}

if [ "$OLD_CONTAINER_PREFIX" != "$NEW_CONTAINER_PREFIX" ]; then
  check_none_grep "container name" "${OLD_PREF_RE}-(webapp|authservice|database|logcollector|dashboard|proxy|ngrok|debug)" "${MANAGED_FILES[@]}"
  check_none_grep "Falco prefix condition" "startswith \"${OLD_PREF_RE}-\"" "detection/falco-rules/s09_credential_access.yaml"
fi
if [ "$OLD_LAB_NET_NAME" != "$NEW_LAB_NET_NAME" ]; then
  check_none_grep "network name" "\\b${OLD_NET_RE}\\b" "${MANAGED_FILES[@]}"
fi
if [ "$OLD_LOG_DIR" != "$NEW_LOG_DIR" ]; then
  check_none_grep "log directory" "${OLD_LOG_RE}" "${MANAGED_FILES[@]}"
fi
if [ "$OLD_WEBAPP_PORT" != "$NEW_WEBAPP_PORT" ] || \
   [ "$OLD_AUTHSERVICE_PORT" != "$NEW_AUTHSERVICE_PORT" ] || \
   [ "$OLD_POSTGRES_PORT" != "$NEW_POSTGRES_PORT" ] || \
   [ "$OLD_GRAFANA_PORT" != "$NEW_GRAFANA_PORT" ] || \
   [ "$OLD_FLUENTD_PORT" != "$NEW_FLUENTD_PORT" ]; then
  check_none_grep "host port" \
    "127\\.0\\.0\\.1:(${OLD_WEBAPP_PORT}|${OLD_AUTHSERVICE_PORT}|${OLD_POSTGRES_PORT}|${OLD_GRAFANA_PORT}|${OLD_FLUENTD_PORT})\\b" \
    "docker-compose.yml" "linux_run/preflight.sh"
fi
if [ "$OLD_DB_NAME" != "$NEW_DB_NAME" ]; then
  check_none_grep "database name" "(DB_NAME=${OLD_DB_RE}\\b|POSTGRES_DB=${OLD_DB_RE}\\b|database:[[:space:]]*${OLD_DB_RE}\\b)" \
    "docker-compose.yml" "services/dashboard/provisioning/datasources.yml"
fi
if [ "$OLD_DB_PASS" != "$NEW_DB_PASS" ]; then
  check_none_grep "database password" "(DB_PASS=${OLD_PASS_RE}\\b|POSTGRES_PASSWORD=${OLD_PASS_RE}\\b|password:[[:space:]]*${OLD_PASS_RE}\\b)" \
    "docker-compose.yml" "services/dashboard/provisioning/datasources.yml"
fi
if [ "$OLD_TEST_PASS" != "$NEW_TEST_PASS" ]; then
  check_none_grep "test user password" "'${OLD_TUSER_RE}', '${OLD_TPASS_RE}'" "services/database/init.sql"
fi

if [ "$LEFT" -ne 0 ]; then
  echo "ERROR: old deployment values remain — files NOT left in a clean state." >&2
  exit 1
fi

echo "OK: switched environment to $TARGET (prefix=$NEW_CONTAINER_PREFIX, net=$NEW_LAB_NET_NAME, log_dir=$NEW_LOG_DIR)"
