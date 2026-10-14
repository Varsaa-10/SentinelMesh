#!/usr/bin/env bash
# set_subnet.sh — rewrite the lab subnet prefix across the five files that hold it.
#
# Usage:  ./linux_run/set_subnet.sh <PREFIX>
#   where <PREFIX> is the first two octets, e.g. 172.18  or  10.20
#
# Lab addresses are <PREFIX>.0.<host>, hosts fixed:
#   database .2  logcollector .3  webapp .4  authservice .5  dashboard .6
# Subnet is <PREFIX>.0.0/16.
#
# The script finds the current prefix automatically, replaces it everywhere in
# the five files, and refuses to finish if any old lab address is left.
set -euo pipefail

# --- locate repo root (this script lives in linux_run/) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- the five files that hold the address ---
FILES=(
  "docker-compose.yml"
  "detection/falco-rules/s05_db_access.yaml"
  "detection/falco-rules/s08_exfiltration.yaml"
  "linux_run/preflight.sh"
  "linux_run/check_run.py"
)

# --- validate argument ---
NEW="${1:-}"
if [[ -z "$NEW" ]]; then
  echo "usage: $0 <PREFIX>   e.g. $0 172.18" >&2
  exit 2
fi
if [[ ! "$NEW" =~ ^[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "ERROR: prefix must be two octets like 172.18 or 10.20 (got '$NEW')" >&2
  exit 2
fi
if [[ "$NEW" == "172.17" ]]; then
  echo "ERROR: 172.17 is Docker's default bridge. Pick another prefix." >&2
  exit 2
fi

# --- detect the current prefix from docker-compose.yml subnet line ---
CUR="$(grep -oE 'subnet:[[:space:]]*[0-9]+\.[0-9]+' docker-compose.yml | head -1 | grep -oE '[0-9]+\.[0-9]+$' || true)"
if [[ -z "$CUR" ]]; then
  echo "ERROR: could not find current 'subnet: X.Y.0.0/16' in docker-compose.yml" >&2
  exit 1
fi

if [[ "$CUR" == "$NEW" ]]; then
  echo "Current prefix is already $NEW — nothing to change."
exit 0
else
  echo "Rewriting lab prefix: $CUR  ->  $NEW"
fi

# --- confirm all files exist first ---
for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || { echo "ERROR: missing file $f" >&2; exit 1; }
done

# --- escape dots for regex matching of the current prefix ---
CUR_RE="${CUR//./\\.}"

# Match the current prefix only when it is the start of a lab address
# (<CUR>.0.<host>) or the subnet (<CUR>.0.0/16). Both begin "<CUR>.0.",
# so we anchor on that and never touch 127.0.0.1, 0.0.0.0, ::1, 127.0.0.11.
for f in "${FILES[@]}"; do
  sed -i -E "s/${CUR_RE}\.0\./${NEW}.0./g" "$f"
done

# --- verify: no old lab address of the form <CUR>.0.<n> remains ---
LEFT=0
for f in "${FILES[@]}"; do
  if grep -qE "${CUR_RE}\.0\.[0-9]" "$f"; then
    echo "LEFTOVER old address in $f:" >&2
    grep -nE "${CUR_RE}\.0\.[0-9]" "$f" >&2
    LEFT=1
  fi
done
if [[ "$LEFT" -ne 0 ]]; then
  echo "ERROR: old addresses remain — files NOT left in a clean state." >&2
  exit 1
fi

# --- confirm the new addresses are present where expected ---
echo
echo "Now using prefix $NEW. Lab addresses:"
echo "  database     ${NEW}.0.2"
echo "  logcollector ${NEW}.0.3"
echo "  webapp       ${NEW}.0.4"
echo "  authservice  ${NEW}.0.5"
echo "  dashboard    ${NEW}.0.6"
echo "  subnet       ${NEW}.0.0/16"
echo
echo "OK: all five files rewritten to ${NEW}.0.0/16"
