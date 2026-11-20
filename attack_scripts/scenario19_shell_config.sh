#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 19 - Modify Shell Configuration File"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec -e MARKER="${CONTAINER_PREFIX}-s19" "$AUTHSERVICE_CONTAINER" python3 -c '
import os
from pathlib import Path
marker = os.environ["MARKER"]
rc = Path("/root/.bashrc")
existed = rc.exists()
orig = rc.read_text(encoding="utf-8") if existed else ""
try:
    with rc.open("a", encoding="utf-8") as f:
        f.write(f"# {marker}\n")
finally:
    if existed:
        cleaned = "".join(
            line for line in rc.read_text(encoding="utf-8").splitlines(keepends=True)
            if marker not in line
        )
        rc.write_text(cleaned if orig else orig, encoding="utf-8")
    elif rc.exists():
        rc.unlink()
'

echo
echo "[✓] Shell configuration modification complete."
