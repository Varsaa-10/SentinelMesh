#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 13 - Fileless Execution via memfd_create"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec "$WEBAPP_CONTAINER" python3 -c '
import os, shutil
from pathlib import Path
bin_path = shutil.which("true") or "/bin/true"
data = Path(bin_path).read_bytes()
fd = os.memfd_create("s13_payload", 0)
os.set_inheritable(fd, True)
os.write(fd, data)
os.lseek(fd, 0, os.SEEK_SET)
os.execv(f"/proc/self/fd/{fd}", ["s13_payload"])
'

echo
echo "[✓] Fileless memfd_create execution complete."
