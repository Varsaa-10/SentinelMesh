#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "========================================="
echo "Scenario 11 - Terminal Shell in Container"
echo "========================================="

PYTHON_BIN=$(command -v python3 2>/dev/null || command -v python)

if [ -t 0 ] && [ -t 1 ]; then
    MSYS_NO_PATHCONV=1 docker exec -it "$WEBAPP_CONTAINER" sh -c "id >/dev/null"
else
    MSYS_NO_PATHCONV=1 "$PYTHON_BIN" -c '
import os, pty, select, subprocess, sys
container = sys.argv[1]
master, slave = pty.openpty()
proc = subprocess.Popen(
    ["docker", "exec", "-it", container, "sh", "-c", "id >/dev/null"],
    stdin=slave,
    stdout=slave,
    stderr=slave,
    close_fds=True,
)
os.close(slave)
while proc.poll() is None:
    r, _, _ = select.select([master], [], [], 0.2)
    if r:
        try:
            os.read(master, 4096)
        except OSError:
            break
os.close(master)
raise SystemExit(proc.returncode or 0)
' "$WEBAPP_CONTAINER"
fi

echo
echo "[✓] Interactive terminal shell simulation complete."
