#!/bin/bash

echo "========================================="
echo "Scenario 14 - PTRACE Attach to Process"
echo "========================================="

MSYS_NO_PATHCONV=1 docker exec sentinelmesh-authservice python3 -c '
import ctypes, os, signal, time
libc = ctypes.CDLL("libc.so.6", use_errno=True)
pid = os.fork()
if pid == 0:
    time.sleep(2)
    os._exit(0)
try:
    res = libc.ptrace(16, pid, 0, 0)
    if res == 0:
        os.waitpid(pid, 0)
        libc.ptrace(17, pid, 0, 0)
finally:
    try:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    except OSError:
        pass
'

echo
echo "[✓] PTRACE attach simulation complete."
