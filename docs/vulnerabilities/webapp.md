# Web Application Service — Planted Vulnerabilities

## Service Info
- **Container name:** `sentinelmesh-webapp`
- **Internal port:** `5000`
- **Base image:** `python:3.11-slim`
- **Structured log path:** `/var/log/sentinelmesh/webapp_events.log` (emits `login_attempt` JSON-lines events)

## Vulnerability 1: SQL Injection in `/login`
- **Scenario #:** S1
- **Type:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Location:** `services/webapp/app.py:90`
- **Description:** User input (`username` and `password`) from the JSON payload is directly formatted into a raw SQL query string using Python f-strings without parameterization, escaping, or sanitization.
- **Exploitation example:**
  ```bash
  curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username": "admin'\'' OR 1=1 --", "password": "anything"}'
  ```
- **Expected result:** HTTP 200 OK response returning `{"status": "success", "message": "Login successful", "user": {"id": 2, "username": "admin", "role": "admin"}}` without needing a valid password.

## Vulnerability 2: Missing Rate Limiting on `/login`
- **Scenario #:** S2
- **Type:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location:** `services/webapp/app.py:60`
- **Description:** The `/login` endpoint lacks any request throttling, IP rate limiting, CAPTCHA validation, or account lockout policy. Automated tools can send unlimited login requests per second.
- **Exploitation example:**
  ```bash
  for i in {1..50}; do curl -s -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"attempt_$i\"}"; done
  ```
- **Expected result:** All authentication requests return immediate 401 Unauthorized or 200 OK responses without receiving HTTP 429 Too Many Requests or encountering any delay.
