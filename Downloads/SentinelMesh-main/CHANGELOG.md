# Changelog — SentinelMesh (Module A1: Lab Infrastructure Build)

All notable changes to the SentinelMesh lab infrastructure will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.1-lab] - 2026-08-04

### Added (Module A1 PRD Addendum — Structured Security Logging)
- **Structured JSON-lines security event logging** for app-layer services to support Person 2's Detection module (A2) log-tail companion:
  - `services/webapp/app.py`: Added `log_security_event()` helper; `/login` endpoint now emits `login_attempt` events (success/failure) to `/var/log/sentinelmesh/webapp_events.log`.
  - `services/authservice/app.py`: Added `log_security_event()` helper; `/auth/login` emits `login_attempt` events and `/auth/verify` emits `jwt_verification` events (valid/invalid/expired) to `/var/log/sentinelmesh/auth_events.log`.
- **Docker Compose volume update**: Added `log_data:/var/log/sentinelmesh` mount to `authservice` so both app-layer services share the log volume with `logcollector`.
- **Vulnerability documentation updated**: Added structured log file paths to `docs/vulnerabilities/authservice.md` and `docs/vulnerabilities/webapp.md` for Person 2 handoff.

---

## [v1.0-lab] - 2026-08-02

### Added
- **5-Service Scaffolding (Phase 1):**
  - `webapp`: Flask web application on port `5000` (Python 3.11-slim).
  - `authservice`: Flask authentication service on port `5001` (Python 3.11-slim).
  - `database`: PostgreSQL 15 database service on port `5432` (PostgreSQL 15-alpine).
  - `logcollector`: Fluentd log collector on port `24224` (Fluentd v1.16-1).
  - `dashboard`: Grafana analytics dashboard on port `3000` (Grafana latest).
  - `docker-compose.yml`: Integrated multi-container compose configuration with internal isolated bridge network (`sentinelmesh_net`) and strict `127.0.0.1` host port bindings.
- **Vulnerability Implantation (Phase 2):**
  - **S1 (CWE-89):** Raw SQL query concatenation in `/login` endpoint of `webapp`.
  - **S2 (CWE-307):** Missing rate-limiting, CAPTCHA, or lockout mechanism on `/login` endpoint of `webapp`.
  - **S3 (CWE-798):** Pre-seeded default admin credentials (`admin` / `admin123`) in `database` and authenticated via `authservice`.
  - **S4 (CWE-327 / CVE-2022-29217):** Algorithm confusion support and vulnerable `PyJWT==1.7.1` dependency in `authservice`.
  - **S5 (CWE-284):** Overly permissive `pg_hba.conf` network trust policy in `database`.
  - **S6 (CWE-732):** World-writable permissions (`777`) on shared log volume path `/var/log/sentinelmesh/` in `logcollector`.
  - **S7 (CWE-798 / CWE-306):** Default admin password (`admin`) and anonymous read access enabled (`GF_AUTH_ANONYMOUS_ENABLED=true`) in `dashboard`.
- **Per-Service Vulnerability Documentation (Phase 3):**
  - `docs/vulnerabilities/webapp.md`
  - `docs/vulnerabilities/authservice.md`
  - `docs/vulnerabilities/database.md`
  - `docs/vulnerabilities/logcollector.md`
  - `docs/vulnerabilities/dashboard.md`
- **Manual Smoke Testing & Results (Phase 4):**
  - `docs/smoke-test-results.md`: Complete empirical execution evidence and pass/fail results proving 100% exploitability across all 7 vulnerability scenarios.
- **Lab Infrastructure Freeze & Automation (Phase 5):**
  - `reset_lab.sh`: Automated Bash reset script for Linux/macOS/Git Bash environments.
  - `reset_lab.ps1`: Automated PowerShell reset script for Windows environments.
  - `CHANGELOG.md`: Infrastructure changelog documenting Module A1 implementation.

### Fixed
- **Integration Fix Buffer (Day 4):**
  - Updated `/auth/verify` exception handler in `services/authservice/app.py` to catch `jwt.PyJWTError` (preventing unhandled 500 internal server errors during signature verification checks).
  - Resolved path conversion handling for Git Bash on Windows during container exec operations.
