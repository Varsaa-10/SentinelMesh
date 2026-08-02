# Database Service — Planted Vulnerabilities

## Service Info
- **Container name:** `sentinelmesh-database`
- **Internal port:** `5432`
- **Base image:** `postgres:15-alpine`

## Vulnerability 1: Permissive `pg_hba.conf` Network Policy (Trust All)
- **Scenario #:** S5
- **Type:** CWE-284 (Improper Access Control)
- **Location:** `services/database/pg_hba.conf:9-11` and `docker-compose.yml:84`
- **Description:** PostgreSQL host-based authentication overrides default rules with `host all all 0.0.0.0/0 trust` and `host all all ::/0 trust`. Any service or container on the network can establish a PostgreSQL connection as any user (including `postgres` superuser) without providing a password.
- **Exploitation example:**
  ```bash
  psql -h 127.0.0.1 -p 5432 -U postgres -d sentinelmesh -c "SELECT username, password, role FROM users;"
  ```
- **Expected result:** Successful execution of PostgreSQL queries without prompting for password authentication, returning all database content including usernames and passwords.
