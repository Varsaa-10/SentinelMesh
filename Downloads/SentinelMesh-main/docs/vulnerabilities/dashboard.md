# Dashboard Service — Planted Vulnerabilities

## Service Info
- **Container name:** `sentinelmesh-dashboard`
- **Internal port:** `3000`
- **Base image:** `grafana/grafana:latest`

## Vulnerability 1: Default Grafana Credentials & Anonymous Access
- **Scenario #:** S7
- **Type:** CWE-798 (Use of Hard-coded Credentials) / CWE-306 (Missing Authentication for Critical Function)
- **Location:** `docker-compose.yml:126-129`
- **Description:** Grafana is deployed with default admin credentials (`admin` / `admin`) via `GF_SECURITY_ADMIN_USER` and `GF_SECURITY_ADMIN_PASSWORD`. In addition, `GF_AUTH_ANONYMOUS_ENABLED=true` permits unauthenticated access to the dashboard UI and REST APIs with `Viewer` privilege.
- **Exploitation example:**
  ```bash
  # Check unauthenticated anonymous access:
  curl -s http://127.0.0.1:3000/api/org
  # Authenticate with default admin credentials:
  curl -s -u admin:admin http://127.0.0.1:3000/api/admin/settings
  ```
- **Expected result:** Anonymous request returns organization details `{"id":1,"name":"Main Org."}` without credentials. Admin request with `admin:admin` succeeds with full administrative control over Grafana settings and datasources.
