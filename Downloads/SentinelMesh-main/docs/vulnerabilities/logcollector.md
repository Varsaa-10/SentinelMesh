# Log Collector Service — Planted Vulnerabilities

## Service Info
- **Container name:** `sentinelmesh-logcollector`
- **Internal port:** `24224`
- **Base image:** `fluentd:v1.16-1`

## Vulnerability 1: World-Writable Log Path
- **Scenario #:** S6
- **Type:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Location:** `services/logcollector/Dockerfile:10-11` and `docker-compose.yml:110`
- **Description:** The log directory `/var/log/sentinelmesh` is created with permissions set to `777` (`chmod -R 777`). Because this path is mounted via shared Docker volume `log_data` across containers, any container or non-root user can tamper with, overwrite, or delete audit logs.
- **Exploitation example:**
  ```bash
  docker exec -it sentinelmesh-webapp sh -c "echo 'AUDIT LOG OVERWRITTEN' > /var/log/sentinelmesh/app.log"
  ```
- **Expected result:** The file content in `/var/log/sentinelmesh/` is altered without permission denied errors, destroying log integrity.
