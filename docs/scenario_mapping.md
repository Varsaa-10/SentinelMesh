# SentinelMesh Scenario Mapping

> **Authoritative source:** [`eval/ground_truth.json`](file:///D:/Project/SentinelMesh/eval/ground_truth.json)
> A separate Falco smoke-test manifest exists at `docs/falco_smoke_tests.json` — it uses its own independent scenario numbering and must not be confused with this table.

| ID | Lab Vulnerability | MITRE Technique | Attack Action | Detection Source |
|----|-------------------|-----------------|---------------|------------------|
| S1 | SQL Injection (CWE-89) | T1190 — Exploit Public-Facing Application | SQLi auth bypass on webapp `/login` | log-tail |
| S2 | No rate limiting (CWE-307) | T1110 — Brute Force | Repeated login attempts | log-tail |
| S3 | Default credentials (CWE-798) | T1078 — Valid Accounts | Login with admin/admin123 | log-tail |
| S4 | JWT alg:none (CVE-2022-29217) | T1212 — Exploitation for Credential Access | Forge unsigned JWT token | log-tail |
| S5 | Permissive pg_hba.conf (CWE-284) | T1021 — Remote Services | Direct DB connection from unauthorized source | falco |
| S6 | World-writable log dir (CWE-732) | T1070 — Indicator Removal | Write/overwrite audit logs | falco |
| S7 | Grafana default admin + anonymous access (CWE-798/CWE-306) | T1078 — Valid Accounts | Login with default creds or browse anonymously | log-tail |
| S8 | No egress restriction | T1041 — Exfiltration Over C2 Channel | Outbound connection to external destination | falco |
| S9 | Credential files readable (CWE-798/CWE-306) | T1003.008 — OS Credential Dumping: /etc/passwd | Read /etc/shadow or SSH keys | falco |
| S10 | Multi-stage chain | Composite (T1190, T1078, T1212, T1003.008, T1041) | S1 → S3 → S4 → S9 → S8 | log-tail + falco |

