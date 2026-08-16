# SentinelMesh Falco Scenario Mapping

| ID | Lab Vulnerability | Attack Action | Falco Detection |
|----|-------------------|---------------|-----------------|
| S1 | SQL Injection | Web exploit causes shell spawn | webapp spawning shell |
| S2 | Rate limit bypass | Brute force requests | repeated connections/log events |
| S3 | Default credentials | Login then privileged action | suspicious auth process |
| S4 | JWT bypass | Token abuse | suspicious process/network activity |
| S5 | DB trust policy | Unauthorized DB access | unexpected DB connection |
| S6 | Writable logs | Modify audit logs | log file write |
| S7 | Dashboard anonymous access | Abuse dashboard | suspicious dashboard process |
| S8 | Exfiltration | Send data outward | unexpected outbound connection |
| S9 | Chain | RCE → privilege → exfil | multiple alerts sequence |
