# KB-P2 — Distractor Records Population

**Status:** Complete  
**Days:** 2–3  
**Branch:** `feature/module-kb-master`

## Objective

Populate tactic-sibling distractor technique and CVE records to make retrieval accuracy a meaningful metric. Distractors share tactics/themes with scenario-critical techniques but are never referenced by any SentinelMesh scenario — they create retrieval noise that prevents Person 2's RAG engine from trivially returning the correct result.

## Technique Distractors Written (28 records)

| Tactic | IDs |
|---|---|
| Initial Access | T1566, T1133, T1195 |
| Credential Access | T1555, T1552, T1528, T1539, T1003 |
| Lateral Movement | T1550, T1563, T1534, T1080 |
| Defense Evasion | T1036, T1027, T1562, T1553 |
| Exfiltration | T1048, T1029 |
| Persistence | T1053.003, T1136, T1098 |
| Discovery | T1082, T1083, T1087 |
| Execution | T1059 |
| Privilege Escalation | T1068 |
| Impact | T1485, T1499 |

Total: **28 distractor techniques** + **8 scenario-critical** = **36 technique records**

## CVE Distractors Written (15 records)

| CVE | Description | Mapped To |
|---|---|---|
| CVE-2021-44228 | Log4Shell (Apache Log4j2 RCE) | T1190 |
| CVE-2021-45046 | Log4j2 CVE-2021-44228 fix bypass | T1190 |
| CVE-2022-0847 | Dirty Pipe (Linux kernel) | T1068 |
| CVE-2021-4034 | PwnKit (polkit pkexec) | T1068 |
| CVE-2021-3156 | Baron Samedit (sudo heap overflow) | T1068 |
| CVE-2021-22555 | Linux netfilter OOB write | T1068 |
| CVE-2022-22965 | Spring4Shell (Spring MVC RCE) | T1190 |
| CVE-2021-41773 | Apache httpd 2.4.49 path traversal | T1190 |
| CVE-2021-26084 | Confluence OGNL injection | T1190 |
| CVE-2020-11651 | SaltStack auth bypass | T1078, T1190 |
| CVE-2019-11043 | PHP-FPM RCE via nginx | T1190 |
| CVE-2020-15257 | containerd-shim socket exposure | T1068, T1021 |
| CVE-2019-14271 | Docker cp shared lib exploit | T1068 |
| CVE-2020-14882 | Oracle WebLogic unauthenticated RCE | T1190 |
| CVE-2018-11776 | Apache Struts2 S2-057 RCE | T1190 |

Total: **15 distractor CVE records** + **1 scenario-critical** = **16 CVE records**

## Final KB Totals

| Category | Count | Meets PRD requirement? |
|---|---|---|
| Scenario-critical techniques | 8 | ✅ (9 scenarios, 8 unique technique IDs) |
| Distractor techniques | 28 | ✅ (PRD: 20–40) |
| **Total techniques** | **36** | ✅ (PRD: 30–50) |
| Lab-planted CVEs | 1 | ✅ |
| Distractor CVEs | 15 | ✅ (PRD: 15–20 total CVE records) |
| **Total CVEs** | **16** | ✅ (PRD: 15–20) |

## Acceptance Criteria

- [x] All 36 technique records pass `validate_schema.py`
- [x] All 16 CVE records pass `validate_schema.py`
- [x] Distractor count (28 techniques, 15 CVEs) meets PRD targets
- [x] No distractor record sets `is_scenario_critical: true`
- [x] No distractor record lists any `scenario_refs`
- [x] All CVE descriptions factually accurate (sourced from NVD/MITRE)
- [x] Committed and pushed
