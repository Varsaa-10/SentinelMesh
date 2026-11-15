# S1. Detector specifications (generated automatically from the detector source by `sentinelmesh_x/knowledge_gen.py`)

Registered ATT&CK id = operator mapping from `eval/ground_truth.json`.

## scenario1_detector.py / SQL Injection Authentication Bypass
- kind: log_tail; registered technique: T1190; severity/priority: CRITICAL
- event types: ['login_attempt']; thresholds: {}; data source: ['Application Log: Application Log Content']
- parser notes: none
- generated description: Application log detector, source log_tail, watches login_attempt events. Condition 1: result in (success); match of pattern [('|--|;|\bOR\b|\bUNION\b|\bAND\b\s+\d+\s*=\s*\d+)] on field username/payload/request/query/body/identifier. Data source: Application Log: Application Log Content.

## scenario2_detector.py / Brute-Force Login Attempt
- kind: log_tail; registered technique: T1110; severity/priority: WARNING
- event types: ['login_attempt']; thresholds: {'count': 5, 'window_seconds': 30}; data source: ['Application Log: Application Log Content']
- parser notes: none
- generated description: Application log detector, source log_tail, watches login_attempt events. Condition 1: result in (fail, failure); event count >= 5. Threshold: count=5, window_seconds=30. Data source: Application Log: Application Log Content.

## scenario3_detector.py / (log detector)
- kind: log_tail; registered technique: T1078; severity/priority: WARNING
- event types: ['login_attempt']; thresholds: {}; data source: ['Application Log: Application Log Content']
- parser notes: none
- generated description: Application log detector, source log_tail, watches login_attempt events. Condition 1: result in (success); identifier/username/user in (admin). Data source: Application Log: Application Log Content.

## scenario4_detector.py / JWT Algorithm Confusion
- kind: log_tail; registered technique: T1212; severity/priority: CRITICAL
- event types: ['jwt_verification']; thresholds: {}; data source: ['Application Log: Application Log Content']
- parser notes: none
- generated description: Application log detector, source log_tail, watches jwt_verification events. Condition 1: result in (valid); details.algorithm in (none). Condition 2: match of pattern [(algorithm|\balg\b|hs256|rs256)] on field reason. Data source: Application Log: Application Log Content.

## scenario7_detector.py / Grafana Login Succeeded (unconfirmed — username not visible in this log line; default admin/admin credentials used by the attack script)
- kind: log_tail; registered technique: T1078; severity/priority: WARNING
- event types: []; thresholds: {}; data source: ['Application Log: Application Log Content']
- parser notes: none
- generated description: Application log detector, source log_tail, watches application events. Condition 1: match of pattern [msg="Request Completed"] on field raw_log_line; match of pattern [method=POST\s+path=/login\s+status=200] on field raw_log_line. Condition 2: match of pattern [msg="Request Completed"] on field raw_log_line; match of pattern [method=GET\s+path=(/api/\S*|/d/\S*)\s+status=200] on field raw_log_line; match of pattern [\buname=\s] on field raw_log_line or match of pattern [\buserId=0\b] on field raw_log_line. Data source: Application Log: Application Log Content.

## s05_db_access.yaml / SentinelMesh Unauthorized Database Connection
- kind: falco; registered technique: T1021; severity/priority: WARNING
- event types: ['accept']; thresholds: {}; data source: ['Network Traffic: Network Traffic Content']
- parser notes: none
- generated description: Kernel runtime detector, source falco. System call accept. Container = sentinelmesh-database. Server port 5432. Peer address not in allow-list of 2 addresses. Priority WARNING. Data source: Network Traffic: Network Traffic Content.

## s06_log_tamper.yaml / SentinelMesh Log Directory Tampering
- kind: falco; registered technique: T1070; severity/priority: WARNING
- event types: ['open', 'openat', 'openat2']; thresholds: {}; data source: ['File: File Access']
- parser notes: none
- generated description: Kernel runtime detector, source falco. System call open, openat, openat2. File opened for writing. Container = sentinelmesh-logcollector. File path startswith /var/log/sentinelmesh/. Priority WARNING. Data source: File: File Access.

## s08_exfiltration.yaml / SentinelMesh Unexpected Outbound Connection
- kind: falco; registered technique: T1041; severity/priority: CRITICAL
- event types: ['connect']; thresholds: {}; data source: ['Network Traffic: Network Connection Creation']
- parser notes: none
- generated description: Kernel runtime detector, source falco. System call connect. fd.typechar = 4. fd.typechar = 6. Container in sentinelmesh-webapp, sentinelmesh-authservice. File path contains ->. Peer address not in allow-list of 9 addresses. Priority CRITICAL. Data source: Network Traffic: Network Connection Creation.

## s09_credential_access.yaml / SentinelMesh Sensitive Credential File Read
- kind: falco; registered technique: T1003.008; severity/priority: CRITICAL
- event types: ['open', 'openat', 'openat2']; thresholds: {}; data source: ['File: File Access']
- parser notes: none
- generated description: Kernel runtime detector, source falco. System call open, openat, openat2. File opened for reading. Container startswith sentinelmesh-. File path = /etc/shadow. File path glob /root/.ssh/*. File path = /root/.aws/credentials. Priority CRITICAL. Data source: File: File Access.

