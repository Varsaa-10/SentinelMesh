# Scenario 8 – Exfiltration

Date: 2026-08-03

Attack Command:
docker exec sentinelmesh-webapp curl http://example.com

Falco Alert:

Warning Possible exfiltration tool executed
user=root
command=curl http://example.com
container=sentinelmesh-webapp

False Positive Reduction:
Excluded Docker health check:
curl -sf http://localhost:5000/health

Result:
Detection successful.
