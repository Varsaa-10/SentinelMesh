# Scenario 6 – Log Tampering

Date: 2026-08-03

Attack Command:
docker exec sentinelmesh-webapp sh -c 'echo "FAKE LOG ENTRY" >> $(ls /var/log/sentinelmesh/app*.log | tail -n1)'

Falco Alert:

Warning Log tampering detected
user=root
command=sh -c echo "FAKE LOG ENTRY" >> ...
file=/var/log/sentinelmesh/app.20260803.log
container=sentinelmesh-webapp

Result:
Detection successful.
