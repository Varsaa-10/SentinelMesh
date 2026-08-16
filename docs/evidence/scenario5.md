# Scenario 5 – Sensitive Credential Access

Date: 2026-08-03

Attack Command:
docker exec sentinelmesh-webapp cat /etc/shadow

Falco Alert:

Sensitive credential file read
user=root
command=cat /etc/shadow
file=/etc/shadow
container=sentinelmesh-webapp

Result:
Detection successful.
False positive from /etc/passwd removed.
