# Scenario 1 – Remote Code Execution Consequence

Date: 2026-08-03

Attack Command:
docker exec sentinelmesh-webapp sh -c "id"

Falco Alert:

Critical Possible RCE detected
user=root
command=sh -c id
parent=containerd-shim
container=sentinelmesh-webapp

Result:
Detection successful.
