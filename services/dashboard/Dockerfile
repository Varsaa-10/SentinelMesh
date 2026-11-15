# SentinelMesh — Dashboard Service (Grafana)
FROM grafana/grafana:13.3.1@sha256:0615ec4fbd4072004b7d86b46ded63013a74b7d6eb1119273dd89e8fa25c13cf

USER root

# Build-time tool for ENV2 S25 scenario (nmap)
RUN apk add --no-cache nmap

USER 472
