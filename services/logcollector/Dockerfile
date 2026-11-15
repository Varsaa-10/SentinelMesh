# SentinelMesh — Log Collector Service
FROM fluentd:v1.16-1@sha256:1ad8ae3e827a63e119717cbc995ba416165edf47f802f35d9ec3a28b90874351

USER root

# Create log output directory with correct ownership for fluent user
# VULNERABLE — INTENTIONAL FOR LAB
# Vulnerability (CWE-732): World-writable log path
# chmod 777 allows ANY container mounting this volume to read/write/delete logs.
RUN mkdir -p /var/log/sentinelmesh && \
    chmod -R 777 /var/log/sentinelmesh && \
    apk add --no-cache tcpdump

COPY fluent.conf /fluentd/etc/fluent.conf

EXPOSE 24224

USER fluent
