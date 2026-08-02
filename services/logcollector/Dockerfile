# SentinelMesh — Log Collector Service
FROM fluentd:v1.16-1

USER root

# Create log output directory with correct ownership for fluent user
# VULNERABLE — INTENTIONAL FOR LAB
# Vulnerability (CWE-732): World-writable log path
# chmod 777 allows ANY container mounting this volume to read/write/delete logs.
RUN mkdir -p /var/log/sentinelmesh && \
    chmod -R 777 /var/log/sentinelmesh

COPY fluent.conf /fluentd/etc/fluent.conf

EXPOSE 24224

USER fluent
