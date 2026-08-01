# SentinelMesh — Log Collector Service
FROM fluentd:v1.16-1

USER root

# Create log output directory with correct ownership for fluent user
RUN mkdir -p /var/log/sentinelmesh && \
    chown -R fluent:fluent /var/log/sentinelmesh

COPY fluent.conf /fluentd/etc/fluent.conf

EXPOSE 24224

USER fluent
