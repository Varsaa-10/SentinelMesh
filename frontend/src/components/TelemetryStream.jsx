import React from 'react';

export default function TelemetryStream({ alerts }) {
    return (
        <section className="panel">
            <div className="panel-header">
                <div className="panel-title">
                    <span>⚡ Live Telemetry Stream</span>
                    <span className="badge-count">{alerts.length} alerts</span>
                </div>
            </div>
            <div className="stream-list">
                {alerts.length === 0 ? (
                    <div className="alert-meta">No alerts ingested yet. Click an attack button to trigger simulation.</div>
                ) : (
                    alerts.slice().reverse().map(alert => {
                        const isActioned = alert.status === "ACTIONED";
                        const sevClass = isActioned
                            ? "sev-resolved"
                            : alert.severity === "CRITICAL"
                                ? "sev-critical"
                                : alert.severity === "HIGH"
                                    ? "sev-high"
                                    : "sev-medium";
                        return (
                            <div className="alert-card" key={alert.alert_id}>
                                <div className="alert-top">
                                    <span className={`sev-tag ${sevClass}`}>
                                        {isActioned ? `RESOLVED (${alert.resolution})` : alert.severity}
                                    </span>
                                    <span className="alert-meta">{alert.scenario || alert.scenario_id || '-'} · {alert.service || '-'}</span>
                                </div>
                                <div className="alert-title">{alert.title}</div>
                                <div className="alert-meta">{JSON.stringify(alert.event || {})}</div>
                            </div>
                        );
                    })
                )}
            </div>
        </section>
    );
}
