import React, { useState, useEffect } from 'react';

export default function LiveContainerStreamer({ onInjectLog }) {
    const [containerId, setContainerId] = useState('webapp');
    const [logLine, setLogLine] = useState("GET /api/v1/user?id=1 UNION SELECT username, password FROM users --");
    const [severity, setSeverity] = useState('CRITICAL');
    const [isAutoStreaming, setIsAutoStreaming] = useState(false);

    useEffect(() => {
        let interval;
        if (isAutoStreaming) {
            const sampleLogs = [
                { service: 'webapp', title: 'Unauthorized Admin Access', severity: 'HIGH', event: { endpoint: '/admin/config', src: '10.0.4.12' } },
                { service: 'auth-service', title: 'Multiple Failed Token Verification', severity: 'MEDIUM', event: { err: 'Invalid signature', count: 12 } },
                { service: 'api-gateway', title: 'Rate Limit Threshold Exceeded', severity: 'MEDIUM', event: { ip: '198.51.100.4', rps: 450 } },
                { service: 'k8s-node-01', title: 'Suspicious Exec Shell Process Spawn', severity: 'CRITICAL', event: { binary: '/bin/bash', ppid: 1042 } },
            ];
            interval = setInterval(() => {
                const rand = sampleLogs[Math.floor(Math.random() * sampleLogs.length)];
                onInjectLog({
                    source: 'docker-live-stream',
                    scenario: 'S3',
                    severity: rand.severity,
                    title: rand.title,
                    service: rand.service,
                    event: rand.event
                });
            }, 3500);
        }
        return () => {
            if (interval) clearInterval(interval);
        };
    }, [isAutoStreaming, onInjectLog]);

    const handleInject = (e) => {
        e.preventDefault();
        if (!logLine.trim()) return;
        onInjectLog({
            source: 'container-live-stream',
            scenario: 'S1',
            severity: severity,
            title: `Live Container Stream (${containerId}): ${logLine.slice(0, 45)}...`,
            service: containerId,
            event: { raw_log: logLine, timestamp: new Date().toISOString() }
        });
    };

    return (
        <div style={{
            background: 'rgba(59, 130, 246, 0.04)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap',
            marginTop: '0.5rem'
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flex: 1, minWidth: '280px' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    🐳 Live Container Streamer:
                </span>
                <select
                    value={containerId}
                    onChange={(e) => setContainerId(e.target.value)}
                    style={{
                        background: '#121826',
                        border: '1px solid var(--panel-border)',
                        color: '#fff',
                        padding: '0.3rem 0.5rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem'
                    }}
                >
                    <option value="webapp">container: webapp</option>
                    <option value="auth-service">container: auth-service</option>
                    <option value="api-gateway">container: api-gateway</option>
                    <option value="k8s-node-01">container: k8s-node-01</option>
                    <option value="db-container">container: db-container</option>
                </select>
                <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    style={{
                        background: '#121826',
                        border: '1px solid var(--panel-border)',
                        color: '#fff',
                        padding: '0.3rem 0.5rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem'
                    }}
                >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                </select>
            </div>

            <form onSubmit={handleInject} style={{ display: 'flex', gap: '0.5rem', flex: 2, minWidth: '320px' }}>
                <input
                    type="text"
                    value={logLine}
                    onChange={(e) => setLogLine(e.target.value)}
                    placeholder="Paste live Docker container log stdout string..."
                    style={{
                        flex: 1,
                        background: 'rgba(0,0,0,0.4)',
                        border: '1px solid var(--panel-border)',
                        color: '#38bdf8',
                        fontFamily: "'Fira Code', monospace",
                        fontSize: '0.75rem',
                        padding: '0.35rem 0.75rem',
                        borderRadius: '6px'
                    }}
                />
                <button
                    type="submit"
                    className="trigger-btn"
                    style={{ background: 'var(--accent-blue)', color: '#fff', fontWeight: 600 }}
                >
                    ⚡ Inject Log Event
                </button>
            </form>

            <button
                type="button"
                onClick={() => setIsAutoStreaming(!isAutoStreaming)}
                className="trigger-btn"
                style={{
                    background: isAutoStreaming ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                    borderColor: isAutoStreaming ? 'var(--accent-red)' : 'var(--accent-green)',
                    color: isAutoStreaming ? 'var(--accent-red)' : 'var(--accent-green)',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem'
                }}
            >
                <span>{isAutoStreaming ? '⏹ Stop Auto-Stream' : '🔌 Start Auto-Stream'}</span>
            </button>
        </div>
    );
}
