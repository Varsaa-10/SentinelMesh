import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import AttackTriggerBar from './components/AttackTriggerBar';
import TelemetryStream from './components/TelemetryStream';
import InvestigationPanel from './components/InvestigationPanel';
import ApprovalQueue from './components/ApprovalQueue';
import MetricsGrid from './components/MetricsGrid';

const API_BASE = import.meta.env.DEV ? `http://${window.location.hostname}:8000` : '';
const WS_URL = (window.location.protocol === 'https:' ? 'wss://' : 'ws://')
    + (import.meta.env.DEV ? `${window.location.hostname}:8000` : window.location.host) + '/ws';

export default function App() {
    const [connected, setConnected] = useState(false);
    const [alerts, setAlerts] = useState([]);
    const [investigationData, setInvestigationData] = useState(null);
    const [investigating, setInvestigating] = useState(false);
    const [metrics, setMetrics] = useState(null);
    const [resolvingIds, setResolvingIds] = useState({});
    const [apiError, setApiError] = useState(null);

    const fetchAlerts = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/alerts`);
            if (res.ok) {
                const data = await res.json();
                setAlerts(data.alerts || []);
                setApiError(null);
            } else {
                setApiError("Cannot reach backend at " + (API_BASE || window.location.origin));
            }
        } catch (e) {
            setApiError("Cannot reach backend at " + (API_BASE || window.location.origin));
        }
    }, []);

    const fetchDecisions = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/decisions`);
            if (res.ok) {
                const data = await res.json();
                if (data.metrics) setMetrics(data.metrics);
                setApiError(null);
            }
        } catch (e) {
            setApiError("Cannot reach backend at " + (API_BASE || window.location.origin));
        }
    }, []);

    useEffect(() => {
        let ws;
        let timer;

        function connect() {
            try {
                ws = new WebSocket(WS_URL);
                ws.onopen = () => {
                    setConnected(true);
                    setApiError(null);
                    fetchAlerts();
                    fetchDecisions();
                };
                ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        if (data.type === "NEW_ALERT" || data.type === "RESET_COMPLETE") {
                            fetchAlerts();
                        } else if (data.type === "DECISION_LOGGED") {
                            if (data.metrics) setMetrics(data.metrics);
                            fetchAlerts();
                        }
                    } catch (e) {
                        console.warn("[App.jsx] Failed to parse WebSocket message:", e);
                    }
                };
                ws.onclose = ws.onerror = () => {
                    setConnected(false);
                    timer = setTimeout(connect, 3000);
                };
            } catch (e) {
                timer = setTimeout(connect, 3000);
            }
        }

        connect();
        return () => {
            if (ws) ws.close();
            if (timer) clearTimeout(timer);
        };
    }, [fetchAlerts, fetchDecisions]);

    const triggerAttack = async (scenarioId) => {
        try {
            const res = await fetch(`${API_BASE}/api/attacks/trigger`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scenario_id: scenarioId })
            });
            if (res.ok) {
                setApiError(null);
                fetchAlerts();
            } else {
                setApiError("Failed to trigger attack scenario " + scenarioId);
            }
        } catch (e) {
            setApiError("Error triggering scenario: " + e.message);
        }
    };

    const resetLab = async () => {
        try {
            const res = await fetch(`${API_BASE}/api/attacks/reset`, { method: "POST" });
            if (res.ok) setApiError(null);
            fetchAlerts();
            fetchDecisions();
        } catch (e) {
            setApiError("Error resetting lab: " + e.message);
        }
    };

    const runInvestigation = async () => {
        setInvestigating(true);
        try {
            const res = await fetch(`${API_BASE}/api/investigate`, { method: "POST" });
            if (res.ok) {
                const data = await res.json();
                setInvestigationData(data);
                setApiError(null);
            } else {
                setApiError("Error running investigation: HTTP " + res.status);
            }
        } catch (e) {
            setInvestigationData({ error: e.message });
            setApiError("Error running investigation: " + e.message);
        } finally {
            setInvestigating(false);
        }
    };

    const submitDecision = async (alertId, scenarioId, action) => {
        setResolvingIds(prev => ({ ...prev, [alertId]: action }));
        try {
            const res = await fetch(`${API_BASE}/api/decisions`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    alert_id: alertId,
                    scenario_id: scenarioId,
                    action: action,
                    analyst_id: "analyst-1",
                    comment: `Analyst selected ${action}`
                })
            });
            if (res.ok) {
                const data = await res.json();
                if (data.metrics) setMetrics(data.metrics);
                setApiError(null);
                setTimeout(() => {
                    setResolvingIds(prev => {
                        const next = { ...prev };
                        delete next[alertId];
                        return next;
                    });
                    fetchAlerts();
                }, 1000);
            } else {
                setApiError("Error submitting decision: HTTP " + res.status);
            }
        } catch (e) {
            setApiError("Error submitting decision: " + e.message);
        }
    };

    const pendingAlerts = alerts.filter(a => a.status === "PENDING_APPROVAL");

    return (
        <React.Fragment>
            <Header connected={connected} />
            {apiError && (
                <div style={{
                    background: '#2A1618', border: '1px solid #E0605A',
                    color: '#E0605A', padding: '0.6rem 1rem',
                    borderRadius: '8px', margin: '0.5rem 2rem'
                }}>
                    {apiError}
                </div>
            )}
            <div style={{ padding: '0 2rem' }}>
                <AttackTriggerBar onTrigger={triggerAttack} onReset={resetLab} />
            </div>
            <main>
                <TelemetryStream alerts={alerts} />
                <InvestigationPanel
                    data={investigationData}
                    investigating={investigating}
                    onRun={runInvestigation}
                />
                <section className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <span>🛡️ Tiered Approval Queue</span>
                            <span className="badge-count">{pendingAlerts.length} pending</span>
                        </div>
                    </div>
                    <ApprovalQueue
                        pendingAlerts={pendingAlerts}
                        resolvingIds={resolvingIds}
                        onSubmitDecision={submitDecision}
                    />
                    {metrics && (
                        <div className="panel-title" style={{ marginTop: '0.5rem', fontSize: '0.9rem' }}>
                            📊 Feedback Loop Metrics
                        </div>
                    )}
                    <MetricsGrid metrics={metrics} />
                </section>
            </main>
        </React.Fragment>
    );
}
