import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import AttackTriggerBar from './components/AttackTriggerBar';
import TelemetryStream from './components/TelemetryStream';
import InvestigationPanel from './components/InvestigationPanel';
import ApprovalQueue from './components/ApprovalQueue';
import MetricsGrid from './components/MetricsGrid';

const HOST = window.location.hostname || "localhost";
const API_BASE = `http://${HOST}:8000`;
const WS_URL = `ws://${HOST}:8000/ws`;

export default function App() {
    const [connected, setConnected] = useState(false);
    const [alerts, setAlerts] = useState([]);
    const [investigationData, setInvestigationData] = useState(null);
    const [investigating, setInvestigating] = useState(false);
    const [metrics, setMetrics] = useState({
        agreement_rate: 1.0,
        override_rate: 0.0,
        mttr_improvement_pct: 28.5,
        threshold_convergence: "Converged"
    });
    const [resolvingIds, setResolvingIds] = useState({});

    const fetchAlerts = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/alerts`);
            if (res.ok) {
                const data = await res.json();
                setAlerts(data.alerts || []);
            }
        } catch (e) { }
    }, []);

    const fetchDecisions = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/decisions`);
            if (res.ok) {
                const data = await res.json();
                if (data.metrics) setMetrics(data.metrics);
            }
        } catch (e) { }
    }, []);

    useEffect(() => {
        let ws;
        let timer;

        function connect() {
            try {
                ws = new WebSocket(WS_URL);
                ws.onopen = () => {
                    setConnected(true);
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
                    } catch (e) { }
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
            if (res.ok) fetchAlerts();
        } catch (e) {
            alert("Error triggering scenario: " + e.message);
        }
    };

    const resetLab = async () => {
        try {
            await fetch(`${API_BASE}/api/attacks/reset`, { method: "POST" });
            fetchAlerts();
            fetchDecisions();
        } catch (e) { }
    };

    const runInvestigation = async () => {
        setInvestigating(true);
        try {
            const res = await fetch(`${API_BASE}/api/investigate`, { method: "POST" });
            if (res.ok) {
                const data = await res.json();
                setInvestigationData(data);
            }
        } catch (e) {
            setInvestigationData({ error: e.message });
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
                setTimeout(() => {
                    setResolvingIds(prev => {
                        const next = { ...prev };
                        delete next[alertId];
                        return next;
                    });
                    fetchAlerts();
                }, 1000);
            }
        } catch (e) {
            alert("Error submitting decision: " + e.message);
        }
    };

    const pendingAlerts = alerts.filter(a => a.status === "PENDING_APPROVAL" || !a.status);

    return (
        <React.Fragment>
            <Header connected={connected} />
            <AttackTriggerBar onTrigger={triggerAttack} onReset={resetLab} />
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
                    <div className="panel-title" style={{ marginTop: '0.5rem', fontSize: '0.9rem' }}>
                        📊 Feedback Loop Metrics
                    </div>
                    <MetricsGrid metrics={metrics} />
                </section>
            </main>
        </React.Fragment>
    );
}
