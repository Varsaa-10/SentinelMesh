import React from 'react';

export default function ApprovalQueue({ pendingAlerts, resolvingIds, onSubmitDecision }) {
    return (
        <div className="queue-container">
            {pendingAlerts.length === 0 ? (
                <div className="empty-queue">
                    🎉 <strong>Approval Queue Clear</strong><br />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        All container threats reviewed and response actions routed.
                    </span>
                </div>
            ) : (
                pendingAlerts.map(alert => {
                    const resolvingAction = resolvingIds[alert.alert_id];
                    const resolvingClass = resolvingAction ? `resolving-${resolvingAction}d` : '';
                    const scenarioId = alert.scenario || alert.scenario_id || '-';
                    const routingTag = alert.routing || '-';
                    const confidenceText = alert.confidence !== undefined && alert.confidence !== null
                        ? Number(alert.confidence).toFixed(4)
                        : '-';
                    const evidenceText = alert.evidence
                        ? (typeof alert.evidence === 'string' ? alert.evidence : JSON.stringify(alert.evidence))
                        : '-';
                    const riskScoreText = alert.risk_score !== undefined && alert.risk_score !== null
                        ? Number(alert.risk_score).toFixed(4)
                        : '-';

                    return (
                        <div className={`approval-card ${resolvingClass}`} key={alert.alert_id}>
                            <div className="alert-top">
                                <span className="sev-tag sev-warning">{routingTag}</span>
                                <span className="alert-meta">{alert.alert_id} · {scenarioId}</span>
                            </div>
                            <div className="alert-title">Proposed Action: {alert.proposed_action || '-'}</div>
                            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                Confidence: {confidenceText} | Risk Score: {riskScoreText} | Evidence: {evidenceText}
                            </p>
                            {alert.error && (
                                <div style={{ color: '#E0605A', fontSize: '0.78rem', marginTop: '0.2rem' }}>
                                    ⚠️ Retrieval Error: {alert.error}
                                </div>
                            )}
                            {resolvingAction ? (
                                <div style={{ fontWeight: 700, fontSize: '0.85rem', padding: '0.3rem 0', color: '#fff' }}>
                                    {resolvingAction === 'approve'
                                        ? '✅ APPROVED & EXECUTED'
                                        : resolvingAction === 'modify'
                                            ? '⚠️ MODIFIED & REROUTED'
                                            : '❌ REJECTED & DROPPED'}
                                </div>
                            ) : (
                                <div className="action-btn-group">
                                    <button className="btn btn-approve" onClick={() => onSubmitDecision(alert.alert_id, scenarioId, 'approve')}>
                                        Approve
                                    </button>
                                    <button className="btn btn-override" onClick={() => onSubmitDecision(alert.alert_id, scenarioId, 'modify')}>
                                        Modify
                                    </button>
                                    <button className="btn btn-reject" onClick={() => onSubmitDecision(alert.alert_id, scenarioId, 'reject')}>
                                        Reject
                                    </button>
                                </div>
                            )}
                        </div>
                    );
                })
            )}
        </div>
    );
}
