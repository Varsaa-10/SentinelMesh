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
                    return (
                        <div className={`approval-card ${resolvingClass}`} key={alert.alert_id}>
                            <div className="alert-top">
                                <span className="sev-tag sev-warning">MEDIUM RISK — ANALYST GATE</span>
                                <span className="alert-meta">{alert.alert_id} · {alert.scenario || 'S1'}</span>
                            </div>
                            <div className="alert-title">Proposed Action: {alert.proposed_action || 'Isolate Container'}</div>
                            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                Confidence Score: {alert.confidence || 0.9412} | Evidence: {alert.evidence || 'Pattern Match'}
                            </p>
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
                                    <button className="btn btn-approve" onClick={() => onSubmitDecision(alert.alert_id, alert.scenario || 'S1', 'approve')}>
                                        Approve
                                    </button>
                                    <button className="btn btn-override" onClick={() => onSubmitDecision(alert.alert_id, alert.scenario || 'S1', 'modify')}>
                                        Modify
                                    </button>
                                    <button className="btn btn-reject" onClick={() => onSubmitDecision(alert.alert_id, alert.scenario || 'S1', 'reject')}>
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
