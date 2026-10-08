import React from 'react';

export default function AttackTriggerBar({ onTrigger, onReset }) {
    const scenarios = [
        { id: 'S1', label: 'S1 SQLi' },
        { id: 'S2', label: 'S2 Brute force' },
        { id: 'S3', label: 'S3 Default creds' },
        { id: 'S4', label: 'S4 JWT forgery' },
        { id: 'S5', label: 'S5 DB access' },
        { id: 'S6', label: 'S6 Log tampering' },
        { id: 'S7', label: 'S7 Grafana' },
        { id: 'S8', label: 'S8 Exfiltration' },
        { id: 'S9', label: 'S9 Credential read' },
        { id: 'S10', label: 'S10 Chain' },
    ];

    return (
        <div className="trigger-bar">
            <div className="trigger-bar-title">
                ⚡ Attack Simulation Triggers:
            </div>
            <div className="trigger-buttons">
                {scenarios.map(sc => (
                    <button
                        key={sc.id}
                        className="trigger-btn"
                        onClick={() => onTrigger(sc.id)}
                    >
                        {sc.label}
                    </button>
                ))}
                <button className="trigger-btn trigger-btn-reset" onClick={onReset}>
                    ↺ Reset Lab
                </button>
            </div>
        </div>
    );
}
