import React from 'react';

export default function MetricsGrid({ metrics }) {
    if (!metrics) return null;
    const pct = (v) => (typeof v === 'number' ? (v * 100).toFixed(1) + '%' : '—');
    const num = (v) => (typeof v === 'number' ? '+' + v + '%' : '—');
    return (
        <div className="metrics-grid">
            <div className="metric-card">
                <div className="metric-val">{pct(metrics.agreement_rate)}</div>
                <div className="metric-lbl">Analyst Agreement</div>
            </div>
            <div className="metric-card">
                <div className="metric-val">{pct(metrics.override_rate)}</div>
                <div className="metric-lbl">Override Rate</div>
            </div>
            <div className="metric-card">
                <div className="metric-val">{num(metrics.mttr_improvement_pct)}</div>
                <div className="metric-lbl">Routing Time Estimate</div>
            </div>
            <div className="metric-card">
                <div className="metric-val">{metrics.threshold_convergence ?? '—'}</div>
                <div className="metric-lbl">Routing Threshold</div>
            </div>
        </div>
    );
}
