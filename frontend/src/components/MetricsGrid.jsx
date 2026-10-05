import React from 'react';

export default function MetricsGrid({ metrics }) {
    if (!metrics) return null;
    return (
        <div className="metrics-grid">
            <div className="metric-card">
                <div className="metric-val">{(metrics.agreement_rate * 100).toFixed(1)}%</div>
                <div className="metric-lbl">Analyst Agreement</div>
            </div>
            <div className="metric-card">
                <div className="metric-val">{(metrics.override_rate * 100).toFixed(1)}%</div>
                <div className="metric-lbl">Override Rate</div>
            </div>
            <div className="metric-card">
                <div className="metric-val">+{metrics.mttr_improvement_pct}%</div>
                <div className="metric-lbl">MTTR Improvement</div>
            </div>
            <div className="metric-card">
                <div className="metric-val">{metrics.threshold_convergence}</div>
                <div className="metric-lbl">Routing Threshold</div>
            </div>
        </div>
    );
}
