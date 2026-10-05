import React from 'react';

export default function Header({ connected }) {
    return (
        <header>
            <div className="brand">
                <div className="brand-logo">S</div>
                <div className="brand-title">
                    <h1>SentinelMesh React Analyst Dashboard</h1>
                    <p>Hierarchical RAG & Attack Graph Threat Investigation</p>
                </div>
            </div>
            <div className="status-badge">
                <div className={`status-dot ${connected ? '' : 'offline'}`}></div>
                <span>{connected ? "Backend Connected (WebSocket Live)" : "Connecting to Backend..."}</span>
            </div>
        </header>
    );
}
