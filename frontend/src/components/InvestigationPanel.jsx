import React from 'react';

export default function InvestigationPanel({ data, investigating, onRun }) {
    return (
        <section className="panel">
            <div className="panel-header">
                <div className="panel-title">
                    <span>🔍 RAG Grounding & Attack Graph</span>
                </div>
                <button
                    className="btn btn-approve"
                    style={{ flex: 'none', padding: '0.3rem 0.6rem' }}
                    onClick={onRun}
                    disabled={investigating}
                >
                    {investigating ? "Running..." : "Run Investigation"}
                </button>
            </div>
            <div className="investigation-box">
                {data
                    ? JSON.stringify(data, null, 2)
                    : 'Click "Run Investigation" to query TwoLayerRAG and reconstruct live Attack Graph.'}
            </div>
        </section>
    );
}
