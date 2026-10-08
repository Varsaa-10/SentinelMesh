import React from 'react';

export default function InvestigationPanel({ data, investigating, onRun }) {
    return (
        <section className="panel">
            <div className="panel-header">
                <div className="panel-title">
                    <span>🔍 RAG Grounding & Attack Graph (Graph-Only Baseline)</span>
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
            <div className="investigation-box" style={{ fontFamily: 'inherit', whiteSpace: 'normal', overflowY: 'auto', maxHeight: '420px' }}>
                {!data ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        Click "Run Investigation" to query TwoLayerRAG and reconstruct live Attack Graph.
                    </div>
                ) : (
                    <div className="investigation-details" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {/* RAG Grounding Card */}
                        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
                            <div style={{ fontWeight: 700, marginBottom: '0.4rem', color: '#60a5fa' }}>🎯 RAG Grounded Threat Intelligence</div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.85rem' }}>
                                <div><strong>Technique:</strong> {data.rag_grounding?.technique || '-'} ({data.rag_grounding?.technique_name || 'Mapped'})</div>
                                <div><strong>Tactic:</strong> {data.rag_grounding?.tactic || '-'}</div>
                            </div>
                            <div style={{ marginTop: '0.5rem', fontSize: '0.85rem' }}>
                                <strong>Matched CVEs:</strong>{' '}
                                {data.rag_grounding?.matched_cves && data.rag_grounding.matched_cves.length > 0 ? (
                                    data.rag_grounding.matched_cves.map(cve => (
                                        <span key={cve} className="sev-tag sev-medium" style={{ marginRight: '0.3rem', fontSize: '0.7rem' }}>{cve}</span>
                                    ))
                                ) : (
                                    <span style={{ color: 'var(--text-muted)' }}>None matched</span>
                                )}
                            </div>
                        </div>

                        {/* Confidence Score Decomposition */}
                        {data.rag_grounding?.confidence_breakdown && (
                            <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <div style={{ fontWeight: 700, marginBottom: '0.4rem', color: '#34d399' }}>📊 Confidence Breakdown</div>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', fontSize: '0.8rem' }}>
                                    <div>Overall: <strong>{data.rag_grounding.confidence_breakdown.overall !== undefined ? Number(data.rag_grounding.confidence_breakdown.overall).toFixed(4) : '-'}</strong></div>
                                    <div>Similarity: <strong>{data.rag_grounding.confidence_breakdown.similarity !== undefined ? Number(data.rag_grounding.confidence_breakdown.similarity).toFixed(4) : '-'}</strong></div>
                                    <div>Source Agreement: <strong>{data.rag_grounding.confidence_breakdown.source_agreement !== undefined ? Number(data.rag_grounding.confidence_breakdown.source_agreement).toFixed(4) : '-'}</strong></div>
                                    <div>Cross-Doc Agreement: <strong>{data.rag_grounding.confidence_breakdown.cross_document_agreement !== undefined ? Number(data.rag_grounding.confidence_breakdown.cross_document_agreement).toFixed(4) : '-'}</strong></div>
                                    <div>Retrieval Consistency: <strong>{data.rag_grounding.confidence_breakdown.retrieval_consistency !== undefined ? Number(data.rag_grounding.confidence_breakdown.retrieval_consistency).toFixed(4) : '-'}</strong></div>
                                </div>
                            </div>
                        )}

                        {/* Attack Graph & Sequence */}
                        {data.attack_graph && (
                            <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <div style={{ fontWeight: 700, marginBottom: '0.4rem', color: '#f472b6' }}>🕸️ Attack Graph & Alert Sequence</div>
                                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                    Reconstructed Nodes: {data.attack_graph.nodes?.length || 0} | Edges: {data.attack_graph.edges?.length || 0} | Paths: {data.attack_graph.paths?.length || 0}
                                </div>
                                {data.chain_timeline && data.chain_timeline.length > 0 && (
                                    <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                                        {data.chain_timeline.map((step, idx) => (
                                            <div key={idx} style={{ fontSize: '0.78rem', background: 'rgba(0,0,0,0.2)', padding: '0.3rem 0.5rem', borderRadius: '4px' }}>
                                                Stage {step.stage || idx + 1}: <strong>{step.scenario || '-'}</strong> ({step.technique || '-'}) - {step.timestamp || ''}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </section>
    );
}
