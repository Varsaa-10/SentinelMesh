"""
Flat-RAG baseline: single-shot retrieval across the whole KB, no
tactic-first narrowing. This is the required Day-4 comparison point
against TwoLayerRAG -- same KB, same embedder, same confidence formula,
the only difference is scoping.
"""
from __future__ import annotations
from typing import List, Optional, Dict
import time
import numpy as np

from kb_loader import KBRecord, CVERecord
from embeddings import BaseEmbedder
from confidence import compute_confidence, ConfidenceBreakdown
from rag_engine import RAGResult


class FlatRAG:
    def __init__(self, records: List[KBRecord], embedder: BaseEmbedder, cve_lookup: Optional[Dict[str, CVERecord]] = None):
        self.records = records
        self.embedder = embedder
        self.cve_lookup = cve_lookup or {}
        self._fit()

    def _fit(self) -> None:
        corpus = [r.to_text() for r in self.records]
        self.embedder.fit(corpus)
        self._record_vecs = self.embedder.embed(corpus)

    def query(
        self,
        alert_output_text: str,
        container_id: str,
        falco_rule: str,
        alert_source: Optional[str] = None,
        top_k: int = 3,
    ) -> RAGResult:
        t0 = time.perf_counter()
        q_vec = self.embedder.embed([alert_output_text])

        sims = self.embedder.similarity_matrix(q_vec, self._record_vecs)[0]
        order = np.argsort(-sims)
        ranked_records = [self.records[i] for i in order]
        ranked_sims = [float(sims[i]) for i in order]
        ranked_tactics = [r.tactic for r in ranked_records]

        top_record = ranked_records[0]
        confidence = compute_confidence(
            ranked_sims,
            ranked_tactics,
            alert_source=alert_source,
            winning_record_sources=top_record.detection_signatures.sources,
            top_k=top_k,
        )

        latency_ms = (time.perf_counter() - t0) * 1000

        kb_detector_ref = None
        kb_falco_rule_name = None
        if top_record.detection_signatures.log_tail:
            kb_detector_ref = top_record.detection_signatures.log_tail.get("detector_ref")
        if top_record.detection_signatures.falco:
            kb_falco_rule_name = top_record.detection_signatures.falco.get("rule_name")

        evidence = {
            "falco_rule": falco_rule,
            "container_id": container_id,
            "attack_id": top_record.id,
            "cve_ids": top_record.related_cves,
            "kb_detector_ref": kb_detector_ref,
            "kb_falco_rule_name": kb_falco_rule_name,
        }

        return RAGResult(
            predicted_technique=top_record.id,
            predicted_technique_name=top_record.technique_name,
            predicted_tactic=top_record.tactic,
            matched_cves=top_record.related_cves,
            confidence=confidence,
            evidence=evidence,
            latency_ms=latency_ms,
            engine="flat",
            embedder=self.embedder.name,
        )
