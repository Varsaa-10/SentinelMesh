"""
Two-layer RAG engine.

Layer 1 (tactic retrieval): embed the alert, compare against tactic-level
  summary documents (one aggregated doc per unique tactic in the KB).
Layer 2 (technique retrieval): scoped to the tactic matched in Layer 1 --
  retrieve only among KB records with that tactic -- plus CVE matching
  against the same scoped set.

This scoping (Layer 2 only searches within Layer 1's winning tactic) is
the entire point of "two-layer" vs. flat/single-shot retrieval; see
flat_rag.py for the unscoped comparison baseline.

Updated Day 3 for the real kb_master schema: technique_name (not name),
dual-source detection_signatures, and CVEs as a separate linked record
type joined via related_cves / related_technique_ids.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Dict
import time
import numpy as np

from kb_loader import KBRecord, CVERecord, tactic_summaries
from embeddings import BaseEmbedder
from confidence import compute_confidence, ConfidenceBreakdown


@dataclass
class RAGResult:
    predicted_technique: str          # ATT&CK ID, e.g. "T1190"
    predicted_technique_name: str
    predicted_tactic: str
    matched_cves: List[str]
    confidence: ConfidenceBreakdown
    evidence: dict                    # citation structure, see output_format_spec.md
    latency_ms: float
    engine: str                       # "two-layer" or "flat"
    embedder: str


class TwoLayerRAG:
    def __init__(self, records: List[KBRecord], embedder: BaseEmbedder, cve_lookup: Optional[Dict[str, CVERecord]] = None):
        self.records = records
        self.embedder = embedder
        self.cve_lookup = cve_lookup or {}
        self._tactic_summaries = tactic_summaries(records)
        self._tactics = list(self._tactic_summaries.keys())
        self._fit()

    def _fit(self) -> None:
        corpus = list(self._tactic_summaries.values()) + [r.to_text() for r in self.records]
        self.embedder.fit(corpus)
        self._tactic_vecs = self.embedder.embed(list(self._tactic_summaries.values()))
        self._record_vecs = self.embedder.embed([r.to_text() for r in self.records])

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

        # --- Layer 1: tactic retrieval ---
        tactic_sims = self.embedder.similarity_matrix(q_vec, self._tactic_vecs)[0]
        best_tactic_idx = int(np.argmax(tactic_sims))
        best_tactic = self._tactics[best_tactic_idx]

        # --- Layer 2: technique retrieval scoped to the matched tactic ---
        scoped_idx = [i for i, r in enumerate(self.records) if r.tactic == best_tactic]
        scoped_vecs = self._record_vecs[scoped_idx]
        scoped_sims = self.embedder.similarity_matrix(q_vec, scoped_vecs)[0]

        order = np.argsort(-scoped_sims)
        ranked_records = [self.records[scoped_idx[i]] for i in order]
        ranked_sims = [float(scoped_sims[i]) for i in order]
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
            engine="two-layer",
            embedder=self.embedder.name,
        )
