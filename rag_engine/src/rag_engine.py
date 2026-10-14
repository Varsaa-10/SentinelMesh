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
    def __init__(
        self,
        records: List[KBRecord],
        embedder: BaseEmbedder,
        cve_lookup: Optional[Dict[str, CVERecord]] = None,
        top_k_tactics: int = 1,
        fallback_threshold: Optional[float] = None,
        reranker: Optional[Any] = None,
    ):
        self.records = records
        self.embedder = embedder
        self.cve_lookup = cve_lookup or {}
        self.top_k_tactics = top_k_tactics
        self.fallback_threshold = fallback_threshold
        self.reranker = reranker
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
        tactic_order = np.argsort(-tactic_sims)
        best_tactic_idx = int(tactic_order[0])
        best_tactic_sim = float(tactic_sims[best_tactic_idx])
        best_tactic = self._tactics[best_tactic_idx]

        fallback_triggered = False
        # Fallback condition: if best tactic similarity is below threshold, fall back to flat search
        if self.fallback_threshold is not None and best_tactic_sim < self.fallback_threshold:
            fallback_triggered = True
            scoped_idx = list(range(len(self.records)))
        else:
            # Scoped to top_k_tactics (beam search)
            selected_tactics = set([self._tactics[tactic_order[i]] for i in range(min(self.top_k_tactics, len(self._tactics)))])
            scoped_idx = [i for i, r in enumerate(self.records) if r.tactic in selected_tactics]
            if not scoped_idx:
                scoped_idx = list(range(len(self.records)))

        # --- Layer 2: technique retrieval ---
        scoped_vecs = self._record_vecs[scoped_idx]
        scoped_sims = self.embedder.similarity_matrix(q_vec, scoped_vecs)[0]

        order = np.argsort(-scoped_sims)
        ranked_records = [self.records[scoped_idx[i]] for i in order]
        ranked_sims = [float(scoped_sims[i]) for i in order]

        # Optional Re-ranker stage over top candidates
        if self.reranker is not None and len(ranked_records) > 1:
            reranked = self.reranker.rerank(alert_output_text, ranked_records[:10], ranked_sims[:10])
            ranked_records = [r[0] for r in reranked]
            ranked_sims = [r[1] for r in reranked]

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

        engine_name = "two-layer"
        if fallback_triggered:
            engine_name = "two-layer-fallback"
        elif self.top_k_tactics > 1:
            engine_name = f"two-layer-top{self.top_k_tactics}"

        evidence = {
            "falco_rule": falco_rule,
            "container_id": container_id,
            "attack_id": top_record.id,
            "cve_ids": top_record.related_cves,
            "kb_detector_ref": kb_detector_ref,
            "kb_falco_rule_name": kb_falco_rule_name,
            "layer1_best_tactic": best_tactic,
            "layer1_similarity": round(best_tactic_sim, 4),
            "fallback_triggered": fallback_triggered,
        }

        return RAGResult(
            predicted_technique=top_record.id,
            predicted_technique_name=top_record.technique_name,
            predicted_tactic=top_record.tactic,
            matched_cves=top_record.related_cves,
            confidence=confidence,
            evidence=evidence,
            latency_ms=latency_ms,
            engine=engine_name,
            embedder=self.embedder.name,
        )

