"""
rag_engine/src/reranker.py — SentinelMesh Module W2: Re-Ranker over Top Candidates.

Implements re-ranking over candidate techniques retrieved by Layer 1 / Layer 2:
1. Lexical-Dense Hybrid Reciprocal Rank Fusion (RRF) Re-Ranker
2. Cross-Score Re-Ranker combining token-level exact match with semantic embedding affinity.

Provides metadata logging (model, version, parameters) per PRD W2.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Tuple
import numpy as np

from kb_loader import KBRecord


class ReRanker:
    """
    Two-stage Re-ranker operating over top-K candidate techniques.
    Combines dense semantic alignment with lexical keyword anchoring (e.g. Falco rule names,
    process names, ports, CVE IDs).
    """
    name = "hybrid-dense-lexical-rrf"
    version = "1.0.0"

    def __init__(self, rrf_k: int = 60, dense_weight: float = 0.6, lexical_weight: float = 0.4):
        self.rrf_k = rrf_k
        self.dense_weight = dense_weight
        self.lexical_weight = lexical_weight

    def _lexical_match_score(self, query: str, record: KBRecord) -> float:
        """Computes domain-aware lexical overlap against record fields."""
        q_tokens = set(re.findall(r"\b\w{3,}\b", query.lower()))
        if not q_tokens:
            return 0.0

        rec_text = f"{record.technique_name} {record.description} {record.detection_signatures.to_text()}".lower()
        rec_tokens = set(re.findall(r"\b\w{3,}\b", rec_text))

        overlap = q_tokens.intersection(rec_tokens)
        base_jaccard = len(overlap) / len(q_tokens.union(rec_tokens)) if rec_tokens else 0.0

        # Exact boost for signature indicators (e.g. /etc/shadow, sql injection, brute, jwt, 5432)
        boost = 0.0
        for token in overlap:
            if token in ("sqli", "sql", "inject", "brute", "jwt", "shadow", "curl", "grafana", "postgres"):
                boost += 0.2

        return min(1.0, base_jaccard * 2.0 + boost)

    def rerank(
        self,
        query_text: str,
        candidates: List[KBRecord],
        candidate_sims: List[float],
        top_n: int = 10,
    ) -> List[Tuple[KBRecord, float]]:
        """
        Re-ranks up to top_n candidates using hybrid reciprocal rank fusion and fine-grained scoring.
        """
        candidates = candidates[:top_n]
        candidate_sims = candidate_sims[:top_n]
        if not candidates:
            return []

        # Dense ranking order
        dense_order = np.argsort(-np.array(candidate_sims))
        dense_ranks = {candidates[idx].id: rank + 1 for rank, idx in enumerate(dense_order)}

        # Lexical scoring & ranking order
        lex_scores = [self._lexical_match_score(query_text, rec) for rec in candidates]
        lex_order = np.argsort(-np.array(lex_scores))
        lex_ranks = {candidates[idx].id: rank + 1 for rank, idx in enumerate(lex_order)}

        # Combined RRF score + weighted blend
        scored: List[Tuple[KBRecord, float]] = []
        for i, rec in enumerate(candidates):
            r_dense = dense_ranks[rec.id]
            r_lex = lex_ranks[rec.id]

            rrf = (self.dense_weight / (self.rrf_k + r_dense)) + (self.lexical_weight / (self.rrf_k + r_lex))
            blended = (self.dense_weight * candidate_sims[i]) + (self.lexical_weight * lex_scores[i])
            final_score = float(rrf * 100.0 + blended)
            scored.append((rec, final_score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored
