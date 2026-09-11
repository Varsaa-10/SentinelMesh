"""
Confidence score = similarity + source agreement + cross-document agreement
                    + retrieval consistency.

Updated Day 3 after Person 1's real schema + handoff notes landed: the real
KB's `detection_signatures` field is dual-source (log_tail / falco per
technique), and the handoff doc explicitly calls this out as a
confidence-scoring signal ("source-agreement between log_tail and falco").
That's a real, KB-native signal the original 3-component formula didn't
have -- it's added here as its own component rather than folded into
cross-document agreement, so each component stays independently auditable.

Each component is normalized to [0, 1] and combined with configurable
weights so the formula and its weighting are explicit and easy to defend/
tune later (and easy to reuse as-is for the risk_score formula in Week 3).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import numpy as np


@dataclass
class ConfidenceBreakdown:
    similarity: float
    source_agreement: float
    cross_document_agreement: float
    retrieval_consistency: float
    weights: tuple  # (w_sim, w_source, w_agree, w_consist)

    @property
    def score(self) -> float:
        w_sim, w_source, w_agree, w_consist = self.weights
        return round(
            w_sim * self.similarity
            + w_source * self.source_agreement
            + w_agree * self.cross_document_agreement
            + w_consist * self.retrieval_consistency,
            4,
        )

    def as_dict(self) -> dict:
        w_sim, w_source, w_agree, w_consist = self.weights
        return {
            "confidence_score": self.score,
            "components": {
                "similarity": round(self.similarity, 4),
                "source_agreement": round(self.source_agreement, 4),
                "cross_document_agreement": round(self.cross_document_agreement, 4),
                "retrieval_consistency": round(self.retrieval_consistency, 4),
            },
            "weights": {
                "similarity": w_sim,
                "source_agreement": w_source,
                "cross_document_agreement": w_agree,
                "retrieval_consistency": w_consist,
            },
        }


def compute_confidence(
    sorted_sims: List[float],
    sorted_tactics: List[str],
    alert_source: Optional[str] = None,
    winning_record_sources: Optional[List[str]] = None,
    top_k: int = 3,
    weights: tuple = (0.4, 0.25, 0.2, 0.15),
) -> ConfidenceBreakdown:
    """
    sorted_sims: cosine similarities of retrieved docs, best-first.
    sorted_tactics: the .tactic of each retrieved doc, same order as sorted_sims.
    alert_source: which detector produced the incoming alert, "log_tail" or
      "falco" (per Week 1's alert-format spec). None if unknown.
    winning_record_sources: the top-1 KB record's DetectionSignature.sources,
      e.g. ["log_tail"], ["falco"], or ["log_tail", "falco"] for dual-source
      techniques like T1041.
    top_k: how many top retrieved docs count toward agreement/consistency.
    """
    if not sorted_sims:
        return ConfidenceBreakdown(0.0, 0.0, 0.0, 0.0, weights)

    top = sorted_sims[:top_k]
    top_tactics = sorted_tactics[:top_k]

    # 1. similarity: top-1 cosine similarity, clipped to [0,1]
    similarity = max(0.0, min(1.0, float(top[0])))

    # 2. source agreement: does the winning KB record actually declare a
    #    detection signature for the source that produced this alert?
    #    A record with only a `falco` signature getting matched to a
    #    `log_tail`-origin alert is a red flag even if text similarity is
    #    high -- this is the KB-native check the handoff notes call for.
    if alert_source and winning_record_sources:
        if alert_source in winning_record_sources:
            source_agreement = 1.0 if len(winning_record_sources) == 1 else 0.85
        else:
            source_agreement = 0.0
    else:
        source_agreement = 0.5  # unknown source on either side -- neutral, not penalized

    # 3. cross-document agreement: fraction of top-k docs that agree with the
    #    top-1 doc's tactic. High agreement = multiple independent KB entries
    #    point the same direction.
    if top_tactics:
        winner_tactic = top_tactics[0]
        agreement = sum(1 for t in top_tactics if t == winner_tactic) / len(top_tactics)
    else:
        agreement = 0.0

    # 4. retrieval consistency: normalized gap between top-1 and top-2 similarity.
    #    A large gap means the top result stands out clearly (consistent/stable
    #    pick); a small gap means the model is nearly torn between two answers.
    if len(top) >= 2:
        gap = top[0] - top[1]
        consistency = max(0.0, min(1.0, gap / max(top[0], 1e-6)))
    else:
        consistency = 1.0  # only one candidate retrieved at all -> nothing to be inconsistent with

    return ConfidenceBreakdown(similarity, source_agreement, agreement, consistency, weights)
