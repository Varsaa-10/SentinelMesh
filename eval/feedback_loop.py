"""
eval/feedback_loop.py — SentinelMesh Module C3, feedback loop.

The rule that adjusts confidence weights / routing thresholds based on
accumulated human approve/reject/modify decisions from prior iterations,
per the execution plan (Week 3, Day 4).

Decision vocabulary (what a human reviewer returns for a routed alert):
  "approve" — the routed decision (and selected action) was correct.
  "reject"  — the routed decision was wrong; the alert should not have
              been auto-executed / the action was inappropriate.
  "modify"  — routing tier was right but the selected action should
              have been different.

Adaptation rule (intentionally simple and explainable for a panel demo):
  - Each REJECT at the "auto" tier nudges the auto threshold DOWN
    (stricter — fewer things get auto-approved) and nudges the analyst
    threshold DOWN too if rejects cluster there.
  - Each consecutive run of APPROVEs at a tier nudges that tier's
    threshold UP slightly (looser — analysts stop being bothered with
    obviously-safe cases), bounded so auto never exceeds a safety
    ceiling.
  - Learning rate decays each iteration so thresholds converge instead
    of oscillating — this decay is what "convergence of approval
    thresholds across iterations" (adaptation metric 4) measures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal

Decision = Literal["approve", "reject", "modify"]

SAFETY_CEILING_AUTO = 0.45   # auto threshold may never rise above this
SAFETY_FLOOR_ANALYST = 0.20  # analyst threshold may never fall below this


@dataclass
class FeedbackLoop:
    auto_threshold: float = 0.30
    analyst_threshold: float = 0.65
    learning_rate: float = 0.05
    decay: float = 0.85
    iteration: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    def current_thresholds(self) -> Dict[str, float]:
        return {"auto": self.auto_threshold, "analyst": self.analyst_threshold}

    def record_iteration(self, decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """`decisions` is a list of dicts: {"routing": "auto"|"analyst"|"admin",
        "human_decision": "approve"|"reject"|"modify"}. Adjusts thresholds
        and returns a summary of what changed this iteration.
        """
        before = self.current_thresholds()

        rejects_at_auto = sum(
            1 for d in decisions if d["routing"] == "auto" and d["human_decision"] == "reject"
        )
        approves_at_auto = sum(
            1 for d in decisions if d["routing"] == "auto" and d["human_decision"] == "approve"
        )
        rejects_at_analyst = sum(
            1 for d in decisions if d["routing"] == "analyst" and d["human_decision"] == "reject"
        )
        approves_at_analyst = sum(
            1 for d in decisions if d["routing"] == "analyst" and d["human_decision"] == "approve"
        )

        lr = self.learning_rate * (self.decay ** self.iteration)

        # Stricter on rejects, looser on sustained approval, always bounded.
        if rejects_at_auto:
            self.auto_threshold = max(0.05, self.auto_threshold - lr * rejects_at_auto)
        elif approves_at_auto:
            self.auto_threshold = min(
                SAFETY_CEILING_AUTO, self.auto_threshold + lr * 0.5 * approves_at_auto
            )

        if rejects_at_analyst:
            self.analyst_threshold = max(
                SAFETY_FLOOR_ANALYST, self.analyst_threshold - lr * rejects_at_analyst
            )
        elif approves_at_analyst:
            self.analyst_threshold = min(0.9, self.analyst_threshold + lr * 0.5 * approves_at_analyst)

        # auto must always stay below analyst
        if self.auto_threshold >= self.analyst_threshold:
            self.auto_threshold = max(0.05, self.analyst_threshold - 0.05)

        after = self.current_thresholds()
        record = {
            "iteration": self.iteration,
            "learning_rate": round(lr, 5),
            "rejects_at_auto": rejects_at_auto,
            "approves_at_auto": approves_at_auto,
            "rejects_at_analyst": rejects_at_analyst,
            "approves_at_analyst": approves_at_analyst,
            "thresholds_before": before,
            "thresholds_after": after,
            "threshold_delta": {
                "auto": round(after["auto"] - before["auto"], 5),
                "analyst": round(after["analyst"] - before["analyst"], 5),
            },
        }
        self.history.append(record)
        self.iteration += 1
        return record

    def convergence_score(self) -> float:
        """Measures how much thresholds are still moving. Lower = more
        converged. Defined as the mean absolute delta over the last 3
        iterations (or all iterations if fewer than 3 exist).
        """
        if not self.history:
            return float("nan")
        recent = self.history[-3:]
        deltas = [abs(r["threshold_delta"]["auto"]) + abs(r["threshold_delta"]["analyst"]) for r in recent]
        return round(sum(deltas) / len(deltas), 5)
