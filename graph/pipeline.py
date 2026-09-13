"""
SentinelMesh Attack-Graph Pipeline Integration (C1-P4).

Wires canonical alerts (and optional RAG results) into full AttackGraph outputs
ready for Risk-Scoring (C2) and Evaluation (C3) consumers.

Pipeline flow:
  Captured Alerts (7-key format)
      ↓
  RAG Engine / Rule Table
      ↓ RAGResult / static mapping
  Graph Constructor (attack_graph.py / graph_only_baseline.py)
      ↓
  Graph JSON/Dict (per graph_output_spec.md)
      ↓
  Risk Scoring & Response (C2) / Evaluation (C3)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from graph.attack_graph import AttackGraph
from graph.graph_only_baseline import GraphOnlyBaseline


class AttackGraphPipeline:
    """
    Unified entry-point for attack-graph generation across both RAG-grounded
    and Graph-Only baseline variants.
    """

    def __init__(self, rag_engine=None, use_baseline: bool = False):
        """
        Parameters
        ----------
        rag_engine : optional
            An instance of TwoLayerRAG or FlatRAG (or duck-typed query engine).
        use_baseline : bool
            If True, forces the pipeline to use the graph-only baseline
            (ignoring RAG).
        """
        self.rag_engine = rag_engine
        self.use_baseline = use_baseline
        self.baseline_builder = GraphOnlyBaseline()

    def run(
        self,
        alerts: List[Dict[str, Any]],
        rag_results: Optional[List[Any]] = None,
        graph_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the end-to-end attack-graph reconstruction pipeline.

        Parameters
        ----------
        alerts : list[dict]
            7-key canonical alerts.
        rag_results : list[RAGResult or dict], optional
            Pre-computed RAG results for each alert. If None and rag_engine is
            available, queries rag_engine for each alert.
        graph_id : str, optional
            Custom identifier for the generated graph.

        Returns
        -------
        dict
            Graph output matching graph_output_spec.md / graph_schema.json.
        """
        if self.use_baseline or (self.rag_engine is None and rag_results is None):
            # Graph-only baseline mode
            graph = self.baseline_builder.build(alerts, graph_id=graph_id)
        else:
            # RAG-grounded mode
            if rag_results is None and self.rag_engine is not None:
                rag_results = self._query_rag(alerts)

            graph = AttackGraph.from_alerts(alerts, rag_results, graph_id=graph_id)

        return graph.to_dict()

    def _query_rag(self, alerts: List[Dict[str, Any]]) -> List[Any]:
        """Query rag_engine for each alert."""
        results = []
        for alert in alerts:
            title = alert.get("title", "")
            service = alert.get("service", "unknown")
            source = alert.get("source", "unknown")

            try:
                res = self.rag_engine.query(
                    alert_output_text=title,
                    container_id=service,
                    falco_rule=title if source == "falco" else "",
                    alert_source=source,
                )
                results.append(res)
            except Exception:
                results.append(None)
        return results


def run_pipeline(
    alerts: List[Dict[str, Any]],
    rag_results: Optional[List[Any]] = None,
    rag_engine=None,
    use_baseline: bool = False,
    graph_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Functional convenience entry-point for running the attack graph pipeline."""
    pipeline = AttackGraphPipeline(rag_engine=rag_engine, use_baseline=use_baseline)
    return pipeline.run(alerts, rag_results=rag_results, graph_id=graph_id)
