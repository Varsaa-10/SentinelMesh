"""
SentinelMesh Attack-Graph Module (C1).

Reconstructs attack paths from canonical alerts and optional RAG results
using four edge-inference rules: technique adjacency, CVE dependency,
process lineage, and network flow.
"""

from graph.attack_graph import AttackGraph, GraphNode, GraphEdge
from graph.edge_rules import (
    technique_adjacency,
    cve_dependency,
    process_lineage,
    network_flow,
    apply_all_rules,
)

__all__ = [
    "AttackGraph",
    "GraphNode",
    "GraphEdge",
    "technique_adjacency",
    "cve_dependency",
    "process_lineage",
    "network_flow",
    "apply_all_rules",
]
