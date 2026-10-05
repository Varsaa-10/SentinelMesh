"""
Core attack-graph data structure.

Provides GraphNode, GraphEdge, and AttackGraph — the foundation for
reconstructing attack paths from SentinelMesh canonical alerts and
optional RAG results.

Input contracts:
  - Alerts conform to alert_spec.md (7-key canonical format).
  - RAG results follow the RAGResult dataclass in rag_engine.py.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Node & Edge types (mirrored in graph_schema.json)
# ---------------------------------------------------------------------------

NODE_TYPES = {"container", "process", "network_connection", "technique", "cve"}
EDGE_TYPES = {"technique_adjacency", "cve_dependency", "process_lineage", "network_flow"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """A single node in the attack graph."""

    id: str
    type: str          # one of NODE_TYPES
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.type not in NODE_TYPES:
            raise ValueError(f"Invalid node type '{self.type}'. Must be one of {NODE_TYPES}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    """A directed edge between two nodes."""

    source: str        # node id
    target: str        # node id
    type: str          # one of EDGE_TYPES
    weight: float = 1.0
    timestamp: Optional[str] = None  # ISO-8601

    def __post_init__(self):
        if self.type not in EDGE_TYPES:
            raise ValueError(f"Invalid edge type '{self.type}'. Must be one of {EDGE_TYPES}")
        self.weight = max(0.0, min(1.0, self.weight))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# AttackGraph
# ---------------------------------------------------------------------------

class AttackGraph:
    """
    Directed graph that reconstructs attack paths from alerts.

    Usage:
        graph = AttackGraph.from_alerts(alerts, rag_results)
        paths = graph.get_paths()
        print(graph.to_json(indent=2))
    """

    def __init__(self, graph_id: Optional[str] = None):
        self.graph_id: str = graph_id or f"graph_{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._paths: List[Dict[str, Any]] = []

    # -- Mutation ----------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Add a node (or update if id already exists)."""
        self._nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge. Both source and target must already exist as nodes."""
        if edge.source not in self._nodes:
            raise KeyError(f"Source node '{edge.source}' not in graph")
        if edge.target not in self._nodes:
            raise KeyError(f"Target node '{edge.target}' not in graph")
        self._edges.append(edge)

    def add_path(self, scenario_id: str, ordered_stages: List[str],
                 technique_sequence: List[str]) -> None:
        """Register a reconstructed attack path."""
        self._paths.append({
            "scenario_id": scenario_id,
            "ordered_stages": ordered_stages,
            "technique_sequence": technique_sequence,
        })

    # -- Query -------------------------------------------------------------

    @property
    def nodes(self) -> List[GraphNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[GraphEdge]:
        return list(self._edges)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_paths(self) -> List[Dict[str, Any]]:
        """Return all registered attack paths."""
        return list(self._paths)

    def neighbors(self, node_id: str) -> List[str]:
        """Return IDs of nodes reachable via outgoing edges from *node_id*."""
        return [e.target for e in self._edges if e.source == node_id]

    # -- Factory -----------------------------------------------------------

    @classmethod
    def from_alerts(cls, alerts: List[Dict[str, Any]],
                    rag_results: Optional[List[Dict[str, Any]]] = None,
                    graph_id: Optional[str] = None) -> "AttackGraph":
        """
        Build a graph from canonical 7-key alerts and optional RAG outputs.

        Parameters
        ----------
        alerts : list[dict]
            Each dict has keys: source, scenario, severity, title,
            timestamp, service, event.
        rag_results : list[dict], optional
            Parallel list of RAG result dicts (one per alert) with keys:
            predicted_technique, predicted_technique_name, predicted_tactic,
            matched_cves, confidence, evidence.
        """
        from graph.edge_rules import apply_all_rules

        graph = cls(graph_id=graph_id)
        rag_results = rag_results or [None] * len(alerts)

        for idx, alert in enumerate(alerts):
            rag = rag_results[idx] if idx < len(rag_results) else None
            _add_nodes_from_alert(graph, alert, rag)

        # Run all edge-inference rules
        inferred_edges = apply_all_rules(graph.nodes)
        for edge in inferred_edges:
            try:
                graph.add_edge(edge)
            except KeyError:
                pass  # skip edges referencing missing nodes

        # Auto-register attack path(s)
        _auto_register_paths(graph, alerts)

        return graph

    # -- Serialization -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "paths": self.get_paths(),
        }

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackGraph":
        """Deserialize a graph from a dict (round-trip support)."""
        graph = cls(graph_id=data.get("graph_id"))
        for nd in data.get("nodes", []):
            graph.add_node(GraphNode(**nd))
        for ed in data.get("edges", []):
            graph.add_edge(GraphEdge(**ed))
        for pth in data.get("paths", []):
            graph.add_path(
                pth["scenario_id"],
                pth["ordered_stages"],
                pth["technique_sequence"],
            )
        return graph


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _add_nodes_from_alert(graph: AttackGraph, alert: Dict[str, Any],
                          rag_result: Optional[Dict[str, Any]] = None) -> None:
    """Create nodes for a single alert + optional RAG result."""

    scenario = alert.get("scenario", "unknown")
    service = alert.get("service", "unknown")
    timestamp = alert.get("timestamp", "")
    event = alert.get("event", {})

    # Container node
    container_id = f"container_{service}"
    if not graph.get_node(container_id):
        graph.add_node(GraphNode(
            id=container_id,
            type="container",
            label=service,
            properties={"service": service},
        ))

    # Process node (from event.proc.name if present)
    proc_name = _deep_get(event, "proc.name") or _deep_get(event, "proc_name")
    if proc_name:
        proc_id = f"process_{service}_{proc_name}"
        proc_pname = _deep_get(event, "proc.pname") or _deep_get(event, "proc_pname") or ""
        if not graph.get_node(proc_id):
            graph.add_node(GraphNode(
                id=proc_id,
                type="process",
                label=proc_name,
                properties={
                    "proc_name": proc_name,
                    "proc_pname": proc_pname,
                    "container": service,
                },
            ))
        # Also create parent process node so process_lineage rule can connect them
        if proc_pname:
            parent_id = f"process_{service}_{proc_pname}"
            if not graph.get_node(parent_id):
                graph.add_node(GraphNode(
                    id=parent_id,
                    type="process",
                    label=proc_pname,
                    properties={
                        "proc_name": proc_pname,
                        "proc_pname": "",
                        "container": service,
                    },
                ))

    # Network node (from event.fd.rip / fd.rport if present)
    rip = _deep_get(event, "fd.rip") or _deep_get(event, "fd_rip")
    rport = _deep_get(event, "fd.rport") or _deep_get(event, "fd_rport")
    if rip:
        net_label = f"{rip}:{rport}" if rport else rip
        net_id = f"network_{net_label}"
        if not graph.get_node(net_id):
            graph.add_node(GraphNode(
                id=net_id,
                type="network_connection",
                label=net_label,
                properties={"ip": rip, "port": rport, "container": service},
            ))

    # Technique node (from RAG result)
    if rag_result:
        tech_id_val = _get_attr_or_key(rag_result, "predicted_technique", "")
        if tech_id_val:
            tech_node_id = f"technique_{tech_id_val}"
            confidence = _get_attr_or_key(rag_result, "confidence", {})
            if hasattr(confidence, "composite"):
                conf_score = float(confidence.composite)
            elif isinstance(confidence, dict):
                conf_score = confidence.get("composite", 0.0)
            elif confidence:
                conf_score = float(confidence)
            else:
                conf_score = 0.0

            if not graph.get_node(tech_node_id):
                graph.add_node(GraphNode(
                    id=tech_node_id,
                    type="technique",
                    label=str(tech_id_val),
                    properties={
                        "technique_id": str(tech_id_val),
                        "technique_name": _get_attr_or_key(rag_result, "predicted_technique_name", ""),
                        "tactic": _get_attr_or_key(rag_result, "predicted_tactic", ""),
                        "confidence": conf_score,
                        "scenario": scenario,
                        "container": service,
                        "timestamp": timestamp,
                    },
                ))

        # CVE nodes
        matched_cves = _get_attr_or_key(rag_result, "matched_cves", []) or []
        for cve_id in matched_cves:
            cve_node_id = f"cve_{cve_id}"
            if not graph.get_node(cve_node_id):
                graph.add_node(GraphNode(
                    id=cve_node_id,
                    type="cve",
                    label=str(cve_id),
                    properties={"cve_id": str(cve_id), "technique": str(tech_id_val)},
                ))


def _auto_register_paths(graph: AttackGraph, alerts: List[Dict[str, Any]]) -> None:
    """Auto-register reconstructed attack path(s) based on technique nodes in the graph.

    BUGFIX: this used to always register exactly ONE path per call, no
    matter how many distinct scenarios were present. That's correct for a
    single scenario, and for the S10 chain (which legitimately *is* one
    path across 5 stages) -- but when the input alerts span several
    *independent* single-technique scenarios at once (e.g. a full
    eval/runs/<ts>/alerts.jsonl, which captures many scenarios back to
    back in one file), it silently collapsed everything into one
    meaningless "multi_stage" path instead of one path per scenario. That
    is why graph_only_baseline run against a real run file produced only
    1 path total across all 9 scenarios instead of one path per scenario.
    """
    tech_nodes = [n for n in graph.nodes if n.type == "technique"]
    if not tech_nodes:
        return
    tech_nodes.sort(key=lambda n: n.properties.get("timestamp", ""))

    scenarios = [n.properties.get("scenario", "") for n in tech_nodes if n.properties.get("scenario")]
    alert_scenarios = [a.get("scenario") for a in alerts if a.get("scenario")]

    def _technique_sequence(nodes: List[GraphNode]) -> List[str]:
        return [n.properties.get("technique_id", n.label) for n in nodes if n.properties.get("technique_id")]

    # S10 chain: always one combined path, exactly as before.
    if "S10" in alert_scenarios or "S10" in scenarios or scenarios == ["S1", "S3", "S4", "S9", "S8"]:
        graph.add_path("S10", scenarios, _technique_sequence(tech_nodes))
        return

    # Single scenario in this batch: one path, exactly as before.
    if scenarios and len(set(scenarios)) == 1:
        graph.add_path(scenarios[0], scenarios, _technique_sequence(tech_nodes))
        return

    # Multiple independent (non-chain) scenarios in one batch: register
    # one path PER scenario instead of collapsing them into a single
    # "multi_stage" blob.
    if scenarios:
        seen_ids: List[str] = []
        for sid in scenarios:
            if sid not in seen_ids:
                seen_ids.append(sid)
        for sid in seen_ids:
            sid_nodes = [n for n in tech_nodes if n.properties.get("scenario") == sid]
            sid_stages = [n.properties.get("scenario", "") for n in sid_nodes]
            graph.add_path(sid, sid_stages, _technique_sequence(sid_nodes))
        return

    # No scenario info on any technique node: fall back to a single
    # best-effort path so something is still recorded.
    graph.add_path("multi_stage", scenarios, _technique_sequence(tech_nodes))


def _get_attr_or_key(obj, key, default=None):
    """Get a value from a dict or object (dataclass/mock) cleanly."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _deep_get(d: Dict, dotted_key: str, default=None):
    """Retrieve a value from a dict, trying the full key as-is first
    (Falco uses literal dotted keys like 'fd.rip'), then falling back
    to nested traversal."""
    if not isinstance(d, dict):
        return default
    # Try flat lookup first (handles "fd.rip", "proc.name", etc.)
    if dotted_key in d:
        return d[dotted_key]
    # Fall back to nested traversal
    keys = dotted_key.split(".")
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d
