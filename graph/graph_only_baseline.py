"""
Graph-only baseline variant (C1-P1).

Reconstructs attack graphs from raw 7-key canonical alerts WITHOUT any
RAG input. Technique inference uses a static rule table derived from
ground_truth.json (scenario → technique mapping) instead of RAG's
predicted_technique.

Reuses the same 4 edge-inference rules from edge_rules.py (DRY) and
produces the same graph JSON structure as the RAG-grounded variant
(AttackGraph), enabling direct comparison in evaluation.

This module has ZERO dependency on rag_engine or any RAG modules.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from graph.attack_graph import AttackGraph, GraphNode, _auto_register_paths
from graph.edge_rules import apply_all_rules


# ---------------------------------------------------------------------------
# Static rule table: scenario → technique mapping
# Derived from eval/ground_truth.json — DRY: loaded once at import time.
# ---------------------------------------------------------------------------

_GROUND_TRUTH_PATH = os.path.join(
    os.path.dirname(__file__), "..", "eval", "ground_truth.json"
)

_RULE_TABLE: Dict[str, Dict[str, Any]] = {}


def _load_rule_table() -> Dict[str, Dict[str, Any]]:
    """Load scenario → technique mapping from ground truth."""
    global _RULE_TABLE
    if _RULE_TABLE:
        return _RULE_TABLE

    try:
        with open(_GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
            gt = json.load(f)
    except FileNotFoundError:
        return {}

    for scenario_id, info in gt.get("scenarios", {}).items():
        _RULE_TABLE[scenario_id] = {
            "technique_id": info.get("technique_id", ""),
            "technique_name": info.get("technique_name", ""),
            "tactic": info.get("tactic", ""),
            "cve": info.get("cve"),
            "severity": info.get("severity", 0),
            "target_container": info.get("target_container", ""),
        }

    return _RULE_TABLE


def get_rule_table() -> Dict[str, Dict[str, Any]]:
    """Public accessor for the scenario → technique rule table."""
    return _load_rule_table()


# ---------------------------------------------------------------------------
# Hardcoded fallback table (used when ground_truth.json is unavailable,
# e.g. in unit tests with isolated fixtures)
# ---------------------------------------------------------------------------

FALLBACK_RULE_TABLE: Dict[str, Dict[str, Any]] = {
    "S1":  {"technique_id": "T1190",     "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",  "cve": None},
    "S2":  {"technique_id": "T1110",     "technique_name": "Brute Force",
            "tactic": "Credential Access", "cve": None},
    "S3":  {"technique_id": "T1078",     "technique_name": "Valid Accounts",
            "tactic": "Initial Access",  "cve": None},
    "S4":  {"technique_id": "T1212",     "technique_name": "Exploitation for Credential Access",
            "tactic": "Credential Access", "cve": "CVE-2022-29217"},
    "S5":  {"technique_id": "T1021",     "technique_name": "Remote Services",
            "tactic": "Lateral Movement", "cve": None},
    "S6":  {"technique_id": "T1070",     "technique_name": "Indicator Removal",
            "tactic": "Defense Evasion", "cve": None},
    "S7":  {"technique_id": "T1078",     "technique_name": "Valid Accounts",
            "tactic": "Initial Access",  "cve": None},
    "S8":  {"technique_id": "T1041",     "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",    "cve": None},
    "S9":  {"technique_id": "T1003.008", "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "tactic": "Credential Access", "cve": None},
    "S10": {"technique_id": "T1190",     "technique_name": "Multi-stage attack chain",
            "tactic": "Multiple (chained)", "cve": "CVE-2022-29217"},
}


# ---------------------------------------------------------------------------
# Graph-only builder
# ---------------------------------------------------------------------------

class GraphOnlyBaseline:
    """
    Builds an attack graph from raw alerts using only the 7-key canonical
    fields — no RAG dependency.

    Usage:
        baseline = GraphOnlyBaseline()
        graph = baseline.build(alerts)
        print(graph.to_json(indent=2))
    """

    def __init__(self, rule_table: Optional[Dict[str, Dict[str, Any]]] = None):
        """
        Parameters
        ----------
        rule_table : dict, optional
            Scenario → technique mapping. If None, loads from
            ground_truth.json (with hardcoded fallback).
        """
        loaded = _load_rule_table()
        self.rule_table = rule_table or loaded or FALLBACK_RULE_TABLE

    def build(self, alerts: List[Dict[str, Any]],
              graph_id: Optional[str] = None) -> AttackGraph:
        """
        Build an attack graph from raw canonical alerts.

        Parameters
        ----------
        alerts : list[dict]
            Each dict has keys: source, scenario, severity, title,
            timestamp, service, event.
        """
        graph = AttackGraph(graph_id=graph_id)

        for alert in alerts:
            self._add_nodes(graph, alert)

        # Reuse the same edge-inference rules as the RAG-grounded variant (DRY)
        inferred_edges = apply_all_rules(graph.nodes)
        for edge in inferred_edges:
            try:
                graph.add_edge(edge)
            except KeyError:
                pass

        # Auto-register attack path(s)
        _auto_register_paths(graph, alerts)

        return graph

    def _add_nodes(self, graph: AttackGraph, alert: Dict[str, Any]) -> None:
        """Create nodes for a single alert using the rule table for technique inference."""
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

        # Process node (from event fields)
        proc_name = _flat_get(event, "proc.name") or _flat_get(event, "proc_name")
        if proc_name:
            proc_id = f"process_{service}_{proc_name}"
            proc_pname = _flat_get(event, "proc.pname") or _flat_get(event, "proc_pname") or ""
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

        # Network node
        rip = _flat_get(event, "fd.sip") or _flat_get(event, "fd.rip") or _flat_get(event, "fd_rip")
        rport = _flat_get(event, "fd.sport") or _flat_get(event, "fd.rport") or _flat_get(event, "fd_rport")
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

        # Technique node — inferred from rule table (NOT from RAG)
        mapping = self.rule_table.get(scenario)
        if mapping:
            tech_id = mapping["technique_id"]
            tech_node_id = f"technique_{tech_id}"
            if not graph.get_node(tech_node_id):
                graph.add_node(GraphNode(
                    id=tech_node_id,
                    type="technique",
                    label=tech_id,
                    properties={
                        "technique_id": tech_id,
                        "technique_name": mapping.get("technique_name", ""),
                        "tactic": mapping.get("tactic", ""),
                        "confidence": 1.0,  # rule-table match is deterministic
                        "scenario": scenario,
                        "container": service,
                        "timestamp": timestamp,
                    },
                ))
            _note_scenario(graph.get_node(tech_node_id), scenario)

            # CVE node
            cve = mapping.get("cve")
            if cve:
                cve_node_id = f"cve_{cve}"
                if not graph.get_node(cve_node_id):
                    graph.add_node(GraphNode(
                        id=cve_node_id,
                        type="cve",
                        label=cve,
                        properties={"cve_id": cve, "technique": tech_id},
                    ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _note_scenario(node, scenario):
    """Record every scenario that maps to this technique node (nodes stay unique per technique)."""
    if node is None or not scenario:
        return
    seen = node.properties.setdefault("scenarios", [node.properties.get("scenario")] if node.properties.get("scenario") else [])
    if scenario not in seen:
        seen.append(scenario)


def _flat_get(d: dict, key: str, default=None):
    """Get a value trying the full key first, then dotted nested access."""
    if not isinstance(d, dict):
        return default
    if key in d:
        return d[key]
    parts = key.split(".")
    for p in parts:
        if isinstance(d, dict):
            d = d.get(p, default)
        else:
            return default
    return d
