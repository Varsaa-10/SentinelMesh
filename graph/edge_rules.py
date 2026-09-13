"""
Edge-inference rules for the SentinelMesh attack graph.

Four rules reconstruct attack paths from captured alerts:
  1. Technique Adjacency  — same tactic or time-window on same container
  2. CVE Dependency        — technique → CVE link
  3. Process Lineage       — parent → child process on same container
  4. Network Flow          — cross-container IP match

Each rule accepts a list of GraphNode objects and returns inferred GraphEdge
objects. apply_all_rules() runs all four (DRY single entry-point).
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from graph.attack_graph import GraphNode, GraphEdge


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TIME_WINDOW_SECONDS = 300  # 5 minutes — technique adjacency window


# ---------------------------------------------------------------------------
# Rule 1: Technique Adjacency
# ---------------------------------------------------------------------------

def technique_adjacency(nodes: List[GraphNode]) -> List[GraphEdge]:
    """
    Connect technique nodes that share the same tactic or appear within
    TIME_WINDOW_SECONDS on the same container.

    Edges are directed from the earlier technique to the later one
    (by timestamp); if timestamps are missing, the insertion order is used.
    """
    tech_nodes = [n for n in nodes if n.type == "technique"]
    if len(tech_nodes) < 2:
        return []

    # Sort by timestamp (fall back to original order)
    def _sort_key(n: GraphNode):
        ts = n.properties.get("timestamp", "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.min

    tech_nodes = sorted(tech_nodes, key=_sort_key)
    edges: List[GraphEdge] = []

    for i in range(len(tech_nodes)):
        for j in range(i + 1, len(tech_nodes)):
            a, b = tech_nodes[i], tech_nodes[j]

            same_tactic = (
                a.properties.get("tactic")
                and a.properties.get("tactic") == b.properties.get("tactic")
            )

            within_window = _within_time_window(
                a.properties.get("timestamp", ""),
                b.properties.get("timestamp", ""),
            )

            same_container = (
                a.properties.get("container")
                and a.properties.get("container") == b.properties.get("container")
            )

            if same_tactic or (within_window and same_container):
                ts = a.properties.get("timestamp") or b.properties.get("timestamp")
                edges.append(GraphEdge(
                    source=a.id,
                    target=b.id,
                    type="technique_adjacency",
                    weight=0.8 if same_tactic else 0.6,
                    timestamp=ts,
                ))

    return edges


# ---------------------------------------------------------------------------
# Rule 2: CVE Dependency
# ---------------------------------------------------------------------------

def cve_dependency(nodes: List[GraphNode]) -> List[GraphEdge]:
    """
    Connect technique → CVE when matched_cves is non-empty.

    Looks for CVE nodes whose cve_id matches a technique node's linked CVE.
    """
    tech_nodes = {n.id: n for n in nodes if n.type == "technique"}
    cve_nodes = {n.id: n for n in nodes if n.type == "cve"}
    edges: List[GraphEdge] = []

    for cve_node in cve_nodes.values():
        linked_tech = cve_node.properties.get("technique", "")
        tech_node_id = f"technique_{linked_tech}"
        if tech_node_id in tech_nodes:
            edges.append(GraphEdge(
                source=tech_node_id,
                target=cve_node.id,
                type="cve_dependency",
                weight=1.0,
                timestamp=tech_nodes[tech_node_id].properties.get("timestamp"),
            ))

    return edges


# ---------------------------------------------------------------------------
# Rule 3: Process Lineage
# ---------------------------------------------------------------------------

def process_lineage(nodes: List[GraphNode]) -> List[GraphEdge]:
    """
    Connect processes where proc.pname of one matches proc.name of another
    on the same container (parent → child).
    """
    proc_nodes = [n for n in nodes if n.type == "process"]
    if len(proc_nodes) < 2:
        return []

    # Build a lookup: (container, proc_name) → node
    by_name = {}
    for n in proc_nodes:
        key = (n.properties.get("container", ""), n.properties.get("proc_name", ""))
        by_name[key] = n

    edges: List[GraphEdge] = []
    for child in proc_nodes:
        pname = child.properties.get("proc_pname", "")
        container = child.properties.get("container", "")
        if not pname:
            continue
        parent = by_name.get((container, pname))
        if parent and parent.id != child.id:
            edges.append(GraphEdge(
                source=parent.id,
                target=child.id,
                type="process_lineage",
                weight=0.9,
            ))

    return edges


# ---------------------------------------------------------------------------
# Rule 4: Network Flow
# ---------------------------------------------------------------------------

def network_flow(nodes: List[GraphNode]) -> List[GraphEdge]:
    """
    Connect containers when fd.rip of one alert matches the IP of another
    container in the Docker network.
    """
    container_ips: dict = {}
    for n in nodes:
        if n.type == "container":
            ip = n.properties.get("ip")
            if ip:
                container_ips[ip] = n.id

    net_nodes = [n for n in nodes if n.type == "network_connection"]
    edges: List[GraphEdge] = []

    for net in net_nodes:
        rip = net.properties.get("ip", "")
        source_container = net.properties.get("container", "")
        source_container_id = f"container_{source_container}"

        # Check if rip matches a known container IP
        target_container_id = container_ips.get(rip)
        if target_container_id and target_container_id != source_container_id:
            edges.append(GraphEdge(
                source=source_container_id,
                target=target_container_id,
                type="network_flow",
                weight=0.7,
            ))

    return edges


# ---------------------------------------------------------------------------
# Aggregate — DRY single entry-point
# ---------------------------------------------------------------------------

def apply_all_rules(nodes: List[GraphNode]) -> List[GraphEdge]:
    """Run all 4 edge-inference rules and return the combined edge list."""
    edges: List[GraphEdge] = []
    edges.extend(technique_adjacency(nodes))
    edges.extend(cve_dependency(nodes))
    edges.extend(process_lineage(nodes))
    edges.extend(network_flow(nodes))
    return edges


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _within_time_window(ts_a: str, ts_b: str) -> bool:
    """Return True if two ISO-8601 timestamps are within TIME_WINDOW_SECONDS."""
    try:
        dt_a = datetime.fromisoformat(ts_a.replace("Z", "+00:00"))
        dt_b = datetime.fromisoformat(ts_b.replace("Z", "+00:00"))
        return abs((dt_b - dt_a).total_seconds()) <= TIME_WINDOW_SECONDS
    except (ValueError, AttributeError):
        return False
