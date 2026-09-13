"""
Unit tests for the SentinelMesh attack-graph module (C1-P0).

Covers:
  - GraphNode / GraphEdge creation and validation
  - AttackGraph add/query/serialization
  - Each of the 4 edge-inference rules
  - apply_all_rules aggregate
  - from_alerts factory with single-scenario fixtures
  - JSON round-trip serialization
  - Schema validation against graph_schema.json
"""

import json
import os
import sys
import unittest

# Ensure the project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from graph.attack_graph import AttackGraph, GraphNode, GraphEdge, NODE_TYPES, EDGE_TYPES
from graph.edge_rules import (
    technique_adjacency,
    cve_dependency,
    process_lineage,
    network_flow,
    apply_all_rules,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_s1_alert():
    """S1 — SQL Injection Authentication Bypass (log-tail)."""
    return {
        "source": "log-tail",
        "scenario": "S1",
        "severity": "CRITICAL",
        "title": "SQL Injection Authentication Bypass",
        "timestamp": "2026-08-04T12:00:00Z",
        "service": "webapp",
        "event": {"login_attempt": True, "result": "success"},
    }


def _make_s4_alert():
    """S4 — JWT Algorithm Confusion (log-tail, has CVE)."""
    return {
        "source": "log-tail",
        "scenario": "S4",
        "severity": "CRITICAL",
        "title": "JWT Algorithm Confusion",
        "timestamp": "2026-08-04T12:01:00Z",
        "service": "authservice",
        "event": {"jwt_verification": True, "algorithm": "none"},
    }


def _make_s5_alert():
    """S5 — Unauthorized Database Connection (Falco, network event)."""
    return {
        "source": "falco",
        "scenario": "S5",
        "severity": "WARNING",
        "title": "SentinelMesh Unauthorized Database Connection",
        "timestamp": "2026-08-04T12:02:00Z",
        "service": "webapp",
        "event": {"fd.rip": "172.18.0.6", "fd.rport": "5432"},
    }


def _make_s9_alert():
    """S9 — Sensitive Credential File Read (Falco, process event)."""
    return {
        "source": "falco",
        "scenario": "S9",
        "severity": "CRITICAL",
        "title": "SentinelMesh Sensitive Credential File Read",
        "timestamp": "2026-08-04T12:03:00Z",
        "service": "webapp",
        "event": {"proc.name": "cat", "proc.pname": "containerd-shim"},
    }


def _make_rag_result(technique_id, technique_name, tactic, cves=None,
                     confidence=0.85, scenario="S1", container="webapp",
                     timestamp="2026-08-04T12:00:00Z"):
    return {
        "predicted_technique": technique_id,
        "predicted_technique_name": technique_name,
        "predicted_tactic": tactic,
        "matched_cves": cves or [],
        "confidence": {"composite": confidence},
        "evidence": {},
        "scenario": scenario,
        "container": container,
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# Test: GraphNode
# ---------------------------------------------------------------------------

class TestGraphNode(unittest.TestCase):

    def test_valid_node_types(self):
        for nt in NODE_TYPES:
            node = GraphNode(id=f"test_{nt}", type=nt, label=f"Test {nt}")
            self.assertEqual(node.type, nt)

    def test_invalid_node_type_raises(self):
        with self.assertRaises(ValueError):
            GraphNode(id="bad", type="invalid_type", label="Bad")

    def test_to_dict(self):
        node = GraphNode(id="n1", type="container", label="webapp",
                         properties={"service": "webapp"})
        d = node.to_dict()
        self.assertEqual(d["id"], "n1")
        self.assertEqual(d["type"], "container")
        self.assertEqual(d["properties"]["service"], "webapp")


# ---------------------------------------------------------------------------
# Test: GraphEdge
# ---------------------------------------------------------------------------

class TestGraphEdge(unittest.TestCase):

    def test_valid_edge_types(self):
        for et in EDGE_TYPES:
            edge = GraphEdge(source="a", target="b", type=et)
            self.assertEqual(edge.type, et)

    def test_invalid_edge_type_raises(self):
        with self.assertRaises(ValueError):
            GraphEdge(source="a", target="b", type="invalid")

    def test_weight_clamped(self):
        edge = GraphEdge(source="a", target="b", type="network_flow", weight=1.5)
        self.assertEqual(edge.weight, 1.0)
        edge2 = GraphEdge(source="a", target="b", type="network_flow", weight=-0.5)
        self.assertEqual(edge2.weight, 0.0)


# ---------------------------------------------------------------------------
# Test: AttackGraph core operations
# ---------------------------------------------------------------------------

class TestAttackGraph(unittest.TestCase):

    def test_add_node_and_query(self):
        g = AttackGraph(graph_id="test-1")
        n = GraphNode(id="c1", type="container", label="webapp")
        g.add_node(n)
        self.assertEqual(len(g.nodes), 1)
        self.assertIsNotNone(g.get_node("c1"))
        self.assertIsNone(g.get_node("nonexistent"))

    def test_add_edge_requires_nodes(self):
        g = AttackGraph()
        g.add_node(GraphNode(id="n1", type="container", label="a"))
        g.add_node(GraphNode(id="n2", type="container", label="b"))
        e = GraphEdge(source="n1", target="n2", type="network_flow")
        g.add_edge(e)
        self.assertEqual(len(g.edges), 1)

    def test_add_edge_missing_source_raises(self):
        g = AttackGraph()
        g.add_node(GraphNode(id="n2", type="container", label="b"))
        with self.assertRaises(KeyError):
            g.add_edge(GraphEdge(source="missing", target="n2", type="network_flow"))

    def test_neighbors(self):
        g = AttackGraph()
        g.add_node(GraphNode(id="a", type="container", label="a"))
        g.add_node(GraphNode(id="b", type="container", label="b"))
        g.add_node(GraphNode(id="c", type="container", label="c"))
        g.add_edge(GraphEdge(source="a", target="b", type="network_flow"))
        g.add_edge(GraphEdge(source="a", target="c", type="network_flow"))
        self.assertEqual(sorted(g.neighbors("a")), ["b", "c"])
        self.assertEqual(g.neighbors("b"), [])

    def test_add_path(self):
        g = AttackGraph()
        g.add_path("S10", ["S1", "S3", "S4"], ["T1190", "T1078", "T1212"])
        paths = g.get_paths()
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["scenario_id"], "S10")


# ---------------------------------------------------------------------------
# Test: JSON serialization round-trip
# ---------------------------------------------------------------------------

class TestSerialization(unittest.TestCase):

    def test_to_json_and_from_dict(self):
        g = AttackGraph(graph_id="round-trip-test")
        g.add_node(GraphNode(id="c1", type="container", label="webapp"))
        g.add_node(GraphNode(id="t1", type="technique", label="T1190",
                             properties={"technique_id": "T1190"}))
        g.add_edge(GraphEdge(source="c1", target="t1", type="technique_adjacency",
                             weight=0.8))
        g.add_path("S1", ["S1"], ["T1190"])

        json_str = g.to_json()
        data = json.loads(json_str)
        g2 = AttackGraph.from_dict(data)

        self.assertEqual(g2.graph_id, "round-trip-test")
        self.assertEqual(len(g2.nodes), 2)
        self.assertEqual(len(g2.edges), 1)
        self.assertEqual(len(g2.get_paths()), 1)

    def test_schema_validation(self):
        """Validate graph output against graph_schema.json."""
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed — skipping schema validation")

        schema_path = os.path.join(os.path.dirname(__file__), "..", "graph_schema.json")
        with open(schema_path) as f:
            schema = json.load(f)

        g = AttackGraph(graph_id="schema-test")
        g.add_node(GraphNode(id="c1", type="container", label="webapp"))
        g.add_node(GraphNode(id="t1", type="technique", label="T1190"))
        g.add_edge(GraphEdge(source="c1", target="t1", type="technique_adjacency"))
        g.add_path("S1", ["S1"], ["T1190"])

        jsonschema.validate(g.to_dict(), schema)  # raises on failure


# ---------------------------------------------------------------------------
# Test: Edge-Inference Rule — Technique Adjacency
# ---------------------------------------------------------------------------

class TestTechniqueAdjacency(unittest.TestCase):

    def test_same_tactic_creates_edge(self):
        nodes = [
            GraphNode(id="technique_T1190", type="technique", label="T1190",
                      properties={"tactic": "Initial Access", "container": "webapp",
                                  "timestamp": "2026-08-04T12:00:00Z"}),
            GraphNode(id="technique_T1078", type="technique", label="T1078",
                      properties={"tactic": "Initial Access", "container": "authservice",
                                  "timestamp": "2026-08-04T12:01:00Z"}),
        ]
        edges = technique_adjacency(nodes)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].type, "technique_adjacency")
        self.assertEqual(edges[0].source, "technique_T1190")
        self.assertEqual(edges[0].target, "technique_T1078")

    def test_time_window_same_container_creates_edge(self):
        nodes = [
            GraphNode(id="technique_T1190", type="technique", label="T1190",
                      properties={"tactic": "Initial Access", "container": "webapp",
                                  "timestamp": "2026-08-04T12:00:00Z"}),
            GraphNode(id="technique_T1041", type="technique", label="T1041",
                      properties={"tactic": "Exfiltration", "container": "webapp",
                                  "timestamp": "2026-08-04T12:04:00Z"}),
        ]
        edges = technique_adjacency(nodes)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].weight, 0.6)  # within window, different tactic

    def test_no_edge_beyond_window_different_tactic(self):
        nodes = [
            GraphNode(id="technique_T1190", type="technique", label="T1190",
                      properties={"tactic": "Initial Access", "container": "webapp",
                                  "timestamp": "2026-08-04T12:00:00Z"}),
            GraphNode(id="technique_T1041", type="technique", label="T1041",
                      properties={"tactic": "Exfiltration", "container": "webapp",
                                  "timestamp": "2026-08-04T12:10:00Z"}),
        ]
        edges = technique_adjacency(nodes)
        self.assertEqual(len(edges), 0)

    def test_single_node_no_edges(self):
        nodes = [
            GraphNode(id="technique_T1190", type="technique", label="T1190",
                      properties={"tactic": "Initial Access"}),
        ]
        self.assertEqual(technique_adjacency(nodes), [])


# ---------------------------------------------------------------------------
# Test: Edge-Inference Rule — CVE Dependency
# ---------------------------------------------------------------------------

class TestCVEDependency(unittest.TestCase):

    def test_technique_cve_link(self):
        nodes = [
            GraphNode(id="technique_T1212", type="technique", label="T1212",
                      properties={"technique_id": "T1212"}),
            GraphNode(id="cve_CVE-2022-29217", type="cve", label="CVE-2022-29217",
                      properties={"cve_id": "CVE-2022-29217", "technique": "T1212"}),
        ]
        edges = cve_dependency(nodes)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].source, "technique_T1212")
        self.assertEqual(edges[0].target, "cve_CVE-2022-29217")
        self.assertEqual(edges[0].weight, 1.0)

    def test_no_matching_technique_no_edge(self):
        nodes = [
            GraphNode(id="cve_CVE-2022-29217", type="cve", label="CVE-2022-29217",
                      properties={"cve_id": "CVE-2022-29217", "technique": "T9999"}),
        ]
        edges = cve_dependency(nodes)
        self.assertEqual(len(edges), 0)


# ---------------------------------------------------------------------------
# Test: Edge-Inference Rule — Process Lineage
# ---------------------------------------------------------------------------

class TestProcessLineage(unittest.TestCase):

    def test_parent_child_connection(self):
        nodes = [
            GraphNode(id="process_webapp_containerd-shim", type="process",
                      label="containerd-shim",
                      properties={"proc_name": "containerd-shim", "proc_pname": "",
                                  "container": "webapp"}),
            GraphNode(id="process_webapp_cat", type="process",
                      label="cat",
                      properties={"proc_name": "cat", "proc_pname": "containerd-shim",
                                  "container": "webapp"}),
        ]
        edges = process_lineage(nodes)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].source, "process_webapp_containerd-shim")
        self.assertEqual(edges[0].target, "process_webapp_cat")
        self.assertEqual(edges[0].type, "process_lineage")

    def test_different_container_no_edge(self):
        nodes = [
            GraphNode(id="process_webapp_bash", type="process",
                      label="bash",
                      properties={"proc_name": "bash", "proc_pname": "",
                                  "container": "webapp"}),
            GraphNode(id="process_auth_cat", type="process",
                      label="cat",
                      properties={"proc_name": "cat", "proc_pname": "bash",
                                  "container": "authservice"}),
        ]
        edges = process_lineage(nodes)
        self.assertEqual(len(edges), 0)


# ---------------------------------------------------------------------------
# Test: Edge-Inference Rule — Network Flow
# ---------------------------------------------------------------------------

class TestNetworkFlow(unittest.TestCase):

    def test_cross_container_connection(self):
        nodes = [
            GraphNode(id="container_webapp", type="container", label="webapp",
                      properties={"service": "webapp", "ip": "172.18.0.3"}),
            GraphNode(id="container_database", type="container", label="database",
                      properties={"service": "database", "ip": "172.18.0.6"}),
            GraphNode(id="network_172.18.0.6:5432", type="network_connection",
                      label="172.18.0.6:5432",
                      properties={"ip": "172.18.0.6", "port": "5432",
                                  "container": "webapp"}),
        ]
        edges = network_flow(nodes)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].source, "container_webapp")
        self.assertEqual(edges[0].target, "container_database")

    def test_same_container_no_edge(self):
        nodes = [
            GraphNode(id="container_webapp", type="container", label="webapp",
                      properties={"service": "webapp", "ip": "172.18.0.3"}),
            GraphNode(id="network_172.18.0.3:8080", type="network_connection",
                      label="172.18.0.3:8080",
                      properties={"ip": "172.18.0.3", "port": "8080",
                                  "container": "webapp"}),
        ]
        edges = network_flow(nodes)
        self.assertEqual(len(edges), 0)


# ---------------------------------------------------------------------------
# Test: apply_all_rules aggregate
# ---------------------------------------------------------------------------

class TestApplyAllRules(unittest.TestCase):

    def test_mixed_nodes_produce_multiple_edge_types(self):
        nodes = [
            # Technique nodes (same tactic → technique_adjacency)
            GraphNode(id="technique_T1190", type="technique", label="T1190",
                      properties={"tactic": "Initial Access", "container": "webapp",
                                  "timestamp": "2026-08-04T12:00:00Z"}),
            GraphNode(id="technique_T1078", type="technique", label="T1078",
                      properties={"tactic": "Initial Access", "container": "authservice",
                                  "timestamp": "2026-08-04T12:01:00Z"}),
            # CVE node (→ cve_dependency)
            GraphNode(id="technique_T1212", type="technique", label="T1212",
                      properties={"tactic": "Credential Access", "container": "authservice",
                                  "timestamp": "2026-08-04T12:01:30Z"}),
            GraphNode(id="cve_CVE-2022-29217", type="cve", label="CVE-2022-29217",
                      properties={"cve_id": "CVE-2022-29217", "technique": "T1212"}),
            # Process nodes (→ process_lineage)
            GraphNode(id="process_webapp_containerd-shim", type="process",
                      label="containerd-shim",
                      properties={"proc_name": "containerd-shim", "proc_pname": "",
                                  "container": "webapp"}),
            GraphNode(id="process_webapp_cat", type="process",
                      label="cat",
                      properties={"proc_name": "cat", "proc_pname": "containerd-shim",
                                  "container": "webapp"}),
        ]
        edges = apply_all_rules(nodes)
        edge_types = {e.type for e in edges}
        self.assertIn("technique_adjacency", edge_types)
        self.assertIn("cve_dependency", edge_types)
        self.assertIn("process_lineage", edge_types)


# ---------------------------------------------------------------------------
# Test: from_alerts factory
# ---------------------------------------------------------------------------

class TestFromAlerts(unittest.TestCase):

    def test_single_alert_without_rag(self):
        alerts = [_make_s1_alert()]
        g = AttackGraph.from_alerts(alerts)
        # Should have at least a container node
        container = g.get_node("container_webapp")
        self.assertIsNotNone(container)
        self.assertEqual(container.type, "container")

    def test_alert_with_rag_creates_technique_node(self):
        alerts = [_make_s1_alert()]
        rag_results = [_make_rag_result("T1190", "Exploit Public-Facing Application",
                                         "Initial Access")]
        g = AttackGraph.from_alerts(alerts, rag_results)
        tech = g.get_node("technique_T1190")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.type, "technique")

    def test_alert_with_cve_creates_cve_node(self):
        alerts = [_make_s4_alert()]
        rag_results = [_make_rag_result("T1212", "Exploitation for Credential Access",
                                         "Credential Access",
                                         cves=["CVE-2022-29217"],
                                         scenario="S4",
                                         container="authservice",
                                         timestamp="2026-08-04T12:01:00Z")]
        g = AttackGraph.from_alerts(alerts, rag_results)
        cve = g.get_node("cve_CVE-2022-29217")
        self.assertIsNotNone(cve)
        self.assertEqual(cve.type, "cve")

    def test_falco_alert_creates_process_nodes(self):
        alerts = [_make_s9_alert()]
        g = AttackGraph.from_alerts(alerts)
        proc = g.get_node("process_webapp_cat")
        self.assertIsNotNone(proc)
        self.assertEqual(proc.properties["proc_pname"], "containerd-shim")

    def test_network_alert_creates_network_node(self):
        alerts = [_make_s5_alert()]
        g = AttackGraph.from_alerts(alerts)
        net = g.get_node("network_172.18.0.6:5432")
        self.assertIsNotNone(net)
        self.assertEqual(net.type, "network_connection")

    def test_multiple_alerts_produce_edges(self):
        alerts = [_make_s1_alert(), _make_s4_alert()]
        rag_results = [
            _make_rag_result("T1190", "Exploit Public-Facing Application",
                             "Initial Access",
                             timestamp="2026-08-04T12:00:00Z"),
            _make_rag_result("T1212", "Exploitation for Credential Access",
                             "Credential Access",
                             cves=["CVE-2022-29217"],
                             scenario="S4", container="authservice",
                             timestamp="2026-08-04T12:01:00Z"),
        ]
        g = AttackGraph.from_alerts(alerts, rag_results)
        # Should have technique_adjacency edge (within time window, same cluster)
        # and cve_dependency edge
        self.assertGreater(len(g.edges), 0)


if __name__ == "__main__":
    unittest.main()
