"""
Unit tests for the graph-only baseline variant (C1-P1).

Covers:
  - Graph-only baseline runs without RAG imports
  - Produces output for all 9 single scenarios
  - Output format matches RAG-grounded variant (same keys)
  - Tests cover log-tail (S1), Falco (S5, S9), and mixed alert sets
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from graph.graph_only_baseline import GraphOnlyBaseline, FALLBACK_RULE_TABLE
from graph.attack_graph import AttackGraph


# ---------------------------------------------------------------------------
# Fixtures — all 9 single-scenario alerts
# ---------------------------------------------------------------------------

ALL_ALERTS = [
    {
        "source": "log-tail", "scenario": "S1", "severity": "CRITICAL",
        "title": "SQL Injection Authentication Bypass",
        "timestamp": "2026-08-04T12:00:00Z", "service": "webapp",
        "event": {"login_attempt": True, "result": "success"},
    },
    {
        "source": "log-tail", "scenario": "S2", "severity": "WARNING",
        "title": "Brute-Force Login Attempt",
        "timestamp": "2026-08-04T12:00:30Z", "service": "webapp",
        "event": {"login_attempt": True, "result": "failure"},
    },
    {
        "source": "log-tail", "scenario": "S3", "severity": "WARNING",
        "title": "Default Credential Login",
        "timestamp": "2026-08-04T12:01:00Z", "service": "authservice",
        "event": {"login_attempt": True, "result": "success", "identifier": "admin"},
    },
    {
        "source": "log-tail", "scenario": "S4", "severity": "CRITICAL",
        "title": "JWT Algorithm Confusion",
        "timestamp": "2026-08-04T12:01:30Z", "service": "authservice",
        "event": {"jwt_verification": True, "algorithm": "none"},
    },
    {
        "source": "falco", "scenario": "S5", "severity": "WARNING",
        "title": "SentinelMesh Unauthorized Database Connection",
        "timestamp": "2026-08-04T12:02:00Z", "service": "webapp",
        "event": {"fd.rip": "172.18.0.6", "fd.rport": "5432"},
    },
    {
        "source": "falco", "scenario": "S6", "severity": "WARNING",
        "title": "SentinelMesh Log Directory Tampering",
        "timestamp": "2026-08-04T12:02:30Z", "service": "logcollector",
        "event": {"fd.name": "/var/log/sentinelmesh/webapp.log"},
    },
    {
        "source": "log-tail", "scenario": "S7", "severity": "WARNING",
        "title": "Grafana Login Succeeded",
        "timestamp": "2026-08-04T12:03:00Z", "service": "dashboard",
        "event": {"path": "/login", "status": 200},
    },
    {
        "source": "falco", "scenario": "S8", "severity": "CRITICAL",
        "title": "SentinelMesh Unexpected Outbound Connection",
        "timestamp": "2026-08-04T12:03:30Z", "service": "webapp",
        "event": {"fd.rip": "203.0.113.50", "fd.rport": "443"},
    },
    {
        "source": "falco", "scenario": "S9", "severity": "CRITICAL",
        "title": "SentinelMesh Sensitive Credential File Read",
        "timestamp": "2026-08-04T12:04:00Z", "service": "webapp",
        "event": {"proc.name": "cat", "proc.pname": "containerd-shim"},
    },
]


# ---------------------------------------------------------------------------
# Test: No RAG dependency
# ---------------------------------------------------------------------------

class TestNoRAGDependency(unittest.TestCase):

    def test_no_rag_module_imported(self):
        """GraphOnlyBaseline must not import any rag_engine modules."""
        import graph.graph_only_baseline as mod
        with open(mod.__file__, "r", encoding="utf-8") as fh:
            source = fh.read()
        self.assertNotIn("from rag_engine", source)
        self.assertNotIn("import rag_engine", source)


# ---------------------------------------------------------------------------
# Test: All 9 scenarios produce output
# ---------------------------------------------------------------------------

class TestAllScenarios(unittest.TestCase):

    def setUp(self):
        self.baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)

    def test_produces_output_for_all_9_scenarios(self):
        graph = self.baseline.build(ALL_ALERTS, graph_id="test-all-9")
        output = graph.to_dict()

        # Must have nodes and edges
        self.assertGreater(len(output["nodes"]), 0)
        # Should have technique nodes for each unique technique
        tech_nodes = [n for n in output["nodes"] if n["type"] == "technique"]
        # S1(T1190), S2(T1110), S3/S7(T1078), S4(T1212), S5(T1021),
        # S6(T1070), S8(T1041), S9(T1003.008) = 8 unique techniques
        self.assertEqual(len(tech_nodes), 8)

    def test_all_containers_present(self):
        graph = self.baseline.build(ALL_ALERTS, graph_id="test-containers")
        containers = {n.label for n in graph.nodes if n.type == "container"}
        self.assertIn("webapp", containers)
        self.assertIn("authservice", containers)
        self.assertIn("logcollector", containers)
        self.assertIn("dashboard", containers)


# ---------------------------------------------------------------------------
# Test: Output format matches RAG-grounded variant
# ---------------------------------------------------------------------------

class TestOutputFormat(unittest.TestCase):

    def setUp(self):
        self.baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)

    def test_output_has_required_keys(self):
        graph = self.baseline.build(ALL_ALERTS, graph_id="test-format")
        output = graph.to_dict()
        self.assertIn("graph_id", output)
        self.assertIn("nodes", output)
        self.assertIn("edges", output)
        self.assertIn("paths", output)

    def test_nodes_have_required_fields(self):
        graph = self.baseline.build(ALL_ALERTS)
        for node in graph.nodes:
            d = node.to_dict()
            self.assertIn("id", d)
            self.assertIn("type", d)
            self.assertIn("label", d)
            self.assertIn("properties", d)

    def test_edges_have_required_fields(self):
        graph = self.baseline.build(ALL_ALERTS)
        for edge in graph.edges:
            d = edge.to_dict()
            self.assertIn("source", d)
            self.assertIn("target", d)
            self.assertIn("type", d)
            self.assertIn("weight", d)

    def test_json_serialization(self):
        graph = self.baseline.build(ALL_ALERTS, graph_id="test-json")
        json_str = graph.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["graph_id"], "test-json")


# ---------------------------------------------------------------------------
# Test: Scenario types — log-tail, Falco, mixed
# ---------------------------------------------------------------------------

class TestScenarioTypes(unittest.TestCase):

    def setUp(self):
        self.baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)

    def test_logtail_scenario_s1(self):
        """Log-tail scenario: S1 SQL Injection."""
        graph = self.baseline.build([ALL_ALERTS[0]])
        tech = graph.get_node("technique_T1190")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.properties["tactic"], "Initial Access")

    def test_falco_scenario_s5(self):
        """Falco scenario: S5 Unauthorized DB Connection (network event)."""
        graph = self.baseline.build([ALL_ALERTS[4]])
        net = graph.get_node("network_172.18.0.6:5432")
        self.assertIsNotNone(net)
        tech = graph.get_node("technique_T1021")
        self.assertIsNotNone(tech)

    def test_falco_scenario_s9(self):
        """Falco scenario: S9 Credential File Read (process event)."""
        graph = self.baseline.build([ALL_ALERTS[8]])
        proc = graph.get_node("process_webapp_cat")
        self.assertIsNotNone(proc)
        self.assertEqual(proc.properties["proc_pname"], "containerd-shim")
        tech = graph.get_node("technique_T1003.008")
        self.assertIsNotNone(tech)

    def test_mixed_logtail_and_falco(self):
        """Mixed: S1 (log-tail) + S5 (Falco) together."""
        mixed = [ALL_ALERTS[0], ALL_ALERTS[4]]
        graph = self.baseline.build(mixed)
        self.assertIsNotNone(graph.get_node("technique_T1190"))
        self.assertIsNotNone(graph.get_node("technique_T1021"))
        self.assertIsNotNone(graph.get_node("network_172.18.0.6:5432"))

    def test_cve_node_created_for_s4(self):
        """S4 (JWT confusion) should produce a CVE node."""
        graph = self.baseline.build([ALL_ALERTS[3]])
        cve = graph.get_node("cve_CVE-2022-29217")
        self.assertIsNotNone(cve)
        self.assertEqual(cve.properties["technique"], "T1212")


# ---------------------------------------------------------------------------
# Test: Edge inference reuses C1-P0 rules
# ---------------------------------------------------------------------------

class TestEdgeInference(unittest.TestCase):

    def setUp(self):
        self.baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)

    def test_technique_adjacency_edges_created(self):
        """S1 (Initial Access) and S3 (Initial Access) should get adjacency edge."""
        alerts = [ALL_ALERTS[0], ALL_ALERTS[2]]  # S1, S3
        graph = self.baseline.build(alerts)
        adj_edges = [e for e in graph.edges if e.type == "technique_adjacency"]
        self.assertGreater(len(adj_edges), 0)

    def test_cve_dependency_edge_created(self):
        """S4 should produce a cve_dependency edge to CVE-2022-29217."""
        graph = self.baseline.build([ALL_ALERTS[3]])
        cve_edges = [e for e in graph.edges if e.type == "cve_dependency"]
        self.assertEqual(len(cve_edges), 1)
        self.assertEqual(cve_edges[0].target, "cve_CVE-2022-29217")

    def test_process_lineage_edge_created(self):
        """S9 has cat spawned from containerd-shim — should get lineage edge."""
        graph = self.baseline.build([ALL_ALERTS[8]])
        lineage = [e for e in graph.edges if e.type == "process_lineage"]
        self.assertEqual(len(lineage), 1)


if __name__ == "__main__":
    unittest.main()
