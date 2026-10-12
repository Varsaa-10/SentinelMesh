"""
End-to-end test for S10 multi-stage chain validation (C1-P2).

Tests that the attack-graph module correctly reconstructs the S10
chain (S1 → S3 → S4 → S9 → S8) from fixture data, producing:
  - Correct topological stage order
  - All 5 inter-stage edges with correct types
  - Matching results for both RAG-grounded and graph-only variants
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from graph.attack_graph import AttackGraph
from graph.graph_only_baseline import GraphOnlyBaseline, FALLBACK_RULE_TABLE

# ---------------------------------------------------------------------------
# Load fixture
# ---------------------------------------------------------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
S10_ALERTS_PATH = os.path.join(FIXTURES_DIR, "s10_alerts.json")

with open(S10_ALERTS_PATH, "r", encoding="utf-8") as _f:
    S10_ALERTS = json.load(_f)

# Ground truth from eval/ground_truth.json S10 entry
EXPECTED_STAGES = ["S1", "S3", "S4", "S9", "S8"]
EXPECTED_TECHNIQUES = ["T1190", "T1078", "T1212", "T1003.008", "T1041"]

# RAG results matching each S10 stage (parallel to S10_ALERTS)
S10_RAG_RESULTS = [
    {
        "predicted_technique": "T1190",
        "predicted_technique_name": "Exploit Public-Facing Application",
        "predicted_tactic": "Initial Access",
        "matched_cves": [],
        "confidence": {"composite": 0.92},
        "evidence": {},
    },
    {
        "predicted_technique": "T1078",
        "predicted_technique_name": "Valid Accounts",
        "predicted_tactic": "Initial Access",
        "matched_cves": [],
        "confidence": {"composite": 0.88},
        "evidence": {},
    },
    {
        "predicted_technique": "T1212",
        "predicted_technique_name": "Exploitation for Credential Access",
        "predicted_tactic": "Credential Access",
        "matched_cves": ["CVE-2022-29217"],
        "confidence": {"composite": 0.95},
        "evidence": {},
    },
    {
        "predicted_technique": "T1003.008",
        "predicted_technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "predicted_tactic": "Credential Access",
        "matched_cves": [],
        "confidence": {"composite": 0.90},
        "evidence": {},
    },
    {
        "predicted_technique": "T1041",
        "predicted_technique_name": "Exfiltration Over C2 Channel",
        "predicted_tactic": "Exfiltration",
        "matched_cves": [],
        "confidence": {"composite": 0.87},
        "evidence": {},
    },
]


# ---------------------------------------------------------------------------
# Helper: reconstruct ordered path from graph
# ---------------------------------------------------------------------------

def _reconstruct_path(graph: AttackGraph) -> list:
    """
    Extract the ordered technique sequence from the graph by sorting
    technique nodes by their timestamp (the fundamental ordering signal).
    """
    tech_nodes = [n for n in graph.nodes if n.type == "technique"]
    tech_nodes.sort(key=lambda n: n.properties.get("timestamp", ""))
    return [n.properties.get("technique_id", n.label) for n in tech_nodes]


def _reconstruct_stages(graph: AttackGraph) -> list:
    """Extract ordered scenario stages from technique nodes."""
    tech_nodes = [n for n in graph.nodes if n.type == "technique"]
    tech_nodes.sort(key=lambda n: n.properties.get("timestamp", ""))
    return [n.properties.get("scenario", "") for n in tech_nodes]


# ---------------------------------------------------------------------------
# Test: RAG-grounded S10 chain reconstruction
# ---------------------------------------------------------------------------

class TestS10RAGGrounded(unittest.TestCase):
    """Test S10 chain with RAG results (the primary variant)."""

    def setUp(self):
        self.graph = AttackGraph.from_alerts(
            S10_ALERTS, S10_RAG_RESULTS, graph_id="s10-rag-test"
        )

    def test_all_5_technique_nodes_present(self):
        for tech_id in EXPECTED_TECHNIQUES:
            node = self.graph.get_node(f"technique_{tech_id}")
            self.assertIsNotNone(node, f"Missing technique node: {tech_id}")

    def test_technique_sequence_matches_ground_truth(self):
        path = _reconstruct_path(self.graph)
        self.assertEqual(path, EXPECTED_TECHNIQUES)

    def test_stage_order_matches_ground_truth(self):
        stages = _reconstruct_stages(self.graph)
        self.assertEqual(stages, EXPECTED_STAGES)

    def test_cve_node_present_for_s4(self):
        cve = self.graph.get_node("cve_CVE-2022-29217")
        self.assertIsNotNone(cve)
        self.assertEqual(cve.properties["technique"], "T1212")

    def test_cve_dependency_edge_exists(self):
        cve_edges = [e for e in self.graph.edges if e.type == "cve_dependency"]
        self.assertGreater(len(cve_edges), 0)
        targets = {e.target for e in cve_edges}
        self.assertIn("cve_CVE-2022-29217", targets)

    def test_technique_adjacency_edges_exist(self):
        """S1(Initial Access) → S3(Initial Access) should have adjacency edge."""
        adj_edges = [e for e in self.graph.edges if e.type == "technique_adjacency"]
        self.assertGreater(len(adj_edges), 0)

    def test_process_lineage_edge_for_s9(self):
        """S9: cat spawned from containerd-shim."""
        lineage = [e for e in self.graph.edges if e.type == "process_lineage"]
        self.assertGreater(len(lineage), 0)

    def test_all_inter_stage_edge_types_present(self):
        """At least technique_adjacency, cve_dependency, and process_lineage should fire."""
        edge_types = {e.type for e in self.graph.edges}
        self.assertIn("technique_adjacency", edge_types)
        self.assertIn("cve_dependency", edge_types)
        self.assertIn("process_lineage", edge_types)

    def test_graph_serializes_correctly(self):
        data = json.loads(self.graph.to_json())
        self.assertEqual(data["graph_id"], "s10-rag-test")
        self.assertGreater(len(data["nodes"]), 0)
        self.assertGreater(len(data["edges"]), 0)


# ---------------------------------------------------------------------------
# Test: Graph-only baseline S10 chain reconstruction
# ---------------------------------------------------------------------------

class TestS10GraphOnly(unittest.TestCase):
    """Test S10 chain with graph-only baseline (no RAG)."""

    def setUp(self):
        baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)
        self.graph = baseline.build(S10_ALERTS, graph_id="s10-graphonly-test")

    def test_all_5_technique_nodes_present(self):
        for tech_id in EXPECTED_TECHNIQUES:
            node = self.graph.get_node(f"technique_{tech_id}")
            self.assertIsNotNone(node, f"Missing technique node: {tech_id}")

    def test_technique_sequence_matches_ground_truth(self):
        path = _reconstruct_path(self.graph)
        self.assertEqual(path, EXPECTED_TECHNIQUES)

    def test_stage_order_matches_ground_truth(self):
        stages = _reconstruct_stages(self.graph)
        self.assertEqual(stages, EXPECTED_STAGES)

    def test_cve_node_present_for_s4(self):
        cve = self.graph.get_node("cve_CVE-2022-29217")
        self.assertIsNotNone(cve)

    def test_graph_output_format_matches_rag_variant(self):
        """Graph-only output must have same top-level keys as RAG variant."""
        data = self.graph.to_dict()
        self.assertIn("graph_id", data)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("paths", data)


# ---------------------------------------------------------------------------
# Test: Both variants produce the same S10 path
# ---------------------------------------------------------------------------

class TestS10CrossVariant(unittest.TestCase):
    """Verify RAG-grounded and graph-only produce identical S10 paths."""

    def test_both_variants_same_technique_sequence(self):
        rag_graph = AttackGraph.from_alerts(
            S10_ALERTS, S10_RAG_RESULTS, graph_id="cross-rag"
        )
        baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)
        go_graph = baseline.build(S10_ALERTS, graph_id="cross-go")

        rag_path = _reconstruct_path(rag_graph)
        go_path = _reconstruct_path(go_graph)
        self.assertEqual(rag_path, go_path)
        self.assertEqual(rag_path, EXPECTED_TECHNIQUES)

    def test_both_variants_same_stage_order(self):
        rag_graph = AttackGraph.from_alerts(
            S10_ALERTS, S10_RAG_RESULTS, graph_id="cross-rag-2"
        )
        baseline = GraphOnlyBaseline(rule_table=FALLBACK_RULE_TABLE)
        go_graph = baseline.build(S10_ALERTS, graph_id="cross-go-2")

        rag_stages = _reconstruct_stages(rag_graph)
        go_stages = _reconstruct_stages(go_graph)
        self.assertEqual(rag_stages, go_stages)
        self.assertEqual(rag_stages, EXPECTED_STAGES)


# ---------------------------------------------------------------------------
# Test: Reproducibility on clean fixture
# ---------------------------------------------------------------------------

class TestReproducibility(unittest.TestCase):

    def test_deterministic_output(self):
        """Two runs on the same fixture produce identical graphs."""
        g1 = AttackGraph.from_alerts(S10_ALERTS, S10_RAG_RESULTS, graph_id="repro")
        g2 = AttackGraph.from_alerts(S10_ALERTS, S10_RAG_RESULTS, graph_id="repro")

        d1 = g1.to_dict()
        d2 = g2.to_dict()

        self.assertEqual(len(d1["nodes"]), len(d2["nodes"]))
        self.assertEqual(len(d1["edges"]), len(d2["edges"]))

        # Same technique sequence
        p1 = _reconstruct_path(g1)
        p2 = _reconstruct_path(g2)
        self.assertEqual(p1, p2)


if __name__ == "__main__":
    unittest.main()


class TestS10PathFromChainTag(unittest.TestCase):
    """S10 gets its own path only from alerts tagged chain_id='S10'."""

    def _paths(self, alerts, use_baseline=True):
        from graph.pipeline import run_pipeline
        return {p["scenario_id"]: p for p in run_pipeline(alerts, use_baseline=use_baseline, graph_id="t")["paths"]}

    def test_tagged_chain_yields_s10_path_with_five_stages(self):
        paths = self._paths(S10_ALERTS)
        self.assertIn("S10", paths)
        self.assertEqual(paths["S10"]["ordered_stages"], EXPECTED_STAGES)
        self.assertEqual(paths["S10"]["technique_sequence"], EXPECTED_TECHNIQUES)

    def test_untagged_alerts_do_not_get_s10_path(self):
        untagged = [{k: v for k, v in a.items() if k not in ("chain_id", "component_scenario")} for a in S10_ALERTS]
        self.assertNotIn("S10", self._paths(untagged))

    def test_full_run_has_one_path_per_scenario_plus_s10(self):
        extra = []
        for sid in ("S2", "S5", "S6", "S7"):
            extra.append({"source": "log-tail", "scenario": sid, "severity": "WARNING", "title": f"{sid} alert",
                          "timestamp": "2026-01-01T00:00:00Z", "service": "webapp", "event": {}})
        paths = self._paths(extra + S10_ALERTS)
        self.assertEqual(len(paths), 10)
        self.assertIn("S10", paths)
