"""
Integration tests for the SentinelMesh Attack-Graph Pipeline (C1-P4).

Covers:
  - End-to-end pipeline execution for all 9 single scenarios
  - S10 multi-stage chain path reconstruction in pipeline context
  - Graph-only baseline execution via pipeline
  - JSON Schema validation of pipeline outputs
  - Mock RAG engine integration
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from graph.pipeline import AttackGraphPipeline, run_pipeline
from graph.tests.test_graph_only import ALL_ALERTS
from graph.tests.test_s10_chain import S10_ALERTS, S10_RAG_RESULTS, EXPECTED_TECHNIQUES, EXPECTED_STAGES

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "graph_schema.json")


# ---------------------------------------------------------------------------
# Test: Single Scenarios via Pipeline
# ---------------------------------------------------------------------------

class TestPipelineSingleScenarios(unittest.TestCase):

    def test_run_baseline_pipeline_all_alerts(self):
        """Pipeline in baseline mode runs end-to-end for all 9 single scenarios."""
        output = run_pipeline(ALL_ALERTS, use_baseline=True, graph_id="pipe-single-baseline")
        self.assertEqual(output["graph_id"], "pipe-single-baseline")
        self.assertGreater(len(output["nodes"]), 0)

    def test_run_rag_pipeline_with_precomputed_results(self):
        """Pipeline in RAG mode with precomputed RAG results."""
        output = run_pipeline(ALL_ALERTS[:1], rag_results=[{
            "predicted_technique": "T1190",
            "predicted_technique_name": "Exploit Public-Facing Application",
            "predicted_tactic": "Initial Access",
            "matched_cves": [],
            "confidence": {"composite": 0.95},
            "evidence": {},
        }], graph_id="pipe-single-rag")

        self.assertEqual(output["graph_id"], "pipe-single-rag")
        tech_node = next(n for n in output["nodes"] if n["id"] == "technique_T1190")
        self.assertIsNotNone(tech_node)


# ---------------------------------------------------------------------------
# Test: S10 Multi-Stage Chain via Pipeline
# ---------------------------------------------------------------------------

class TestPipelineS10Chain(unittest.TestCase):

    def test_s10_chain_pipeline_rag_grounded(self):
        """S10 chain reconstructed via pipeline matching ground truth."""
        output = run_pipeline(S10_ALERTS, rag_results=S10_RAG_RESULTS, graph_id="pipe-s10-rag")
        self.assertEqual(output["graph_id"], "pipe-s10-rag")

        # Verify paths
        self.assertEqual(len(output["paths"]), 1)
        path_data = output["paths"][0]
        self.assertEqual(path_data["scenario_id"], "S10")
        self.assertEqual(path_data["ordered_stages"], EXPECTED_STAGES)
        self.assertEqual(path_data["technique_sequence"], EXPECTED_TECHNIQUES)

    def test_s10_chain_pipeline_baseline(self):
        """S10 chain reconstructed via pipeline in baseline mode."""
        output = run_pipeline(S10_ALERTS, use_baseline=True, graph_id="pipe-s10-baseline")
        self.assertEqual(output["graph_id"], "pipe-s10-baseline")

        # Verify paths
        self.assertEqual(len(output["paths"]), 1)
        path_data = output["paths"][0]
        self.assertEqual(path_data["scenario_id"], "S10")
        self.assertEqual(path_data["ordered_stages"], EXPECTED_STAGES)
        self.assertEqual(path_data["technique_sequence"], EXPECTED_TECHNIQUES)


# ---------------------------------------------------------------------------
# Test: Mock RAG Engine Integration
# ---------------------------------------------------------------------------

class TestMockRAGEngineIntegration(unittest.TestCase):

    def test_pipeline_queries_mock_rag_engine(self):
        mock_rag = MagicMock()
        mock_rag.query.return_value = MagicMock(
            predicted_technique="T1078",
            predicted_technique_name="Valid Accounts",
            predicted_tactic="Initial Access",
            matched_cves=[],
            confidence=MagicMock(composite=0.9),
            evidence={},
        )

        pipeline = AttackGraphPipeline(rag_engine=mock_rag)
        output = pipeline.run([ALL_ALERTS[0]], graph_id="pipe-mock-rag")

        mock_rag.query.assert_called_once()
        self.assertIn("technique_T1078", [n["id"] for n in output["nodes"]])


# ---------------------------------------------------------------------------
# Test: JSON Schema Validation for Pipeline Outputs
# ---------------------------------------------------------------------------

class TestPipelineSchemaValidation(unittest.TestCase):

    def setUp(self):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema package not installed")
    def test_s10_pipeline_output_validates_against_frozen_schema(self):
        output = run_pipeline(S10_ALERTS, rag_results=S10_RAG_RESULTS, graph_id="pipe-val-schema")
        jsonschema.validate(instance=output, schema=self.schema)

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema package not installed")
    def test_baseline_pipeline_output_validates_against_frozen_schema(self):
        output = run_pipeline(ALL_ALERTS, use_baseline=True, graph_id="pipe-val-baseline-schema")
        jsonschema.validate(instance=output, schema=self.schema)


if __name__ == "__main__":
    unittest.main()
