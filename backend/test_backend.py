"""
Unit tests for SentinelMesh FastAPI backend endpoints.
"""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from backend.app import app, ALERTS_STORE, DECISIONS_STORE, METRICS


class TestBackendAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        ALERTS_STORE.clear()
        DECISIONS_STORE.clear()
        METRICS["total_decisions"] = 0
        METRICS["approvals"] = 0
        METRICS["rejections"] = 0
        METRICS["modifications"] = 0
        METRICS["agreement_rate"] = 1.0
        METRICS["override_rate"] = 0.0

    def test_root(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "online")

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")

    def test_create_and_get_alerts(self):
        alert_payload = {
            "source": "log-tail",
            "scenario": "S1",
            "severity": "CRITICAL",
            "title": "SQL Injection Authentication Bypass",
            "service": "webapp",
            "event": {"payload": "' OR '1'='1"},
        }
        res_post = self.client.post("/api/alerts", json=alert_payload)
        self.assertEqual(res_post.status_code, 200)
        post_data = res_post.json()
        self.assertEqual(post_data["status"], "success")
        self.assertEqual(post_data["alert"]["title"], "SQL Injection Authentication Bypass")

        res_get = self.client.get("/api/alerts")
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.json()
        self.assertEqual(get_data["count"], 1)

    def test_investigate_alerts(self):
        # Post alert
        alert_payload = {
            "source": "log-tail",
            "scenario": "S1",
            "severity": "CRITICAL",
            "title": "SQL Injection Authentication Bypass",
            "service": "webapp",
            "event": {"payload": "' OR '1'='1"},
        }
        self.client.post("/api/alerts", json=alert_payload)

        res_inv = self.client.post("/api/investigate")
        self.assertEqual(res_inv.status_code, 200)
        inv_data = res_inv.json()
        self.assertEqual(inv_data["status"], "success")
        self.assertIn("investigations", inv_data)
        self.assertIn("attack_graph", inv_data)

    def test_decisions_flow(self):
        decision_payload = {
            "alert_id": "ALT-0001",
            "scenario_id": "S1",
            "action": "approve",
            "analyst_id": "analyst-test",
            "comment": "Verified SQLi attack",
        }
        res_dec = self.client.post("/api/decisions", json=decision_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.json()
        self.assertEqual(dec_data["status"], "success")
        self.assertEqual(dec_data["metrics"]["approvals"], 1)

        res_get = self.client.get("/api/decisions")
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.json()
        self.assertEqual(len(get_data["decisions"]), 1)


if __name__ == "__main__":
    unittest.main()
