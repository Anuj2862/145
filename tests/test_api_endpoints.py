"""Unit and integration tests for FastAPI REST API (Member 3)."""

import unittest
from fastapi.testclient import TestClient
from api.app import app, pipeline
from schemas import Alert, Incident, ThreatClass, Severity


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("stats", data)
        self.assertIn("threat_classes_monitored", data)

    def test_alerts_endpoint(self):
        # Insert a sample alert into pipeline
        alert = Alert(
            alert_id="ALT-API-TEST-01",
            timestamp_iso="2026-08-31T12:00:00Z",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            severity=Severity.HIGH,
            confidence=0.95,
            source_ip="10.0.0.99",
            summary="API test alert",
            evidence_count=2,
        )
        pipeline.alerts.append(alert)

        response = self.client.get("/alerts")
        self.assertEqual(response.status_code, 200)
        alerts_list = response.json()
        self.assertGreaterEqual(len(alerts_list), 1)

        single_res = self.client.get(f"/alerts/{alert.alert_id}")
        self.assertEqual(single_res.status_code, 200)
        self.assertEqual(single_res.json()["alert_id"], alert.alert_id)

    def test_entities_and_graph_endpoints(self):
        # Add entity node and edge to graph
        pipeline.entity_graph.add_edge("10.0.0.99", "198.51.100.1", "COMMUNICATES_WITH")
        pipeline.entity_memory.get_or_create_profile("10.0.0.99")

        entities_res = self.client.get("/entities")
        self.assertEqual(entities_res.status_code, 200)
        self.assertGreaterEqual(entities_res.json()["count"], 1)

        graph_res = self.client.get("/graph")
        self.assertEqual(graph_res.status_code, 200)
        graph_data = graph_res.json()
        self.assertIn("nodes", graph_data)
        self.assertIn("links", graph_data)


if __name__ == "__main__":
    unittest.main()
