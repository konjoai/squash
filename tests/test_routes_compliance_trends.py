"""tests/test_routes_compliance_trends.py — API integration tests.

Covers:
  * POST /api/compliance/scan      — multi-framework scan + auto-record
  * POST /api/analysis/cluster     — TF-IDF k-means
  * POST /api/analyses             — explicit recorder
  * GET  /api/trends/risk          — daily aggregates + trend direction
"""

from __future__ import annotations

import datetime
import os
import tempfile
import unittest


def _client_with_isolated_store():
    """Return a fresh TestClient that writes to a throwaway SQLite file."""
    # Pin a fresh DB path BEFORE importing the app so the route module
    # never sees the developer's real history file.
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.environ["SQUASH_ANALYSIS_HISTORY_PATH"] = tmp.name
    # Force the route module to drop any previously-cached connection.
    from squash.routes import trends as _trends
    _trends.reset_store_for_tests(tmp.name)

    from fastapi.testclient import TestClient
    from squash.api import app
    return TestClient(app), tmp.name


class TestComplianceScanEndpoint(unittest.TestCase):
    def setUp(self):
        self.client, self.db = _client_with_isolated_store()

    def test_scan_returns_full_report(self):
        r = self.client.post("/api/compliance/scan", json={
            "clauses": [
                "Multi-factor authentication is required for admin access.",
                "Cardholder data is tokenized; CVV is never stored.",
                "BAA is signed before any PHI is shared.",
            ],
            "frameworks": ["SOC2", "HIPAA", "PCI_DSS"],
            "min_confidence": 0.5,
        })
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("framework_results", body)
        self.assertSetEqual(
            set(body["framework_results"].keys()),
            {"SOC2", "HIPAA", "PCI_DSS"},
        )
        self.assertIn(body["overall_risk"],
                      {"low", "medium", "high", "critical"})
        self.assertTrue(body["recorded"])

    def test_scan_rejects_bad_framework(self):
        r = self.client.post("/api/compliance/scan", json={
            "clauses": ["irrelevant clause"],
            "frameworks": ["XYZ-99"],
        })
        self.assertEqual(r.status_code, 400)

    def test_scan_rejects_empty_clauses(self):
        r = self.client.post("/api/compliance/scan", json={"clauses": []})
        self.assertEqual(r.status_code, 422)

    def test_scan_does_not_record_when_flag_false(self):
        r = self.client.post("/api/compliance/scan", json={
            "clauses": ["irrelevant"],
            "frameworks": ["SOC2"],
            "record": False,
        })
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["recorded"])


class TestClusteringEndpoint(unittest.TestCase):
    def setUp(self):
        self.client, _ = _client_with_isolated_store()

    def test_cluster_returns_structured_result(self):
        r = self.client.post("/api/analysis/cluster", json={
            "clauses": [
                "Customer shall indemnify Provider.",
                "Provider shall indemnify Customer.",
                "Liability is capped at twelve months of fees.",
                "In no event shall total liability exceed prior-year fees.",
            ],
            "k": 2,
            "seed": 42,
        })
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["requested_k"], 2)
        self.assertEqual(len(body["clusters"]), 2)
        for cl in body["clusters"]:
            self.assertIn("centroid_terms", cl)
            self.assertIn("intra_cluster_similarity", cl)
            for clause in cl["clauses"]:
                self.assertIn("similarity_to_centroid", clause)

    def test_cluster_validates_k(self):
        r = self.client.post("/api/analysis/cluster", json={
            "clauses": ["a", "b"], "k": 0,
        })
        self.assertEqual(r.status_code, 422)


class TestTrendsRecordAndQuery(unittest.TestCase):
    def setUp(self):
        self.client, _ = _client_with_isolated_store()

    def test_post_analyses_records_row(self):
        r = self.client.post("/api/analyses", json={
            "doc_hash": "abc123",
            "risk_score": 72.5,
            "framework": "SOC2",
            "clause_count": 12,
            "high_risk_count": 1,
        })
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("id", body)
        self.assertTrue(body["recorded"])

    def test_trend_returns_data_points_for_window(self):
        # seed three scans across two days
        today = datetime.datetime.now(datetime.timezone.utc)
        yesterday = today - datetime.timedelta(days=1)
        for ts, score in (
            (yesterday.isoformat(), 30.0),
            (today.isoformat(), 60.0),
            (today.isoformat(), 70.0),
        ):
            self.client.post("/api/analyses", json={
                "doc_hash": "d-" + ts[:10],
                "risk_score": score,
                "framework": "SOC2",
                "clause_count": 10,
                "high_risk_count": 2,
                "timestamp": ts,
            })
        r = self.client.get("/api/trends/risk?days=7&framework=SOC2")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["days"], 7)
        self.assertEqual(body["framework"], "SOC2")
        # 7 fully-filled day buckets, regardless of whether scans landed
        self.assertEqual(len(body["data_points"]), 7)
        # at least one populated day
        self.assertTrue(any(p["doc_count"] > 0 for p in body["data_points"]))
        self.assertIn(body["trend_direction"],
                      {"improving", "stable", "degrading"})
        self.assertIn("avg_risk_score", body["period_summary"])

    def test_trend_filters_framework(self):
        today = datetime.datetime.now(datetime.timezone.utc).isoformat()
        soc2_post = self.client.post("/api/analyses", json={
            "doc_hash": "soc2-doc", "risk_score": 90.0, "framework": "SOC2",
            "clause_count": 10, "high_risk_count": 0, "timestamp": today,
        })
        self.assertEqual(soc2_post.status_code, 200, soc2_post.text)
        hipaa_post = self.client.post("/api/analyses", json={
            "doc_hash": "hipaa-doc", "risk_score": 10.0, "framework": "HIPAA",
            "clause_count": 10, "high_risk_count": 8, "timestamp": today,
        })
        self.assertEqual(hipaa_post.status_code, 200, hipaa_post.text)
        soc2 = self.client.get("/api/trends/risk?days=3&framework=SOC2").json()
        hipaa = self.client.get("/api/trends/risk?days=3&framework=HIPAA").json()
        self.assertEqual(soc2["period_summary"]["avg_risk_score"], 90.0)
        self.assertEqual(hipaa["period_summary"]["avg_risk_score"], 10.0)

    def test_trend_rejects_bad_days(self):
        r = self.client.get("/api/trends/risk?days=0")
        self.assertEqual(r.status_code, 400)
        r2 = self.client.get("/api/trends/risk?days=400")
        self.assertEqual(r2.status_code, 400)

    def test_scan_then_query_trend_observes_record(self):
        self.client.post("/api/compliance/scan", json={
            "clauses": [
                "MFA is required.",
                "BAA signed before PHI sharing.",
                "Cardholder data is tokenized.",
            ],
            "frameworks": ["SOC2", "HIPAA", "PCI_DSS"],
        })
        r = self.client.get("/api/trends/risk?days=2")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        # aggregate '*' rows are recorded so even unfiltered query sees data
        self.assertGreater(body["period_summary"]["total_scans"], 0)


if __name__ == "__main__":
    unittest.main()
