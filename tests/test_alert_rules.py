"""tests/test_alert_rules.py — alert rule store + webhook fan-out + API."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from squash.alerts import (
    AlertFiring,
    AlertRule,
    AlertStore,
    RISK_RANKS,
    dispatch,
    evaluate,
    reset_store_for_tests,
)


def _isolated_store() -> AlertStore:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return AlertStore(tmp.name)


def _report(overall_risk: str, overall_cov: float, per_fw):
    """Build a duck-typed compliance report."""
    framework_results = {}
    for fw, (cov, gaps) in per_fw.items():
        framework_results[fw] = SimpleNamespace(coverage_pct=cov, gaps=gaps)
    return SimpleNamespace(
        overall_risk=overall_risk,
        overall_coverage_pct=lambda: overall_cov,
        framework_results=framework_results,
    )


# ── store CRUD ────────────────────────────────────────────────────────────────


class TestAlertStoreCRUD(unittest.TestCase):
    def setUp(self):
        self.store = _isolated_store()

    def test_create_and_list(self):
        r1 = self.store.create(
            name="hipaa-watch",
            notify_webhook="https://example.test/h",
            framework="HIPAA",
        )
        r2 = self.store.create(
            name="pci-watch",
            notify_webhook="https://example.test/p",
            framework="PCI_DSS",
        )
        rules = self.store.list()
        self.assertEqual(len(rules), 2)
        ids = {r.id for r in rules}
        self.assertEqual(ids, {r1.id, r2.id})

    def test_create_validates_min_overall_risk(self):
        with self.assertRaises(ValueError):
            self.store.create(
                name="x", notify_webhook="https://e.test/x",
                min_overall_risk="catastrophic",
            )

    def test_create_validates_required_fields(self):
        with self.assertRaises(ValueError):
            self.store.create(name="", notify_webhook="https://e.test/x")
        with self.assertRaises(ValueError):
            self.store.create(name="x", notify_webhook="")

    def test_get_returns_rule(self):
        r = self.store.create(
            name="x", notify_webhook="https://e.test/x",
        )
        fetched = self.store.get(r.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.name, "x")

    def test_delete_soft_deletes(self):
        r = self.store.create(name="x", notify_webhook="https://e.test/x")
        self.assertTrue(self.store.delete(r.id))
        # default list filters active=True → rule no longer visible
        self.assertEqual([x.id for x in self.store.list()], [])
        # but a non-active-only listing should still see it
        self.assertIn(r.id, [x.id for x in self.store.list(active_only=False)])
        self.assertFalse(self.store.delete("nonexistent-id"))


# ── evaluate() semantics ──────────────────────────────────────────────────────


class TestEvaluate(unittest.TestCase):
    def test_fires_when_min_risk_satisfied(self):
        rule = AlertRule(
            id="r1", name="x", framework="HIPAA",
            min_overall_risk="high",
            notify_webhook="https://e.test/x", active=True,
        )
        report = _report("critical", 25.0, {"HIPAA": (20.0, ["G1", "G2"])})
        firings = evaluate(rule, report)
        self.assertEqual(len(firings), 1)
        self.assertEqual(firings[0].framework, "HIPAA")
        self.assertEqual(firings[0].framework_gap_count, 2)

    def test_does_not_fire_below_min_risk(self):
        rule = AlertRule(
            id="r1", name="x", framework="HIPAA",
            min_overall_risk="critical",
            notify_webhook="https://e.test/x", active=True,
        )
        report = _report("medium", 60.0, {"HIPAA": (60.0, [])})
        self.assertEqual(evaluate(rule, report), [])

    def test_wildcard_framework_fires_per_framework(self):
        rule = AlertRule(
            id="r1", name="x", framework="*",
            min_overall_risk="high",
            notify_webhook="https://e.test/x", active=True,
        )
        report = _report("high", 40.0, {
            "SOC2":  (35.0, ["S1"]),
            "HIPAA": (45.0, ["H1"]),
        })
        firings = evaluate(rule, report)
        self.assertEqual(len(firings), 2)
        self.assertEqual({f.framework for f in firings}, {"SOC2", "HIPAA"})

    def test_max_coverage_pct_gates(self):
        rule = AlertRule(
            id="r1", name="x", framework="HIPAA",
            min_overall_risk="medium",
            max_coverage_pct=50.0,
            notify_webhook="https://e.test/x", active=True,
        )
        # Coverage 60% exceeds the ceiling → no fire even though risk satisfies
        rep_high_cov = _report("medium", 60.0, {"HIPAA": (60.0, [])})
        self.assertEqual(evaluate(rule, rep_high_cov), [])
        rep_low_cov = _report("medium", 40.0, {"HIPAA": (40.0, ["G1"])})
        self.assertEqual(len(evaluate(rule, rep_low_cov)), 1)

    def test_inactive_rule_never_fires(self):
        rule = AlertRule(
            id="r1", name="x", framework="HIPAA",
            min_overall_risk="low",
            notify_webhook="https://e.test/x", active=False,
        )
        rep = _report("critical", 5.0, {"HIPAA": (5.0, ["g"])})
        self.assertEqual(evaluate(rule, rep), [])


# ── dispatch() and HMAC signing ───────────────────────────────────────────────


class TestDispatch(unittest.TestCase):
    def _firing(self, secret: str = "topsecret") -> AlertFiring:
        rule = AlertRule(
            id="rule-1", name="x", framework="HIPAA",
            min_overall_risk="high",
            notify_webhook="https://example.test/hook",
            webhook_secret=secret, active=True,
        )
        return AlertFiring(
            rule=rule, report_overall_risk="critical",
            report_overall_coverage_pct=20.0,
            framework="HIPAA", framework_coverage_pct=10.0,
            framework_gap_count=5,
        )

    def test_dispatch_signs_payload_with_hmac(self):
        captured: dict = {}

        def fake(url, *, payload, headers, timeout_s):
            captured["url"] = url
            captured["payload"] = payload
            captured["headers"] = dict(headers)
            return 202, ""

        firing = self._firing()
        result = dispatch(firing, http_call=fake)
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 202)
        self.assertEqual(captured["url"], firing.rule.notify_webhook)

        # Validate the signature header
        sig = captured["headers"].get("X-Squash-Signature")
        self.assertTrue(sig and sig.startswith("sha256="))
        expected = "sha256=" + hmac.new(
            b"topsecret", captured["payload"], hashlib.sha256,
        ).hexdigest()
        self.assertEqual(sig, expected)

    def test_dispatch_no_secret_omits_signature(self):
        captured: dict = {}

        def fake(url, *, payload, headers, timeout_s):
            captured["headers"] = dict(headers)
            return 200, ""

        firing = self._firing(secret="")
        dispatch(firing, http_call=fake)
        self.assertNotIn("X-Squash-Signature", captured["headers"])

    def test_dispatch_non_2xx_marks_failure(self):
        def fake(url, *, payload, headers, timeout_s):
            return 500, "bad gateway"

        result = dispatch(self._firing(), http_call=fake)
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 500)
        self.assertIn("500", result.error)


# ── evaluate_and_dispatch end-to-end ──────────────────────────────────────────


class TestStoreEvaluateAndDispatch(unittest.TestCase):
    def test_walks_active_rules_and_records_fire(self):
        store = _isolated_store()
        r1 = store.create(
            name="hipaa", notify_webhook="https://example.test/h",
            framework="HIPAA", min_overall_risk="high",
        )
        # an inactive (deleted) rule must not fire
        r2 = store.create(
            name="dead", notify_webhook="https://example.test/dead",
            framework="HIPAA", min_overall_risk="high",
        )
        store.delete(r2.id)

        captured = []

        def fake(url, *, payload, headers, timeout_s):
            captured.append(url)
            return 200, ""

        report = _report("critical", 20.0, {"HIPAA": (10.0, ["g"])})
        results = store.evaluate_and_dispatch(report, http_call=fake)
        self.assertEqual(len(results), 1)
        self.assertEqual(captured, ["https://example.test/h"])
        # fire_count incremented on the surviving rule
        self.assertEqual(store.get(r1.id).fire_count, 1)
        self.assertNotEqual(store.get(r1.id).last_fired_at, "")


# ── HTTP route layer ──────────────────────────────────────────────────────────


def _api_client_with_isolated_alerts():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.environ["SQUASH_ALERT_STORE_PATH"] = tmp.name
    # also isolate the trends DB so /api/compliance/scan rows are throwaway
    tmp2 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp2.close()
    os.environ["SQUASH_ANALYSIS_HISTORY_PATH"] = tmp2.name
    reset_store_for_tests(tmp.name)
    from squash.routes import trends as _trends
    _trends.reset_store_for_tests(tmp2.name)

    from fastapi.testclient import TestClient
    from squash.api import app
    return TestClient(app)


class TestAlertsApi(unittest.TestCase):
    def setUp(self):
        self.client = _api_client_with_isolated_alerts()

    def test_create_list_delete_round_trip(self):
        r = self.client.post("/api/alerts", json={
            "name": "hipaa-watch",
            "notify_webhook": "https://example.test/h",
            "framework": "HIPAA", "min_overall_risk": "high",
        })
        self.assertEqual(r.status_code, 200, r.text)
        rid = r.json()["id"]

        r = self.client.get("/api/alerts")
        self.assertEqual(r.json()["count"], 1)
        self.assertEqual(r.json()["rules"][0]["id"], rid)

        r = self.client.get(f"/api/alerts/{rid}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["name"], "hipaa-watch")

        r = self.client.delete(f"/api/alerts/{rid}")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["deleted"])

        # default listing now empty
        r = self.client.get("/api/alerts")
        self.assertEqual(r.json()["count"], 0)

    def test_create_validates_min_overall_risk(self):
        r = self.client.post("/api/alerts", json={
            "name": "x", "notify_webhook": "https://e.test/x",
            "min_overall_risk": "catastrophic",
        })
        self.assertEqual(r.status_code, 422)

    def test_get_unknown_id_returns_404(self):
        r = self.client.get("/api/alerts/does-not-exist")
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
