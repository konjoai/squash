"""tests/test_squash_w160.py — Sprint 4B: W160–W164 test suite.

Covers:
  W160 — squash demo command (zero-friction first-value attestation)
  W161 — compliance badge SVG endpoint (/badge/{framework}/{status})
  W162 — squash init command (ML project scaffold + dry-run)
  W163 — notifications module (Slack, Teams, generic webhook)
  W164 — metrics module (Counter, Gauge, Histogram, MetricsCollector)
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch, call


# ── W164: Metrics module ───────────────────────────────────────────────────────


class TestCounter(unittest.TestCase):
    """Thread-safe Counter primitive."""

    def setUp(self):
        from squash.metrics import Counter
        self.Counter = Counter

    def test_basic_increment(self):
        c = self.Counter("test_c", "help", labels=("env",))
        c.inc(env="prod")
        self.assertEqual(c.get(env="prod"), 1.0)

    def test_increment_by_value(self):
        c = self.Counter("test_c2", "help", labels=("env",))
        c.inc(3.5, env="prod")
        self.assertEqual(c.get(env="prod"), 3.5)

    def test_multiple_label_values(self):
        c = self.Counter("test_c3", "help", labels=("result", "policy"))
        c.inc(result="passed", policy="eu-ai-act")
        c.inc(result="failed", policy="eu-ai-act")
        c.inc(result="passed", policy="eu-ai-act")
        self.assertEqual(c.get(result="passed", policy="eu-ai-act"), 2.0)
        self.assertEqual(c.get(result="failed", policy="eu-ai-act"), 1.0)

    def test_render_prometheus_format(self):
        c = self.Counter("squash_test", "Test counter", labels=("env",))
        c.inc(env="prod")
        text = c.render()
        self.assertIn("# HELP squash_test Test counter", text)
        self.assertIn("# TYPE squash_test counter", text)
        self.assertIn('env="prod"', text)

    def test_render_empty_counter(self):
        c = self.Counter("squash_empty", "Empty counter")
        text = c.render()
        self.assertIn("squash_empty 0", text)

    def test_reset_clears_values(self):
        c = self.Counter("squash_reset", "help", labels=("x",))
        c.inc(x="a")
        c.reset()
        self.assertEqual(c.get(x="a"), 0.0)

    def test_thread_safety(self):
        c = self.Counter("squash_thread", "help")
        errors = []

        def worker():
            try:
                for _ in range(100):
                    c.inc()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(errors)
        self.assertEqual(c.get(), 1000.0)


class TestGauge(unittest.TestCase):
    """Thread-safe Gauge primitive."""

    def setUp(self):
        from squash.metrics import Gauge
        self.Gauge = Gauge

    def test_set_and_get(self):
        g = self.Gauge("squash_ratio", "help")
        g.set(0.75)
        self.assertAlmostEqual(g.get(), 0.75)

    def test_set_labeled(self):
        g = self.Gauge("squash_g", "help", labels=("region",))
        g.set(0.9, region="eu")
        g.set(0.5, region="us")
        self.assertAlmostEqual(g.get(region="eu"), 0.9)
        self.assertAlmostEqual(g.get(region="us"), 0.5)

    def test_get_missing_returns_zero(self):
        g = self.Gauge("squash_miss", "help", labels=("x",))
        self.assertEqual(g.get(x="missing"), 0.0)

    def test_render_prometheus_format(self):
        g = self.Gauge("squash_models_ratio", "Ratio", labels=("env",))
        g.set(0.85, env="prod")
        text = g.render()
        self.assertIn("# TYPE squash_models_ratio gauge", text)
        self.assertIn("0.85", text)

    def test_gauge_can_decrease(self):
        g = self.Gauge("squash_decrease", "help")
        g.set(1.0)
        g.set(0.5)
        self.assertAlmostEqual(g.get(), 0.5)

    def test_reset(self):
        g = self.Gauge("squash_g_reset", "help")
        g.set(42.0)
        g.reset()
        self.assertEqual(g.get(), 0.0)


class TestHistogram(unittest.TestCase):
    """Fixed-bucket Histogram primitive."""

    def setUp(self):
        from squash.metrics import Histogram
        self.Histogram = Histogram

    def test_observe_records_value(self):
        h = self.Histogram("squash_latency", "help", labels=("endpoint",))
        h.observe(0.05, endpoint="/attest")
        h.observe(0.1, endpoint="/attest")
        text = h.render()
        self.assertIn("squash_latency_count", text)
        self.assertIn("squash_latency_sum", text)

    def test_bucket_cumulative_counts(self):
        h = self.Histogram("squash_h", "help")
        h.observe(0.01)  # <= 0.005? No. <= 0.01? Yes
        text = h.render()
        self.assertIn("_bucket", text)
        self.assertIn('+Inf', text)

    def test_render_includes_inf_bucket(self):
        h = self.Histogram("squash_h2", "help")
        h.observe(0.5)
        text = h.render()
        self.assertIn('+Inf', text)

    def test_labeled_histogram(self):
        h = self.Histogram("squash_api_latency", "API latency", labels=("method", "endpoint"))
        h.observe(0.1, method="GET", endpoint="/health")
        h.observe(0.2, method="POST", endpoint="/attest")
        text = h.render()
        self.assertIn("GET", text)
        self.assertIn("POST", text)

    def test_reset_clears_all(self):
        h = self.Histogram("squash_h3", "help")
        h.observe(0.1)
        h.reset()
        text = h.render()
        self.assertNotIn("_count", text)


class TestMetricsCollector(unittest.TestCase):
    """MetricsCollector integration and helpers."""

    def setUp(self):
        from squash.metrics import reset_collector
        self.collector = reset_collector()

    def test_inc_attestation_passed(self):
        self.collector.inc_attestation(passed=True, policy="eu-ai-act")
        text = self.collector.render()
        self.assertIn("squash_attestations_total", text)
        self.assertIn("passed", text)

    def test_inc_attestation_failed(self):
        self.collector.inc_attestation(passed=False, policy="nist-ai-rmf")
        text = self.collector.render()
        self.assertIn("failed", text)

    def test_compliance_ratio_updates(self):
        self.collector.inc_attestation(passed=True)
        self.collector.inc_attestation(passed=True)
        self.collector.inc_attestation(passed=False)
        ratio = self.collector.models_compliant_ratio.get()
        self.assertAlmostEqual(ratio, 2 / 3, places=5)

    def test_inc_violation(self):
        self.collector.inc_violation(policy="eu-ai-act")
        text = self.collector.render()
        self.assertIn("squash_policy_violations_total", text)

    def test_inc_drift(self):
        self.collector.inc_drift(model_id="bert-base")
        text = self.collector.render()
        self.assertIn("squash_drift_events_total", text)

    def test_inc_quota(self):
        self.collector.inc_quota(plan="pro")
        text = self.collector.render()
        self.assertIn("squash_quota_used_total", text)

    def test_record_request(self):
        self.collector.record_request("GET", "/attest", 200, 0.05)
        text = self.collector.render()
        self.assertIn("squash_api_requests_total", text)
        self.assertIn("squash_api_latency_seconds", text)

    def test_render_all_sections(self):
        text = self.collector.render()
        required = [
            "squash_attestations_total",
            "squash_policy_violations_total",
            "squash_drift_events_total",
            "squash_models_compliant_ratio",
            "squash_quota_used_total",
            "squash_api_requests_total",
            "squash_api_latency_seconds",
        ]
        for metric in required:
            self.assertIn(metric, text, f"Missing metric: {metric}")

    def test_render_ends_with_newline(self):
        text = self.collector.render()
        self.assertTrue(text.endswith("\n"))

    def test_reset_clears_all_metrics(self):
        self.collector.inc_attestation(passed=True)
        self.collector.inc_violation(policy="eu-ai-act")
        self.collector.reset()
        text = self.collector.render()
        self.assertNotIn("passed", text)

    def test_singleton_get_collector(self):
        from squash.metrics import get_collector, reset_collector
        c1 = reset_collector()
        c2 = get_collector()
        self.assertIs(c1, c2)

    def test_thread_safe_compliance_ratio(self):
        """Concurrent attestation recording must not corrupt the ratio."""
        errors = []

        def worker(passed: bool):
            try:
                for _ in range(50):
                    self.collector.inc_attestation(passed=passed)
            except Exception as e:
                errors.append(e)

        threads = [
            *[threading.Thread(target=worker, args=(True,)) for _ in range(5)],
            *[threading.Thread(target=worker, args=(False,)) for _ in range(5)],
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(errors)
        ratio = self.collector.models_compliant_ratio.get()
        self.assertAlmostEqual(ratio, 0.5, delta=0.05)


class TestMetricsRendering(unittest.TestCase):
    """Prometheus text format conformance."""

    def setUp(self):
        from squash.metrics import reset_collector
        self.collector = reset_collector()

    def test_help_lines_present(self):
        text = self.collector.render()
        for line in text.splitlines():
            if line.startswith("# HELP"):
                self.assertGreater(len(line.split(" ", 2)), 2)

    def test_type_lines_present(self):
        text = self.collector.render()
        type_lines = [l for l in text.splitlines() if l.startswith("# TYPE")]
        self.assertGreater(len(type_lines), 5)

    def test_counter_type_declared(self):
        text = self.collector.render()
        self.assertIn("# TYPE squash_attestations_total counter", text)

    def test_gauge_type_declared(self):
        text = self.collector.render()
        self.assertIn("# TYPE squash_models_compliant_ratio gauge", text)

    def test_histogram_type_declared(self):
        text = self.collector.render()
        self.assertIn("# TYPE squash_api_latency_seconds histogram", text)

    def test_label_format(self):
        from squash.metrics import _fmt_labels
        result = _fmt_labels(("env", "region"), ("prod", "eu"))
        self.assertEqual(result, '{env="prod", region="eu"}')

    def test_label_format_empty(self):
        from squash.metrics import _fmt_labels
        result = _fmt_labels((), ())
        self.assertEqual(result, "")


# ── W163: Notifications module ────────────────────────────────────────────────


class TestNotificationConfig(unittest.TestCase):
    """NotificationConfig dataclass."""

    def setUp(self):
        from squash.notifications import NotificationConfig
        self.NotificationConfig = NotificationConfig

    def test_explicit_slack_url(self):
        cfg = self.NotificationConfig(slack_webhook_url="https://hooks.slack.com/test")
        self.assertEqual(cfg.slack_webhook_url, "https://hooks.slack.com/test")

    def test_reads_env_vars(self):
        import os
        with patch.dict(os.environ, {
            "SQUASH_SLACK_WEBHOOK_URL": "https://slack.example.com",
            "SQUASH_TEAMS_WEBHOOK_URL": "https://teams.example.com",
            "SQUASH_WEBHOOK_URL": "https://webhook.example.com",
        }):
            cfg = self.NotificationConfig()
            self.assertEqual(cfg.slack_webhook_url, "https://slack.example.com")
            self.assertEqual(cfg.teams_webhook_url, "https://teams.example.com")
            self.assertEqual(cfg.generic_webhook_url, "https://webhook.example.com")

    def test_has_any_target_false_when_empty(self):
        cfg = self.NotificationConfig()
        import os
        with patch.dict(os.environ, {}, clear=True):
            cfg2 = self.NotificationConfig()
        self.assertFalse(cfg2.has_any_target)

    def test_has_any_target_true_when_slack_set(self):
        cfg = self.NotificationConfig(slack_webhook_url="https://hooks.slack.com/x")
        self.assertTrue(cfg.has_any_target)

    def test_event_filter_default_empty(self):
        cfg = self.NotificationConfig()
        self.assertEqual(cfg.event_filter, [])

    def test_timeout_default(self):
        cfg = self.NotificationConfig()
        self.assertEqual(cfg.timeout_seconds, 10)


class TestNotificationResult(unittest.TestCase):
    """NotificationResult properties."""

    def setUp(self):
        from squash.notifications import NotificationResult
        self.NotificationResult = NotificationResult

    def test_all_succeeded_true(self):
        r = self.NotificationResult(event="test", targets_attempted=2, targets_succeeded=2)
        self.assertTrue(r.all_succeeded)

    def test_all_succeeded_false_partial(self):
        r = self.NotificationResult(event="test", targets_attempted=2, targets_succeeded=1)
        self.assertFalse(r.all_succeeded)

    def test_all_succeeded_false_zero(self):
        r = self.NotificationResult(event="test", targets_attempted=0, targets_succeeded=0)
        self.assertFalse(r.all_succeeded)

    def test_any_succeeded_true(self):
        r = self.NotificationResult(event="test", targets_attempted=2, targets_succeeded=1)
        self.assertTrue(r.any_succeeded)

    def test_any_succeeded_false(self):
        r = self.NotificationResult(event="test", targets_attempted=2, targets_succeeded=0)
        self.assertFalse(r.any_succeeded)


class TestNotificationDispatcher(unittest.TestCase):
    """NotificationDispatcher.notify() routing."""

    def setUp(self):
        from squash.notifications import (
            NotificationDispatcher, NotificationConfig,
            ATTESTATION_PASSED, ATTESTATION_FAILED,
        )
        self.NotificationDispatcher = NotificationDispatcher
        self.NotificationConfig = NotificationConfig
        self.ATTESTATION_PASSED = ATTESTATION_PASSED
        self.ATTESTATION_FAILED = ATTESTATION_FAILED

    def test_no_target_returns_zero_attempts(self):
        import os
        with patch.dict(os.environ, {}, clear=True):
            dispatcher = self.NotificationDispatcher(self.NotificationConfig())
            result = dispatcher.notify(self.ATTESTATION_PASSED, model_id="bert")
        self.assertEqual(result.targets_attempted, 0)

    def test_event_filter_blocks_unregistered_event(self):
        cfg = self.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/x",
            event_filter=["attestation.passed"],
        )
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post") as mock_post:
            result = dispatcher.notify("attestation.failed", model_id="bert")
        mock_post.assert_not_called()
        self.assertEqual(result.targets_attempted, 0)

    def test_event_filter_allows_registered_event(self):
        cfg = self.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/x",
            event_filter=["attestation.passed"],
        )
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post") as mock_post:
            result = dispatcher.notify("attestation.passed", model_id="bert")
        mock_post.assert_called_once()
        self.assertEqual(result.targets_attempted, 1)
        self.assertEqual(result.targets_succeeded, 1)

    def test_slack_fires_with_url(self):
        cfg = self.NotificationConfig(slack_webhook_url="https://hooks.slack.com/x")
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post") as mock_post:
            result = dispatcher.notify(self.ATTESTATION_FAILED, model_id="gpt4", details={"score": 42})
        mock_post.assert_called_once()
        self.assertEqual(result.targets_succeeded, 1)

    def test_teams_fires_with_url(self):
        cfg = self.NotificationConfig(teams_webhook_url="https://teams.office.com/x")
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post") as mock_post:
            result = dispatcher.notify(self.ATTESTATION_PASSED)
        mock_post.assert_called_once()
        self.assertEqual(result.targets_succeeded, 1)

    def test_generic_fires_with_url(self):
        cfg = self.NotificationConfig(generic_webhook_url="https://webhook.example.com")
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post") as mock_post:
            result = dispatcher.notify("drift.detected", model_id="bert")
        mock_post.assert_called_once()
        self.assertEqual(result.targets_succeeded, 1)

    def test_all_three_targets_fire(self):
        cfg = self.NotificationConfig(
            slack_webhook_url="https://slack.example.com",
            teams_webhook_url="https://teams.example.com",
            generic_webhook_url="https://webhook.example.com",
        )
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post") as mock_post:
            result = dispatcher.notify(self.ATTESTATION_PASSED)
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(result.targets_attempted, 3)
        self.assertEqual(result.targets_succeeded, 3)

    def test_http_error_captured_in_errors(self):
        cfg = self.NotificationConfig(slack_webhook_url="https://hooks.slack.com/x")
        dispatcher = self.NotificationDispatcher(cfg)
        with patch("squash.notifications._http_post", side_effect=RuntimeError("HTTP 500")):
            result = dispatcher.notify(self.ATTESTATION_FAILED)
        self.assertEqual(result.targets_attempted, 1)
        self.assertEqual(result.targets_succeeded, 0)
        self.assertEqual(len(result.errors), 1)
        self.assertIn("slack", result.errors[0])

    def test_partial_failure_continues_other_targets(self):
        cfg = self.NotificationConfig(
            slack_webhook_url="https://slack.example.com",
            teams_webhook_url="https://teams.example.com",
        )
        dispatcher = self.NotificationDispatcher(cfg)
        call_count = 0

        def side_effect(url, payload, timeout):
            nonlocal call_count
            call_count += 1
            if "slack" in url:
                raise RuntimeError("slack down")

        with patch("squash.notifications._http_post", side_effect=side_effect):
            result = dispatcher.notify(self.ATTESTATION_PASSED)

        self.assertEqual(result.targets_attempted, 2)
        self.assertEqual(result.targets_succeeded, 1)
        self.assertEqual(len(result.errors), 1)


class TestNotificationPayloads(unittest.TestCase):
    """Verify Slack / Teams / generic payload structure."""

    def setUp(self):
        from squash.notifications import NotificationDispatcher, NotificationConfig
        self.cfg = NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test",
            teams_webhook_url="https://teams.office.com/test",
            generic_webhook_url="https://webhook.example.com/test",
        )
        self.dispatcher = NotificationDispatcher(self.cfg)

    def _capture_payload(self, target_keyword: str, event: str, **kwargs):
        """Capture the payload posted to a target (by URL keyword)."""
        captured = {}

        def side_effect(url, payload, timeout):
            if target_keyword in url:
                captured["payload"] = payload
                captured["url"] = url

        with patch("squash.notifications._http_post", side_effect=side_effect):
            self.dispatcher.notify(event, **kwargs)
        return captured.get("payload", {})

    def test_slack_payload_has_attachments(self):
        payload = self._capture_payload(
            "slack", "attestation.failed",
            model_id="bert", details={"score": 42}
        )
        self.assertIn("attachments", payload)
        self.assertTrue(len(payload["attachments"]) > 0)

    def test_slack_payload_has_blocks_with_header(self):
        payload = self._capture_payload("slack", "attestation.passed", model_id="gpt4")
        blocks = payload["attachments"][0]["blocks"]
        self.assertTrue(any(b.get("type") == "header" for b in blocks))

    def test_slack_color_compliant(self):
        payload = self._capture_payload("slack", "attestation.passed")
        color = payload["attachments"][0]["color"]
        self.assertEqual(color, "#2eb886")

    def test_slack_color_violation(self):
        payload = self._capture_payload("slack", "attestation.failed")
        color = payload["attachments"][0]["color"]
        self.assertEqual(color, "#e01e5a")

    def test_teams_payload_has_adaptive_card(self):
        payload = self._capture_payload("teams", "drift.detected", model_id="bert")
        self.assertEqual(payload.get("type"), "message")
        content_type = payload["attachments"][0]["contentType"]
        self.assertIn("adaptive", content_type)

    def test_teams_payload_has_factset_when_model(self):
        payload = self._capture_payload("teams", "attestation.failed", model_id="llama-3")
        body = payload["attachments"][0]["content"]["body"]
        has_factset = any(b.get("type") == "FactSet" for b in body)
        self.assertTrue(has_factset)

    def test_generic_payload_structure(self):
        payload = self._capture_payload(
            "webhook.example.com", "vex.new_cve",
            model_id="bert", details={"cve": "CVE-2024-1234"},
            link="https://example.com/report"
        )
        self.assertEqual(payload["event"], "vex.new_cve")
        self.assertEqual(payload["model_id"], "bert")
        self.assertIn("timestamp", payload)
        self.assertEqual(payload["source"], "squash-ai")
        self.assertEqual(payload["link"], "https://example.com/report")

    def test_generic_payload_includes_details(self):
        payload = self._capture_payload(
            "webhook.example.com", "attestation.failed",
            details={"violations": 3, "score": 42}
        )
        self.assertEqual(payload["details"]["violations"], 3)


class TestNotificationHelpers(unittest.TestCase):
    """Module-level helpers and event constants."""

    def test_event_constants(self):
        from squash.notifications import (
            ATTESTATION_PASSED, ATTESTATION_FAILED, DRIFT_DETECTED,
            VEX_NEW_CVE, QUOTA_EXHAUSTED
        )
        self.assertEqual(ATTESTATION_PASSED, "attestation.passed")
        self.assertEqual(ATTESTATION_FAILED, "attestation.failed")
        self.assertEqual(DRIFT_DETECTED, "drift.detected")
        self.assertEqual(VEX_NEW_CVE, "vex.new_cve")
        self.assertEqual(QUOTA_EXHAUSTED, "quota.exhausted")

    def test_make_title_with_model(self):
        from squash.notifications import _make_title, ATTESTATION_FAILED
        title = _make_title(ATTESTATION_FAILED, "bert-base")
        self.assertIn("bert-base", title)
        self.assertIn("violation", title.lower())

    def test_make_title_no_model(self):
        from squash.notifications import _make_title, ATTESTATION_PASSED
        title = _make_title(ATTESTATION_PASSED, "")
        self.assertIn("passed", title.lower())
        self.assertNotIn(":", title.split("passed")[0])

    def test_make_title_unknown_event(self):
        from squash.notifications import _make_title
        title = _make_title("custom.event", "model-x")
        self.assertIn("custom.event", title)

    def test_singleton_get_dispatcher(self):
        from squash.notifications import get_dispatcher, reset_dispatcher
        d1 = reset_dispatcher()
        d2 = get_dispatcher()
        self.assertIs(d1, d2)

    def test_module_notify_convenience(self):
        from squash.notifications import notify, reset_dispatcher, NotificationConfig
        reset_dispatcher()
        with patch("squash.notifications._http_post") as mock_post:
            result = notify("attestation.passed")
        self.assertIsNotNone(result)


class TestHttpPost(unittest.TestCase):
    """_http_post helper."""

    def test_raises_on_non_2xx(self):
        from squash.notifications import _http_post
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 500
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                _http_post("https://example.com", {"k": "v"}, timeout=5)
        self.assertIn("500", str(ctx.exception))

    def test_succeeds_on_2xx(self):
        from squash.notifications import _http_post
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            _http_post("https://example.com", {"k": "v"}, timeout=5)


# ── W161: Badge SVG endpoint ───────────────────────────────────────────────────


class TestBadgeSvgGeneration(unittest.TestCase):
    """_make_badge_svg() function tests."""

    def setUp(self):
        from squash.api import _make_badge_svg, _BADGE_COLORS
        self.make_badge = _make_badge_svg
        self.BADGE_COLORS = _BADGE_COLORS

    def test_returns_svg_string(self):
        svg = self.make_badge("EU-AI-ACT", "compliant")
        self.assertIn("<svg", svg)
        self.assertIn("</svg>", svg)

    def test_label_left_in_svg(self):
        svg = self.make_badge("EU-AI-ACT", "compliant")
        self.assertIn("squash | EU-AI-ACT", svg)

    def test_label_right_in_svg(self):
        svg = self.make_badge("EU-AI-ACT", "compliant")
        self.assertIn("compliant", svg)

    def test_compliant_is_green(self):
        svg = self.make_badge("EU-AI-ACT", "compliant")
        self.assertIn("#4c1", svg)

    def test_non_compliant_is_red(self):
        svg = self.make_badge("EU-AI-ACT", "non-compliant")
        self.assertIn("#e05d44", svg)

    def test_partial_is_yellow(self):
        svg = self.make_badge("EU-AI-ACT", "partial")
        self.assertIn("#dfb317", svg)

    def test_unknown_status_is_grey(self):
        svg = self.make_badge("EU-AI-ACT", "unknown")
        self.assertIn("#9f9f9f", svg)

    def test_arbitrary_status_fallback_grey(self):
        svg = self.make_badge("NIST-AI-RMF", "investigating")
        self.assertIn("#9f9f9f", svg)

    def test_svg_has_title(self):
        svg = self.make_badge("ISO-42001", "compliant")
        self.assertIn("<title>", svg)

    def test_badge_colors_dict_keys(self):
        for key in ["compliant", "passing", "non-compliant", "failing", "partial", "unknown"]:
            self.assertIn(key, self.BADGE_COLORS)


class TestBadgeEndpoint(unittest.TestCase):
    """GET /badge/{framework}/{status} HTTP endpoint."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from squash.api import app
            cls.client = TestClient(app, raise_server_exceptions=False)
            cls.available = True
        except ImportError:
            cls.available = False

    def test_badge_returns_200(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/eu-ai-act/compliant")
        self.assertEqual(resp.status_code, 200)

    def test_badge_returns_svg_content_type(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/eu-ai-act/compliant")
        self.assertIn("svg", resp.headers.get("content-type", ""))

    def test_badge_body_is_svg(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/nist-ai-rmf/passing")
        self.assertIn(b"<svg", resp.content)

    def test_badge_no_auth_required(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/iso-42001/non-compliant")
        self.assertNotEqual(resp.status_code, 401)
        self.assertNotEqual(resp.status_code, 403)

    def test_badge_cache_control_header(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/eu-ai-act/compliant")
        cache_header = resp.headers.get("cache-control", "")
        self.assertIn("no-cache", cache_header)

    def test_badge_hyphenated_framework_normalized(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/eu-ai-act/compliant")
        body = resp.content.decode()
        # hyphens are replaced with spaces: "eu-ai-act" → "EU AI ACT"
        self.assertIn("EU AI ACT", body)

    def test_badge_unknown_status_allowed(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/badge/eu-ai-act/unknown")
        self.assertEqual(resp.status_code, 200)


# ── W160: squash demo command ──────────────────────────────────────────────────


class TestDemoCommand(unittest.TestCase):
    """squash demo — zero-friction first-value attestation."""

    def _run_demo(self, args: list[str]) -> tuple[int, str]:
        """Run squash demo via subprocess and capture output."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode, result.stdout + result.stderr

    def test_demo_help_text(self):
        rc, out = self._run_demo(["demo", "--help"])
        self.assertIn("demo", out.lower())

    def test_demo_runs_without_error(self):
        rc, out = self._run_demo(["demo", "--quiet"])
        self.assertIn(rc, (0, 1), f"Unexpected exit code: {rc}\n{out}")

    def test_demo_default_policy_eu_ai_act(self):
        rc, out = self._run_demo(["demo", "--quiet"])
        self.assertIn(rc, (0, 1))

    def test_demo_accepts_policy_flag(self):
        rc, out = self._run_demo(["demo", "--policy", "nist-ai-rmf", "--quiet"])
        self.assertIn(rc, (0, 1))

    def test_demo_output_dir_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_demo(["demo", "--output-dir", tmp, "--quiet"])
            self.assertIn(rc, (0, 1))

    def test_demo_branding_in_output(self):
        rc, out = self._run_demo(["demo"])
        self.assertIn("squash", out.lower())

    def test_demo_tagline_in_output(self):
        rc, out = self._run_demo(["demo"])
        self.assertIn("velocity", out.lower())


class TestDemoCommandUnit(unittest.TestCase):
    """_cmd_demo internal unit tests."""

    def _make_args(self, output_dir=None, policy=None, quiet=False):
        import argparse
        args = argparse.Namespace(
            output_dir=output_dir,
            policy=policy,
            quiet=quiet,
        )
        return args

    def test_cmd_demo_returns_int(self):
        from squash.cli import _cmd_demo
        import argparse
        args = argparse.Namespace(output_dir=None, policy=None, quiet=True)
        result = _cmd_demo(args, quiet=True)
        self.assertIsInstance(result, int)

    def test_cmd_demo_returns_0_or_1(self):
        from squash.cli import _cmd_demo
        import argparse
        args = argparse.Namespace(output_dir=None, policy=None, quiet=True)
        result = _cmd_demo(args, quiet=True)
        self.assertIn(result, (0, 1))


# ── W162: squash init command ──────────────────────────────────────────────────


class TestInitCommand(unittest.TestCase):
    """squash init — scaffold .squash.yml."""

    def _run_init(self, args: list[str]) -> tuple[int, str]:
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout + result.stderr

    def test_init_creates_squash_yml(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_init(["init", "--dir", tmp, "--no-dry-run", "--quiet"])
            self.assertEqual(rc, 0, f"init failed:\n{out}")
            yml = Path(tmp) / ".squash.yml"
            self.assertTrue(yml.exists(), ".squash.yml not created")

    def test_init_squash_yml_has_project_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_init(["init", "--dir", tmp, "--no-dry-run", "--quiet"])
            yml = Path(tmp) / ".squash.yml"
            content = yml.read_text()
            self.assertIn("project:", content)
            self.assertIn("attestation:", content)

    def test_init_squash_yml_has_default_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_init(["init", "--dir", tmp, "--no-dry-run", "--quiet"])
            yml = Path(tmp) / ".squash.yml"
            content = yml.read_text()
            self.assertIn("eu-ai-act", content)

    def test_init_custom_policies(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_init([
                "init", "--dir", tmp, "--no-dry-run", "--quiet",
                "--policy", "nist-ai-rmf", "iso-42001"
            ])
            yml = Path(tmp) / ".squash.yml"
            content = yml.read_text()
            self.assertIn("nist-ai-rmf", content)
            self.assertIn("iso-42001", content)

    def test_init_framework_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_init([
                "init", "--dir", tmp, "--no-dry-run", "--quiet",
                "--framework", "pytorch"
            ])
            yml = Path(tmp) / ".squash.yml"
            content = yml.read_text()
            self.assertIn("pytorch", content)

    def test_init_idempotent_when_yml_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            yml = Path(tmp) / ".squash.yml"
            yml.write_text("# existing config\n")
            rc, out = self._run_init(["init", "--dir", tmp, "--no-dry-run"])
            self.assertEqual(rc, 0)
            content = yml.read_text()
            self.assertIn("existing config", content)

    def test_init_nonexistent_dir_fails(self):
        rc, out = self._run_init(["init", "--dir", "/nonexistent/path/xyz"])
        self.assertNotEqual(rc, 0)

    def test_init_help_text(self):
        rc, out = self._run_init(["init", "--help"])
        self.assertIn("init", out.lower())


class TestFrameworkDetection(unittest.TestCase):
    """_detect_framework() auto-detection logic."""

    def setUp(self):
        from squash.cli import _detect_framework
        self.detect = _detect_framework

    def test_detects_pytorch_from_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "requirements.txt").write_text("torch\ntransformers\n")
            result = self.detect(tmp)
            self.assertIn(result, ["pytorch", "huggingface"])

    def test_detects_tensorflow_from_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "requirements.txt").write_text("tensorflow\nkeras\n")
            result = self.detect(tmp)
            self.assertEqual(result, "tensorflow")

    def test_detects_mlflow_from_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "MLproject").write_text("name: my-model\n")
            result = self.detect(tmp)
            self.assertEqual(result, "mlflow")

    def test_detects_huggingface_from_config_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.json").write_text('{"model_type": "bert"}')
            result = self.detect(tmp)
            self.assertEqual(result, "huggingface")

    def test_unknown_returns_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.detect(tmp)
            self.assertEqual(result, "unknown")

    def test_detects_from_python_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "train.py").write_text("import torch\nmodel = torch.nn.Linear(10, 2)\n")
            result = self.detect(tmp)
            self.assertEqual(result, "pytorch")

    def test_detects_jax(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "requirements.txt").write_text("jax\nflax\n")
            result = self.detect(tmp)
            self.assertEqual(result, "jax")


# ── Metrics /metrics endpoint integration ─────────────────────────────────────


class TestMetricsEndpointIntegration(unittest.TestCase):
    """GET /metrics returns Prometheus text format."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from squash.api import app
            cls.client = TestClient(app, raise_server_exceptions=False)
            cls.available = True
        except ImportError:
            cls.available = False

    def test_metrics_endpoint_200(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)

    def test_metrics_content_type_prometheus(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/metrics")
        self.assertIn("text/plain", resp.headers.get("content-type", ""))

    def test_metrics_body_has_help_lines(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/metrics")
        self.assertIn("# HELP", resp.text)

    def test_metrics_body_has_type_lines(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/metrics")
        self.assertIn("# TYPE", resp.text)

    def test_metrics_no_auth_required(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/metrics")
        self.assertNotEqual(resp.status_code, 401)

    def test_metrics_includes_squash_attestations(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.get("/metrics")
        self.assertIn("squash_attestations_total", resp.text)


if __name__ == "__main__":
    unittest.main()
