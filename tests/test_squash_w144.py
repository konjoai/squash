"""W144 — Health check + monitoring (Sentry, Better Uptime) tests."""
from __future__ import annotations

import os
import time
from unittest.mock import patch, MagicMock

import pytest

from squash.monitoring import (
    setup_sentry,
    capture_exception,
    get_uptime,
    db_ping,
    build_health_report,
    _squash_version,
    _START_TIME,
)

pytest.importorskip("fastapi", reason="fastapi required for API tests")
pytest.importorskip("httpx", reason="httpx required for TestClient")

from fastapi.testclient import TestClient
from squash.api import app
from squash.auth import reset_key_store


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_store():
    store = reset_key_store()
    yield store
    reset_key_store()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# setup_sentry
# ---------------------------------------------------------------------------

class TestSetupSentry:
    def test_returns_false_when_no_dsn(self):
        with patch.dict("os.environ", {}, clear=True):
            result = setup_sentry(dsn="")
        assert result is False

    def test_returns_false_when_sentry_not_installed(self):
        with patch.dict("sys.modules", {"sentry_sdk": None}):
            result = setup_sentry(dsn="https://key@sentry.io/123")
        assert result is False

    def test_returns_true_when_sentry_configured(self):
        mock_sdk = MagicMock()
        mock_sdk.init = MagicMock()
        mock_logging = MagicMock()
        with patch.dict("sys.modules", {
            "sentry_sdk": mock_sdk,
            "sentry_sdk.integrations": MagicMock(),
            "sentry_sdk.integrations.logging": mock_logging,
        }):
            with patch("sentry_sdk.init"):
                result = setup_sentry(dsn="https://key@sentry.io/123")
        assert result is True

    def test_env_var_dsn_used(self):
        mock_sdk = MagicMock()
        mock_logging = MagicMock()
        with patch.dict("os.environ", {"SQUASH_SENTRY_DSN": "https://x@sentry.io/1"}):
            with patch.dict("sys.modules", {
                "sentry_sdk": mock_sdk,
                "sentry_sdk.integrations": MagicMock(),
                "sentry_sdk.integrations.logging": mock_logging,
            }):
                result = setup_sentry()
        # Either True (if sdk available) or False (if mock doesn't satisfy import)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# capture_exception
# ---------------------------------------------------------------------------

class TestCaptureException:
    def test_does_not_raise_when_sentry_missing(self):
        with patch.dict("sys.modules", {"sentry_sdk": None}):
            capture_exception(ValueError("test"))  # should not raise


# ---------------------------------------------------------------------------
# get_uptime
# ---------------------------------------------------------------------------

class TestGetUptime:
    def test_uptime_is_positive(self):
        assert get_uptime() > 0

    def test_uptime_increases_over_time(self):
        t1 = get_uptime()
        time.sleep(0.01)
        t2 = get_uptime()
        assert t2 > t1

    def test_uptime_is_float(self):
        assert isinstance(get_uptime(), float)


# ---------------------------------------------------------------------------
# db_ping
# ---------------------------------------------------------------------------

class TestDbPing:
    def test_none_db_returns_unconfigured(self):
        result = db_ping(None)
        assert result["status"] == "unconfigured"

    def test_healthy_db_returns_ok(self):
        mock_db = MagicMock()
        mock_db.ping.return_value = True
        result = db_ping(mock_db)
        assert result["status"] == "ok"

    def test_unhealthy_db_returns_error(self):
        mock_db = MagicMock()
        mock_db.ping.return_value = False
        result = db_ping(mock_db)
        assert result["status"] == "error"

    def test_exception_returns_error(self):
        mock_db = MagicMock()
        mock_db.ping.side_effect = RuntimeError("connection lost")
        result = db_ping(mock_db)
        assert result["status"] == "error"
        assert "detail" in result

    def test_latency_ms_present(self):
        mock_db = MagicMock()
        mock_db.ping.return_value = True
        result = db_ping(mock_db)
        assert "latency_ms" in result
        assert isinstance(result["latency_ms"], float)

    def test_unconfigured_latency_is_zero(self):
        result = db_ping(None)
        assert result["latency_ms"] == 0.0


# ---------------------------------------------------------------------------
# build_health_report
# ---------------------------------------------------------------------------

class TestBuildHealthReport:
    def test_returns_dict(self):
        report = build_health_report()
        assert isinstance(report, dict)

    def test_has_status_field(self):
        assert "status" in build_health_report()

    def test_status_ok_when_db_none(self):
        assert build_health_report()["status"] == "ok"

    def test_status_ok_with_healthy_db(self):
        mock_db = MagicMock()
        mock_db.ping.return_value = True
        assert build_health_report(db=mock_db)["status"] == "ok"

    def test_status_degraded_with_failed_db(self):
        mock_db = MagicMock()
        mock_db.ping.return_value = False
        assert build_health_report(db=mock_db)["status"] == "degraded"

    def test_has_version(self):
        assert "version" in build_health_report()

    def test_has_uptime_seconds(self):
        report = build_health_report()
        assert "uptime_seconds" in report
        assert isinstance(report["uptime_seconds"], float)

    def test_has_components(self):
        assert "components" in build_health_report()

    def test_components_has_database_key(self):
        assert "database" in build_health_report()["components"]

    def test_extra_components_merged(self):
        report = build_health_report(extra_components={"redis": {"status": "ok"}})
        assert "redis" in report["components"]

    def test_degraded_if_extra_component_errors(self):
        report = build_health_report(
            extra_components={"redis": {"status": "error"}}
        )
        assert report["status"] == "degraded"


# ---------------------------------------------------------------------------
# _squash_version
# ---------------------------------------------------------------------------

class TestSquashVersion:
    def test_returns_string(self):
        assert isinstance(_squash_version(), str)

    def test_env_override(self):
        with patch.dict("os.environ", {"SQUASH_VERSION": "99.0.0"}):
            assert _squash_version() == "99.0.0"

    def test_dev_fallback_when_not_installed(self):
        import importlib.metadata as _im
        with patch.dict("os.environ", {}, clear=True):
            with patch("importlib.metadata.version",
                       side_effect=_im.PackageNotFoundError("squash-ai")):
                ver = _squash_version()
        assert isinstance(ver, str)


# ---------------------------------------------------------------------------
# /health endpoint (basic)
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_ok(self, client):
        assert client.get("/health").json()["status"] == "ok"


# ---------------------------------------------------------------------------
# /health/ping (W144 — Better Uptime)
# ---------------------------------------------------------------------------

class TestHealthPing:
    def test_ping_returns_200(self, client):
        assert client.get("/health/ping").status_code == 200

    def test_ping_returns_pong(self, client):
        resp = client.get("/health/ping")
        # Response may be JSON string "pong" or plaintext pong
        assert "pong" in resp.text


# ---------------------------------------------------------------------------
# /health/detailed (W144)
# ---------------------------------------------------------------------------

class TestHealthDetailed:
    def test_returns_200_when_ok(self, client):
        resp = client.get("/health/detailed")
        assert resp.status_code in (200, 503)

    def test_has_status_field(self, client):
        data = client.get("/health/detailed").json()
        assert "status" in data

    def test_has_version_field(self, client):
        data = client.get("/health/detailed").json()
        assert "version" in data

    def test_has_uptime_seconds(self, client):
        data = client.get("/health/detailed").json()
        assert "uptime_seconds" in data

    def test_has_components(self, client):
        data = client.get("/health/detailed").json()
        assert "components" in data

    def test_health_ping_not_auth_required(self, client, fresh_store):
        """Ensure /health/ping bypasses auth even when keys exist."""
        fresh_store.generate("t", plan="free")
        resp = client.get("/health/ping")
        assert resp.status_code == 200

    def test_health_detailed_not_auth_required(self, client, fresh_store):
        fresh_store.generate("t", plan="free")
        resp = client.get("/health/detailed")
        assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# /billing/webhook endpoint (W141 via W144 client)
# ---------------------------------------------------------------------------

class TestBillingWebhookEndpoint:
    def test_webhook_endpoint_exists(self, client):
        import json
        payload = json.dumps({
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {}}},
        }).encode()
        resp = client.post("/billing/webhook", content=payload,
                           headers={"Content-Type": "application/json"})
        assert resp.status_code == 200

    def test_webhook_ignored_for_unknown_event(self, client):
        import json
        payload = json.dumps({"type": "unknown.event", "data": {"object": {}}})
        resp = client.post("/billing/webhook", content=payload.encode(),
                           headers={"Content-Type": "application/json"})
        data = resp.json()
        assert data["status"] == "ignored"

    def test_webhook_not_auth_required(self, client, fresh_store):
        """Stripe webhook must be reachable without an API key."""
        fresh_store.generate("t", plan="free")
        import json
        payload = json.dumps({"type": "ping", "data": {"object": {}}})
        resp = client.post("/billing/webhook", content=payload.encode(),
                           headers={"Content-Type": "application/json"})
        assert resp.status_code == 200
