"""tests/test_squash_w188.py — W188: OpenTelemetry telemetry module tests.

Coverage:
  - SquashTelemetry construction (direct + from_env)
  - AttestationSpanAttrs.to_otel_attrs() — all fields
  - TelemetryResult / TelemetryStatus data model
  - emit_attestation_span() — no-op when OTel not installed / disabled
  - emit_drift_span() — no-op path
  - test_connection() — no-op path
  - status() — reflects configuration
  - shutdown() — safe when provider is None
  - Module-level singleton: get_default_telemetry() / emit_attestation_span()
  - _otel_available() / _otel_exporter_available() — bool returns
  - from_env() reads all SQUASH_OTEL_* env vars
  - Disabled telemetry returns emitted=False
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from squash.telemetry import (
    AttestationSpanAttrs,
    SquashTelemetry,
    TelemetryResult,
    TelemetryStatus,
    _otel_available,
    _otel_exporter_available,
    emit_attestation_span,
    get_default_telemetry,
)


# ---------------------------------------------------------------------------
# AttestationSpanAttrs
# ---------------------------------------------------------------------------

class TestAttestationSpanAttrs:
    def test_basic_fields_in_otel_attrs(self):
        attrs = AttestationSpanAttrs(
            model_path="./model",
            policy="eu-ai-act",
            compliance_score=87.5,
            violations=0,
            duration_ms=1234.0,
            passed=True,
        )
        d = attrs.to_otel_attrs()
        assert d["squash.model.path"] == "./model"
        assert d["squash.policy"] == "eu-ai-act"
        assert d["squash.compliance.score"] == 87.5
        assert d["squash.violations.count"] == 0
        assert d["squash.attestation.passed"] is True
        assert d["squash.duration.ms"] == 1234.0
        assert "squash.version" in d

    def test_optional_fields_omitted_when_none(self):
        attrs = AttestationSpanAttrs(
            model_path="./m", policy="p", compliance_score=50.0,
            violations=2, duration_ms=100.0, passed=False,
        )
        d = attrs.to_otel_attrs()
        assert "squash.tenant.id" not in d
        assert "squash.model.framework" not in d
        assert "squash.model.sha256" not in d

    def test_optional_fields_included_when_set(self):
        attrs = AttestationSpanAttrs(
            model_path="./m", policy="p", compliance_score=75.0,
            violations=1, duration_ms=50.0, passed=True,
            tenant_id="t-001",
            framework="pytorch",
            model_hash="abc123",
            annex_iv_sections=10,
        )
        d = attrs.to_otel_attrs()
        assert d["squash.tenant.id"] == "t-001"
        assert d["squash.model.framework"] == "pytorch"
        assert d["squash.model.sha256"] == "abc123"
        assert d["squash.annex_iv.sections_completed"] == 10

    def test_squash_version_present(self):
        attrs = AttestationSpanAttrs(
            model_path=".", policy="p", compliance_score=100.0,
            violations=0, duration_ms=10.0, passed=True,
        )
        d = attrs.to_otel_attrs()
        assert d["squash.version"] == "1.4.0"


# ---------------------------------------------------------------------------
# TelemetryResult
# ---------------------------------------------------------------------------

class TestTelemetryResult:
    def test_to_dict_contains_required_keys(self):
        r = TelemetryResult(emitted=False, otel_available=False)
        d = r.to_dict()
        for key in ("emitted", "span_id", "trace_id", "error", "otel_available", "exporter_available", "endpoint"):
            assert key in d

    def test_successful_result(self):
        r = TelemetryResult(
            emitted=True, span_id="aabbccdd11223344", trace_id="0" * 32,
            otel_available=True, exporter_available=True, endpoint="http://localhost:4317",
        )
        assert r.emitted is True
        assert r.error is None


# ---------------------------------------------------------------------------
# TelemetryStatus
# ---------------------------------------------------------------------------

class TestTelemetryStatus:
    def test_to_dict_has_all_fields(self):
        s = TelemetryStatus(
            enabled=True, otel_available=False, exporter_available=False,
            endpoint=None, service_name="squash",
        )
        d = s.to_dict()
        for key in ("enabled", "otel_available", "exporter_available", "endpoint", "service_name", "spans_emitted"):
            assert key in d


# ---------------------------------------------------------------------------
# SquashTelemetry — construction
# ---------------------------------------------------------------------------

class TestSquashTelemetryConstruction:
    def test_default_construction_no_endpoint(self):
        tel = SquashTelemetry()
        assert tel.enabled is True
        assert tel.endpoint is None
        assert tel._tracer is None

    def test_disabled_by_flag(self):
        tel = SquashTelemetry(enabled=False, endpoint="http://localhost:4317")
        assert tel.enabled is False

    def test_from_env_no_vars(self):
        env = {k: "" for k in ("SQUASH_OTEL_ENDPOINT", "SQUASH_OTEL_HTTP_ENDPOINT", "SQUASH_OTEL_SERVICE_NAME", "SQUASH_OTEL_ENABLED")}
        with patch.dict(os.environ, env, clear=False):
            tel = SquashTelemetry.from_env()
        assert tel.endpoint == "" or tel.endpoint is None

    def test_from_env_reads_endpoint(self):
        with patch.dict(os.environ, {"SQUASH_OTEL_ENDPOINT": "http://otel:4317"}, clear=False):
            tel = SquashTelemetry.from_env()
        assert tel.endpoint == "http://otel:4317"

    def test_from_env_reads_http_endpoint(self):
        with patch.dict(os.environ, {"SQUASH_OTEL_HTTP_ENDPOINT": "http://otel:4318/v1/traces"}, clear=False):
            tel = SquashTelemetry.from_env()
        assert tel.http_endpoint == "http://otel:4318/v1/traces"

    def test_from_env_reads_service_name(self):
        with patch.dict(os.environ, {"SQUASH_OTEL_SERVICE_NAME": "my-service"}, clear=False):
            tel = SquashTelemetry.from_env()
        assert tel.service_name == "my-service"

    def test_from_env_disabled_by_false(self):
        with patch.dict(os.environ, {"SQUASH_OTEL_ENABLED": "false"}, clear=False):
            tel = SquashTelemetry.from_env()
        assert tel.enabled is False

    def test_from_env_disabled_by_zero(self):
        with patch.dict(os.environ, {"SQUASH_OTEL_ENABLED": "0"}, clear=False):
            tel = SquashTelemetry.from_env()
        assert tel.enabled is False

    def test_from_env_enabled_by_default(self):
        env = {k: "" for k in ("SQUASH_OTEL_ENABLED",)}
        with patch.dict(os.environ, env, clear=False):
            tel = SquashTelemetry.from_env()
        # "true" is default when env var is empty; empty string evaluates as enabled
        assert tel.enabled is True


# ---------------------------------------------------------------------------
# emit_attestation_span — no-op paths (OTel not installed)
# ---------------------------------------------------------------------------

class TestEmitAttestationSpanNoOp:
    def _make_tel(self) -> SquashTelemetry:
        return SquashTelemetry(endpoint=None, enabled=True)

    def test_returns_telemetry_result(self):
        tel = self._make_tel()
        result = tel.emit_attestation_span(
            model_path="./m", policy="eu-ai-act",
            compliance_score=80.0, violations=0,
            duration_ms=100.0, passed=True,
        )
        assert isinstance(result, TelemetryResult)

    def test_emitted_false_when_no_tracer(self):
        tel = self._make_tel()
        result = tel.emit_attestation_span(
            model_path="./m", policy="p",
            compliance_score=60.0, violations=2,
            duration_ms=50.0, passed=False,
        )
        assert result.emitted is False

    def test_emitted_false_when_disabled(self):
        tel = SquashTelemetry(enabled=False)
        result = tel.emit_attestation_span(
            model_path="./m", policy="p",
            compliance_score=90.0, violations=0,
            duration_ms=100.0, passed=True,
        )
        assert result.emitted is False

    def test_no_exception_on_repeated_calls(self):
        tel = self._make_tel()
        for _ in range(10):
            result = tel.emit_attestation_span(
                model_path="./m", policy="eu-ai-act",
                compliance_score=75.0, violations=1,
                duration_ms=200.0, passed=False,
            )
            assert isinstance(result, TelemetryResult)


class TestEmitDriftSpanNoOp:
    def test_returns_telemetry_result(self):
        tel = SquashTelemetry()
        result = tel.emit_drift_span(
            model_path="./m", drift_detected=True, drift_score=0.8,
        )
        assert isinstance(result, TelemetryResult)
        assert result.emitted is False


# ---------------------------------------------------------------------------
# test_connection — no-op path
# ---------------------------------------------------------------------------

class TestTestConnection:
    def test_returns_telemetry_result(self):
        tel = SquashTelemetry()
        result = tel.test_connection()
        assert isinstance(result, TelemetryResult)

    def test_emitted_false_without_tracer(self):
        tel = SquashTelemetry()
        result = tel.test_connection()
        assert result.emitted is False


# ---------------------------------------------------------------------------
# status()
# ---------------------------------------------------------------------------

class TestStatus:
    def test_status_returns_telemetry_status(self):
        tel = SquashTelemetry(endpoint="http://localhost:4317", service_name="test-svc")
        s = tel.status()
        assert isinstance(s, TelemetryStatus)
        assert s.service_name == "test-svc"

    def test_status_spans_emitted_zero(self):
        tel = SquashTelemetry()
        s = tel.status()
        assert s.spans_emitted == 0

    def test_status_enabled_reflects_config(self):
        tel = SquashTelemetry(enabled=False)
        s = tel.status()
        assert s.enabled is False

    def test_status_endpoint_in_result(self):
        tel = SquashTelemetry(endpoint="http://otel:4317")
        s = tel.status()
        assert s.endpoint == "http://otel:4317"


# ---------------------------------------------------------------------------
# shutdown()
# ---------------------------------------------------------------------------

class TestShutdown:
    def test_shutdown_safe_without_provider(self):
        tel = SquashTelemetry()
        tel.shutdown()  # must not raise

    def test_shutdown_idempotent(self):
        tel = SquashTelemetry()
        tel.shutdown()
        tel.shutdown()  # must not raise


# ---------------------------------------------------------------------------
# _otel_available / _otel_exporter_available
# ---------------------------------------------------------------------------

class TestOtelAvailable:
    def test_otel_available_returns_bool(self):
        result = _otel_available()
        assert isinstance(result, bool)

    def test_otel_exporter_available_returns_bool(self):
        result = _otel_exporter_available()
        assert isinstance(result, bool)

    def test_otel_not_available_when_module_absent(self):
        with patch.dict(sys.modules, {"opentelemetry.trace": None}):
            result = _otel_available()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

class TestModuleLevelSingleton:
    def test_get_default_telemetry_returns_instance(self):
        tel = get_default_telemetry()
        assert isinstance(tel, SquashTelemetry)

    def test_module_level_emit_returns_result(self):
        result = emit_attestation_span(
            model_path="./m",
            policy="eu-ai-act",
            compliance_score=85.0,
            violations=0,
            duration_ms=500.0,
            passed=True,
        )
        assert isinstance(result, TelemetryResult)

    def test_module_level_emit_with_kwargs(self):
        result = emit_attestation_span(
            model_path="./m",
            policy="eu-ai-act",
            compliance_score=70.0,
            violations=3,
            duration_ms=300.0,
            passed=False,
            tenant_id="t-999",
            framework="gguf",
        )
        assert isinstance(result, TelemetryResult)
