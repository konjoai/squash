"""squash/telemetry.py — OpenTelemetry integration for squash attestation runs.

Every call to ``squash attest`` can emit an OpenTelemetry span with compliance
metadata as span attributes.  The integration degrades gracefully when the
``opentelemetry-api`` package is not installed — all public functions remain
callable and return sensible defaults.

Environment variables
---------------------
SQUASH_OTEL_ENDPOINT
    OTLP gRPC endpoint, e.g. ``http://localhost:4317``.
    When set, telemetry is enabled by default.
SQUASH_OTEL_HTTP_ENDPOINT
    OTLP HTTP/protobuf endpoint, e.g. ``http://localhost:4318/v1/traces``.
    Takes precedence over SQUASH_OTEL_ENDPOINT for HTTP transport.
SQUASH_OTEL_SERVICE_NAME
    Service name recorded on every span. Default: ``squash``.
SQUASH_OTEL_ENABLED
    Set to ``"false"`` or ``"0"`` to explicitly disable even when an endpoint
    is configured.

Usage
-----
::

    from squash.telemetry import SquashTelemetry

    tel = SquashTelemetry.from_env()
    tel.emit_attestation_span(
        model_path="./my-model",
        policy="eu-ai-act",
        compliance_score=87.5,
        violations=0,
        duration_ms=1234.0,
        passed=True,
    )

CLI integration
---------------
``squash telemetry configure --endpoint http://otelcollector:4317``
``squash telemetry test``
``squash telemetry status``
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OTel availability check
# ---------------------------------------------------------------------------

def _otel_available() -> bool:
    try:
        import opentelemetry.trace  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


def _otel_exporter_available() -> bool:
    """Check for OTLP exporter packages."""
    try:
        import opentelemetry.exporter.otlp.proto.grpc.trace_exporter  # type: ignore  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import opentelemetry.exporter.otlp.proto.http.trace_exporter  # type: ignore  # noqa: F401
        return True
    except ImportError:
        pass
    return False


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AttestationSpanAttrs:
    """Attributes emitted on every squash attestation OTel span."""
    model_path: str
    policy: str
    compliance_score: float
    violations: int
    duration_ms: float
    passed: bool
    tenant_id: str | None = None
    squash_version: str = "1.4.0"
    framework: str | None = None        # e.g. "pytorch", "tensorflow", "gguf"
    model_hash: str | None = None       # SHA-256 of model artifact, if available
    annex_iv_sections: int | None = None  # number of Annex IV sections completed

    def to_otel_attrs(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "squash.model.path": self.model_path,
            "squash.policy": self.policy,
            "squash.compliance.score": self.compliance_score,
            "squash.violations.count": self.violations,
            "squash.attestation.passed": self.passed,
            "squash.duration.ms": self.duration_ms,
            "squash.version": self.squash_version,
        }
        if self.tenant_id is not None:
            attrs["squash.tenant.id"] = self.tenant_id
        if self.framework is not None:
            attrs["squash.model.framework"] = self.framework
        if self.model_hash is not None:
            attrs["squash.model.sha256"] = self.model_hash
        if self.annex_iv_sections is not None:
            attrs["squash.annex_iv.sections_completed"] = self.annex_iv_sections
        return attrs


@dataclass
class TelemetryResult:
    emitted: bool
    span_id: str | None = None
    trace_id: str | None = None
    error: str | None = None
    otel_available: bool = False
    exporter_available: bool = False
    endpoint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "emitted": self.emitted,
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "error": self.error,
            "otel_available": self.otel_available,
            "exporter_available": self.exporter_available,
            "endpoint": self.endpoint,
        }


@dataclass
class TelemetryStatus:
    enabled: bool
    otel_available: bool
    exporter_available: bool
    endpoint: str | None
    service_name: str
    spans_emitted: int = 0
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "otel_available": self.otel_available,
            "exporter_available": self.exporter_available,
            "endpoint": self.endpoint,
            "service_name": self.service_name,
            "spans_emitted": self.spans_emitted,
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class SquashTelemetry:
    """Emits OpenTelemetry spans for squash attestation runs.

    Degrades gracefully when ``opentelemetry-api`` is not installed — every
    public method returns a valid (no-op) result.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        http_endpoint: str | None = None,
        service_name: str = "squash",
        enabled: bool = True,
    ) -> None:
        self.endpoint = endpoint
        self.http_endpoint = http_endpoint
        self.service_name = service_name
        self.enabled = enabled
        self._spans_emitted = 0
        self._last_error: str | None = None
        self._tracer: Any = None
        self._tracer_provider: Any = None

        if self.enabled and (endpoint or http_endpoint):
            self._init_provider()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "SquashTelemetry":
        """Construct from SQUASH_OTEL_* environment variables."""
        enabled_str = os.environ.get("SQUASH_OTEL_ENABLED", "true").lower()
        enabled = enabled_str not in ("false", "0", "no", "off")
        return cls(
            endpoint=os.environ.get("SQUASH_OTEL_ENDPOINT"),
            http_endpoint=os.environ.get("SQUASH_OTEL_HTTP_ENDPOINT"),
            service_name=os.environ.get("SQUASH_OTEL_SERVICE_NAME", "squash"),
            enabled=enabled,
        )

    # ------------------------------------------------------------------
    # Provider init
    # ------------------------------------------------------------------

    def _init_provider(self) -> None:
        if not _otel_available():
            log.debug("opentelemetry-api not installed — telemetry disabled")
            return
        try:
            from opentelemetry import trace as otel_trace  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore

            resource = Resource({"service.name": self.service_name, "service.version": "1.4.0"})
            provider = TracerProvider(resource=resource)

            exporter = self._build_exporter()
            if exporter is not None:
                provider.add_span_processor(BatchSpanProcessor(exporter))

            self._tracer_provider = provider
            self._tracer = provider.get_tracer("squash", "1.4.0")
        except Exception as exc:
            self._last_error = str(exc)
            log.debug("Failed to init OTel provider: %s", exc)

    def _build_exporter(self) -> Any:
        """Build the best available OTLP exporter."""
        if self.http_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
                    OTLPSpanExporter,
                )
                return OTLPSpanExporter(endpoint=self.http_endpoint)
            except ImportError:
                pass
        if self.endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore
                    OTLPSpanExporter,
                )
                return OTLPSpanExporter(endpoint=self.endpoint)
            except ImportError:
                pass
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def emit_attestation_span(
        self,
        model_path: str,
        policy: str,
        compliance_score: float,
        violations: int,
        duration_ms: float,
        passed: bool,
        tenant_id: str | None = None,
        framework: str | None = None,
        model_hash: str | None = None,
        annex_iv_sections: int | None = None,
    ) -> TelemetryResult:
        """Emit a span for a completed attestation run.

        Returns a :class:`TelemetryResult` regardless of whether OTel is
        installed.  ``result.emitted`` is ``True`` only when a span was
        actually recorded.
        """
        attrs = AttestationSpanAttrs(
            model_path=model_path,
            policy=policy,
            compliance_score=compliance_score,
            violations=violations,
            duration_ms=duration_ms,
            passed=passed,
            tenant_id=tenant_id,
            framework=framework,
            model_hash=model_hash,
            annex_iv_sections=annex_iv_sections,
        )
        return self._emit_span("squash.attest", attrs)

    def emit_drift_span(
        self,
        model_path: str,
        drift_detected: bool,
        drift_score: float,
        tenant_id: str | None = None,
    ) -> TelemetryResult:
        """Emit a span when drift detection runs."""
        if not self.enabled or self._tracer is None:
            return TelemetryResult(
                emitted=False,
                otel_available=_otel_available(),
                exporter_available=_otel_exporter_available(),
                endpoint=self.endpoint or self.http_endpoint,
            )
        try:
            from opentelemetry.trace import StatusCode  # type: ignore

            with self._tracer.start_as_current_span("squash.drift") as span:
                span.set_attribute("squash.model.path", model_path)
                span.set_attribute("squash.drift.detected", drift_detected)
                span.set_attribute("squash.drift.score", drift_score)
                if tenant_id:
                    span.set_attribute("squash.tenant.id", tenant_id)
                ctx = span.get_span_context()
                self._spans_emitted += 1
                return TelemetryResult(
                    emitted=True,
                    span_id=format(ctx.span_id, "016x") if ctx else None,
                    trace_id=format(ctx.trace_id, "032x") if ctx else None,
                    otel_available=True,
                    exporter_available=_otel_exporter_available(),
                    endpoint=self.endpoint or self.http_endpoint,
                )
        except Exception as exc:
            self._last_error = str(exc)
            return TelemetryResult(
                emitted=False,
                error=str(exc),
                otel_available=_otel_available(),
                exporter_available=_otel_exporter_available(),
            )

    def test_connection(self) -> TelemetryResult:
        """Emit a test span. Used by ``squash telemetry test``."""
        return self._emit_span(
            "squash.telemetry.test",
            AttestationSpanAttrs(
                model_path="__test__",
                policy="__test__",
                compliance_score=100.0,
                violations=0,
                duration_ms=0.0,
                passed=True,
            ),
        )

    def status(self) -> TelemetryStatus:
        """Return current telemetry configuration status."""
        return TelemetryStatus(
            enabled=self.enabled,
            otel_available=_otel_available(),
            exporter_available=_otel_exporter_available(),
            endpoint=self.endpoint or self.http_endpoint,
            service_name=self.service_name,
            spans_emitted=self._spans_emitted,
            last_error=self._last_error,
        )

    def shutdown(self) -> None:
        """Flush and shut down the tracer provider."""
        if self._tracer_provider is not None:
            try:
                self._tracer_provider.shutdown()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_span(self, span_name: str, attrs: AttestationSpanAttrs) -> TelemetryResult:
        otel_ok = _otel_available()
        exp_ok = _otel_exporter_available()
        ep = self.endpoint or self.http_endpoint

        if not self.enabled:
            return TelemetryResult(emitted=False, otel_available=otel_ok, exporter_available=exp_ok, endpoint=ep)
        if self._tracer is None:
            return TelemetryResult(emitted=False, otel_available=otel_ok, exporter_available=exp_ok, endpoint=ep)

        try:
            from opentelemetry.trace import StatusCode  # type: ignore

            otel_attrs = attrs.to_otel_attrs()
            with self._tracer.start_as_current_span(span_name) as span:
                for k, v in otel_attrs.items():
                    span.set_attribute(k, v)
                if not attrs.passed:
                    span.set_status(StatusCode.ERROR, f"compliance violations: {attrs.violations}")
                ctx = span.get_span_context()
                self._spans_emitted += 1
                return TelemetryResult(
                    emitted=True,
                    span_id=format(ctx.span_id, "016x") if ctx else None,
                    trace_id=format(ctx.trace_id, "032x") if ctx else None,
                    otel_available=True,
                    exporter_available=exp_ok,
                    endpoint=ep,
                )
        except Exception as exc:
            self._last_error = str(exc)
            log.debug("OTel span emission failed: %s", exc)
            return TelemetryResult(emitted=False, error=str(exc), otel_available=otel_ok, exporter_available=exp_ok)


# ---------------------------------------------------------------------------
# Module-level convenience (singleton from env)
# ---------------------------------------------------------------------------

_default_telemetry: SquashTelemetry | None = None


def get_default_telemetry() -> SquashTelemetry:
    """Return (or lazily create) the module-level telemetry instance."""
    global _default_telemetry
    if _default_telemetry is None:
        _default_telemetry = SquashTelemetry.from_env()
    return _default_telemetry


def emit_attestation_span(
    model_path: str,
    policy: str,
    compliance_score: float,
    violations: int,
    duration_ms: float,
    passed: bool,
    **kwargs: Any,
) -> TelemetryResult:
    """Emit via the module-level singleton. Zero-config usage."""
    return get_default_telemetry().emit_attestation_span(
        model_path=model_path,
        policy=policy,
        compliance_score=compliance_score,
        violations=violations,
        duration_ms=duration_ms,
        passed=passed,
        **kwargs,
    )
