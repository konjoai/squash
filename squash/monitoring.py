"""squash/monitoring.py — W144: Sentry error tracking + health check helpers.

Provides:
    setup_sentry()       — initialise Sentry SDK from env vars
    get_uptime()         — seconds since process start
    db_ping()            — quick database liveness probe
    build_health_report()— dict for /health/detailed endpoint

Environment variables:
    SQUASH_SENTRY_DSN    — Sentry project DSN (omit to disable Sentry)
    SQUASH_SENTRY_ENV    — environment tag (default: production)
    SQUASH_VERSION       — overrides the reported release version

Usage::

    from squash.monitoring import setup_sentry, build_health_report
    setup_sentry()       # call once at startup
    report = build_health_report()  # for /health/detailed
"""
from __future__ import annotations

import importlib.metadata
import logging
import os
import time
from typing import Any

log = logging.getLogger(__name__)

# Monotonic timestamp at module import — used for uptime calculation.
_START_TIME: float = time.monotonic()


# ---------------------------------------------------------------------------
# Sentry
# ---------------------------------------------------------------------------

def setup_sentry(dsn: str | None = None, environment: str | None = None) -> bool:
    """Initialise the Sentry SDK.

    Args:
        dsn:         Sentry project DSN.  Falls back to ``SQUASH_SENTRY_DSN``.
        environment: Sentry environment tag.  Falls back to ``SQUASH_SENTRY_ENV``.

    Returns:
        True if Sentry was initialised, False if DSN is absent or SDK missing.
    """
    dsn = dsn or os.environ.get("SQUASH_SENTRY_DSN", "")
    if not dsn:
        log.debug("monitoring: SQUASH_SENTRY_DSN not set — Sentry disabled")
        return False

    try:
        import sentry_sdk  # type: ignore
        from sentry_sdk.integrations.logging import LoggingIntegration  # type: ignore
    except ImportError:
        log.debug("monitoring: sentry-sdk not installed — Sentry disabled")
        return False

    env = environment or os.environ.get("SQUASH_SENTRY_ENV", "production")
    version = _squash_version()

    sentry_sdk.init(
        dsn=dsn,
        environment=env,
        release=f"squash-ai@{version}",
        traces_sample_rate=float(os.environ.get("SQUASH_SENTRY_TRACES", "0.1")),
        integrations=[
            LoggingIntegration(level=logging.WARNING, event_level=logging.ERROR),
        ],
        send_default_pii=False,
    )
    log.info("monitoring: Sentry initialised (env=%s, release=squash-ai@%s)", env, version)
    return True


def capture_exception(exc: BaseException) -> None:
    """Forward an exception to Sentry if it is configured."""
    try:
        import sentry_sdk  # type: ignore
        sentry_sdk.capture_exception(exc)
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Uptime
# ---------------------------------------------------------------------------

def get_uptime() -> float:
    """Return seconds since the monitoring module was first imported."""
    return time.monotonic() - _START_TIME


# ---------------------------------------------------------------------------
# Database probe
# ---------------------------------------------------------------------------

def db_ping(db: Any = None) -> dict[str, Any]:
    """Probe the database and return a status dict.

    Args:
        db:  A CloudDB, PostgresDB, or anything with a ``ping()`` method.
             Pass None to skip the probe.

    Returns:
        {"status": "ok" | "error" | "unconfigured", "latency_ms": float}
    """
    if db is None:
        return {"status": "unconfigured", "latency_ms": 0.0}
    t0 = time.monotonic()
    try:
        ok = db.ping()
        latency = round((time.monotonic() - t0) * 1000, 2)
        return {"status": "ok" if ok else "error", "latency_ms": latency}
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 2)
        return {"status": "error", "latency_ms": latency, "detail": str(exc)}


# ---------------------------------------------------------------------------
# Health report
# ---------------------------------------------------------------------------

def build_health_report(
    db: Any = None,
    extra_components: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the /health/detailed response body.

    Args:
        db:               Database instance for liveness probe.
        extra_components: Additional component status dicts to merge.

    Returns:
        Dict suitable for JSON serialisation.
    """
    db_status = db_ping(db)
    overall = "ok" if db_status["status"] in ("ok", "unconfigured") else "degraded"

    components: dict[str, Any] = {
        "database": db_status,
        **(extra_components or {}),
    }
    if any(c.get("status") == "error" for c in components.values()):
        overall = "degraded"

    return {
        "status": overall,
        "version": _squash_version(),
        "uptime_seconds": round(get_uptime(), 1),
        "components": components,
    }


# ---------------------------------------------------------------------------
# Version helper
# ---------------------------------------------------------------------------

def _squash_version() -> str:
    ver = os.environ.get("SQUASH_VERSION", "")
    if ver:
        return ver
    try:
        return importlib.metadata.version("squash-ai")
    except importlib.metadata.PackageNotFoundError:
        return "dev"
