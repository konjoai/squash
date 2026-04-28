"""squash/middleware.py — Drop-in compliance middleware for FastAPI and Django.

Adds a ``X-Squash-Compliant`` response header to every request when a model
attestation has been verified. Optionally blocks requests when the attestation
is expired or absent, turning squash into a compliance gate at the framework
level rather than a CI-only check.

FastAPI usage::

    from squash.middleware import SquashComplianceMiddleware

    app = FastAPI()
    app.add_middleware(
        SquashComplianceMiddleware,
        model_id="my-model-v2",
        attestation_path="./attestation/cyclonedx.json",
        block_on_missing=False,     # set True to enforce in prod
    )

Django usage::

    # settings.py
    MIDDLEWARE = [
        ...
        "squash.middleware.SquashDjangoMiddleware",
    ]
    SQUASH_MIDDLEWARE = {
        "model_id": "my-model-v2",
        "attestation_path": "./attestation/cyclonedx.json",
        "block_on_missing": False,
    }

Response headers
----------------
``X-Squash-Compliant: true|false``  — present on every response.
``X-Squash-Model: <model_id>``      — model identifier if set.
``X-Squash-Policy: <policy>``       — policy framework if detected.
``X-Squash-Attested-At: <iso8601>`` — attestation timestamp if available.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

# ── Attestation state ──────────────────────────────────────────────────────────


@dataclass
class AttestationState:
    """Cached result of reading an attestation artifact."""

    compliant: bool = False
    model_id: str = ""
    policy: str = ""
    attested_at: str = ""
    error: str = ""

    @classmethod
    def from_cyclonedx(cls, path: str | Path) -> "AttestationState":
        """Parse a CycloneDX JSON attestation and return state."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            metadata = data.get("metadata", {})
            component = metadata.get("component", {})
            properties = {
                p["name"]: p.get("value", "")
                for p in metadata.get("properties", [])
                if "name" in p
            }

            model_id = component.get("name", "") or properties.get("squash:model_id", "")
            policy = properties.get("squash:policy", "")
            attested_at = metadata.get("timestamp", "")
            compliant = properties.get("squash:passed", "true").lower() == "true"

            return cls(
                compliant=compliant,
                model_id=model_id,
                policy=policy,
                attested_at=attested_at,
            )
        except FileNotFoundError:
            return cls(compliant=False, error="attestation file not found")
        except (json.JSONDecodeError, KeyError) as exc:
            return cls(compliant=False, error=f"parse error: {exc}")

    @classmethod
    def from_squash_report(cls, path: str | Path) -> "AttestationState":
        """Parse a squash JSON report (squash_report.json)."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return cls(
                compliant=bool(data.get("passed", False)),
                model_id=data.get("model_id", ""),
                policy=data.get("policy", ""),
                attested_at=data.get("timestamp", ""),
            )
        except FileNotFoundError:
            return cls(compliant=False, error="report file not found")
        except (json.JSONDecodeError, KeyError) as exc:
            return cls(compliant=False, error=f"parse error: {exc}")


# ── FastAPI middleware ─────────────────────────────────────────────────────────


class SquashComplianceMiddleware:
    """ASGI/FastAPI middleware that injects squash compliance headers.

    Compatible with Starlette ``add_middleware()`` and any ASGI framework.
    """

    def __init__(
        self,
        app: Any,
        *,
        model_id: str = "",
        attestation_path: str = "",
        block_on_missing: bool = False,
        refresh_interval_seconds: int = 300,
    ) -> None:
        self.app = app
        self.model_id = model_id
        self.attestation_path = attestation_path
        self.block_on_missing = block_on_missing
        self.refresh_interval_seconds = refresh_interval_seconds

        self._state: AttestationState | None = None
        self._last_loaded: float = 0.0

    def _load_state(self) -> AttestationState:
        import time
        now = time.monotonic()
        if self._state is None or (now - self._last_loaded) > self.refresh_interval_seconds:
            if self.attestation_path:
                p = Path(self.attestation_path)
                if p.suffix == ".json" and p.exists():
                    try:
                        data = json.loads(p.read_text())
                        if "bomFormat" in data:
                            self._state = AttestationState.from_cyclonedx(p)
                        else:
                            self._state = AttestationState.from_squash_report(p)
                    except Exception as exc:  # noqa: BLE001
                        self._state = AttestationState(compliant=False, error=str(exc))
                else:
                    self._state = AttestationState(compliant=False, error="attestation_path not found")
            else:
                self._state = AttestationState(compliant=False, error="no attestation_path configured")
            self._last_loaded = now
        return self._state

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        state = self._load_state()

        if self.block_on_missing and not state.compliant:
            response = _make_503_response(state)
            await response(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-squash-compliant", b"true" if state.compliant else b"false"))
                if self.model_id or state.model_id:
                    mid = (self.model_id or state.model_id).encode()
                    headers.append((b"x-squash-model", mid))
                if state.policy:
                    headers.append((b"x-squash-policy", state.policy.encode()))
                if state.attested_at:
                    headers.append((b"x-squash-attested-at", state.attested_at.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _make_503_response(state: AttestationState) -> Any:
    """Build a minimal ASGI 503 response for missing/failed attestation."""
    body = json.dumps({
        "error": "model attestation required",
        "detail": state.error or "attestation not compliant",
    }).encode()

    async def response(scope: dict, receive: Any, send: Any) -> None:
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-squash-compliant", b"false"),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    return response


# ── Django middleware ──────────────────────────────────────────────────────────


class SquashDjangoMiddleware:
    """Django WSGI middleware that injects squash compliance headers.

    Configure via ``settings.SQUASH_MIDDLEWARE`` dict::

        SQUASH_MIDDLEWARE = {
            "model_id": "my-model-v2",
            "attestation_path": "./attestation/cyclonedx.json",
            "block_on_missing": False,
        }
    """

    _state: AttestationState | None = None
    _last_loaded: float = 0.0

    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response
        self._config = self._read_django_config()

    @staticmethod
    def _read_django_config() -> dict:
        try:
            from django.conf import settings
            return getattr(settings, "SQUASH_MIDDLEWARE", {})
        except ImportError:
            return {}

    def _load_state(self) -> AttestationState:
        import time
        now = time.monotonic()
        refresh = self._config.get("refresh_interval_seconds", 300)
        if self._state is None or (now - self._last_loaded) > refresh:
            apath = self._config.get("attestation_path", "")
            if apath and Path(apath).exists():
                try:
                    data = json.loads(Path(apath).read_text())
                    if "bomFormat" in data:
                        self.__class__._state = AttestationState.from_cyclonedx(apath)
                    else:
                        self.__class__._state = AttestationState.from_squash_report(apath)
                except Exception as exc:  # noqa: BLE001
                    self.__class__._state = AttestationState(compliant=False, error=str(exc))
            else:
                self.__class__._state = AttestationState(compliant=False, error="attestation_path not set")
            self.__class__._last_loaded = now
        return self._state  # type: ignore[return-value]

    def __call__(self, request: Any) -> Any:
        state = self._load_state()
        block = self._config.get("block_on_missing", False)

        if block and not state.compliant:
            try:
                from django.http import JsonResponse
                return JsonResponse(
                    {"error": "model attestation required", "detail": state.error},
                    status=503,
                )
            except ImportError:
                pass

        response = self.get_response(request)

        response["X-Squash-Compliant"] = "true" if state.compliant else "false"
        model_id = self._config.get("model_id", "") or state.model_id
        if model_id:
            response["X-Squash-Model"] = model_id
        if state.policy:
            response["X-Squash-Policy"] = state.policy
        if state.attested_at:
            response["X-Squash-Attested-At"] = state.attested_at

        return response
