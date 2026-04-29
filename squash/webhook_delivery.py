"""squash/webhook_delivery.py — Generic outbound webhook delivery.

Registers HTTP endpoints and delivers squash compliance events to them.
Signed with HMAC-SHA256 so receivers can verify authenticity.

Event types delivered
---------------------
- ``attestation.complete`` — attestation run finished (pass or fail)
- ``violation.detected``   — policy violations found during attestation
- ``drift.detected``       — model drift detected via ``squash watch``
- ``vex.alert``            — new CVE matched a deployed model
- ``score.changed``        — compliance score changed by more than the threshold

Usage
-----
::

    from squash.webhook_delivery import WebhookDelivery, WebhookEvent

    wh = WebhookDelivery()
    endpoint = wh.register(
        url="https://my.soar.platform/squash-events",
        events=[WebhookEvent.ATTESTATION_COMPLETE, WebhookEvent.VIOLATION_DETECTED],
    )

    results = wh.dispatch(
        WebhookEvent.ATTESTATION_COMPLETE,
        payload={"model": "my-model", "score": 87.5, "passed": True},
    )

CLI integration
---------------
``squash webhook add --url https://... --events attestation.complete``
``squash webhook list``
``squash webhook remove <id>``
``squash webhook test --url https://...``
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import time
import urllib.request
import urllib.error
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

class WebhookEvent(str, Enum):
    ATTESTATION_COMPLETE = "attestation.complete"
    VIOLATION_DETECTED   = "violation.detected"
    DRIFT_DETECTED       = "drift.detected"
    VEX_ALERT            = "vex.alert"
    SCORE_CHANGED        = "score.changed"

    @classmethod
    def all(cls) -> list["WebhookEvent"]:
        return list(cls)

    @classmethod
    def from_str(cls, s: str) -> "WebhookEvent":
        for member in cls:
            if member.value == s:
                return member
        raise ValueError(f"Unknown webhook event: {s!r}")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WebhookEndpoint:
    id: str
    url: str
    events: list[WebhookEvent]
    secret: str
    created_at: str
    active: bool = True
    delivery_count: int = 0
    last_delivery_at: str | None = None
    last_status_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "events": [e.value for e in self.events],
            "created_at": self.created_at,
            "active": self.active,
            "delivery_count": self.delivery_count,
            "last_delivery_at": self.last_delivery_at,
            "last_status_code": self.last_status_code,
            # secret intentionally omitted from dict output
        }


@dataclass
class WebhookPayload:
    id: str
    event: WebhookEvent
    created_at: str
    data: dict[str, Any]
    squash_version: str = "1.4.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event": self.event.value,
            "created_at": self.created_at,
            "squash_version": self.squash_version,
            "data": self.data,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":")).encode()


@dataclass
class WebhookDeliveryResult:
    endpoint_id: str
    endpoint_url: str
    event: WebhookEvent
    payload_id: str
    success: bool
    status_code: int | None = None
    duration_ms: float = 0.0
    error: str | None = None
    response_body: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "endpoint_url": self.endpoint_url,
            "event": self.event.value,
            "payload_id": self.payload_id,
            "success": self.success,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------

def sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Return ``sha256=<hex>`` signature for *payload_bytes* using *secret*."""
    mac = hmac.new(secret.encode(), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_signature(payload_bytes: bytes, secret: str, signature: str) -> bool:
    """Constant-time comparison of the expected vs. received signature."""
    expected = sign_payload(payload_bytes, secret)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def _deliver_once(
    endpoint: WebhookEndpoint,
    payload_bytes: bytes,
    event: WebhookEvent,
    payload_id: str,
    timeout_s: float = 10.0,
) -> WebhookDeliveryResult:
    """Make a single HTTP POST delivery attempt."""
    signature = sign_payload(payload_bytes, endpoint.secret)
    headers = {
        "Content-Type": "application/json",
        "X-Squash-Event": event.value,
        "X-Squash-Signature": signature,
        "X-Squash-Delivery": payload_id,
        "User-Agent": "squash-webhook/1.4.0",
    }

    t0 = time.monotonic()
    try:
        req = urllib.request.Request(
            endpoint.url,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = resp.getcode()
            try:
                body = resp.read(512).decode(errors="replace")
            except Exception:
                body = None
            duration_ms = (time.monotonic() - t0) * 1000
            success = 200 <= status < 300
            return WebhookDeliveryResult(
                endpoint_id=endpoint.id,
                endpoint_url=endpoint.url,
                event=event,
                payload_id=payload_id,
                success=success,
                status_code=status,
                duration_ms=duration_ms,
                response_body=body,
            )
    except urllib.error.HTTPError as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        return WebhookDeliveryResult(
            endpoint_id=endpoint.id,
            endpoint_url=endpoint.url,
            event=event,
            payload_id=payload_id,
            success=False,
            status_code=exc.code,
            duration_ms=duration_ms,
            error=str(exc),
        )
    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        return WebhookDeliveryResult(
            endpoint_id=endpoint.id,
            endpoint_url=endpoint.url,
            event=event,
            payload_id=payload_id,
            success=False,
            duration_ms=duration_ms,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    events TEXT NOT NULL,
    secret TEXT NOT NULL,
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    delivery_count INTEGER NOT NULL DEFAULT 0,
    last_delivery_at TEXT,
    last_status_code INTEGER
);
"""


class WebhookDelivery:
    """Manages webhook endpoint registration and event delivery.

    Thread-safe for read operations; uses WAL mode for SQLite.
    Uses stdlib ``urllib`` for HTTP — no requests dependency.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        url: str,
        events: list[WebhookEvent] | None = None,
        secret: str | None = None,
    ) -> WebhookEndpoint:
        """Register a new webhook endpoint.

        Args:
            url:    HTTPS (or HTTP for localhost) endpoint to POST events to.
            events: List of :class:`WebhookEvent` to subscribe to.
                    Defaults to all events.
            secret: HMAC-SHA256 signing secret.  Auto-generated if not provided.

        Returns:
            The newly created :class:`WebhookEndpoint`.
        """
        if events is None:
            events = WebhookEvent.all()
        if secret is None:
            secret = secrets.token_hex(32)

        endpoint_id = str(uuid.uuid4())
        created_at = _utc_now()
        events_json = json.dumps([e.value for e in events])

        self._conn.execute(
            "INSERT INTO webhook_endpoints (id, url, events, secret, created_at) VALUES (?,?,?,?,?)",
            (endpoint_id, url, events_json, secret, created_at),
        )
        self._conn.commit()

        endpoint = WebhookEndpoint(
            id=endpoint_id,
            url=url,
            events=events,
            secret=secret,
            created_at=created_at,
        )
        log.debug("Registered webhook endpoint %s → %s", endpoint_id, url)
        return endpoint

    def get(self, endpoint_id: str) -> WebhookEndpoint | None:
        row = self._conn.execute(
            "SELECT id, url, events, secret, created_at, active, delivery_count, last_delivery_at, last_status_code "
            "FROM webhook_endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        return _row_to_endpoint(row) if row else None

    def list_endpoints(self, active_only: bool = True) -> list[WebhookEndpoint]:
        query = "SELECT id, url, events, secret, created_at, active, delivery_count, last_delivery_at, last_status_code FROM webhook_endpoints"
        if active_only:
            query += " WHERE active = 1"
        rows = self._conn.execute(query).fetchall()
        return [_row_to_endpoint(r) for r in rows if r]

    def remove(self, endpoint_id: str) -> bool:
        """Deactivate (soft-delete) a webhook endpoint.

        Returns:
            ``True`` if the endpoint existed and was deactivated.
        """
        cur = self._conn.execute(
            "UPDATE webhook_endpoints SET active = 0 WHERE id = ?", (endpoint_id,)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def permanently_delete(self, endpoint_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM webhook_endpoints WHERE id = ?", (endpoint_id,)
        )
        self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch(
        self,
        event: WebhookEvent,
        data: dict[str, Any],
        timeout_s: float = 10.0,
    ) -> list[WebhookDeliveryResult]:
        """Fire *event* with *data* to all subscribed endpoints.

        Returns a list of :class:`WebhookDeliveryResult` — one per endpoint
        that subscribed to this event.  Endpoints that fail do not prevent
        delivery to other endpoints.
        """
        endpoints = self.list_endpoints(active_only=True)
        subscribed = [ep for ep in endpoints if event in ep.events]

        if not subscribed:
            return []

        payload_id = str(uuid.uuid4())
        payload = WebhookPayload(
            id=payload_id,
            event=event,
            created_at=_utc_now(),
            data=data,
        )
        payload_bytes = payload.to_json_bytes()

        results: list[WebhookDeliveryResult] = []
        for endpoint in subscribed:
            result = _deliver_once(endpoint, payload_bytes, event, payload_id, timeout_s)
            results.append(result)
            self._update_stats(endpoint.id, result)

        return results

    def test_endpoint(
        self,
        url: str,
        secret: str = "test-secret",
        timeout_s: float = 10.0,
    ) -> WebhookDeliveryResult:
        """Send a test event to *url* without persisting an endpoint."""
        ep = WebhookEndpoint(
            id="__test__",
            url=url,
            events=[WebhookEvent.ATTESTATION_COMPLETE],
            secret=secret,
            created_at=_utc_now(),
        )
        payload = WebhookPayload(
            id=str(uuid.uuid4()),
            event=WebhookEvent.ATTESTATION_COMPLETE,
            created_at=_utc_now(),
            data={"test": True, "message": "squash webhook test event"},
        )
        return _deliver_once(ep, payload.to_json_bytes(), WebhookEvent.ATTESTATION_COMPLETE, payload.id, timeout_s)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _update_stats(self, endpoint_id: str, result: WebhookDeliveryResult) -> None:
        self._conn.execute(
            "UPDATE webhook_endpoints SET delivery_count = delivery_count + 1, "
            "last_delivery_at = ?, last_status_code = ? WHERE id = ?",
            (_utc_now(), result.status_code, endpoint_id),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"


def _row_to_endpoint(row: tuple) -> WebhookEndpoint:
    (eid, url, events_json, secret, created_at, active, delivery_count, last_delivery_at, last_status_code) = row
    events = [WebhookEvent.from_str(e) for e in json.loads(events_json)]
    return WebhookEndpoint(
        id=eid,
        url=url,
        events=events,
        secret=secret,
        created_at=created_at,
        active=bool(active),
        delivery_count=delivery_count,
        last_delivery_at=last_delivery_at,
        last_status_code=last_status_code,
    )
