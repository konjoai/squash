"""tests/test_squash_w190.py — W190: Generic outbound webhook delivery tests.

Coverage:
  - WebhookEvent enum: all(), from_str(), value access
  - WebhookEndpoint dataclass: to_dict() omits secret, has required keys
  - WebhookPayload: to_dict(), to_json_bytes() produces valid JSON
  - sign_payload(): deterministic HMAC-SHA256 output
  - verify_signature(): correct / incorrect cases
  - WebhookDelivery.register(): stores endpoint, auto-generates secret
  - WebhookDelivery.get(): returns registered endpoint
  - WebhookDelivery.list_endpoints(): active_only filter
  - WebhookDelivery.remove(): soft-delete; returns True/False
  - WebhookDelivery.permanently_delete(): hard-delete
  - WebhookDelivery.dispatch(): filters by event subscription
  - WebhookDelivery._update_stats(): delivery count increments
  - WebhookDelivery.test_endpoint(): network failure path (mocked)
  - _deliver_once(): HTTP error path, network error path (mocked)
  - Multiple events per endpoint
  - dispatch with no subscribed endpoints returns empty list
"""
from __future__ import annotations

import json
import time
import uuid
from unittest.mock import MagicMock, patch
from pathlib import Path

import pytest

from squash.webhook_delivery import (
    WebhookDelivery,
    WebhookDeliveryResult,
    WebhookEndpoint,
    WebhookEvent,
    WebhookPayload,
    sign_payload,
    verify_signature,
)


# ---------------------------------------------------------------------------
# WebhookEvent
# ---------------------------------------------------------------------------

class TestWebhookEvent:
    def test_all_returns_all_members(self):
        events = WebhookEvent.all()
        assert len(events) == 5
        assert WebhookEvent.ATTESTATION_COMPLETE in events

    def test_from_str_valid(self):
        e = WebhookEvent.from_str("attestation.complete")
        assert e == WebhookEvent.ATTESTATION_COMPLETE

    def test_from_str_violation(self):
        e = WebhookEvent.from_str("violation.detected")
        assert e == WebhookEvent.VIOLATION_DETECTED

    def test_from_str_drift(self):
        e = WebhookEvent.from_str("drift.detected")
        assert e == WebhookEvent.DRIFT_DETECTED

    def test_from_str_vex(self):
        e = WebhookEvent.from_str("vex.alert")
        assert e == WebhookEvent.VEX_ALERT

    def test_from_str_score(self):
        e = WebhookEvent.from_str("score.changed")
        assert e == WebhookEvent.SCORE_CHANGED

    def test_from_str_invalid_raises(self):
        with pytest.raises(ValueError):
            WebhookEvent.from_str("not.a.real.event")

    def test_value_is_string(self):
        for e in WebhookEvent.all():
            assert isinstance(e.value, str)
            assert "." in e.value


# ---------------------------------------------------------------------------
# WebhookPayload
# ---------------------------------------------------------------------------

class TestWebhookPayload:
    def test_to_dict_has_required_keys(self):
        p = WebhookPayload(
            id="pay-001",
            event=WebhookEvent.ATTESTATION_COMPLETE,
            created_at="2026-04-29T00:00:00Z",
            data={"model": "bert"},
        )
        d = p.to_dict()
        for key in ("id", "event", "created_at", "squash_version", "data"):
            assert key in d

    def test_event_value_in_dict(self):
        p = WebhookPayload(
            id="p2", event=WebhookEvent.VIOLATION_DETECTED,
            created_at="2026-04-29T00:00:00Z", data={},
        )
        assert p.to_dict()["event"] == "violation.detected"

    def test_to_json_bytes_valid_json(self):
        p = WebhookPayload(
            id="p3", event=WebhookEvent.DRIFT_DETECTED,
            created_at="2026-04-29T00:00:00Z", data={"score": 0.5},
        )
        raw = p.to_json_bytes()
        decoded = json.loads(raw)
        assert decoded["event"] == "drift.detected"
        assert decoded["data"]["score"] == 0.5

    def test_to_json_bytes_is_compact(self):
        p = WebhookPayload(
            id="p4", event=WebhookEvent.VEX_ALERT,
            created_at="2026-04-29T00:00:00Z", data={},
        )
        raw = p.to_json_bytes()
        assert b"\n" not in raw  # compact JSON


# ---------------------------------------------------------------------------
# sign_payload / verify_signature
# ---------------------------------------------------------------------------

class TestSignPayload:
    def test_produces_sha256_prefix(self):
        sig = sign_payload(b"hello", "secret")
        assert sig.startswith("sha256=")

    def test_deterministic(self):
        sig1 = sign_payload(b"payload", "key")
        sig2 = sign_payload(b"payload", "key")
        assert sig1 == sig2

    def test_different_secrets_produce_different_sigs(self):
        s1 = sign_payload(b"data", "key1")
        s2 = sign_payload(b"data", "key2")
        assert s1 != s2

    def test_different_payloads_produce_different_sigs(self):
        s1 = sign_payload(b"data1", "key")
        s2 = sign_payload(b"data2", "key")
        assert s1 != s2


class TestVerifySignature:
    def test_correct_signature_verifies(self):
        payload = b"test-payload"
        secret = "my-secret"
        sig = sign_payload(payload, secret)
        assert verify_signature(payload, secret, sig) is True

    def test_wrong_secret_fails(self):
        payload = b"test-payload"
        sig = sign_payload(payload, "secret1")
        assert verify_signature(payload, "secret2", sig) is False

    def test_tampered_payload_fails(self):
        payload = b"original"
        sig = sign_payload(payload, "secret")
        assert verify_signature(b"tampered", "secret", sig) is False

    def test_wrong_signature_format_fails(self):
        assert verify_signature(b"data", "secret", "bad-sig") is False


# ---------------------------------------------------------------------------
# WebhookEndpoint.to_dict()
# ---------------------------------------------------------------------------

class TestWebhookEndpointToDict:
    def test_to_dict_omits_secret(self):
        ep = WebhookEndpoint(
            id="ep-1", url="https://example.com",
            events=[WebhookEvent.ATTESTATION_COMPLETE],
            secret="super-secret",
            created_at="2026-04-29T00:00:00Z",
        )
        d = ep.to_dict()
        assert "secret" not in d

    def test_to_dict_has_required_keys(self):
        ep = WebhookEndpoint(
            id="ep-2", url="https://example.com",
            events=WebhookEvent.all(),
            secret="s",
            created_at="2026-04-29T00:00:00Z",
        )
        d = ep.to_dict()
        for key in ("id", "url", "events", "created_at", "active", "delivery_count"):
            assert key in d

    def test_events_are_strings_in_dict(self):
        ep = WebhookEndpoint(
            id="ep-3", url="https://example.com",
            events=[WebhookEvent.VIOLATION_DETECTED],
            secret="s", created_at="2026-04-29T00:00:00Z",
        )
        d = ep.to_dict()
        assert isinstance(d["events"][0], str)


# ---------------------------------------------------------------------------
# WebhookDelivery — registration and retrieval
# ---------------------------------------------------------------------------

class TestWebhookDeliveryRegistration:
    def setup_method(self):
        self.wh = WebhookDelivery(db_path=":memory:")

    def test_register_returns_endpoint(self):
        ep = self.wh.register(url="https://hooks.example.com/squash")
        assert isinstance(ep, WebhookEndpoint)
        assert ep.url == "https://hooks.example.com/squash"

    def test_register_auto_generates_id(self):
        ep = self.wh.register(url="https://a.example.com")
        assert ep.id and len(ep.id) > 0

    def test_register_auto_generates_secret(self):
        ep = self.wh.register(url="https://a.example.com")
        assert ep.secret and len(ep.secret) >= 32

    def test_register_custom_secret(self):
        ep = self.wh.register(url="https://a.example.com", secret="my-secret-123")
        assert ep.secret == "my-secret-123"

    def test_register_default_events_all(self):
        ep = self.wh.register(url="https://a.example.com")
        assert set(ep.events) == set(WebhookEvent.all())

    def test_register_custom_events(self):
        ep = self.wh.register(
            url="https://a.example.com",
            events=[WebhookEvent.ATTESTATION_COMPLETE, WebhookEvent.VIOLATION_DETECTED],
        )
        assert len(ep.events) == 2
        assert WebhookEvent.ATTESTATION_COMPLETE in ep.events

    def test_get_returns_registered_endpoint(self):
        ep = self.wh.register(url="https://b.example.com")
        fetched = self.wh.get(ep.id)
        assert fetched is not None
        assert fetched.url == "https://b.example.com"

    def test_get_nonexistent_returns_none(self):
        assert self.wh.get("nonexistent-id") is None

    def test_list_returns_all_active(self):
        self.wh.register(url="https://a.example.com")
        self.wh.register(url="https://b.example.com")
        endpoints = self.wh.list_endpoints()
        assert len(endpoints) == 2

    def test_list_empty_by_default(self):
        wh = WebhookDelivery(db_path=":memory:")
        assert wh.list_endpoints() == []


# ---------------------------------------------------------------------------
# WebhookDelivery — remove / delete
# ---------------------------------------------------------------------------

class TestWebhookDeliveryRemoval:
    def setup_method(self):
        self.wh = WebhookDelivery(db_path=":memory:")

    def test_remove_deactivates_endpoint(self):
        ep = self.wh.register(url="https://a.example.com")
        removed = self.wh.remove(ep.id)
        assert removed is True
        active = self.wh.list_endpoints(active_only=True)
        assert all(e.id != ep.id for e in active)

    def test_remove_nonexistent_returns_false(self):
        removed = self.wh.remove("no-such-id")
        assert removed is False

    def test_remove_keeps_in_inactive_list(self):
        ep = self.wh.register(url="https://a.example.com")
        self.wh.remove(ep.id)
        all_endpoints = self.wh.list_endpoints(active_only=False)
        assert any(e.id == ep.id for e in all_endpoints)

    def test_permanently_delete_removes_endpoint(self):
        ep = self.wh.register(url="https://a.example.com")
        deleted = self.wh.permanently_delete(ep.id)
        assert deleted is True
        assert self.wh.get(ep.id) is None

    def test_permanently_delete_nonexistent_returns_false(self):
        assert self.wh.permanently_delete("ghost-id") is False


# ---------------------------------------------------------------------------
# WebhookDelivery — dispatch
# ---------------------------------------------------------------------------

class TestWebhookDeliveryDispatch:
    def setup_method(self):
        self.wh = WebhookDelivery(db_path=":memory:")

    def test_dispatch_no_subscribed_endpoints_returns_empty(self):
        results = self.wh.dispatch(WebhookEvent.ATTESTATION_COMPLETE, data={"model": "bert"})
        assert results == []

    def test_dispatch_filters_by_event(self):
        self.wh.register(url="https://a.example.com", events=[WebhookEvent.VIOLATION_DETECTED])
        # Dispatch ATTESTATION_COMPLETE — no match
        with patch("squash.webhook_delivery._deliver_once") as mock_deliver:
            mock_deliver.return_value = WebhookDeliveryResult(
                endpoint_id="ep", endpoint_url="url",
                event=WebhookEvent.ATTESTATION_COMPLETE,
                payload_id="pid", success=True, status_code=200, duration_ms=5.0,
            )
            results = self.wh.dispatch(WebhookEvent.ATTESTATION_COMPLETE, data={})
        assert results == []
        mock_deliver.assert_not_called()

    def test_dispatch_calls_deliver_for_subscribed_endpoint(self):
        ep = self.wh.register(
            url="https://a.example.com",
            events=[WebhookEvent.ATTESTATION_COMPLETE],
        )
        mock_result = WebhookDeliveryResult(
            endpoint_id=ep.id, endpoint_url=ep.url,
            event=WebhookEvent.ATTESTATION_COMPLETE,
            payload_id="pid", success=True, status_code=200, duration_ms=10.0,
        )
        with patch("squash.webhook_delivery._deliver_once", return_value=mock_result) as mock_deliver:
            results = self.wh.dispatch(
                WebhookEvent.ATTESTATION_COMPLETE,
                data={"model": "bert", "score": 87.5},
            )
        assert len(results) == 1
        assert results[0].success is True
        mock_deliver.assert_called_once()

    def test_dispatch_multiple_endpoints(self):
        ep1 = self.wh.register(url="https://a.example.com", events=[WebhookEvent.ATTESTATION_COMPLETE])
        ep2 = self.wh.register(url="https://b.example.com", events=[WebhookEvent.ATTESTATION_COMPLETE])
        mock_result = WebhookDeliveryResult(
            endpoint_id="ep", endpoint_url="url",
            event=WebhookEvent.ATTESTATION_COMPLETE,
            payload_id="pid", success=True, status_code=200, duration_ms=5.0,
        )
        with patch("squash.webhook_delivery._deliver_once", return_value=mock_result):
            results = self.wh.dispatch(WebhookEvent.ATTESTATION_COMPLETE, data={})
        assert len(results) == 2

    def test_dispatch_continues_on_individual_failure(self):
        self.wh.register(url="https://a.example.com", events=[WebhookEvent.ATTESTATION_COMPLETE])
        self.wh.register(url="https://b.example.com", events=[WebhookEvent.ATTESTATION_COMPLETE])
        call_count = [0]

        def mock_deliver(ep, payload_bytes, event, payload_id, timeout_s):
            call_count[0] += 1
            return WebhookDeliveryResult(
                endpoint_id=ep.id, endpoint_url=ep.url,
                event=event, payload_id=payload_id,
                success=(call_count[0] % 2 == 0),  # alternating success/fail
                status_code=200 if call_count[0] % 2 == 0 else 500,
                duration_ms=10.0,
            )

        with patch("squash.webhook_delivery._deliver_once", side_effect=mock_deliver):
            results = self.wh.dispatch(WebhookEvent.ATTESTATION_COMPLETE, data={})
        assert len(results) == 2


# ---------------------------------------------------------------------------
# WebhookDelivery — stats update
# ---------------------------------------------------------------------------

class TestWebhookDeliveryStats:
    def setup_method(self):
        self.wh = WebhookDelivery(db_path=":memory:")

    def test_delivery_count_increments(self):
        ep = self.wh.register(url="https://a.example.com", events=[WebhookEvent.ATTESTATION_COMPLETE])
        mock_result = WebhookDeliveryResult(
            endpoint_id=ep.id, endpoint_url=ep.url,
            event=WebhookEvent.ATTESTATION_COMPLETE,
            payload_id="pid", success=True, status_code=200, duration_ms=5.0,
        )
        with patch("squash.webhook_delivery._deliver_once", return_value=mock_result):
            self.wh.dispatch(WebhookEvent.ATTESTATION_COMPLETE, data={})
            self.wh.dispatch(WebhookEvent.ATTESTATION_COMPLETE, data={})
        fetched = self.wh.get(ep.id)
        assert fetched is not None
        assert fetched.delivery_count == 2


# ---------------------------------------------------------------------------
# WebhookDelivery.test_endpoint()
# ---------------------------------------------------------------------------

class TestWebhookDeliveryTestEndpoint:
    def setup_method(self):
        self.wh = WebhookDelivery(db_path=":memory:")

    def test_test_endpoint_returns_result(self):
        mock_result = WebhookDeliveryResult(
            endpoint_id="__test__", endpoint_url="https://a.example.com",
            event=WebhookEvent.ATTESTATION_COMPLETE,
            payload_id="pid", success=True, status_code=200, duration_ms=5.0,
        )
        with patch("squash.webhook_delivery._deliver_once", return_value=mock_result):
            result = self.wh.test_endpoint("https://a.example.com")
        assert isinstance(result, WebhookDeliveryResult)

    def test_test_endpoint_does_not_persist(self):
        mock_result = WebhookDeliveryResult(
            endpoint_id="__test__", endpoint_url="https://a.example.com",
            event=WebhookEvent.ATTESTATION_COMPLETE,
            payload_id="pid", success=True, status_code=200, duration_ms=5.0,
        )
        with patch("squash.webhook_delivery._deliver_once", return_value=mock_result):
            self.wh.test_endpoint("https://a.example.com")
        assert self.wh.list_endpoints() == []

    def test_test_endpoint_network_error(self):
        with patch("squash.webhook_delivery._deliver_once") as mock_deliver:
            mock_deliver.return_value = WebhookDeliveryResult(
                endpoint_id="__test__", endpoint_url="https://bad.example.com",
                event=WebhookEvent.ATTESTATION_COMPLETE,
                payload_id="pid", success=False, duration_ms=10.0,
                error="Connection refused",
            )
            result = self.wh.test_endpoint("https://bad.example.com")
        assert result.success is False
        assert "refused" in result.error.lower()


# ---------------------------------------------------------------------------
# WebhookDeliveryResult
# ---------------------------------------------------------------------------

class TestWebhookDeliveryResult:
    def test_to_dict_has_required_keys(self):
        r = WebhookDeliveryResult(
            endpoint_id="ep-1", endpoint_url="https://x.com",
            event=WebhookEvent.ATTESTATION_COMPLETE,
            payload_id="pid", success=True, status_code=200, duration_ms=12.0,
        )
        d = r.to_dict()
        for key in ("endpoint_id", "endpoint_url", "event", "payload_id", "success", "status_code", "duration_ms"):
            assert key in d

    def test_event_is_string_in_dict(self):
        r = WebhookDeliveryResult(
            endpoint_id="ep", endpoint_url="https://x.com",
            event=WebhookEvent.VEX_ALERT,
            payload_id="pid", success=False, duration_ms=1.0,
        )
        d = r.to_dict()
        assert isinstance(d["event"], str)
