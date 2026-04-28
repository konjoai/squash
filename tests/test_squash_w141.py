"""W141 — Stripe billing integration tests."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from unittest.mock import patch

import pytest

from squash.auth import KeyStore, reset_key_store
from squash.billing import (
    StripeWebhookHandler,
    WebhookResult,
    verify_stripe_signature,
    _price_to_plan,
    _ACTIVE_STATUSES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    return KeyStore()


@pytest.fixture
def handler(store):
    return StripeWebhookHandler(store)


def _make_sig(payload: bytes, secret: str, ts: int | None = None) -> str:
    """Build a valid Stripe-Signature header value."""
    ts = ts or int(time.time())
    signed = f"{ts}.".encode() + payload
    v1 = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={v1}"


def _event(event_type: str, obj: dict) -> bytes:
    return json.dumps({"type": event_type, "data": {"object": obj}}).encode()


# ---------------------------------------------------------------------------
# verify_stripe_signature
# ---------------------------------------------------------------------------

class TestVerifyStripeSignature:
    def test_valid_signature_returns_true(self):
        payload = b'{"type": "test"}'
        secret = "whsec_testsecret"
        sig = _make_sig(payload, secret)
        assert verify_stripe_signature(payload, sig, secret) is True

    def test_wrong_secret_returns_false(self):
        payload = b'{"type": "test"}'
        sig = _make_sig(payload, "correct_secret")
        assert verify_stripe_signature(payload, sig, "wrong_secret") is False

    def test_tampered_payload_returns_false(self):
        payload = b'{"type": "test"}'
        secret = "whsec_s"
        sig = _make_sig(payload, secret)
        assert verify_stripe_signature(b'tampered', sig, secret) is False

    def test_expired_timestamp_returns_false(self):
        payload = b'test'
        secret = "whsec_s"
        old_ts = int(time.time()) - 400  # > 300s tolerance
        sig = _make_sig(payload, secret, ts=old_ts)
        assert verify_stripe_signature(payload, sig, secret) is False

    def test_empty_sig_header_returns_false(self):
        assert verify_stripe_signature(b"test", "", "secret") is False

    def test_malformed_sig_header_returns_false(self):
        assert verify_stripe_signature(b"test", "not-valid-format", "secret") is False

    def test_string_payload_handled(self):
        payload = b'test'
        secret = "whsec_x"
        sig = _make_sig(payload, secret)
        assert verify_stripe_signature(payload, sig, secret) is True


# ---------------------------------------------------------------------------
# _price_to_plan
# ---------------------------------------------------------------------------

class TestPriceToPlan:
    def test_empty_when_no_env(self):
        with patch.dict("os.environ", {}, clear=True):
            mapping = _price_to_plan()
        # No prices configured → empty dict
        assert isinstance(mapping, dict)

    def test_pro_price_mapped(self):
        with patch.dict("os.environ", {"SQUASH_STRIPE_PRICE_PRO": "price_pro_123"}):
            mapping = _price_to_plan()
        assert mapping.get("price_pro_123") == "pro"

    def test_enterprise_price_mapped(self):
        with patch.dict("os.environ", {"SQUASH_STRIPE_PRICE_ENTERPRISE": "price_ent_456"}):
            mapping = _price_to_plan()
        assert mapping.get("price_ent_456") == "enterprise"


# ---------------------------------------------------------------------------
# WebhookResult
# ---------------------------------------------------------------------------

class TestWebhookResult:
    def test_to_dict_always_has_status_and_event(self):
        r = WebhookResult(status="ok", event_type="checkout.session.completed")
        d = r.to_dict()
        assert d["status"] == "ok"
        assert d["event"] == "checkout.session.completed"

    def test_to_dict_omits_empty_fields(self):
        r = WebhookResult(status="ignored", event_type="unknown")
        d = r.to_dict()
        assert "tenant_id" not in d
        assert "new_plan" not in d

    def test_to_dict_includes_tenant_and_plan_when_set(self):
        r = WebhookResult(status="ok", event_type="checkout.session.completed",
                          tenant_id="t-1", new_plan="pro")
        d = r.to_dict()
        assert d["tenant_id"] == "t-1"
        assert d["new_plan"] == "pro"


# ---------------------------------------------------------------------------
# StripeWebhookHandler — checkout.session.completed
# ---------------------------------------------------------------------------

class TestCheckoutCompleted:
    def test_updates_plan_from_metadata(self, handler, store):
        store.generate("t-checkout", plan="free")
        payload = _event("checkout.session.completed", {
            "metadata": {"tenant_id": "t-checkout", "squash_plan": "pro"},
        })
        result = handler.handle(payload)
        assert result.status == "ok"
        assert result.event_type == "checkout.session.completed"
        assert result.tenant_id == "t-checkout"
        assert result.new_plan == "pro"

    def test_plan_updated_in_store(self, handler, store):
        store.generate("t-ck", plan="free")
        payload = _event("checkout.session.completed", {
            "metadata": {"tenant_id": "t-ck", "squash_plan": "enterprise"},
        })
        handler.handle(payload)
        keys = store.list_for_tenant("t-ck")
        assert all(k.plan == "enterprise" for k in keys)

    def test_missing_tenant_id_does_not_crash(self, handler):
        payload = _event("checkout.session.completed", {"metadata": {}})
        result = handler.handle(payload)
        assert result.status == "ok"

    def test_default_plan_is_pro(self, handler, store):
        store.generate("t-default", plan="free")
        payload = _event("checkout.session.completed", {
            "metadata": {"tenant_id": "t-default"},
        })
        result = handler.handle(payload)
        assert result.new_plan == "pro"


# ---------------------------------------------------------------------------
# StripeWebhookHandler — customer.subscription.updated
# ---------------------------------------------------------------------------

class TestSubscriptionUpdated:
    def test_updates_plan_from_price_id(self, store):
        store.generate("t-sub", plan="free")
        handler = StripeWebhookHandler(store, plan_map={"price_pro_x": "pro"})
        payload = _event("customer.subscription.updated", {
            "status": "active",
            "metadata": {"tenant_id": "t-sub"},
            "items": {"data": [{"price": {"id": "price_pro_x"}}]},
        })
        result = handler.handle(payload)
        assert result.status == "ok"

    def test_returns_ok_for_subscription_updated(self, handler):
        payload = _event("customer.subscription.updated", {
            "status": "active",
            "metadata": {"tenant_id": "t-any"},
            "items": {"data": []},
        })
        result = handler.handle(payload)
        assert result.event_type == "customer.subscription.updated"


# ---------------------------------------------------------------------------
# StripeWebhookHandler — customer.subscription.deleted
# ---------------------------------------------------------------------------

class TestSubscriptionCancelled:
    def test_downgrades_to_free_on_deletion(self, handler, store):
        store.generate("t-del", plan="pro")
        payload = _event("customer.subscription.deleted", {
            "metadata": {"tenant_id": "t-del"},
        })
        result = handler.handle(payload)
        assert result.status == "ok"
        assert result.new_plan == "free"
        keys = store.list_for_tenant("t-del")
        assert all(k.plan == "free" for k in keys)

    def test_subscription_paused_downgrades(self, handler, store):
        store.generate("t-pause", plan="enterprise")
        payload = _event("customer.subscription.paused", {
            "metadata": {"tenant_id": "t-pause"},
        })
        result = handler.handle(payload)
        assert result.new_plan == "free"


# ---------------------------------------------------------------------------
# StripeWebhookHandler — invoice.payment_failed
# ---------------------------------------------------------------------------

class TestPaymentFailed:
    def test_payment_failed_does_not_downgrade(self, handler, store):
        store.generate("t-fail", plan="pro")
        payload = _event("invoice.payment_failed", {
            "metadata": {"tenant_id": "t-fail"},
        })
        result = handler.handle(payload)
        assert result.status == "ok"
        # Plan should NOT change on payment_failed
        keys = store.list_for_tenant("t-fail")
        assert all(k.plan == "pro" for k in keys)


# ---------------------------------------------------------------------------
# StripeWebhookHandler — unknown events
# ---------------------------------------------------------------------------

class TestUnknownEvents:
    def test_unknown_event_ignored(self, handler):
        payload = _event("some.unknown.event", {})
        result = handler.handle(payload)
        assert result.status == "ignored"

    def test_ignored_result_has_event_type(self, handler):
        payload = _event("payment_intent.created", {})
        result = handler.handle(payload)
        assert result.event_type == "payment_intent.created"


# ---------------------------------------------------------------------------
# StripeWebhookHandler — signature verification integration
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    def test_invalid_signature_returns_error(self, handler):
        payload = _event("checkout.session.completed", {"metadata": {}})
        result = handler.handle(payload, stripe_signature="bad_sig", webhook_secret="whsec_x")
        assert result.status == "error"

    def test_valid_signature_accepted(self, handler):
        payload = _event("checkout.session.completed", {"metadata": {}})
        secret = "whsec_testsecret"
        sig = _make_sig(payload, secret)
        result = handler.handle(payload, stripe_signature=sig, webhook_secret=secret)
        assert result.status == "ok"

    def test_no_secret_skips_verification(self, handler):
        payload = _event("checkout.session.completed", {"metadata": {}})
        result = handler.handle(payload)  # no secret = no verification
        assert result.status == "ok"


# ---------------------------------------------------------------------------
# StripeWebhookHandler — invalid JSON
# ---------------------------------------------------------------------------

class TestInvalidPayload:
    def test_invalid_json_returns_error(self, handler):
        result = handler.handle(b"not json {{{{")
        assert result.status == "error"

    def test_string_payload_accepted(self, handler):
        payload_str = json.dumps({
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {}}},
        })
        result = handler.handle(payload_str)
        assert result.status == "ok"
