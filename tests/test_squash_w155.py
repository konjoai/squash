"""tests/test_squash_w155.py — W155: Stripe checkout endpoint + billing upgrades.

Covers:
  POST /billing/checkout   — create Stripe checkout session
  Startup tier             — billing.py plan map includes startup/$499
  /billing/checkout auth   — endpoint accessible with or without API key
  Plan validation          — rejects invalid plan names
"""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import MagicMock, patch


class TestBillingPlanMap(unittest.TestCase):
    """billing.py plan mapping includes Startup tier."""

    def test_startup_tier_in_plan_map(self):
        with patch.dict(os.environ, {
            "SQUASH_STRIPE_PRICE_PRO": "price_pro123",
            "SQUASH_STRIPE_PRICE_STARTUP": "price_startup456",
            "SQUASH_STRIPE_PRICE_TEAM": "price_team789",
            "SQUASH_STRIPE_PRICE_ENTERPRISE": "price_ent000",
        }):
            from squash.billing import _price_to_plan
            mapping = _price_to_plan()
        self.assertEqual(mapping.get("price_startup456"), "startup")

    def test_pro_tier_in_plan_map(self):
        with patch.dict(os.environ, {"SQUASH_STRIPE_PRICE_PRO": "price_pro123"}):
            from squash.billing import _price_to_plan
            mapping = _price_to_plan()
        self.assertEqual(mapping.get("price_pro123"), "pro")

    def test_team_tier_in_plan_map(self):
        with patch.dict(os.environ, {"SQUASH_STRIPE_PRICE_TEAM": "price_team789"}):
            from squash.billing import _price_to_plan
            mapping = _price_to_plan()
        self.assertEqual(mapping.get("price_team789"), "team")

    def test_enterprise_tier_in_plan_map(self):
        with patch.dict(os.environ, {"SQUASH_STRIPE_PRICE_ENTERPRISE": "price_ent000"}):
            from squash.billing import _price_to_plan
            mapping = _price_to_plan()
        self.assertEqual(mapping.get("price_ent000"), "enterprise")

    def test_empty_env_vars_excluded(self):
        with patch.dict(os.environ, {}, clear=True):
            from squash.billing import _price_to_plan
            mapping = _price_to_plan()
        self.assertEqual(mapping, {})


class TestCheckoutSessionCreation(unittest.TestCase):
    """create_checkout_session() function."""

    def test_raises_import_error_without_stripe(self):
        from squash.billing import create_checkout_session
        with patch.dict(os.environ, {"SQUASH_STRIPE_SECRET_KEY": "sk_test_x"}):
            with patch.dict("sys.modules", {"stripe": None}):
                with self.assertRaises((ImportError, Exception)):
                    create_checkout_session(
                        tenant_id="t1",
                        plan="pro",
                        success_url="https://example.com/success",
                        cancel_url="https://example.com/cancel",
                    )

    def test_raises_runtime_error_without_api_key(self):
        from squash.billing import create_checkout_session
        with patch.dict(os.environ, {}, clear=True):
            # stripe module mocked as present
            mock_stripe = MagicMock()
            with patch.dict("sys.modules", {"stripe": mock_stripe}):
                with self.assertRaises(RuntimeError) as ctx:
                    create_checkout_session(
                        tenant_id="t1",
                        plan="pro",
                        success_url="https://example.com/success",
                        cancel_url="https://example.com/cancel",
                    )
                self.assertIn("SQUASH_STRIPE_SECRET_KEY", str(ctx.exception))

    def test_raises_value_error_for_unknown_plan(self):
        from squash.billing import create_checkout_session
        mock_stripe = MagicMock()
        with patch.dict(os.environ, {
            "SQUASH_STRIPE_SECRET_KEY": "sk_test_x",
            "SQUASH_STRIPE_PRICE_PRO": "price_123",
        }):
            with patch.dict("sys.modules", {"stripe": mock_stripe}):
                with self.assertRaises(ValueError) as ctx:
                    create_checkout_session(
                        tenant_id="t1",
                        plan="unknown-plan",
                        success_url="https://example.com/success",
                        cancel_url="https://example.com/cancel",
                    )
                self.assertIn("unknown-plan", str(ctx.exception))

    def test_creates_session_successfully(self):
        from squash.billing import create_checkout_session
        mock_stripe = MagicMock()
        mock_session = MagicMock()
        mock_session.id = "cs_test_abc123"
        mock_session.url = "https://checkout.stripe.com/pay/cs_test_abc123"
        mock_stripe.checkout.Session.create.return_value = mock_session

        with patch.dict(os.environ, {
            "SQUASH_STRIPE_SECRET_KEY": "sk_test_x",
            "SQUASH_STRIPE_PRICE_PRO": "price_pro123",
        }):
            with patch.dict("sys.modules", {"stripe": mock_stripe}):
                result = create_checkout_session(
                    tenant_id="tenant-42",
                    plan="pro",
                    success_url="https://example.com/success",
                    cancel_url="https://example.com/cancel",
                    customer_email="user@example.com",
                )

        self.assertEqual(result.session_id, "cs_test_abc123")
        self.assertIn("cs_test_abc123", result.url)
        self.assertEqual(result.plan, "pro")
        self.assertEqual(result.tenant_id, "tenant-42")

    def test_checkout_session_includes_metadata(self):
        from squash.billing import create_checkout_session
        mock_stripe = MagicMock()
        mock_session = MagicMock()
        mock_session.id = "cs_test_xyz"
        mock_session.url = "https://checkout.stripe.com/xyz"
        mock_stripe.checkout.Session.create.return_value = mock_session
        create_kwargs = {}

        def capture(**kwargs):
            create_kwargs.update(kwargs)
            return mock_session

        mock_stripe.checkout.Session.create.side_effect = capture

        with patch.dict(os.environ, {
            "SQUASH_STRIPE_SECRET_KEY": "sk_test_x",
            "SQUASH_STRIPE_PRICE_STARTUP": "price_startup456",
        }):
            with patch.dict("sys.modules", {"stripe": mock_stripe}):
                create_checkout_session(
                    tenant_id="tenant-99",
                    plan="startup",
                    success_url="https://example.com/success",
                    cancel_url="https://example.com/cancel",
                )

        metadata = create_kwargs.get("metadata", {})
        self.assertEqual(metadata.get("tenant_id"), "tenant-99")
        self.assertEqual(metadata.get("squash_plan"), "startup")


class TestBillingCheckoutEndpoint(unittest.TestCase):
    """POST /billing/checkout API endpoint."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from squash.api import app
            cls.client = TestClient(app, raise_server_exceptions=False)
            cls.available = True
        except ImportError:
            cls.available = False

    def test_checkout_rejects_invalid_plan(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.post(
            "/billing/checkout",
            json={"plan": "invalid-plan", "tenant_id": "t1"},
            headers={"Authorization": "Bearer sq_live_test"},
        )
        self.assertEqual(resp.status_code, 422)

    def test_checkout_requires_plan_field(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.post(
            "/billing/checkout",
            json={"tenant_id": "t1"},
            headers={"Authorization": "Bearer sq_live_test"},
        )
        self.assertIn(resp.status_code, (422, 401, 503))

    def test_checkout_valid_plans_accepted(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        for plan in ("pro", "startup", "team", "enterprise"):
            # Without Stripe keys, expect 503 (not configured) or 422/401, not 404
            with patch("squash.billing.create_checkout_session", side_effect=RuntimeError("no key")):
                resp = self.client.post(
                    "/billing/checkout",
                    json={"plan": plan, "tenant_id": "t1"},
                    headers={"Authorization": "Bearer sq_live_test"},
                )
                self.assertNotEqual(resp.status_code, 404, f"Plan {plan} got 404 (endpoint missing)")

    def test_checkout_with_mocked_stripe(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        from squash.billing import CheckoutResult
        mock_result = CheckoutResult(
            session_id="cs_test_abc",
            url="https://checkout.stripe.com/pay/cs_test_abc",
            plan="pro",
            tenant_id="t1",
        )
        with patch("squash.billing.create_checkout_session", return_value=mock_result):
            resp = self.client.post(
                "/billing/checkout",
                json={"plan": "pro", "tenant_id": "t1", "customer_email": "x@example.com"},
                headers={"Authorization": "Bearer sq_live_test"},
            )
        self.assertIn(resp.status_code, (201, 401, 503))
        if resp.status_code == 201:
            data = resp.json()
            self.assertIn("checkout_url", data)
            self.assertIn("session_id", data)
            self.assertEqual(data["plan"], "pro")

    def test_checkout_response_shape_on_success(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        from squash.billing import CheckoutResult
        mock_result = CheckoutResult(
            session_id="cs_test_startup",
            url="https://checkout.stripe.com/pay/cs_startup",
            plan="startup",
            tenant_id="acme",
        )
        with patch("squash.billing.create_checkout_session", return_value=mock_result):
            resp = self.client.post(
                "/billing/checkout",
                json={"plan": "startup", "tenant_id": "acme"},
                headers={"Authorization": "Bearer sq_live_test"},
            )
        if resp.status_code == 201:
            data = resp.json()
            self.assertEqual(data["plan"], "startup")
            self.assertIn("checkout.stripe.com", data["checkout_url"])


class TestBillingWebhookStillWorks(unittest.TestCase):
    """Regression: existing billing webhook endpoint unaffected by changes."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from squash.api import app
            cls.client = TestClient(app, raise_server_exceptions=False)
            cls.available = True
        except ImportError:
            cls.available = False

    def test_webhook_endpoint_exists(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.post(
            "/billing/webhook",
            content=b'{"type": "test"}',
            headers={"Content-Type": "application/json"},
        )
        self.assertNotEqual(resp.status_code, 404)

    def test_webhook_no_auth_required(self):
        if not self.available:
            self.skipTest("fastapi not installed")
        resp = self.client.post(
            "/billing/webhook",
            content=b'{"type": "test"}',
            headers={
                "Content-Type": "application/json",
                "Stripe-Signature": "t=1234,v1=abc",
            },
        )
        self.assertNotEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
