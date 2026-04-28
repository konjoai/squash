"""squash/billing.py — W141: Stripe subscription billing integration.

Handles Stripe checkout sessions, subscription lifecycle events, and plan
synchronisation with the KeyStore.

Stripe plans (price IDs configured via env vars):
    SQUASH_STRIPE_PRICE_PRO         → maps to plan="pro"
    SQUASH_STRIPE_PRICE_ENTERPRISE  → maps to plan="enterprise"

Webhook secret:
    SQUASH_STRIPE_WEBHOOK_SECRET    → used to verify Stripe-Signature header

Stripe secret key:
    SQUASH_STRIPE_SECRET_KEY        → sk_live_* or sk_test_*

Usage::

    handler = StripeWebhookHandler(key_store)
    result = handler.handle(raw_body, stripe_signature, webhook_secret)
    # result: {"status": "ok", "event": "checkout.session.completed", ...}

The handler is deliberately side-effect-free for unknown event types — it
returns {"status": "ignored", "event": event_type} so CI pipelines can test
without a live Stripe account.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from squash.auth import KeyStore

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plan mapping  (Stripe price ID → squash plan name)
# ---------------------------------------------------------------------------

def _price_to_plan() -> dict[str, str]:
    mapping: dict[str, str] = {}
    pro_price = os.environ.get("SQUASH_STRIPE_PRICE_PRO", "")
    ent_price = os.environ.get("SQUASH_STRIPE_PRICE_ENTERPRISE", "")
    if pro_price:
        mapping[pro_price] = "pro"
    if ent_price:
        mapping[ent_price] = "enterprise"
    return mapping


STRIPE_PLAN_MAP: dict[str, str] = _price_to_plan()

# Stripe subscription statuses that mean the subscription is active
_ACTIVE_STATUSES = frozenset({"active", "trialing"})

# ---------------------------------------------------------------------------
# Stripe signature verification (no stripe-python required for webhooks)
# ---------------------------------------------------------------------------

def verify_stripe_signature(
    payload: bytes,
    sig_header: str,
    webhook_secret: str,
    tolerance: int = 300,
) -> bool:
    """Verify a Stripe-Signature header using HMAC-SHA256.

    Args:
        payload:         Raw request body bytes.
        sig_header:      Value of the ``Stripe-Signature`` HTTP header.
        webhook_secret:  The ``whsec_*`` string from the Stripe dashboard.
        tolerance:       Max age of the timestamp in seconds (default 300).

    Returns:
        True if valid and within tolerance, False otherwise.
    """
    try:
        parts = {kv.split("=", 1)[0]: kv.split("=", 1)[1]
                 for kv in sig_header.split(",") if "=" in kv}
        ts = int(parts.get("t", "0"))
        v1 = parts.get("v1", "")
    except (ValueError, AttributeError):
        return False

    if tolerance and abs(int(time.time()) - ts) > tolerance:
        log.warning("billing: Stripe webhook timestamp too old (%s)", ts)
        return False

    signed_payload = f"{ts}.".encode() + payload
    expected = hmac.new(
        webhook_secret.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, v1)


# ---------------------------------------------------------------------------
# Checkout session builder (returns URL for redirect)
# ---------------------------------------------------------------------------

@dataclass
class CheckoutResult:
    session_id: str
    url: str
    plan: str
    tenant_id: str


def create_checkout_session(
    tenant_id: str,
    plan: str,
    success_url: str,
    cancel_url: str,
    customer_email: str = "",
) -> CheckoutResult:
    """Create a Stripe Checkout session for *tenant_id* upgrading to *plan*.

    Requires ``SQUASH_STRIPE_SECRET_KEY`` to be set.

    Args:
        tenant_id:     Internal tenant identifier (stored as metadata).
        plan:          Target plan: "pro" or "enterprise".
        success_url:   Redirect URL on payment success.
        cancel_url:    Redirect URL on payment cancellation.
        customer_email: Pre-fill email in Stripe Checkout.

    Returns:
        CheckoutResult with Stripe session_id and checkout URL.

    Raises:
        ImportError: if stripe-python is not installed.
        ValueError:  if the plan has no configured price ID.
        RuntimeError: if SQUASH_STRIPE_SECRET_KEY is not set.
    """
    try:
        import stripe as _stripe  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "stripe is required for checkout. Install with: pip install stripe"
        ) from exc

    secret_key = os.environ.get("SQUASH_STRIPE_SECRET_KEY", "")
    if not secret_key:
        raise RuntimeError("SQUASH_STRIPE_SECRET_KEY environment variable not set")

    _stripe.api_key = secret_key
    price_map = {v: k for k, v in _price_to_plan().items()}  # plan → price_id
    price_id = price_map.get(plan)
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan {plan!r}. "
                         f"Set SQUASH_STRIPE_PRICE_{plan.upper()}")

    kwargs: dict[str, Any] = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "metadata": {"tenant_id": tenant_id, "squash_plan": plan},
    }
    if customer_email:
        kwargs["customer_email"] = customer_email

    session = _stripe.checkout.Session.create(**kwargs)
    return CheckoutResult(
        session_id=session.id,
        url=session.url,
        plan=plan,
        tenant_id=tenant_id,
    )


# ---------------------------------------------------------------------------
# Webhook event handler
# ---------------------------------------------------------------------------

@dataclass
class WebhookResult:
    status: str          # "ok" | "ignored" | "error"
    event_type: str
    tenant_id: str = ""
    new_plan: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"status": self.status, "event": self.event_type}
        if self.tenant_id:
            d["tenant_id"] = self.tenant_id
        if self.new_plan:
            d["new_plan"] = self.new_plan
        if self.detail:
            d["detail"] = self.detail
        return d


class StripeWebhookHandler:
    """Process Stripe webhook events and synchronise plan state with the KeyStore.

    Args:
        key_store:   The KeyStore to update when subscriptions change.
        plan_map:    Optional override for Stripe price ID → plan name mapping.
                     Defaults to reading from environment variables.
    """

    def __init__(
        self,
        key_store: "KeyStore",
        plan_map: dict[str, str] | None = None,
    ) -> None:
        self._store = key_store
        self._plan_map = plan_map if plan_map is not None else _price_to_plan()

    def handle(
        self,
        payload: bytes | str,
        stripe_signature: str = "",
        webhook_secret: str = "",
    ) -> WebhookResult:
        """Parse and dispatch a Stripe webhook event.

        Signature verification is skipped when *webhook_secret* is empty
        (useful for testing without a live Stripe account).

        Args:
            payload:          Raw request body (bytes or str).
            stripe_signature: Value of ``Stripe-Signature`` header.
            webhook_secret:   Webhook signing secret (``whsec_*``).

        Returns:
            WebhookResult describing what was done.
        """
        if isinstance(payload, str):
            payload = payload.encode()

        # Verify signature when secret is provided
        if webhook_secret and stripe_signature:
            if not verify_stripe_signature(payload, stripe_signature, webhook_secret):
                return WebhookResult(
                    status="error",
                    event_type="unknown",
                    detail="Invalid Stripe signature",
                )

        try:
            event = json.loads(payload)
        except json.JSONDecodeError as exc:
            return WebhookResult(status="error", event_type="unknown", detail=str(exc))

        event_type: str = event.get("type", "unknown")
        data_object: dict[str, Any] = event.get("data", {}).get("object", {})

        if event_type == "checkout.session.completed":
            return self._handle_checkout_completed(data_object)
        elif event_type in ("customer.subscription.updated",):
            return self._handle_subscription_updated(data_object)
        elif event_type in ("customer.subscription.deleted",
                            "customer.subscription.paused"):
            return self._handle_subscription_cancelled(data_object)
        elif event_type == "invoice.payment_failed":
            return self._handle_payment_failed(data_object)
        else:
            log.debug("billing: ignored Stripe event %s", event_type)
            return WebhookResult(status="ignored", event_type=event_type)

    # ── Event handlers ────────────────────────────────────────────────────────

    def _handle_checkout_completed(self, obj: dict[str, Any]) -> WebhookResult:
        tenant_id = (obj.get("metadata") or {}).get("tenant_id", "")
        plan = (obj.get("metadata") or {}).get("squash_plan", "")

        if not tenant_id:
            # Fall back to matching price ID from line items (if available)
            pass

        if not plan:
            plan = "pro"  # safe default

        if tenant_id and plan:
            self._store.update_plan(tenant_id, plan)
            log.info("billing: checkout.completed → tenant=%s plan=%s", tenant_id, plan)

        return WebhookResult(
            status="ok",
            event_type="checkout.session.completed",
            tenant_id=tenant_id,
            new_plan=plan,
        )

    def _handle_subscription_updated(self, obj: dict[str, Any]) -> WebhookResult:
        status: str = obj.get("status", "")
        tenant_id: str = (obj.get("metadata") or {}).get("tenant_id", "")
        items = obj.get("items", {}).get("data", [])
        price_id = items[0].get("price", {}).get("id", "") if items else ""
        plan = self._plan_map.get(price_id, "")

        if not plan:
            # Downgrade to free if no recognised price
            if status not in _ACTIVE_STATUSES:
                plan = "free"

        if tenant_id and plan:
            self._store.update_plan(tenant_id, plan)
            log.info("billing: subscription.updated → tenant=%s plan=%s", tenant_id, plan)

        return WebhookResult(
            status="ok",
            event_type="customer.subscription.updated",
            tenant_id=tenant_id,
            new_plan=plan,
        )

    def _handle_subscription_cancelled(self, obj: dict[str, Any]) -> WebhookResult:
        tenant_id: str = (obj.get("metadata") or {}).get("tenant_id", "")
        if tenant_id:
            self._store.update_plan(tenant_id, "free")
            log.info("billing: subscription.deleted → tenant=%s downgraded to free", tenant_id)
        return WebhookResult(
            status="ok",
            event_type="customer.subscription.deleted",
            tenant_id=tenant_id,
            new_plan="free",
        )

    def _handle_payment_failed(self, obj: dict[str, Any]) -> WebhookResult:
        # Do not immediately downgrade — Stripe will retry and send subscription.deleted
        tenant_id: str = (obj.get("metadata") or {}).get("tenant_id", "")
        log.warning("billing: payment_failed for tenant=%s — no plan change yet", tenant_id)
        return WebhookResult(
            status="ok",
            event_type="invoice.payment_failed",
            tenant_id=tenant_id,
        )
