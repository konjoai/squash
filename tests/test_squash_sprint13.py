"""tests/test_squash_sprint13.py — Sprint 13 (W202–W204) tests.

Sprint 13: Startup Pricing Tier (Tier 2 #19).

W202 — Plan.STARTUP + Plan.TEAM in PLAN_LIMITS with quotas, seats,
       entitlements; KeyRecord.has_entitlement / max_seats / entitlements
W203 — has_entitlement(plan, name) helper; gating in NotificationDispatcher
       (slack_delivery / teams_delivery) and TicketDispatcher (github_issues
       / jira / linear)
W204 — Stripe checkout supports plan="startup" (in-process via mocked stripe)
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch


# ── W202 — Plan.STARTUP + Plan.TEAM ──────────────────────────────────────────


class TestW202PlanRegistry(unittest.TestCase):
    def test_startup_plan_registered(self) -> None:
        from squash.auth import PLAN_LIMITS
        self.assertIn("startup", PLAN_LIMITS)

    def test_team_plan_registered(self) -> None:
        from squash.auth import PLAN_LIMITS
        self.assertIn("team", PLAN_LIMITS)

    def test_startup_quota_is_500(self) -> None:
        from squash.auth import PLAN_LIMITS
        self.assertEqual(PLAN_LIMITS["startup"]["monthly_quota"], 500)

    def test_team_quota_is_1000(self) -> None:
        from squash.auth import PLAN_LIMITS
        self.assertEqual(PLAN_LIMITS["team"]["monthly_quota"], 1000)

    def test_startup_max_seats_is_3(self) -> None:
        from squash.auth import plan_max_seats
        self.assertEqual(plan_max_seats("startup"), 3)

    def test_team_max_seats_is_10(self) -> None:
        from squash.auth import plan_max_seats
        self.assertEqual(plan_max_seats("team"), 10)

    def test_enterprise_max_seats_unlimited(self) -> None:
        from squash.auth import plan_max_seats
        self.assertIsNone(plan_max_seats("enterprise"))

    def test_existing_plans_quota_unchanged(self) -> None:
        """Backward compat: free / pro / enterprise quotas unchanged."""
        from squash.auth import PLAN_LIMITS
        self.assertEqual(PLAN_LIMITS["free"]["monthly_quota"], 10)
        self.assertEqual(PLAN_LIMITS["pro"]["monthly_quota"], 500)
        self.assertIsNone(PLAN_LIMITS["enterprise"]["monthly_quota"])

    def test_existing_plans_now_carry_entitlements(self) -> None:
        from squash.auth import PLAN_LIMITS
        for plan in ("free", "pro", "startup", "team", "enterprise"):
            self.assertIn("entitlements", PLAN_LIMITS[plan])
            self.assertIn("max_seats", PLAN_LIMITS[plan])


class TestW202KeyRecordEntitlements(unittest.TestCase):
    def _make_record(self, plan: str):
        from squash.auth import KeyRecord
        return KeyRecord(
            key_id="kid_test", key_hash="h", tenant_id="t", plan=plan,
            name="t", created_at="2026-04-30T00:00:00Z",
        )

    def test_max_seats_property_for_startup(self) -> None:
        rec = self._make_record("startup")
        self.assertEqual(rec.max_seats, 3)

    def test_entitlements_set_for_startup(self) -> None:
        rec = self._make_record("startup")
        self.assertIn("vex_read", rec.entitlements)
        self.assertIn("github_issues", rec.entitlements)
        self.assertIn("slack_delivery", rec.entitlements)

    def test_entitlements_set_for_pro_excludes_vex_read(self) -> None:
        rec = self._make_record("pro")
        self.assertNotIn("vex_read", rec.entitlements)
        self.assertNotIn("github_issues", rec.entitlements)
        # But pro still has slack
        self.assertIn("slack_delivery", rec.entitlements)

    def test_has_entitlement_method(self) -> None:
        rec = self._make_record("startup")
        self.assertTrue(rec.has_entitlement("vex_read"))
        self.assertFalse(rec.has_entitlement("on_premise"))

    def test_to_dict_exposes_entitlements_and_seats(self) -> None:
        rec = self._make_record("startup")
        d = rec.to_dict()
        self.assertIn("entitlements", d)
        self.assertIn("max_seats", d)
        self.assertEqual(d["max_seats"], 3)


# ── W203 — has_entitlement helper + gating in dispatchers ────────────────────


class TestW203HasEntitlement(unittest.TestCase):
    def test_free_has_no_entitlements(self) -> None:
        from squash.auth import has_entitlement
        for ent in ("vex_read", "slack_delivery", "github_issues",
                    "saml_sso", "on_premise"):
            self.assertFalse(has_entitlement("free", ent))

    def test_pro_has_slack_not_vex_or_github(self) -> None:
        from squash.auth import has_entitlement
        self.assertTrue(has_entitlement("pro", "slack_delivery"))
        self.assertFalse(has_entitlement("pro", "vex_read"))
        self.assertFalse(has_entitlement("pro", "github_issues"))

    def test_startup_unlocks_vex_and_github(self) -> None:
        from squash.auth import has_entitlement
        self.assertTrue(has_entitlement("startup", "vex_read"))
        self.assertTrue(has_entitlement("startup", "github_issues"))
        self.assertTrue(has_entitlement("startup", "slack_delivery"))
        # But still no SAML
        self.assertFalse(has_entitlement("startup", "saml_sso"))

    def test_team_unlocks_saml_jira_linear(self) -> None:
        from squash.auth import has_entitlement
        self.assertTrue(has_entitlement("team", "saml_sso"))
        self.assertTrue(has_entitlement("team", "jira"))
        self.assertTrue(has_entitlement("team", "linear"))
        self.assertTrue(has_entitlement("team", "audit_export"))

    def test_enterprise_unlocks_on_premise_air_gapped(self) -> None:
        from squash.auth import has_entitlement
        self.assertTrue(has_entitlement("enterprise", "on_premise"))
        self.assertTrue(has_entitlement("enterprise", "air_gapped"))

    def test_empty_plan_returns_false_for_everything(self) -> None:
        """Safe default: unauthenticated callers get nothing."""
        from squash.auth import has_entitlement
        for ent in ("vex_read", "slack_delivery", "github_issues"):
            self.assertFalse(has_entitlement("", ent))

    def test_unknown_plan_falls_back_to_free(self) -> None:
        from squash.auth import has_entitlement
        self.assertFalse(has_entitlement("totally-fake-plan", "vex_read"))


class TestW203NotificationGating(unittest.TestCase):
    """Slack / Teams delivery gated by entitlements when `plan` is supplied."""

    def _make_dispatcher(self):
        from squash.notifications import NotificationConfig, NotificationDispatcher
        cfg = NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/services/T/B/X",
            teams_webhook_url="https://acme.webhook.office.com/X",
        )
        return NotificationDispatcher(cfg)

    def test_no_plan_argument_preserves_existing_behaviour(self) -> None:
        d = self._make_dispatcher()
        with patch.object(d, "_post_slack") as ps, \
             patch.object(d, "_post_teams") as pt:
            r = d.notify("attestation.failed", model_id="m1")
        ps.assert_called_once()
        pt.assert_called_once()
        self.assertEqual(r.targets_attempted, 2)

    def test_free_plan_skips_slack_and_teams(self) -> None:
        d = self._make_dispatcher()
        with patch.object(d, "_post_slack") as ps, \
             patch.object(d, "_post_teams") as pt:
            r = d.notify("attestation.failed", model_id="m1", plan="free")
        ps.assert_not_called()
        pt.assert_not_called()
        self.assertEqual(r.targets_attempted, 0)

    def test_pro_plan_allows_slack_and_teams(self) -> None:
        d = self._make_dispatcher()
        with patch.object(d, "_post_slack") as ps, \
             patch.object(d, "_post_teams") as pt:
            d.notify("attestation.failed", model_id="m1", plan="pro")
        ps.assert_called_once()
        pt.assert_called_once()

    def test_startup_plan_allows_slack(self) -> None:
        d = self._make_dispatcher()
        with patch.object(d, "_post_slack") as ps:
            d.notify("attestation.failed", model_id="m1", plan="startup")
        ps.assert_called_once()


class TestW203TicketingGating(unittest.TestCase):
    """GitHub / Jira / Linear gated by entitlements when `plan` is supplied."""

    def _make_dispatcher(self, backend: str):
        from squash.ticketing import TicketConfig, TicketDispatcher
        cfg = TicketConfig(
            backend=backend,
            github_token="tok", github_repo="acme/m",
            jira_url="https://acme.atlassian.net", jira_user="x@y.com",
            jira_token="t", jira_project="ML",
            linear_token="lin_key", linear_team_id="t1",
        )
        return TicketDispatcher(cfg)

    def test_no_plan_argument_preserves_behaviour(self) -> None:
        d = self._make_dispatcher("github")
        with patch.object(d, "_create_github") as gh:
            from squash.ticketing import TicketResult
            gh.return_value = TicketResult(success=True, backend="github",
                                            ticket_url="https://github.com/i/1",
                                            ticket_id="1")
            r = d.create_ticket("title", "body")
        gh.assert_called_once()
        self.assertTrue(r.success)

    def test_free_plan_blocks_github_issues(self) -> None:
        d = self._make_dispatcher("github")
        with patch.object(d, "_create_github") as gh:
            r = d.create_ticket("title", "body", plan="free")
        gh.assert_not_called()
        self.assertFalse(r.success)
        self.assertIn("entitlement", r.error.lower())

    def test_pro_plan_blocks_github_issues(self) -> None:
        d = self._make_dispatcher("github")
        with patch.object(d, "_create_github") as gh:
            r = d.create_ticket("title", "body", plan="pro")
        gh.assert_not_called()
        self.assertFalse(r.success)

    def test_startup_plan_allows_github_issues(self) -> None:
        d = self._make_dispatcher("github")
        with patch.object(d, "_create_github") as gh:
            from squash.ticketing import TicketResult
            gh.return_value = TicketResult(success=True, backend="github",
                                            ticket_url="https://github.com/i/1",
                                            ticket_id="1")
            r = d.create_ticket("title", "body", plan="startup")
        gh.assert_called_once()
        self.assertTrue(r.success)

    def test_startup_plan_blocks_jira(self) -> None:
        """jira requires team+ — startup is not enough."""
        d = self._make_dispatcher("jira")
        with patch.object(d, "_create_jira") as j:
            r = d.create_ticket("title", "body", plan="startup")
        j.assert_not_called()
        self.assertFalse(r.success)

    def test_team_plan_allows_jira(self) -> None:
        d = self._make_dispatcher("jira")
        with patch.object(d, "_create_jira") as j:
            from squash.ticketing import TicketResult
            j.return_value = TicketResult(success=True, backend="jira",
                                          ticket_url="x", ticket_id="ML-1")
            r = d.create_ticket("title", "body", plan="team")
        j.assert_called_once()
        self.assertTrue(r.success)


# ── W204 — Stripe checkout supports plan=startup ─────────────────────────────


class TestW204StartupCheckout(unittest.TestCase):
    """Validate that Stripe checkout flows through for plan='startup'."""

    def setUp(self) -> None:
        # Save and clean env so test is hermetic
        self._saved = {
            k: os.environ.get(k)
            for k in (
                "SQUASH_STRIPE_SECRET_KEY",
                "SQUASH_STRIPE_PRICE_PRO",
                "SQUASH_STRIPE_PRICE_STARTUP",
                "SQUASH_STRIPE_PRICE_TEAM",
                "SQUASH_STRIPE_PRICE_ENTERPRISE",
            )
        }
        os.environ["SQUASH_STRIPE_SECRET_KEY"] = "sk_test_dummy"
        os.environ["SQUASH_STRIPE_PRICE_STARTUP"] = "price_startup_xxx"
        # Make sure other plans don't accidentally satisfy
        os.environ.pop("SQUASH_STRIPE_PRICE_PRO", None)

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_create_checkout_session_supports_startup(self) -> None:
        from squash.billing import create_checkout_session
        fake_stripe = MagicMock()
        fake_stripe.checkout.Session.create.return_value = MagicMock(
            id="cs_test_123",
            url="https://checkout.stripe.com/c/cs_test_123",
        )
        with patch.dict("sys.modules", {"stripe": fake_stripe}):
            result = create_checkout_session(
                tenant_id="acme",
                plan="startup",
                success_url="https://x/success",
                cancel_url="https://x/cancel",
                customer_email="founder@acme.io",
            )
        self.assertEqual(result.plan, "startup")
        self.assertEqual(result.tenant_id, "acme")
        self.assertEqual(result.url, "https://checkout.stripe.com/c/cs_test_123")
        fake_stripe.checkout.Session.create.assert_called_once()
        kwargs = fake_stripe.checkout.Session.create.call_args.kwargs
        self.assertEqual(kwargs["line_items"][0]["price"], "price_startup_xxx")
        self.assertEqual(kwargs["metadata"]["squash_plan"], "startup")

    def test_create_checkout_session_raises_when_startup_price_missing(self) -> None:
        os.environ.pop("SQUASH_STRIPE_PRICE_STARTUP", None)
        from squash.billing import create_checkout_session
        fake_stripe = MagicMock()
        with patch.dict("sys.modules", {"stripe": fake_stripe}):
            with self.assertRaises(ValueError) as ctx:
                create_checkout_session(
                    tenant_id="acme",
                    plan="startup",
                    success_url="https://x/success",
                    cancel_url="https://x/cancel",
                )
        self.assertIn("STARTUP", str(ctx.exception))


class TestW204BillingWebhookStartupSync(unittest.TestCase):
    """Verify the Stripe price_id → plan map recognises STARTUP."""

    def test_startup_price_id_maps_to_plan(self) -> None:
        # Set price ID env, re-read map
        prev = os.environ.get("SQUASH_STRIPE_PRICE_STARTUP")
        os.environ["SQUASH_STRIPE_PRICE_STARTUP"] = "price_startup_yyy"
        try:
            from squash.billing import _price_to_plan
            mapping = _price_to_plan()
            self.assertEqual(mapping.get("price_startup_yyy"), "startup")
        finally:
            if prev is None:
                os.environ.pop("SQUASH_STRIPE_PRICE_STARTUP", None)
            else:
                os.environ["SQUASH_STRIPE_PRICE_STARTUP"] = prev


# ── Module count gate (Sprint 13 added 0 new modules) ────────────────────────


class TestSprint13ModuleCountUnchanged(unittest.TestCase):
    """Sprint 13 added 0 modules (count 71 at ship). Sprint 14 W205 (B1)
    since added hf_scanner.py — current 72."""

    def test_module_count_is_71(self) -> None:
        from pathlib import Path
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        self.assertEqual(len(py_files), 78,
                         msg="Sprint 13 added 0 modules; B1 (W205) added hf_scanner.py.")


if __name__ == "__main__":
    unittest.main()
