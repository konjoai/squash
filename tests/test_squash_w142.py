"""W142 — Attestation counter + monthly quota enforcement tests."""
from __future__ import annotations

import pytest

from squash.auth import KeyRecord, KeyStore, PLAN_LIMITS, _billing_period_start
from squash.quota import QuotaEnforcer, QuotaCheckResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    return KeyStore()


@pytest.fixture
def enforcer(store):
    return QuotaEnforcer(store)


def _make_rec(plan: str = "free", count: int = 0) -> KeyRecord:
    return KeyRecord(
        key_id="kid_q",
        key_hash="h",
        tenant_id="t",
        plan=plan,
        name="test",
        created_at="2026-04-28T00:00:00Z",
        attestation_count=count,
        billing_period_start=_billing_period_start(),
    )


# ---------------------------------------------------------------------------
# QuotaCheckResult
# ---------------------------------------------------------------------------

class TestQuotaCheckResult:
    def test_allowed_true_for_remaining_quota(self):
        r = QuotaCheckResult(allowed=True, used=5, limit=10, remaining=5)
        assert r.allowed is True

    def test_allowed_false_when_exhausted(self):
        r = QuotaCheckResult(allowed=False, used=10, limit=10, remaining=0)
        assert r.allowed is False

    def test_headers_include_used(self):
        r = QuotaCheckResult(allowed=True, used=3, limit=10, remaining=7)
        assert r.headers["X-Quota-Used"] == "3"

    def test_headers_include_limit_and_remaining(self):
        r = QuotaCheckResult(allowed=True, used=3, limit=10, remaining=7)
        assert r.headers["X-Quota-Limit"] == "10"
        assert r.headers["X-Quota-Remaining"] == "7"

    def test_unlimited_headers(self):
        r = QuotaCheckResult(allowed=True, used=100, limit=None, remaining=None)
        assert r.headers["X-Quota-Limit"] == "unlimited"
        assert r.headers["X-Quota-Remaining"] == "unlimited"


# ---------------------------------------------------------------------------
# QuotaEnforcer.check — free plan
# ---------------------------------------------------------------------------

class TestQuotaEnforcerFree:
    def test_zero_count_allowed(self, enforcer):
        rec = _make_rec("free", 0)
        result = enforcer.check(rec)
        assert result.allowed is True

    def test_below_limit_allowed(self, enforcer):
        rec = _make_rec("free", 9)
        result = enforcer.check(rec)
        assert result.allowed is True

    def test_at_limit_not_allowed(self, enforcer):
        rec = _make_rec("free", 10)
        result = enforcer.check(rec)
        assert result.allowed is False

    def test_over_limit_not_allowed(self, enforcer):
        rec = _make_rec("free", 99)
        result = enforcer.check(rec)
        assert result.allowed is False

    def test_remaining_counts_down(self, enforcer):
        rec = _make_rec("free", 7)
        result = enforcer.check(rec)
        assert result.remaining == 3

    def test_remaining_zero_at_limit(self, enforcer):
        rec = _make_rec("free", 10)
        result = enforcer.check(rec)
        assert result.remaining == 0

    def test_limit_equals_plan_quota(self, enforcer):
        rec = _make_rec("free", 0)
        result = enforcer.check(rec)
        assert result.limit == PLAN_LIMITS["free"]["monthly_quota"]


# ---------------------------------------------------------------------------
# QuotaEnforcer.check — pro plan
# ---------------------------------------------------------------------------

class TestQuotaEnforcerPro:
    def test_pro_allows_up_to_500(self, enforcer):
        rec = _make_rec("pro", 499)
        result = enforcer.check(rec)
        assert result.allowed is True

    def test_pro_blocks_at_500(self, enforcer):
        rec = _make_rec("pro", 500)
        result = enforcer.check(rec)
        assert result.allowed is False

    def test_pro_limit_is_500(self, enforcer):
        rec = _make_rec("pro", 0)
        assert enforcer.check(rec).limit == 500


# ---------------------------------------------------------------------------
# QuotaEnforcer.check — enterprise plan
# ---------------------------------------------------------------------------

class TestQuotaEnforcerEnterprise:
    def test_enterprise_always_allowed(self, enforcer):
        rec = _make_rec("enterprise", 999999)
        result = enforcer.check(rec)
        assert result.allowed is True

    def test_enterprise_limit_is_none(self, enforcer):
        rec = _make_rec("enterprise", 0)
        assert enforcer.check(rec).limit is None

    def test_enterprise_remaining_is_none(self, enforcer):
        rec = _make_rec("enterprise", 100)
        assert enforcer.check(rec).remaining is None


# ---------------------------------------------------------------------------
# QuotaEnforcer.consume
# ---------------------------------------------------------------------------

class TestQuotaEnforcerConsume:
    def test_consume_increments_count(self, store, enforcer):
        _, rec = store.generate("t", plan="free")
        count = enforcer.consume(rec.key_id)
        assert count == 1

    def test_consume_twice_returns_2(self, store, enforcer):
        _, rec = store.generate("t", plan="free")
        enforcer.consume(rec.key_id)
        count = enforcer.consume(rec.key_id)
        assert count == 2

    def test_consume_nonexistent_key_returns_0(self, enforcer):
        assert enforcer.consume("kid_ghost") == 0

    def test_check_after_consume_reflects_new_count(self, store, enforcer):
        _, rec = store.generate("t", plan="free", name="k")
        for _ in range(5):
            enforcer.consume(rec.key_id)
        fresh_rec = store.get(rec.key_id)
        result = enforcer.check(fresh_rec)
        assert result.used == 5
        assert result.remaining == 5


# ---------------------------------------------------------------------------
# QuotaEnforcer.reset
# ---------------------------------------------------------------------------

class TestQuotaEnforcerReset:
    def test_reset_clears_count(self, store, enforcer):
        _, rec = store.generate("t", plan="free")
        enforcer.consume(rec.key_id)
        enforcer.consume(rec.key_id)
        enforcer.reset(rec.key_id)
        fresh = store.get(rec.key_id)
        assert fresh.attestation_count == 0

    def test_reset_allows_further_attestations(self, store, enforcer):
        _, rec = store.generate("t", plan="free")
        for _ in range(10):
            enforcer.consume(rec.key_id)
        enforcer.reset(rec.key_id)
        fresh = store.get(rec.key_id)
        result = enforcer.check(fresh)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Quota enforcement contract: check-before-attest / consume-after-attest
# ---------------------------------------------------------------------------

class TestQuotaContract:
    def test_free_plan_allows_exactly_10_attestations(self, store, enforcer):
        _, rec = store.generate("t-contract", plan="free")
        allowed_count = 0
        for i in range(15):
            fresh = store.get(rec.key_id)
            qr = enforcer.check(fresh)
            if qr.allowed:
                enforcer.consume(rec.key_id)
                allowed_count += 1
        assert allowed_count == 10

    def test_enterprise_allows_unlimited_attestations(self, store, enforcer):
        _, rec = store.generate("t-ent", plan="enterprise")
        for _ in range(1000):
            fresh = store.get(rec.key_id)
            qr = enforcer.check(fresh)
            assert qr.allowed is True
            enforcer.consume(rec.key_id)
