"""W138 — Per-tier sliding-window rate limiter tests."""
from __future__ import annotations

import time

import pytest

from squash.auth import PLAN_LIMITS
from squash.rate_limiter import (
    RateLimiter,
    RateCheckResult,
    WINDOW_SECONDS,
    get_rate_limiter,
    reset_rate_limiter,
)


@pytest.fixture
def rl():
    return RateLimiter()


class TestRateLimiterBasic:
    def test_first_request_allowed(self, rl):
        result = rl.check("kid_1", "free")
        assert result.allowed is True

    def test_result_is_named_tuple(self, rl):
        result = rl.check("kid_1", "free")
        assert isinstance(result, RateCheckResult)

    def test_allowed_result_has_zero_retry_after(self, rl):
        result = rl.check("kid_1", "free")
        assert result.retry_after == 0

    def test_window_limit_matches_plan(self, rl):
        result = rl.check("kid_1", "free")
        assert result.window_limit == PLAN_LIMITS["free"]["rate_per_min"]

    def test_window_used_increments(self, rl):
        rl.check("kid_x", "free")
        result = rl.check("kid_x", "free")
        assert result.window_used == 2

    def test_unknown_plan_falls_back_to_free(self, rl):
        result = rl.check("kid_1", "unknown_plan")
        assert result.window_limit == PLAN_LIMITS["free"]["rate_per_min"]


class TestRateLimiterPerPlan:
    def test_pro_limit_higher_than_free(self, rl):
        r_free = rl.check("f", "free")
        r_pro = rl.check("p", "pro")
        assert r_pro.window_limit > r_free.window_limit

    def test_enterprise_limit_highest(self, rl):
        r_pro = rl.check("p", "pro")
        r_ent = rl.check("e", "enterprise")
        assert r_ent.window_limit > r_pro.window_limit


class TestRateLimiterEnforcement:
    def test_exceeding_limit_returns_not_allowed(self):
        rl = RateLimiter()
        limit = 3
        # Patch in a tiny limit by using a custom RateLimiter-like approach:
        # Override PLAN_LIMITS for the test by using a fresh store with a mock plan
        from squash.auth import PLAN_LIMITS as PL
        original = PL.get("__test__")
        PL["__test__"] = {"monthly_quota": 10, "rate_per_min": 3, "export_scope": "test"}
        try:
            for _ in range(3):
                r = rl.check("kid_over", "__test__")
                assert r.allowed
            r = rl.check("kid_over", "__test__")
            assert r.allowed is False
        finally:
            if original is None:
                PL.pop("__test__", None)
            else:
                PL["__test__"] = original

    def test_not_allowed_has_positive_retry_after(self):
        rl = RateLimiter()
        from squash.auth import PLAN_LIMITS as PL
        PL["__tiny__"] = {"monthly_quota": 10, "rate_per_min": 1, "export_scope": "test"}
        try:
            rl.check("kid_tiny", "__tiny__")  # first — OK
            r = rl.check("kid_tiny", "__tiny__")  # second — blocked
            assert r.allowed is False
            assert r.retry_after > 0
        finally:
            PL.pop("__tiny__", None)

    def test_not_allowed_window_used_equals_limit(self):
        rl = RateLimiter()
        from squash.auth import PLAN_LIMITS as PL
        PL["__t2__"] = {"monthly_quota": 10, "rate_per_min": 2, "export_scope": "test"}
        try:
            rl.check("k", "__t2__")
            rl.check("k", "__t2__")
            r = rl.check("k", "__t2__")
            assert r.window_used == 2
        finally:
            PL.pop("__t2__", None)


class TestRateLimiterIsolation:
    def test_different_keys_independent(self, rl):
        from squash.auth import PLAN_LIMITS as PL
        PL["__iso__"] = {"monthly_quota": 10, "rate_per_min": 1, "export_scope": "test"}
        try:
            rl.check("key_a", "__iso__")  # exhausts key_a
            r_b = rl.check("key_b", "__iso__")  # key_b still fresh
            assert r_b.allowed is True
        finally:
            PL.pop("__iso__", None)

    def test_reset_clears_window(self, rl):
        from squash.auth import PLAN_LIMITS as PL
        PL["__rst__"] = {"monthly_quota": 10, "rate_per_min": 1, "export_scope": "test"}
        try:
            rl.check("kid_r", "__rst__")
            r = rl.check("kid_r", "__rst__")
            assert r.allowed is False
            rl.reset("kid_r")
            r2 = rl.check("kid_r", "__rst__")
            assert r2.allowed is True
        finally:
            PL.pop("__rst__", None)

    def test_reset_all_clears_all_windows(self, rl):
        from squash.auth import PLAN_LIMITS as PL
        PL["__rall__"] = {"monthly_quota": 10, "rate_per_min": 1, "export_scope": "test"}
        try:
            rl.check("a", "__rall__")
            rl.check("b", "__rall__")
            rl.reset_all()
            assert rl.check("a", "__rall__").allowed is True
            assert rl.check("b", "__rall__").allowed is True
        finally:
            PL.pop("__rall__", None)


class TestRateLimiterCurrentUsage:
    def test_current_usage_zero_initially(self, rl):
        assert rl.current_usage("new_key") == 0

    def test_current_usage_tracks_requests(self, rl):
        rl.check("kid_cu", "free")
        rl.check("kid_cu", "free")
        assert rl.current_usage("kid_cu") == 2

    def test_current_usage_does_not_add_to_window(self, rl):
        rl.check("kid_cu2", "free")
        before = rl.current_usage("kid_cu2")
        rl.current_usage("kid_cu2")  # should not increment
        after = rl.current_usage("kid_cu2")
        assert before == after


class TestRateLimiterModuleSingleton:
    def test_get_rate_limiter_returns_instance(self):
        rl = reset_rate_limiter()
        assert isinstance(rl, RateLimiter)

    def test_reset_gives_fresh_instance(self):
        from squash.auth import PLAN_LIMITS as PL
        PL["__sngl__"] = {"monthly_quota": 10, "rate_per_min": 1, "export_scope": "test"}
        try:
            rl1 = reset_rate_limiter()
            rl1.check("k", "__sngl__")
            rl1.check("k", "__sngl__")  # blocked
            rl2 = reset_rate_limiter()
            assert rl2.check("k", "__sngl__").allowed is True
        finally:
            PL.pop("__sngl__", None)

    def test_get_rate_limiter_returns_same_instance(self):
        reset_rate_limiter()
        assert get_rate_limiter() is get_rate_limiter()
