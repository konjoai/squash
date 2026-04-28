"""squash/rate_limiter.py — W138: Per-key, per-tier sliding-window rate limiter.

Limits are enforced per API key (not per IP), using the plan's ``rate_per_min``
ceiling.  The sliding window is 60 seconds.

Limits per plan:
    free:       60  req/min
    pro:        600 req/min
    enterprise: 6000 req/min

Usage::

    limiter = RateLimiter()
    allowed, retry_after = limiter.check("kid_abc", plan="pro")
    if not allowed:
        return 429, {"Retry-After": retry_after}

Thread-safe.  No external dependencies — uses only stdlib ``collections.deque``
and ``time.monotonic``.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import NamedTuple

from squash.auth import PLAN_LIMITS

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class RateCheckResult(NamedTuple):
    allowed: bool
    retry_after: int      # seconds until next slot opens (0 if allowed)
    window_used: int      # requests in the current 60-s window
    window_limit: int     # limit for the plan

# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------

WINDOW_SECONDS = 60


class RateLimiter:
    """Per-key sliding-window rate limiter.

    Args:
        window_seconds:  Sliding window duration (default: 60 s).
    """

    def __init__(self, window_seconds: int = WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        # key_id → deque of monotonic timestamps for requests in the window
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key_id: str, plan: str) -> RateCheckResult:
        """Check whether *key_id* is within its plan's rate limit.

        Side effect: records this request if allowed.

        Returns:
            RateCheckResult(allowed, retry_after, window_used, window_limit)
        """
        limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["rate_per_min"]
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            window = self._windows[key_id]
            # Evict timestamps outside the sliding window
            while window and window[0] < cutoff:
                window.popleft()

            used = len(window)

            if used >= limit:
                retry_after = int(self._window - (now - window[0])) + 1
                return RateCheckResult(
                    allowed=False,
                    retry_after=retry_after,
                    window_used=used,
                    window_limit=limit,
                )

            window.append(now)
            return RateCheckResult(
                allowed=True,
                retry_after=0,
                window_used=used + 1,
                window_limit=limit,
            )

    def reset(self, key_id: str) -> None:
        """Clear the sliding window for a key (used in tests)."""
        with self._lock:
            self._windows.pop(key_id, None)

    def reset_all(self) -> None:
        """Clear all sliding windows."""
        with self._lock:
            self._windows.clear()

    def current_usage(self, key_id: str) -> int:
        """Return the number of requests in the current window without recording a new one."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            window = self._windows.get(key_id, deque())
            return sum(1 for t in window if t >= cutoff)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_RATE_LIMITER: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _RATE_LIMITER
    if _RATE_LIMITER is None:
        _RATE_LIMITER = RateLimiter()
    return _RATE_LIMITER


def reset_rate_limiter() -> RateLimiter:
    global _RATE_LIMITER
    _RATE_LIMITER = RateLimiter()
    return _RATE_LIMITER
