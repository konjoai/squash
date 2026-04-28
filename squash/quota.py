"""squash/quota.py — W142: Attestation counter + monthly quota enforcement.

Monthly quotas per plan:
    free:       10  attestations / month
    pro:        500 attestations / month
    enterprise: unlimited (None)

The quota resets at the start of each calendar month (UTC).  The enforcement
is applied by the API middleware before the attestation pipeline runs, so
quota-exceeded requests never consume compute.

Usage::

    enforcer = QuotaEnforcer(key_store)

    # Before running an attestation:
    result = enforcer.check(key_record)
    if not result.allowed:
        return 429, {"X-Quota-Remaining": "0", "X-Quota-Limit": str(result.limit)}

    # After attestation completes:
    new_count = enforcer.consume(key_id)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from squash.auth import KeyRecord, KeyStore

from squash.auth import PLAN_LIMITS

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class QuotaCheckResult:
    allowed: bool
    used: int           # attestations consumed this period
    limit: int | None   # None = unlimited
    remaining: int | None  # None = unlimited

    @property
    def headers(self) -> dict[str, str]:
        """HTTP headers to include in every attestation response."""
        h: dict[str, str] = {
            "X-Quota-Used": str(self.used),
        }
        if self.limit is not None:
            h["X-Quota-Limit"] = str(self.limit)
            h["X-Quota-Remaining"] = str(self.remaining or 0)
        else:
            h["X-Quota-Limit"] = "unlimited"
            h["X-Quota-Remaining"] = "unlimited"
        return h

# ---------------------------------------------------------------------------
# QuotaEnforcer
# ---------------------------------------------------------------------------

class QuotaEnforcer:
    """Check and consume monthly attestation quota for an API key.

    Args:
        key_store:  The KeyStore instance (used to increment counters).
    """

    def __init__(self, key_store: "KeyStore") -> None:
        self._store = key_store

    def check(self, record: "KeyRecord") -> QuotaCheckResult:
        """Check whether *record*'s tenant has quota remaining.

        Does NOT consume quota — call ``consume()`` after a successful attestation.
        """
        limit = PLAN_LIMITS.get(record.plan, PLAN_LIMITS["free"])["monthly_quota"]
        used = record.attestation_count
        if limit is None:
            return QuotaCheckResult(allowed=True, used=used, limit=None, remaining=None)
        remaining = max(0, limit - used)
        return QuotaCheckResult(
            allowed=remaining > 0,
            used=used,
            limit=limit,
            remaining=remaining,
        )

    def consume(self, key_id: str) -> int:
        """Increment the attestation counter and return the new count."""
        return self._store.increment_attestation_count(key_id)

    def reset(self, key_id: str) -> None:
        """Reset counter for *key_id* (called at billing period renewal)."""
        self._store.reset_quota(key_id)
