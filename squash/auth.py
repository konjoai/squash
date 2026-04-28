"""squash/auth.py — W137: DB-backed API key auth + bearer token middleware.

API key format:  sq_live_<32-char-hex>   (production)
                 sq_test_<32-char-hex>   (test / sandbox)

Keys are never stored in plaintext. The full key string is SHA-256 hashed and
stored as the lookup token.  Key IDs (``kid_<16-char-hex>``) are safe to log.

Usage::

    store = KeyStore()
    plaintext, record = store.generate("tenant-123", plan="pro", name="CI key")
    # → plaintext = "sq_live_abc123..."
    # → record.key_id = "kid_..."

    verified = store.verify(plaintext)  # → KeyRecord | None

Environment variables:

    SQUASH_API_KEYS_DB   Path to SQLite file for persistence (default: in-memory only)
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

KEY_PREFIX_LIVE = "sq_live_"
KEY_PREFIX_TEST = "sq_test_"

# Plan → monthly attestation quota and per-minute request rate
PLAN_LIMITS: dict[str, dict[str, Any]] = {
    "free":       {"monthly_quota": 10,   "rate_per_min": 60,   "export_scope": "summary"},
    "pro":        {"monthly_quota": 500,  "rate_per_min": 600,  "export_scope": "compliance"},
    "enterprise": {"monthly_quota": None, "rate_per_min": 6000, "export_scope": "full"},
}

# ---------------------------------------------------------------------------
# KeyRecord
# ---------------------------------------------------------------------------

@dataclass
class KeyRecord:
    key_id: str
    key_hash: str           # SHA-256 hex of plaintext key
    tenant_id: str
    plan: str               # "free" | "pro" | "enterprise"
    name: str               # human label (e.g. "GitHub Actions CI")
    created_at: str         # ISO-8601 UTC
    last_used_at: str | None = None
    is_active: bool = True
    attestation_count: int = 0      # running total for current billing period
    billing_period_start: str = ""  # ISO-8601 date of period start

    @property
    def monthly_quota(self) -> int | None:
        return PLAN_LIMITS.get(self.plan, PLAN_LIMITS["free"])["monthly_quota"]

    @property
    def rate_per_min(self) -> int:
        return PLAN_LIMITS.get(self.plan, PLAN_LIMITS["free"])["rate_per_min"]

    @property
    def quota_remaining(self) -> int | None:
        quota = self.monthly_quota
        if quota is None:
            return None
        return max(0, quota - self.attestation_count)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "plan": self.plan,
            "name": self.name,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "is_active": self.is_active,
            "attestation_count": self.attestation_count,
            "billing_period_start": self.billing_period_start,
            "monthly_quota": self.monthly_quota,
            "quota_remaining": self.quota_remaining,
            "rate_per_min": self.rate_per_min,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_key(plaintext: str) -> str:
    """SHA-256 hex digest of the plaintext key (used as lookup token)."""
    return hashlib.sha256(plaintext.encode()).hexdigest()


def _new_kid() -> str:
    return "kid_" + secrets.token_hex(8)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _billing_period_start() -> str:
    """First day of the current UTC month as ISO-8601 date string."""
    now = datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}-01"


# ---------------------------------------------------------------------------
# KeyStore — thread-safe, optionally SQLite-backed
# ---------------------------------------------------------------------------

class KeyStore:
    """Thread-safe API key store.

    Defaults to pure in-memory storage suitable for tests and single-process
    deployments.  Set ``db_path`` to persist keys across restarts.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        # In-memory indexes
        self._by_kid: dict[str, KeyRecord] = {}   # key_id → record
        self._by_hash: dict[str, str] = {}         # key_hash → key_id
        # SQLite persistence
        self._conn: sqlite3.Connection | None = None
        if db_path:
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
            self._load_from_db()

    # ── Schema ──────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id               TEXT PRIMARY KEY,
                key_hash             TEXT UNIQUE NOT NULL,
                tenant_id            TEXT NOT NULL,
                plan                 TEXT NOT NULL DEFAULT 'free',
                name                 TEXT NOT NULL DEFAULT '',
                created_at           TEXT NOT NULL,
                last_used_at         TEXT,
                is_active            INTEGER NOT NULL DEFAULT 1,
                attestation_count    INTEGER NOT NULL DEFAULT 0,
                billing_period_start TEXT NOT NULL DEFAULT ''
            );
        """)
        self._conn.commit()

    def _load_from_db(self) -> None:
        assert self._conn is not None
        rows = self._conn.execute("SELECT * FROM api_keys").fetchall()
        for row in rows:
            rec = KeyRecord(
                key_id=row["key_id"],
                key_hash=row["key_hash"],
                tenant_id=row["tenant_id"],
                plan=row["plan"],
                name=row["name"],
                created_at=row["created_at"],
                last_used_at=row["last_used_at"],
                is_active=bool(row["is_active"]),
                attestation_count=row["attestation_count"],
                billing_period_start=row["billing_period_start"],
            )
            self._by_kid[rec.key_id] = rec
            self._by_hash[rec.key_hash] = rec.key_id

    def _upsert_db(self, rec: KeyRecord) -> None:
        if self._conn is None:
            return
        self._conn.execute("""
            INSERT OR REPLACE INTO api_keys
            (key_id, key_hash, tenant_id, plan, name, created_at,
             last_used_at, is_active, attestation_count, billing_period_start)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rec.key_id, rec.key_hash, rec.tenant_id, rec.plan, rec.name,
            rec.created_at, rec.last_used_at, int(rec.is_active),
            rec.attestation_count, rec.billing_period_start,
        ))
        self._conn.commit()

    # ── Public API ───────────────────────────────────────────────────────────

    def generate(
        self,
        tenant_id: str,
        *,
        plan: str = "free",
        name: str = "",
        live: bool = True,
    ) -> tuple[str, KeyRecord]:
        """Generate a new API key for *tenant_id*.

        Returns:
            (plaintext_key, KeyRecord) — store the plaintext; it is never
            recoverable after this call.
        """
        if plan not in PLAN_LIMITS:
            raise ValueError(f"Unknown plan: {plan!r}. Valid: {list(PLAN_LIMITS)}")
        prefix = KEY_PREFIX_LIVE if live else KEY_PREFIX_TEST
        raw = prefix + secrets.token_hex(16)
        kid = _new_kid()
        rec = KeyRecord(
            key_id=kid,
            key_hash=_hash_key(raw),
            tenant_id=tenant_id,
            plan=plan,
            name=name or f"{plan} key",
            created_at=_now_iso(),
            billing_period_start=_billing_period_start(),
        )
        with self._lock:
            self._by_kid[kid] = rec
            self._by_hash[rec.key_hash] = kid
            self._upsert_db(rec)
        log.info("auth: generated key %s for tenant %s (plan=%s)", kid, tenant_id, plan)
        return raw, rec

    def verify(self, raw_key: str) -> KeyRecord | None:
        """Verify a plaintext key and return its record, or None if invalid/inactive."""
        if not raw_key:
            return None
        h = _hash_key(raw_key)
        with self._lock:
            kid = self._by_hash.get(h)
            if not kid:
                return None
            rec = self._by_kid.get(kid)
        if rec is None or not rec.is_active:
            return None
        return rec

    def get(self, key_id: str) -> KeyRecord | None:
        """Retrieve a record by key_id (safe to use in logs)."""
        with self._lock:
            return self._by_kid.get(key_id)

    def list_for_tenant(self, tenant_id: str) -> list[KeyRecord]:
        """Return all records for a tenant (active and inactive)."""
        with self._lock:
            return [r for r in self._by_kid.values() if r.tenant_id == tenant_id]

    def revoke(self, key_id: str) -> bool:
        """Deactivate a key. Returns True if found, False if not."""
        with self._lock:
            rec = self._by_kid.get(key_id)
            if rec is None:
                return False
            rec.is_active = False
            self._upsert_db(rec)
        log.info("auth: revoked key %s", key_id)
        return True

    def update_last_used(self, key_id: str) -> None:
        """Record the current timestamp as last_used_at."""
        with self._lock:
            rec = self._by_kid.get(key_id)
            if rec:
                rec.last_used_at = _now_iso()
                self._upsert_db(rec)

    def increment_attestation_count(self, key_id: str) -> int:
        """Increment the attestation counter and return the new count.

        Automatically resets the counter when the billing period has rolled over.
        """
        with self._lock:
            rec = self._by_kid.get(key_id)
            if rec is None:
                return 0
            current_period = _billing_period_start()
            if rec.billing_period_start != current_period:
                rec.attestation_count = 0
                rec.billing_period_start = current_period
            rec.attestation_count += 1
            self._upsert_db(rec)
            return rec.attestation_count

    def update_plan(self, tenant_id: str, new_plan: str) -> list[KeyRecord]:
        """Update the plan on all active keys for a tenant (called by billing webhook)."""
        if new_plan not in PLAN_LIMITS:
            raise ValueError(f"Unknown plan: {new_plan!r}")
        updated: list[KeyRecord] = []
        with self._lock:
            for rec in self._by_kid.values():
                if rec.tenant_id == tenant_id and rec.is_active:
                    rec.plan = new_plan
                    self._upsert_db(rec)
                    updated.append(rec)
        log.info("auth: updated plan → %s for %d keys (tenant=%s)", new_plan, len(updated), tenant_id)
        return updated

    def reset_quota(self, key_id: str) -> None:
        """Reset the attestation counter (used at billing period renewal)."""
        with self._lock:
            rec = self._by_kid.get(key_id)
            if rec:
                rec.attestation_count = 0
                rec.billing_period_start = _billing_period_start()
                self._upsert_db(rec)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_kid)


# ---------------------------------------------------------------------------
# Module-level singleton (used by api.py middleware)
# ---------------------------------------------------------------------------

import os as _os

_KEY_STORE: KeyStore | None = None


def get_key_store() -> KeyStore:
    """Return the module-level KeyStore singleton, creating it on first call."""
    global _KEY_STORE
    if _KEY_STORE is None:
        db_path = _os.environ.get("SQUASH_API_KEYS_DB")
        _KEY_STORE = KeyStore(db_path=db_path or None)
    return _KEY_STORE


def reset_key_store(db_path: str | Path | None = None) -> KeyStore:
    """Replace the singleton (used in tests to get a clean store)."""
    global _KEY_STORE
    _KEY_STORE = KeyStore(db_path=db_path)
    return _KEY_STORE


def extract_bearer(authorization_header: str) -> str:
    """Extract the token from a 'Bearer <token>' header value."""
    if authorization_header.startswith("Bearer "):
        return authorization_header[7:].strip()
    return ""
