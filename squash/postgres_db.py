"""squash/postgres_db.py — W140: PostgreSQL cloud DB (Neon) connector.

Provides a PostgresDB class with the same interface as CloudDB (SQLite) so
the API layer can swap backends by changing a single factory call.

Connection is configured via ``SQUASH_DATABASE_URL``:
    postgresql://user:pass@host/dbname         (psycopg2 sync)
    postgresql+asyncpg://user:pass@host/dbname (asyncpg async — future)

Falls back gracefully: if psycopg2 is not installed or the connection string
is absent, ``make_postgres_db()`` returns None and the caller falls back to
SQLite via CloudDB.

Usage::

    db = make_postgres_db()     # None if not configured
    if db is None:
        db = make_sqlite_db()   # CloudDB

    db.upsert_tenant("t-123", {"plan": "pro"})
    rows = db.list_records("inventory", "t-123")
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema DDL (idempotent CREATE IF NOT EXISTS)
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    record      JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS event_log (
    id          BIGSERIAL PRIMARY KEY,
    table_name  TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    record      JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS event_log_tenant ON event_log (table_name, tenant_id);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id               TEXT PRIMARY KEY,
    key_hash             TEXT UNIQUE NOT NULL,
    tenant_id            TEXT NOT NULL,
    plan                 TEXT NOT NULL DEFAULT 'free',
    name                 TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL,
    last_used_at         TEXT,
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    attestation_count    INTEGER NOT NULL DEFAULT 0,
    billing_period_start TEXT NOT NULL DEFAULT ''
);
"""

# ---------------------------------------------------------------------------
# PostgresDB
# ---------------------------------------------------------------------------

class PostgresDB:
    """Synchronous PostgreSQL backend mirroring the CloudDB interface.

    Uses psycopg2 with a simple connection-per-call pattern suitable for
    low-to-medium throughput.  For high-throughput production use, replace
    with a connection pool (psycopg2.pool or asyncpg + connection pool).
    """

    def __init__(self, dsn: str) -> None:
        import psycopg2  # type: ignore
        import psycopg2.extras  # type: ignore
        self._dsn = dsn
        self._lock = threading.Lock()
        self._conn = psycopg2.connect(dsn)
        self._conn.autocommit = True
        with self._conn.cursor() as cur:
            cur.execute(_DDL)
        log.info("postgres_db: connected to PostgreSQL")

    # ── Tenant store ─────────────────────────────────────────────────────────

    def upsert_tenant(self, tenant_id: str, record: dict[str, Any]) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (tenant_id, record)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO UPDATE SET record = EXCLUDED.record
            """, (tenant_id, json.dumps(record)))

    def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT record FROM tenants WHERE tenant_id = %s", (tenant_id,))
            row = cur.fetchone()
        if row is None:
            return None
        rec = row[0]
        return rec if isinstance(rec, dict) else json.loads(rec)

    def list_tenants(self) -> list[dict[str, Any]]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT tenant_id, record FROM tenants ORDER BY tenant_id")
            rows = cur.fetchall()
        result = []
        for tid, rec in rows:
            d = rec if isinstance(rec, dict) else json.loads(rec)
            d["tenant_id"] = tid
            result.append(d)
        return result

    # ── Event log (inventory, vex_alerts, drift_events, …) ───────────────────

    def append_record(self, table_name: str, tenant_id: str, record: dict[str, Any]) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("""
                INSERT INTO event_log (table_name, tenant_id, record)
                VALUES (%s, %s, %s)
            """, (table_name, tenant_id, json.dumps(record)))

    def list_records(
        self,
        table_name: str,
        tenant_id: str,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("""
                SELECT record FROM event_log
                WHERE table_name = %s AND tenant_id = %s
                ORDER BY id DESC LIMIT %s
            """, (table_name, tenant_id, limit))
            rows = cur.fetchall()
        result = []
        for (rec,) in rows:
            result.append(rec if isinstance(rec, dict) else json.loads(rec))
        return list(reversed(result))

    # ── API keys table ────────────────────────────────────────────────────────

    def upsert_api_key(self, record: dict[str, Any]) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("""
                INSERT INTO api_keys
                (key_id, key_hash, tenant_id, plan, name, created_at,
                 last_used_at, is_active, attestation_count, billing_period_start)
                VALUES (%(key_id)s, %(key_hash)s, %(tenant_id)s, %(plan)s, %(name)s,
                        %(created_at)s, %(last_used_at)s, %(is_active)s,
                        %(attestation_count)s, %(billing_period_start)s)
                ON CONFLICT (key_id) DO UPDATE SET
                    plan = EXCLUDED.plan,
                    last_used_at = EXCLUDED.last_used_at,
                    is_active = EXCLUDED.is_active,
                    attestation_count = EXCLUDED.attestation_count,
                    billing_period_start = EXCLUDED.billing_period_start
            """, record)

    def get_api_key_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("""
                SELECT key_id, key_hash, tenant_id, plan, name, created_at,
                       last_used_at, is_active, attestation_count, billing_period_start
                FROM api_keys WHERE key_hash = %s
            """, (key_hash,))
            row = cur.fetchone()
        if row is None:
            return None
        cols = ["key_id", "key_hash", "tenant_id", "plan", "name", "created_at",
                "last_used_at", "is_active", "attestation_count", "billing_period_start"]
        return dict(zip(cols, row))

    # ── Health / diagnostics ──────────────────────────────────────────────────

    def ping(self) -> bool:
        """Return True if the database connection is healthy."""
        try:
            with self._conn.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_postgres_db(dsn: str | None = None) -> PostgresDB | None:
    """Create a PostgresDB from *dsn* (or ``SQUASH_DATABASE_URL`` env var).

    Returns None if psycopg2 is not installed, the DSN is missing, or the
    connection fails — the caller should fall back to SQLite.
    """
    dsn = dsn or os.environ.get("SQUASH_DATABASE_URL", "")
    if not dsn:
        return None
    try:
        return PostgresDB(dsn)
    except ImportError:
        log.debug("postgres_db: psycopg2 not installed — PostgreSQL unavailable")
        return None
    except Exception as exc:
        log.warning("postgres_db: connection failed (%s) — falling back to SQLite", exc)
        return None
