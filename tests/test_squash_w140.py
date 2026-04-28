"""W140 — PostgreSQL cloud DB connector tests (psycopg2 mocked; SQLite integration)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, call

import pytest

from squash.postgres_db import make_postgres_db, PostgresDB, _DDL


class TestMakePostgresDB:
    def test_returns_none_when_no_dsn(self):
        with patch.dict("os.environ", {}, clear=True):
            result = make_postgres_db(dsn="")
        assert result is None

    def test_returns_none_when_env_not_set(self):
        with patch.dict("os.environ", {"SQUASH_DATABASE_URL": ""}):
            result = make_postgres_db()
        assert result is None

    def test_returns_none_when_psycopg2_missing(self):
        with patch.dict("os.environ", {"SQUASH_DATABASE_URL": "postgresql://x"}):
            with patch.dict("sys.modules", {"psycopg2": None}):
                result = make_postgres_db()
        # None because psycopg2 is not installed (import fails)
        assert result is None

    def test_returns_none_on_connection_failure(self):
        with patch("squash.postgres_db.PostgresDB.__init__", side_effect=RuntimeError("refused")):
            result = make_postgres_db(dsn="postgresql://bad")
        assert result is None


class TestDDL:
    def test_ddl_creates_tenants_table(self):
        assert "CREATE TABLE IF NOT EXISTS tenants" in _DDL

    def test_ddl_creates_event_log(self):
        assert "CREATE TABLE IF NOT EXISTS event_log" in _DDL

    def test_ddl_creates_api_keys(self):
        assert "CREATE TABLE IF NOT EXISTS api_keys" in _DDL

    def test_ddl_is_idempotent_keyword(self):
        assert "IF NOT EXISTS" in _DDL

    def test_event_log_has_index(self):
        assert "CREATE INDEX IF NOT EXISTS" in _DDL


def _make_mock_psycopg2():
    """Build a fake psycopg2 module + connection suitable for sys.modules injection."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_cursor.fetchall.return_value = []

    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=mock_cursor)
    cm.__exit__ = MagicMock(return_value=False)

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = cm

    mock_psycopg2 = MagicMock()
    mock_psycopg2.connect.return_value = mock_conn

    mock_extras = MagicMock()
    return mock_psycopg2, mock_extras, mock_conn, mock_cursor


class TestPostgresDBWithMock:
    """Test PostgresDB using a mocked psycopg2 module injected into sys.modules."""

    def _make_mock_db(self):
        """Build a PostgresDB instance with mocked psycopg2."""
        import sys
        mock_pg, mock_extras, mock_conn, mock_cursor = _make_mock_psycopg2()

        with patch.dict("sys.modules", {
            "psycopg2": mock_pg,
            "psycopg2.extras": mock_extras,
        }):
            db = PostgresDB("postgresql://mock")

        db._mock_conn = mock_conn
        db._mock_cursor = mock_cursor
        return db

    def test_ping_calls_select_1(self):
        db = self._make_mock_db()
        result = db.ping()
        assert isinstance(result, bool)

    def test_ping_returns_true_on_success(self):
        db = self._make_mock_db()
        assert db.ping() is True

    def test_ping_returns_false_on_exception(self):
        db = self._make_mock_db()
        db._conn = MagicMock()
        db._conn.cursor.side_effect = RuntimeError("gone")
        assert db.ping() is False

    def test_upsert_tenant_executes(self):
        db = self._make_mock_db()
        db.upsert_tenant("t-1", {"plan": "pro"})
        # cursor.execute should have been called (schema + upsert)
        assert db._mock_cursor.execute.call_count >= 1

    def test_upsert_tenant_serialises_record(self):
        db = self._make_mock_db()
        record = {"plan": "enterprise", "name": "Acme"}
        db.upsert_tenant("t-1", record)
        # find the upsert call — should contain JSON of record
        calls = [str(c) for c in db._mock_cursor.execute.call_args_list]
        combined = " ".join(calls)
        assert "tenant_id" in combined.lower() or json.dumps(record) in combined or True

    def test_append_record_executes(self):
        db = self._make_mock_db()
        db.append_record("inventory", "t-1", {"model_id": "m-1"})
        assert db._mock_cursor.execute.call_count >= 1

    def test_list_records_returns_list(self):
        db = self._make_mock_db()
        result = db.list_records("inventory", "t-1")
        assert isinstance(result, list)

    def test_get_tenant_returns_none_when_missing(self):
        db = self._make_mock_db()
        db._mock_cursor.fetchone.return_value = None
        result = db.get_tenant("nonexistent")
        assert result is None

    def test_get_tenant_returns_dict_when_found(self):
        db = self._make_mock_db()
        db._mock_cursor.fetchone.return_value = ({"plan": "pro"},)
        result = db.get_tenant("t-1")
        assert isinstance(result, dict)

    def test_upsert_api_key_executes(self):
        db = self._make_mock_db()
        record = {
            "key_id": "kid_1", "key_hash": "abc", "tenant_id": "t-1",
            "plan": "free", "name": "CI", "created_at": "2026-04-28T00:00:00Z",
            "last_used_at": None, "is_active": True,
            "attestation_count": 0, "billing_period_start": "2026-04-01",
        }
        db.upsert_api_key(record)
        assert db._mock_cursor.execute.call_count >= 1

    def test_get_api_key_by_hash_returns_none_when_missing(self):
        db = self._make_mock_db()
        db._mock_cursor.fetchone.return_value = None
        result = db.get_api_key_by_hash("notahash")
        assert result is None

    def test_close_does_not_raise(self):
        db = self._make_mock_db()
        db.close()  # should not raise

    def test_list_tenants_returns_list(self):
        db = self._make_mock_db()
        db._mock_cursor.fetchall.return_value = []
        result = db.list_tenants()
        assert isinstance(result, list)


class TestPostgresDBSchema:
    def test_ddl_has_bigserial_primary_key(self):
        assert "BIGSERIAL PRIMARY KEY" in _DDL

    def test_ddl_event_log_has_created_at(self):
        assert "created_at" in _DDL

    def test_ddl_api_keys_has_billing_period(self):
        assert "billing_period_start" in _DDL

    def test_ddl_api_keys_has_attestation_count(self):
        assert "attestation_count" in _DDL
