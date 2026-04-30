"""W137 — API key auth + bearer token middleware tests."""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest

from squash.auth import (
    PLAN_LIMITS,
    KeyRecord,
    KeyStore,
    _billing_period_start,
    _hash_key,
    _now_iso,
    extract_bearer,
    get_key_store,
    reset_key_store,
    KEY_PREFIX_LIVE,
    KEY_PREFIX_TEST,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    return KeyStore()


@pytest.fixture
def store_with_sqlite(tmp_path):
    s = KeyStore(db_path=tmp_path / "keys.db")
    yield s
    s.close()


# ---------------------------------------------------------------------------
# PLAN_LIMITS contract
# ---------------------------------------------------------------------------

class TestPlanLimits:
    def test_all_plans_present(self):
        # Sprint 13 (W202) added startup + team to the plan registry.
        assert set(PLAN_LIMITS.keys()) == {
            "free", "pro", "startup", "team", "enterprise",
        }

    def test_free_quota(self):
        assert PLAN_LIMITS["free"]["monthly_quota"] == 10

    def test_pro_quota(self):
        assert PLAN_LIMITS["pro"]["monthly_quota"] == 500

    def test_enterprise_quota_unlimited(self):
        assert PLAN_LIMITS["enterprise"]["monthly_quota"] is None

    def test_rate_limits_ascending(self):
        assert PLAN_LIMITS["free"]["rate_per_min"] < PLAN_LIMITS["pro"]["rate_per_min"]
        assert PLAN_LIMITS["pro"]["rate_per_min"] < PLAN_LIMITS["enterprise"]["rate_per_min"]

    def test_export_scopes_distinct(self):
        scopes = {v["export_scope"] for v in PLAN_LIMITS.values()}
        assert len(scopes) == 3


# ---------------------------------------------------------------------------
# _hash_key / extract_bearer helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_hash_key_is_sha256_hex(self):
        raw = "sq_live_abc123"
        expected = hashlib.sha256(raw.encode()).hexdigest()
        assert _hash_key(raw) == expected

    def test_hash_key_same_input_same_output(self):
        assert _hash_key("abc") == _hash_key("abc")

    def test_hash_key_different_inputs_different(self):
        assert _hash_key("a") != _hash_key("b")

    def test_extract_bearer_standard(self):
        assert extract_bearer("Bearer sq_live_xyz") == "sq_live_xyz"

    def test_extract_bearer_empty_header(self):
        assert extract_bearer("") == ""

    def test_extract_bearer_no_bearer_prefix(self):
        assert extract_bearer("sq_live_xyz") == ""

    def test_extract_bearer_strips_whitespace(self):
        assert extract_bearer("Bearer  sq_live_xyz  ") == "sq_live_xyz"

    def test_billing_period_start_format(self):
        bp = _billing_period_start()
        parts = bp.split("-")
        assert len(parts) == 3
        assert parts[2] == "01"

    def test_now_iso_format(self):
        ts = _now_iso()
        assert ts.endswith("Z")
        assert "T" in ts


# ---------------------------------------------------------------------------
# KeyRecord dataclass
# ---------------------------------------------------------------------------

class TestKeyRecord:
    def test_monthly_quota_free(self):
        rec = KeyRecord(
            key_id="kid_1", key_hash="h", tenant_id="t1",
            plan="free", name="k", created_at="2026-04-28T00:00:00Z",
        )
        assert rec.monthly_quota == 10

    def test_monthly_quota_enterprise_is_none(self):
        rec = KeyRecord(
            key_id="kid_2", key_hash="h", tenant_id="t1",
            plan="enterprise", name="k", created_at="2026-04-28T00:00:00Z",
        )
        assert rec.monthly_quota is None

    def test_rate_per_min_pro(self):
        rec = KeyRecord(
            key_id="kid_3", key_hash="h", tenant_id="t1",
            plan="pro", name="k", created_at="2026-04-28T00:00:00Z",
        )
        assert rec.rate_per_min == 600

    def test_quota_remaining_free(self):
        rec = KeyRecord(
            key_id="kid_4", key_hash="h", tenant_id="t1",
            plan="free", name="k", created_at="2026-04-28T00:00:00Z",
            attestation_count=7,
        )
        assert rec.quota_remaining == 3

    def test_quota_remaining_enterprise_is_none(self):
        rec = KeyRecord(
            key_id="kid_5", key_hash="h", tenant_id="t1",
            plan="enterprise", name="k", created_at="2026-04-28T00:00:00Z",
            attestation_count=9999,
        )
        assert rec.quota_remaining is None

    def test_to_dict_contains_required_keys(self):
        rec = KeyRecord(
            key_id="kid_6", key_hash="h", tenant_id="t1",
            plan="pro", name="CI", created_at="2026-04-28T00:00:00Z",
        )
        d = rec.to_dict()
        for key in ("key_id", "tenant_id", "plan", "name", "created_at",
                    "is_active", "attestation_count", "monthly_quota",
                    "quota_remaining", "rate_per_min"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_no_key_hash(self):
        rec = KeyRecord(
            key_id="kid_7", key_hash="secret", tenant_id="t1",
            plan="free", name="k", created_at="2026-04-28T00:00:00Z",
        )
        assert "key_hash" not in rec.to_dict()


# ---------------------------------------------------------------------------
# KeyStore — in-memory
# ---------------------------------------------------------------------------

class TestKeyStoreInMemory:
    def test_generate_returns_plaintext_and_record(self, store):
        raw, rec = store.generate("tenant-1", plan="pro", name="test key")
        assert isinstance(raw, str)
        assert isinstance(rec, KeyRecord)

    def test_generated_key_has_live_prefix(self, store):
        raw, _ = store.generate("t", plan="free")
        assert raw.startswith(KEY_PREFIX_LIVE)

    def test_generated_test_key_has_test_prefix(self, store):
        raw, _ = store.generate("t", plan="free", live=False)
        assert raw.startswith(KEY_PREFIX_TEST)

    def test_key_minimum_length(self, store):
        raw, _ = store.generate("t", plan="free")
        assert len(raw) >= len(KEY_PREFIX_LIVE) + 32

    def test_verify_valid_key(self, store):
        raw, rec = store.generate("t", plan="free")
        verified = store.verify(raw)
        assert verified is not None
        assert verified.key_id == rec.key_id

    def test_verify_invalid_key_returns_none(self, store):
        assert store.verify("sq_live_notarealkey") is None

    def test_verify_empty_returns_none(self, store):
        assert store.verify("") is None

    def test_verify_revoked_key_returns_none(self, store):
        raw, rec = store.generate("t", plan="free")
        store.revoke(rec.key_id)
        assert store.verify(raw) is None

    def test_get_by_key_id(self, store):
        _, rec = store.generate("t", plan="pro")
        retrieved = store.get(rec.key_id)
        assert retrieved is not None
        assert retrieved.key_id == rec.key_id

    def test_get_unknown_key_id_returns_none(self, store):
        assert store.get("kid_nonexistent") is None

    def test_revoke_existing_returns_true(self, store):
        _, rec = store.generate("t")
        assert store.revoke(rec.key_id) is True

    def test_revoke_nonexistent_returns_false(self, store):
        assert store.revoke("kid_ghost") is False

    def test_update_last_used(self, store):
        _, rec = store.generate("t")
        assert rec.last_used_at is None
        store.update_last_used(rec.key_id)
        updated = store.get(rec.key_id)
        assert updated.last_used_at is not None

    def test_increment_attestation_count(self, store):
        _, rec = store.generate("t")
        assert store.increment_attestation_count(rec.key_id) == 1
        assert store.increment_attestation_count(rec.key_id) == 2
        assert store.increment_attestation_count(rec.key_id) == 3

    def test_increment_resets_on_new_billing_period(self, store):
        _, rec = store.generate("t")
        # Simulate old billing period
        rec.billing_period_start = "2020-01-01"
        rec.attestation_count = 99
        new_count = store.increment_attestation_count(rec.key_id)
        assert new_count == 1  # reset + increment

    def test_len(self, store):
        assert len(store) == 0
        store.generate("t")
        assert len(store) == 1
        store.generate("t")
        assert len(store) == 2

    def test_list_for_tenant(self, store):
        store.generate("tenant-A")
        store.generate("tenant-A")
        store.generate("tenant-B")
        keys_a = store.list_for_tenant("tenant-A")
        assert len(keys_a) == 2
        assert all(r.tenant_id == "tenant-A" for r in keys_a)

    def test_update_plan(self, store):
        _, rec = store.generate("t", plan="free")
        updated = store.update_plan("t", "pro")
        assert len(updated) == 1
        assert updated[0].plan == "pro"
        assert store.get(rec.key_id).plan == "pro"

    def test_update_plan_invalid_raises(self, store):
        with pytest.raises(ValueError):
            store.update_plan("t", "diamond")

    def test_reset_quota(self, store):
        _, rec = store.generate("t")
        store.increment_attestation_count(rec.key_id)
        store.increment_attestation_count(rec.key_id)
        store.reset_quota(rec.key_id)
        assert store.get(rec.key_id).attestation_count == 0

    def test_key_ids_are_unique(self, store):
        keys = [store.generate("t")[1].key_id for _ in range(20)]
        assert len(set(keys)) == 20

    def test_generate_invalid_plan_raises(self, store):
        with pytest.raises(ValueError):
            store.generate("t", plan="invalid")


# ---------------------------------------------------------------------------
# KeyStore — SQLite persistence
# ---------------------------------------------------------------------------

class TestKeyStoreSQLite:
    def test_keys_persist_across_instances(self, tmp_path):
        db = tmp_path / "keys.db"
        s1 = KeyStore(db_path=db)
        raw, rec = s1.generate("t", plan="pro")
        s1.close()

        s2 = KeyStore(db_path=db)
        verified = s2.verify(raw)
        assert verified is not None
        assert verified.key_id == rec.key_id
        s2.close()

    def test_revocation_persists(self, tmp_path):
        db = tmp_path / "keys.db"
        s1 = KeyStore(db_path=db)
        raw, rec = s1.generate("t")
        s1.revoke(rec.key_id)
        s1.close()

        s2 = KeyStore(db_path=db)
        assert s2.verify(raw) is None
        s2.close()

    def test_attestation_count_persists(self, tmp_path):
        db = tmp_path / "keys.db"
        s1 = KeyStore(db_path=db)
        _, rec = s1.generate("t")
        s1.increment_attestation_count(rec.key_id)
        s1.increment_attestation_count(rec.key_id)
        s1.close()

        s2 = KeyStore(db_path=db)
        loaded = s2.get(rec.key_id)
        assert loaded.attestation_count == 2
        s2.close()


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

class TestModuleSingleton:
    def test_get_key_store_returns_store(self):
        store = reset_key_store()
        assert isinstance(store, KeyStore)

    def test_reset_key_store_gives_fresh_store(self):
        s1 = reset_key_store()
        s1.generate("t")
        s2 = reset_key_store()
        assert len(s2) == 0

    def test_get_key_store_returns_same_instance(self):
        reset_key_store()
        assert get_key_store() is get_key_store()
