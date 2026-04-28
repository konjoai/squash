"""W143 — GET /account/status + GET /account/usage endpoint tests."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi required for API tests")
pytest.importorskip("httpx", reason="httpx required for TestClient")

from fastapi.testclient import TestClient

from squash.api import app
from squash.auth import reset_key_store, KeyStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_store():
    """Each test gets a clean in-memory key store."""
    store = reset_key_store()
    yield store
    reset_key_store()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=True)


def _auth_header(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# ---------------------------------------------------------------------------
# /account/status (W143)
# ---------------------------------------------------------------------------

class TestAccountStatus:
    def test_no_auth_with_empty_store_returns_status(self, client, fresh_store):
        """Dev mode: no keys configured → pass through."""
        resp = client.get("/account/status")
        # 401 because no key_record attached in dev mode
        assert resp.status_code == 401

    def test_valid_key_returns_200(self, client, fresh_store):
        key, rec = fresh_store.generate("tenant-1", plan="pro", name="CI")
        resp = client.get("/account/status", headers=_auth_header(key))
        assert resp.status_code == 200

    def test_status_contains_plan(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="enterprise")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert data["plan"] == "enterprise"

    def test_status_contains_key_id(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="free")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert data["key_id"] == rec.key_id

    def test_status_contains_tenant_id(self, client, fresh_store):
        key, rec = fresh_store.generate("my-tenant", plan="pro")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert data["tenant_id"] == "my-tenant"

    def test_status_contains_quota_fields(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="free")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert "quota_used" in data
        assert "quota_limit" in data
        assert "quota_remaining" in data

    def test_status_quota_limit_matches_plan(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="free")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert data["quota_limit"] == 10

    def test_status_enterprise_quota_null(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="enterprise")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert data["quota_limit"] is None

    def test_status_rate_limit_matches_plan(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="pro")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert data["rate_limit_per_minute"] == 600

    def test_status_billing_period_start_present(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="free")
        data = client.get("/account/status", headers=_auth_header(key)).json()
        assert "billing_period_start" in data
        assert data["billing_period_start"].endswith("-01")

    def test_revoked_key_returns_401(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="free")
        fresh_store.revoke(rec.key_id)
        resp = client.get("/account/status", headers=_auth_header(key))
        assert resp.status_code == 401

    def test_invalid_key_returns_401(self, client, fresh_store):
        # Ensure at least one key exists so dev-mode bypass is off
        fresh_store.generate("t")
        resp = client.get("/account/status", headers=_auth_header("sq_live_notareal"))
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /account/usage (W143)
# ---------------------------------------------------------------------------

class TestAccountUsage:
    def test_valid_key_returns_200(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="free")
        resp = client.get("/account/usage", headers=_auth_header(key))
        assert resp.status_code == 200

    def test_usage_contains_key_id(self, client, fresh_store):
        key, rec = fresh_store.generate("t")
        data = client.get("/account/usage", headers=_auth_header(key)).json()
        assert data["key_id"] == rec.key_id

    def test_usage_contains_tenant_id(self, client, fresh_store):
        key, rec = fresh_store.generate("my-t")
        data = client.get("/account/usage", headers=_auth_header(key)).json()
        assert data["tenant_id"] == "my-t"

    def test_usage_total_attestations_starts_at_zero(self, client, fresh_store):
        key, rec = fresh_store.generate("t")
        data = client.get("/account/usage", headers=_auth_header(key)).json()
        assert data["total_attestations"] == 0

    def test_usage_after_consume(self, client, fresh_store):
        key, rec = fresh_store.generate("t")
        fresh_store.increment_attestation_count(rec.key_id)
        fresh_store.increment_attestation_count(rec.key_id)
        data = client.get("/account/usage", headers=_auth_header(key)).json()
        assert data["total_attestations"] == 2

    def test_usage_contains_period_start(self, client, fresh_store):
        key, rec = fresh_store.generate("t")
        data = client.get("/account/usage", headers=_auth_header(key)).json()
        assert "period_start" in data

    def test_usage_monthly_quota_present(self, client, fresh_store):
        key, rec = fresh_store.generate("t", plan="pro")
        data = client.get("/account/usage", headers=_auth_header(key)).json()
        assert data["monthly_quota"] == 500

    def test_usage_no_auth_returns_401(self, client, fresh_store):
        # Ensure dev-mode bypass is off
        fresh_store.generate("t")
        resp = client.get("/account/usage")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /keys endpoint (W137 via W143 test client)
# ---------------------------------------------------------------------------

class TestKeysEndpoint:
    def test_create_key_in_dev_mode(self, client, fresh_store):
        """Dev mode: no keys → can create first key without auth."""
        resp = client.post("/keys", json={"tenant_id": "t1", "plan": "free", "name": "first"})
        assert resp.status_code == 201
        data = resp.json()
        assert "key" in data
        assert data["key"].startswith("sq_live_") or data["key"].startswith("sq_test_")

    def test_create_key_returns_key_once(self, client, fresh_store):
        resp = client.post("/keys", json={"tenant_id": "t1"})
        key1 = resp.json()["key"]
        # The key is in the response body only — verify it works
        resp2 = client.get("/account/status", headers=_auth_header(key1))
        assert resp2.status_code == 200

    def test_create_key_with_valid_auth(self, client, fresh_store):
        key, rec = fresh_store.generate("t1", plan="pro")
        resp = client.post("/keys", json={"tenant_id": "t1", "plan": "free"},
                           headers=_auth_header(key))
        assert resp.status_code == 201

    def test_create_key_invalid_plan_returns_400(self, client, fresh_store):
        resp = client.post("/keys", json={"tenant_id": "t1", "plan": "diamond"})
        assert resp.status_code == 400

    def test_create_test_key(self, client, fresh_store):
        resp = client.post("/keys", json={"tenant_id": "t1", "test": True})
        data = resp.json()
        assert data["key"].startswith("sq_test_")

    def test_revoke_key(self, client, fresh_store):
        key, rec = fresh_store.generate("t1")
        # Ensure store has keys so we're not in dev mode
        resp = client.delete(f"/keys/{rec.key_id}", headers=_auth_header(key))
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    def test_revoke_nonexistent_key_returns_404(self, client, fresh_store):
        key, rec = fresh_store.generate("t1")
        resp = client.delete("/keys/kid_ghost", headers=_auth_header(key))
        assert resp.status_code == 404
