"""tests/test_squash_b5_gateway.py — Track B / B5 — API Gateway runtime gate.

Covers:

  * `squash.integrations.gateway.evaluate_token` — every reason code
  * GatewayDecision.to_kong_exit / to_iam_policy round-tripping
  * `_parse_token` — uri / sha256 / entry_id / invalid
  * `emit_kong_config` declarative-config wiring
  * `emit_kong_plugin_dir` Lua source bundle (schema + handler + readme)
  * `emit_aws_apigw_sam` SAM template wiring
  * `emit_aws_authorizer_dir` Python Lambda authorizer bundle
  * `squash gateway-config` CLI dispatcher (kong / aws-apigw / errors)
  * `POST /v1/gateway/verify` FastAPI endpoint (allow + deny round-trip)
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Stub registry (duck-typed — gateway only calls .get_entry/.verify) ───────


class _StubEntry:
    def __init__(self, *, entry_id="abcd1234abcd1234", model_id="acme/m",
                 score=0.92, frameworks=("eu-ai-act",),
                 published="2026-04-29T00:00:00+00:00", revoked=False):
        self.entry_id = entry_id
        self.org = "acme"
        self.model_id = model_id
        self.model_version = "1.0"
        self.published_at = published
        self.attestation_hash = "deadbeef" * 8
        self.payload_size_bytes = 100
        self.frameworks = list(frameworks)
        self.compliance_score = score
        self.uri = f"att://x/acme/m/{entry_id}"
        self.verify_url = ""
        self.is_public = True
        self.revoked = revoked


class _StubVR:
    def __init__(self, *, hash_verified=True, revoked=False, error=""):
        self.hash_verified = hash_verified
        self.revoked = revoked
        self.error = error


class _StubRegistry:
    def __init__(self, entries=None, hash_verified=True):
        self.entries = entries or {}
        self.hash_verified = hash_verified

    def get_entry(self, entry_id):
        return self.entries.get(entry_id)

    def verify(self, entry_id):
        entry = self.entries.get(entry_id)
        if entry is None:
            return _StubVR(hash_verified=False, error="not found")
        if entry.revoked:
            return _StubVR(hash_verified=False, revoked=True, error="revoked")
        return _StubVR(hash_verified=self.hash_verified,
                       error="" if self.hash_verified else "hash mismatch")


def _registry_with_one(**entry_kwargs) -> _StubRegistry:
    e = _StubEntry(**entry_kwargs)
    return _StubRegistry({e.entry_id: e})


# ── _parse_token ─────────────────────────────────────────────────────────────


class TestParseToken(unittest.TestCase):
    def test_uri_form(self):
        from squash.integrations.gateway import _parse_token
        kind, val = _parse_token("att://x/acme/m/abcd1234abcd1234")
        self.assertEqual(kind, "uri")
        self.assertEqual(val, "abcd1234abcd1234")

    def test_sha256_form(self):
        from squash.integrations.gateway import _parse_token
        kind, val = _parse_token("sha256:" + "a" * 64)
        self.assertEqual(kind, "sha256")
        self.assertEqual(val, "a" * 64)

    def test_bare_entry_id(self):
        from squash.integrations.gateway import _parse_token
        kind, val = _parse_token("abcd1234abcd1234")
        self.assertEqual(kind, "entry_id")
        self.assertEqual(val, "abcd1234abcd1234")

    def test_invalid_empty(self):
        from squash.integrations.gateway import _parse_token
        self.assertEqual(_parse_token("")[0], "invalid")
        self.assertEqual(_parse_token("   ")[0], "invalid")

    def test_invalid_garbage(self):
        from squash.integrations.gateway import _parse_token
        self.assertEqual(_parse_token("not!hex@token#")[0], "invalid")

    def test_invalid_sha256_hex_chars(self):
        from squash.integrations.gateway import _parse_token
        self.assertEqual(_parse_token("sha256:ZZZZ")[0], "invalid")

    def test_uri_with_only_host_is_invalid(self):
        from squash.integrations.gateway import _parse_token
        self.assertEqual(_parse_token("att://")[0], "invalid")


# ── evaluate_token ───────────────────────────────────────────────────────────


class TestEvaluateToken(unittest.TestCase):
    def test_allow_path(self):
        from squash.integrations.gateway import evaluate_token, REASON_OK
        reg = _registry_with_one()
        d = evaluate_token("att://x/acme/m/abcd1234abcd1234", reg, min_score=0.8)
        self.assertTrue(d.allow)
        self.assertEqual(d.reason, REASON_OK)
        self.assertEqual(d.http_status, 200)
        self.assertEqual(d.entry_id, "abcd1234abcd1234")
        self.assertEqual(d.model_id, "acme/m")
        self.assertIn("X-Squash-Attestation-Id", d.headers)
        self.assertEqual(d.headers["X-Squash-Attestation-Id"], "abcd1234abcd1234")

    def test_missing_token_is_401(self):
        from squash.integrations.gateway import evaluate_token, REASON_MISSING_TOKEN
        d = evaluate_token(None, _StubRegistry())
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, REASON_MISSING_TOKEN)
        self.assertEqual(d.http_status, 401)

    def test_empty_string_token_is_401(self):
        from squash.integrations.gateway import evaluate_token, REASON_MISSING_TOKEN
        d = evaluate_token("   ", _StubRegistry())
        self.assertEqual(d.reason, REASON_MISSING_TOKEN)
        self.assertEqual(d.http_status, 401)

    def test_malformed_token_is_401(self):
        from squash.integrations.gateway import evaluate_token, REASON_MALFORMED_TOKEN
        d = evaluate_token("!!not-a-token!!", _StubRegistry())
        self.assertEqual(d.reason, REASON_MALFORMED_TOKEN)
        self.assertEqual(d.http_status, 401)

    def test_not_found_is_403(self):
        from squash.integrations.gateway import evaluate_token, REASON_NOT_FOUND
        d = evaluate_token("0123456789abcdef", _StubRegistry())
        self.assertEqual(d.reason, REASON_NOT_FOUND)
        self.assertEqual(d.http_status, 403)

    def test_revoked_is_403(self):
        from squash.integrations.gateway import evaluate_token, REASON_REVOKED
        reg = _registry_with_one(revoked=True)
        d = evaluate_token("abcd1234abcd1234", reg)
        self.assertEqual(d.reason, REASON_REVOKED)
        self.assertEqual(d.http_status, 403)
        self.assertEqual(d.model_id, "acme/m")

    def test_hash_mismatch_is_403(self):
        from squash.integrations.gateway import evaluate_token, REASON_HASH_MISMATCH
        reg = _StubRegistry({"abcd1234abcd1234": _StubEntry()}, hash_verified=False)
        d = evaluate_token("abcd1234abcd1234", reg)
        self.assertEqual(d.reason, REASON_HASH_MISMATCH)
        self.assertEqual(d.http_status, 403)

    def test_below_min_score_is_403(self):
        from squash.integrations.gateway import evaluate_token, REASON_LOW_SCORE
        reg = _registry_with_one(score=0.50)
        d = evaluate_token("abcd1234abcd1234", reg, min_score=0.8)
        self.assertEqual(d.reason, REASON_LOW_SCORE)
        self.assertEqual(d.http_status, 403)
        self.assertAlmostEqual(d.compliance_score, 0.50, places=3)

    def test_min_score_normalises_0_to_100(self):
        from squash.integrations.gateway import evaluate_token, REASON_LOW_SCORE
        reg = _registry_with_one(score=0.50)
        d = evaluate_token("abcd1234abcd1234", reg, min_score=80.0)
        self.assertEqual(d.reason, REASON_LOW_SCORE)

    def test_expired_is_403(self):
        from squash.integrations.gateway import evaluate_token, REASON_EXPIRED
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=120)).isoformat()
        reg = _registry_with_one(published=old)
        d = evaluate_token("abcd1234abcd1234", reg, max_age_days=30)
        self.assertEqual(d.reason, REASON_EXPIRED)
        self.assertEqual(d.http_status, 403)

    def test_age_check_skipped_when_max_age_none(self):
        from squash.integrations.gateway import evaluate_token, REASON_OK
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400)).isoformat()
        reg = _registry_with_one(published=old)
        d = evaluate_token("abcd1234abcd1234", reg, max_age_days=None)
        self.assertEqual(d.reason, REASON_OK)

    def test_required_framework_missing(self):
        from squash.integrations.gateway import evaluate_token, REASON_FRAMEWORK_GAP
        reg = _registry_with_one(frameworks=("nist-rmf",))
        d = evaluate_token("abcd1234abcd1234", reg,
                           required_frameworks=["eu-ai-act"])
        self.assertEqual(d.reason, REASON_FRAMEWORK_GAP)
        self.assertIn("eu-ai-act", d.detail)

    def test_required_framework_subset_ok(self):
        from squash.integrations.gateway import evaluate_token, REASON_OK
        reg = _registry_with_one(frameworks=("eu-ai-act", "nist-rmf"))
        d = evaluate_token("abcd1234abcd1234", reg,
                           required_frameworks=["eu-ai-act"])
        self.assertEqual(d.reason, REASON_OK)

    def test_sha256_token_resolves_via_prefix(self):
        from squash.integrations.gateway import evaluate_token, REASON_OK
        reg = _registry_with_one(entry_id="abcd1234abcd1234")
        full_hash = "abcd1234abcd1234" + "0" * 48
        d = evaluate_token(f"sha256:{full_hash}", reg, min_score=0.5)
        self.assertEqual(d.reason, REASON_OK)


# ── GatewayDecision host translations ────────────────────────────────────────


class TestDecisionHostTranslation(unittest.TestCase):
    def test_to_kong_exit_deny_shape(self):
        from squash.integrations.gateway import GatewayDecision, REASON_REVOKED
        d = GatewayDecision(allow=False, reason=REASON_REVOKED, http_status=403,
                            entry_id="x", detail="revoked")
        status, body = d.to_kong_exit()
        self.assertEqual(status, 403)
        self.assertEqual(body["reason"], REASON_REVOKED)
        self.assertEqual(body["entry_id"], "x")
        self.assertIn("rejected", body["message"])

    def test_to_iam_policy_allow(self):
        from squash.integrations.gateway import GatewayDecision, REASON_OK
        d = GatewayDecision(allow=True, reason=REASON_OK, http_status=200,
                            entry_id="x", model_id="m", compliance_score=0.92)
        pol = d.to_iam_policy("anon", "arn:aws:execute-api:eu-west-1:1:abc/prod/POST/predict")
        self.assertEqual(pol["policyDocument"]["Statement"][0]["Effect"], "Allow")
        self.assertEqual(pol["context"]["squash_entry_id"], "x")
        self.assertEqual(pol["context"]["squash_score"], "0.92")

    def test_to_iam_policy_deny(self):
        from squash.integrations.gateway import GatewayDecision, REASON_LOW_SCORE
        d = GatewayDecision(allow=False, reason=REASON_LOW_SCORE, http_status=403,
                            entry_id="x")
        pol = d.to_iam_policy("anon", "arn:aws:execute-api:1:abc/prod/POST/predict")
        self.assertEqual(pol["policyDocument"]["Statement"][0]["Effect"], "Deny")
        self.assertEqual(pol["context"]["squash_reason"], REASON_LOW_SCORE)


# ── Config emitters ──────────────────────────────────────────────────────────


class TestKongConfigEmitter(unittest.TestCase):
    def test_minimal_config_contains_plugin_block(self):
        from squash.integrations.gateway import emit_kong_config
        yaml_str = emit_kong_config(min_score=0.85)
        self.assertIn("squash-attest", yaml_str)
        self.assertIn("min_score: 0.85", yaml_str)
        self.assertIn("X-Squash-Attestation", yaml_str)
        self.assertIn("api.getsquash.dev", yaml_str)

    def test_route_paths_appear(self):
        from squash.integrations.gateway import emit_kong_config
        yaml_str = emit_kong_config(route_paths=["/predict", "/embed"])
        self.assertIn("/predict", yaml_str)
        self.assertIn("/embed", yaml_str)

    def test_required_frameworks_serialised(self):
        from squash.integrations.gateway import emit_kong_config
        yaml_str = emit_kong_config(required_frameworks=["eu-ai-act", "iso-42001"])
        self.assertIn("eu-ai-act", yaml_str)
        self.assertIn("iso-42001", yaml_str)

    def test_max_age_null_when_disabled(self):
        from squash.integrations.gateway import emit_kong_config
        yaml_str = emit_kong_config(max_age_days=None)
        self.assertIn("max_age_days: null", yaml_str)


class TestAwsSamEmitter(unittest.TestCase):
    def test_sam_template_wires_authorizer(self):
        from squash.integrations.gateway import emit_aws_apigw_sam
        sam = emit_aws_apigw_sam(min_score=0.9)
        self.assertIn("AWS::Serverless::Function", sam)
        self.assertIn("AWS::Serverless::Api", sam)
        self.assertIn("SquashAttestAuthorizer", sam)
        self.assertIn("DefaultAuthorizer: SquashAttestAuth", sam)
        self.assertIn("SQUASH_MIN_SCORE", sam)
        self.assertIn("\"0.9\"", sam)

    def test_required_frameworks_env_var(self):
        from squash.integrations.gateway import emit_aws_apigw_sam
        sam = emit_aws_apigw_sam(required_frameworks=["eu-ai-act", "nist-rmf"])
        self.assertIn("SQUASH_REQUIRED_FRAMEWORKS", sam)
        self.assertIn("eu-ai-act,nist-rmf", sam)


class TestPluginSourceBundles(unittest.TestCase):
    def test_kong_plugin_dir_has_three_files(self):
        from squash.integrations.gateway import emit_kong_plugin_dir
        files = emit_kong_plugin_dir()
        self.assertEqual(set(files.keys()), {"schema.lua", "handler.lua", "README.md"})

    def test_kong_schema_lua_declares_required_fields(self):
        from squash.integrations.gateway import emit_kong_plugin_dir
        schema = emit_kong_plugin_dir()["schema.lua"]
        self.assertIn('name = "squash-attest"', schema)
        self.assertIn("min_score", schema)
        self.assertIn("required_frameworks", schema)
        self.assertIn("cache_ttl_seconds", schema)

    def test_kong_handler_lua_has_access_phase(self):
        from squash.integrations.gateway import emit_kong_plugin_dir
        handler = emit_kong_plugin_dir()["handler.lua"]
        self.assertIn("function SquashAttest:access(conf)", handler)
        self.assertIn("/v1/gateway/verify", handler)
        self.assertIn("MISSING_TOKEN", handler)

    def test_aws_authorizer_dir_has_three_files(self):
        from squash.integrations.gateway import emit_aws_authorizer_dir
        files = emit_aws_authorizer_dir()
        self.assertEqual(set(files.keys()), {"handler.py", "requirements.txt", "README.md"})

    def test_aws_handler_compiles_and_defines_authorize(self):
        """The Lambda handler must be syntactically valid Python."""
        from squash.integrations.gateway import emit_aws_authorizer_dir
        handler = emit_aws_authorizer_dir()["handler.py"]
        self.assertIn("def authorize(event: dict, context)", handler)
        compile(handler, "<emit_aws_authorizer_dir>", "exec")  # raises if invalid


# ── CLI dispatcher ───────────────────────────────────────────────────────────


def _ns(**kw):
    return argparse.Namespace(**kw)


class TestCliDispatcher(unittest.TestCase):
    def test_kong_emits_to_stdout_by_default(self):
        from squash.cli import _cmd_gateway_config
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_gateway_config(_ns(
                gateway_target="kong", min_score=0.8,
                header_name="X-Squash-Attestation",
                squash_api_url="https://api.x", service_name="ai",
                upstream_url="http://up:8080", route_paths=["/p"],
                max_age_days=30, required_frameworks=None,
                emit_plugin=False, output=None,
            ), quiet=True)
        self.assertEqual(rc, 0)
        self.assertIn("squash-attest", buf.getvalue())

    def test_kong_writes_to_file_when_output_given(self):
        from squash.cli import _cmd_gateway_config
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "kong.yaml"
            rc = _cmd_gateway_config(_ns(
                gateway_target="kong", min_score=0.8,
                header_name="H", squash_api_url="https://api.x",
                service_name="ai", upstream_url="http://up", route_paths=None,
                max_age_days=None, required_frameworks=None,
                emit_plugin=False, output=str(out),
            ), quiet=True)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            self.assertIn("squash-attest", out.read_text())

    def test_kong_emit_plugin_writes_three_files(self):
        from squash.cli import _cmd_gateway_config
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "squash-attest"
            rc = _cmd_gateway_config(_ns(
                gateway_target="kong", min_score=0.8,
                header_name="H", squash_api_url="https://api.x",
                service_name="ai", upstream_url="http://up", route_paths=None,
                max_age_days=None, required_frameworks=None,
                emit_plugin=True, output=str(out),
            ), quiet=True)
            self.assertEqual(rc, 0)
            self.assertTrue((out / "schema.lua").exists())
            self.assertTrue((out / "handler.lua").exists())
            self.assertTrue((out / "README.md").exists())

    def test_kong_emit_plugin_without_output_errors(self):
        from squash.cli import _cmd_gateway_config
        rc = _cmd_gateway_config(_ns(
            gateway_target="kong", min_score=0.8, header_name="H",
            squash_api_url="x", service_name="ai", upstream_url="x",
            route_paths=None, max_age_days=None, required_frameworks=None,
            emit_plugin=True, output=None,
        ), quiet=True)
        self.assertEqual(rc, 2)

    def test_aws_default_emits_sam_template(self):
        from squash.cli import _cmd_gateway_config
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_gateway_config(_ns(
                gateway_target="aws-apigw", min_score=0.8,
                header_name="H", squash_api_url="x",
                function_name="F", max_age_days=30,
                required_frameworks=None, runtime="python3.11",
                emit_handler=False, emit_authorizer_dir=False, output=None,
            ), quiet=True)
        self.assertEqual(rc, 0)
        self.assertIn("AWS::Serverless::Function", buf.getvalue())

    def test_aws_emit_handler_writes_handler_only(self):
        from squash.cli import _cmd_gateway_config
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_gateway_config(_ns(
                gateway_target="aws-apigw", min_score=0.8,
                header_name="H", squash_api_url="x",
                function_name="F", max_age_days=30,
                required_frameworks=None, runtime="python3.11",
                emit_handler=True, emit_authorizer_dir=False, output=None,
            ), quiet=True)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("def authorize(event: dict, context)", out)

    def test_aws_emit_authorizer_dir_creates_three_files(self):
        from squash.cli import _cmd_gateway_config
        with tempfile.TemporaryDirectory() as td:
            rc = _cmd_gateway_config(_ns(
                gateway_target="aws-apigw", min_score=0.8,
                header_name="H", squash_api_url="x",
                function_name="F", max_age_days=30,
                required_frameworks=None, runtime="python3.11",
                emit_handler=False, emit_authorizer_dir=True, output=td,
            ), quiet=True)
            self.assertEqual(rc, 0)
            self.assertTrue((Path(td) / "handler.py").exists())
            self.assertTrue((Path(td) / "requirements.txt").exists())
            self.assertTrue((Path(td) / "README.md").exists())

    def test_unknown_target_errors(self):
        from squash.cli import _cmd_gateway_config
        rc = _cmd_gateway_config(_ns(gateway_target=None, output=None), quiet=True)
        self.assertEqual(rc, 1)


# ── /v1/gateway/verify FastAPI endpoint ──────────────────────────────────────


class TestGatewayVerifyEndpoint(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi.testclient import TestClient  # noqa: F401
            from squash.api import app  # noqa: F401
        except Exception as exc:  # pragma: no cover — env guard
            self.skipTest(f"api/testclient not available: {exc}")

    def _client(self):
        from fastapi.testclient import TestClient
        from squash.api import app
        return TestClient(app, raise_server_exceptions=False)

    def test_allow_round_trip(self):
        client = self._client()
        reg = _registry_with_one(score=0.9)
        class _CM:
            def __enter__(self_inner): return reg
            def __exit__(self_inner, *a): return False
        with mock.patch("squash.attestation_registry.AttestationRegistry",
                        return_value=_CM()):
            resp = client.post("/v1/gateway/verify", json={
                "token": "att://x/acme/m/abcd1234abcd1234",
                "min_score": 0.8,
            })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["allow"])
        self.assertEqual(body["reason"], "OK")
        self.assertEqual(body["entry_id"], "abcd1234abcd1234")

    def test_deny_missing_token(self):
        client = self._client()
        reg = _StubRegistry()
        class _CM:
            def __enter__(self_inner): return reg
            def __exit__(self_inner, *a): return False
        with mock.patch("squash.attestation_registry.AttestationRegistry",
                        return_value=_CM()):
            resp = client.post("/v1/gateway/verify", json={"token": None})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["allow"])
        self.assertEqual(body["reason"], "MISSING_TOKEN")
        self.assertEqual(body["http_status"], 401)

    def test_bad_request_body(self):
        client = self._client()
        resp = client.post("/v1/gateway/verify", content=b"not-json",
                           headers={"Content-Type": "application/json"})
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertEqual(body["reason"], "BAD_REQUEST")


if __name__ == "__main__":
    unittest.main()
