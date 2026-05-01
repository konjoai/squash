"""tests/test_squash_d1_github_app.py — Track D / D1 — squash GitHub App.

D1 exit criteria:
  * 1 new module (github_app.py) — App auth, REST client, webhook handler
  * Webhook HMAC-SHA256 verification (X-Hub-Signature-256)
  * GitHub App JWT (RS256) generation + installation token exchange
  * Check Run create/update via REST API
  * Pull-request and push event dispatch
  * Pattern-based detection of model file changes
  * AttestationRunner that wraps squash.attest.AttestPipeline
  * CLI: github-app serve | attest | config | verify-webhook
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def _has_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def _gen_rsa_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ── Module surface ────────────────────────────────────────────────────────────


class TestModuleSurface(unittest.TestCase):
    def test_public_api_exposed(self):
        from squash import github_app
        for n in (
            "GitHubAppConfig", "GitHubAppAuth", "GitHubAppClient",
            "WebhookVerifier", "ModelFileMatcher", "AttestationRunner",
            "AttestationOutcome", "WebhookHandler", "WebhookOutcome",
            "GitHubApiError", "make_jwt", "load_config",
            "dump_config_template", "serve", "clone_repo_at_sha",
            "DEFAULT_API_BASE", "DEFAULT_MODEL_PATTERNS",
        ):
            self.assertIn(n, github_app.__all__, msg=n)
            self.assertTrue(hasattr(github_app, n), msg=n)

    def test_default_patterns_cover_safetensors_and_gguf(self):
        from squash.github_app import DEFAULT_MODEL_PATTERNS
        joined = " ".join(DEFAULT_MODEL_PATTERNS)
        for needle in ("safetensors", "gguf", "pytorch_model", "tokenizer"):
            self.assertIn(needle, joined, msg=needle)


# ── Webhook HMAC ──────────────────────────────────────────────────────────────


class TestWebhookVerifier(unittest.TestCase):
    def test_rejects_missing_header(self):
        from squash.github_app import WebhookVerifier
        v = WebhookVerifier("secret")
        self.assertFalse(v.verify(b"body", None))
        self.assertFalse(v.verify(b"body", ""))
        self.assertFalse(v.verify(b"body", "sha1=deadbeef"))

    def test_accepts_valid_signature(self):
        from squash.github_app import WebhookVerifier
        v = WebhookVerifier("secret")
        body = b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(v.verify(body, sig))

    def test_rejects_tampered_body(self):
        from squash.github_app import WebhookVerifier
        v = WebhookVerifier("secret")
        body = b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertFalse(v.verify(b'{"action":"closed"}', sig))

    def test_constructor_rejects_empty_secret(self):
        from squash.github_app import WebhookVerifier
        with self.assertRaises(ValueError):
            WebhookVerifier("")


# ── JWT ───────────────────────────────────────────────────────────────────────


@unittest.skipUnless(_has_cryptography(), "cryptography not installed")
class TestJwt(unittest.TestCase):
    def test_jwt_three_segments(self):
        from squash.github_app import make_jwt
        token = make_jwt(123, _gen_rsa_pem(), now=1700000000)
        parts = token.split(".")
        self.assertEqual(len(parts), 3)

    def test_jwt_payload_has_required_claims(self):
        from squash.github_app import make_jwt
        token = make_jwt(456, _gen_rsa_pem(), now=1700000000)
        body = token.split(".")[1]
        body += "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body))
        self.assertEqual(payload["iss"], 456)
        self.assertEqual(payload["iat"], 1700000000 - 60)
        self.assertEqual(payload["exp"], 1700000000 - 60 + 9 * 60)

    def test_jwt_signature_verifies(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from squash.github_app import make_jwt

        pem = _gen_rsa_pem()
        token = make_jwt(789, pem, now=1700000000)
        signing_input, sig_b64 = token.rsplit(".", 1)
        sig_b64 += "=" * (-len(sig_b64) % 4)
        sig = base64.urlsafe_b64decode(sig_b64)

        priv = serialization.load_pem_private_key(pem, password=None)
        priv.public_key().verify(
            sig, signing_input.encode(),
            padding.PKCS1v15(), hashes.SHA256(),
        )


# ── Auth: installation token cache ────────────────────────────────────────────


class TestGitHubAppAuth(unittest.TestCase):
    def _cfg(self):
        from squash.github_app import GitHubAppConfig
        # private key never read because http_call is mocked.
        return GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )

    def test_token_cached_until_expiry(self):
        from squash.github_app import GitHubAppAuth
        cfg = self._cfg()
        calls = []
        future = "2999-01-01T00:00:00Z"

        def fake_http(method, url, *, headers=None, body=None, **kw):
            calls.append((method, url))
            return {"token": "v1.token", "expires_at": future}

        auth = GitHubAppAuth(cfg, http_call=fake_http, clock=lambda: 1.0)
        # JWT minting is bypassed by patching the method.
        with mock.patch.object(auth, "jwt", return_value="JWT"):
            t1 = auth.installation_token(99)
            t2 = auth.installation_token(99)
        self.assertEqual(t1, "v1.token")
        self.assertEqual(t1, t2)
        self.assertEqual(len(calls), 1)

    def test_invalidate_forces_refresh(self):
        from squash.github_app import GitHubAppAuth
        cfg = self._cfg()
        seq = iter(["a", "b"])

        def fake_http(*a, **kw):
            return {"token": next(seq), "expires_at": "2999-01-01T00:00:00Z"}

        auth = GitHubAppAuth(cfg, http_call=fake_http, clock=lambda: 1.0)
        with mock.patch.object(auth, "jwt", return_value="JWT"):
            self.assertEqual(auth.installation_token(1), "a")
            auth.invalidate(1)
            self.assertEqual(auth.installation_token(1), "b")

    def test_missing_token_raises(self):
        from squash.github_app import GitHubAppAuth
        cfg = self._cfg()
        auth = GitHubAppAuth(
            cfg, http_call=lambda *a, **kw: {},
            clock=lambda: 1.0,
        )
        with mock.patch.object(auth, "jwt", return_value="JWT"):
            with self.assertRaises(RuntimeError):
                auth.installation_token(7)


# ── REST client ───────────────────────────────────────────────────────────────


class _FakeHttp:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, method, url, *, headers=None, body=None, **kw):
        self.calls.append({
            "method": method, "url": url,
            "headers": dict(headers or {}), "body": body,
        })
        return self.response if not callable(self.response) else self.response(
            method, url, headers=headers, body=body,
        )


class TestGitHubAppClient(unittest.TestCase):
    def _client(self, response):
        from squash.github_app import (
            GitHubAppAuth, GitHubAppClient, GitHubAppConfig,
        )
        cfg = GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )
        auth = GitHubAppAuth(
            cfg, http_call=lambda *a, **kw: {
                "token": "TKN", "expires_at": "2999-01-01T00:00:00Z",
            }, clock=lambda: 1.0,
        )
        with mock.patch.object(auth, "jwt", return_value="JWT"):
            auth.installation_token(7)  # warm cache
        fake = _FakeHttp(response)
        return GitHubAppClient(auth, http_call=fake), fake

    def test_create_check_run_payload(self):
        client, http = self._client({"id": 1234})
        out = client.create_check_run(
            installation_id=7, owner="oct", repo="repo",
            head_sha="abc", name="squash", status="in_progress",
            output={"title": "t", "summary": "s"},
        )
        self.assertEqual(out["id"], 1234)
        call = http.calls[-1]
        self.assertEqual(call["method"], "POST")
        self.assertIn("/repos/oct/repo/check-runs", call["url"])
        self.assertEqual(call["body"]["head_sha"], "abc")
        self.assertEqual(call["body"]["status"], "in_progress")
        self.assertEqual(call["body"]["output"]["title"], "t")
        self.assertEqual(call["headers"]["Authorization"], "token TKN")

    def test_update_check_run_omits_unset_fields(self):
        client, http = self._client({"id": 1})
        client.update_check_run(
            installation_id=7, owner="oct", repo="repo",
            check_run_id=1, conclusion="failure",
        )
        body = http.calls[-1]["body"]
        self.assertEqual(body, {"conclusion": "failure"})

    def test_list_pull_request_files_paginates(self):
        from squash.github_app import GitHubAppClient

        responses = iter([
            {"_list": [{"filename": f"f{i}"} for i in range(100)]},
            {"_list": [{"filename": "tail.safetensors"}]},
        ])

        client, _ = self._client(lambda *a, **kw: next(responses))
        out = client.list_pull_request_files(
            installation_id=7, owner="oct", repo="repo", number=42,
        )
        self.assertEqual(len(out), 101)
        self.assertEqual(out[-1]["filename"], "tail.safetensors")


# ── ModelFileMatcher ──────────────────────────────────────────────────────────


class TestModelFileMatcher(unittest.TestCase):
    def test_default_matches_weights(self):
        from squash.github_app import ModelFileMatcher
        m = ModelFileMatcher()
        self.assertTrue(m.matches("model.safetensors"))
        self.assertTrue(m.matches("weights/model.safetensors"))
        self.assertTrue(m.matches("model.gguf"))
        self.assertTrue(m.matches("config.json"))
        self.assertTrue(m.matches("models/MODEL_CARD.md"))

    def test_no_match_for_unrelated(self):
        from squash.github_app import ModelFileMatcher
        m = ModelFileMatcher()
        self.assertFalse(m.matches("README.md"))
        self.assertFalse(m.matches("src/foo.py"))
        self.assertFalse(m.matches("docs/index.md"))

    def test_changed_filter(self):
        from squash.github_app import ModelFileMatcher
        m = ModelFileMatcher()
        out = m.changed_model_files([
            "README.md", "weights/model.safetensors", "src/foo.py",
            "tokenizer.json", "data/sample.csv",
        ])
        self.assertEqual(out, ["weights/model.safetensors", "tokenizer.json"])

    def test_custom_pattern(self):
        from squash.github_app import ModelFileMatcher
        m = ModelFileMatcher(["*.weights"])
        self.assertTrue(m.matches("foo.weights"))
        self.assertFalse(m.matches("foo.safetensors"))


# ── AttestationRunner ─────────────────────────────────────────────────────────


class TestAttestationRunner(unittest.TestCase):
    def setUp(self):
        from squash.github_app import GitHubAppConfig
        self.cfg = GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )

    def test_no_changed_files_passes(self):
        from squash.github_app import AttestationRunner
        with tempfile.TemporaryDirectory() as tmp:
            r = AttestationRunner(self.cfg)
            out = r.run(workdir=tmp, changed_model_files=[], model_id="m")
        self.assertTrue(out.passed)
        self.assertEqual(out.conclusion, "success")
        self.assertIn("No model files", out.summary)

    def test_missing_workdir_fails(self):
        from squash.github_app import AttestationRunner
        r = AttestationRunner(self.cfg)
        out = r.run(
            workdir="/does/not/exist/blob",
            changed_model_files=["model.safetensors"],
        )
        self.assertFalse(out.passed)
        self.assertIn("workdir_missing", out.violations)

    def test_attest_callable_called_when_files_present(self):
        from squash.github_app import AttestationRunner
        captured = {}

        def fake_attest(cfg):
            captured["cfg"] = cfg
            return SimpleNamespace(
                passed=True, model_id="m", policy_results={},
                scan_result=SimpleNamespace(status="safe"),
                error="",
                cyclonedx_path="cdx.json", spdx_json_path=None,
                spdx_tv_path=None, signature_path=None,
                master_record_path=None, vex_report_path=None,
            )

        with tempfile.TemporaryDirectory() as tmp:
            wd = Path(tmp)
            (wd / "model.safetensors").write_bytes(b"weights")
            r = AttestationRunner(self.cfg, attest_callable=fake_attest)
            out = r.run(
                workdir=wd, changed_model_files=["model.safetensors"],
                model_id="m",
            )
        self.assertTrue(out.passed)
        self.assertEqual(captured["cfg"].model_id, "m")
        self.assertIn("cdx.json", out.artifacts)

    def test_attest_failure_recorded(self):
        from squash.github_app import AttestationRunner
        def fake_attest(cfg):
            return SimpleNamespace(
                passed=False, model_id="m",
                policy_results={
                    "enterprise-strict": SimpleNamespace(
                        passed=False, failed_rules=["R1", "R2"],
                    ),
                },
                scan_result=SimpleNamespace(status="unsafe"),
                error="",
            )
        with tempfile.TemporaryDirectory() as tmp:
            wd = Path(tmp)
            (wd / "model.safetensors").write_bytes(b"weights")
            r = AttestationRunner(self.cfg, attest_callable=fake_attest)
            out = r.run(
                workdir=wd, changed_model_files=["model.safetensors"],
            )
        self.assertFalse(out.passed)
        self.assertEqual(out.conclusion, "failure")
        self.assertIn("R1", out.violations)
        self.assertIn("scan:unsafe", out.violations)
        # detail markdown contains policy table
        self.assertIn("Policy results", out.detail_md)


# ── WebhookHandler ────────────────────────────────────────────────────────────


class _FakeClient:
    def __init__(self, files=None):
        self.files = files or []
        self.creates = []
        self.updates = []
        self._next_id = 100

    def list_pull_request_files(self, **kw):
        return list(self.files)

    def create_check_run(self, **kw):
        cid = self._next_id
        self._next_id += 1
        self.creates.append({**kw, "id": cid})
        return {"id": cid, "_status": 201}

    def update_check_run(self, **kw):
        self.updates.append(kw)
        return {"_status": 200}


def _fake_runner_factory(passed: bool, summary: str = "ok"):
    from squash.github_app import AttestationRunner, AttestationOutcome

    class _R(AttestationRunner):
        def __init__(self, cfg):
            super().__init__(cfg)
        def run(self, workdir, changed_model_files, *, model_id=""):
            return AttestationOutcome(
                passed=passed, model_id=model_id or "repo",
                summary=summary,
                detail_md="ok",
                violations=[] if passed else ["X"],
            )

    return _R


def _fake_cloner(*, clone_url, sha, destination, depth=1, **kw):
    Path(destination).mkdir(parents=True, exist_ok=True)
    (Path(destination) / "model.safetensors").write_bytes(b"weights")
    return Path(destination)


class TestWebhookHandlerPullRequest(unittest.TestCase):
    def _handler(self, files, passed=True):
        from squash.github_app import GitHubAppConfig, WebhookHandler
        cfg = GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )
        client = _FakeClient(files=files)
        # Sidestep the auth construction by directly assembling.
        h = WebhookHandler.__new__(WebhookHandler)
        h._config = cfg
        from squash.github_app import ModelFileMatcher
        h._matcher = ModelFileMatcher(cfg.model_patterns)
        h._auth = None
        h._client = client
        h._runner = _fake_runner_factory(passed=passed)(cfg)
        h._cloner = _fake_cloner
        return h, client

    def _payload(self, action="opened"):
        return {
            "action": action,
            "installation": {"id": 5},
            "repository": {
                "name": "repo",
                "owner": {"login": "oct"},
                "clone_url": "https://github.com/oct/repo.git",
            },
            "pull_request": {
                "number": 42,
                "head": {"sha": "deadbeefcafe"},
            },
        }

    def test_ignores_unwanted_action(self):
        h, client = self._handler(files=[])
        out = h.handle("pull_request", self._payload(action="closed"))
        self.assertTrue(out.handled)
        self.assertEqual(client.creates, [])

    def test_no_model_files_posts_neutral_check(self):
        h, client = self._handler(
            files=[{"filename": "README.md"}, {"filename": "src/foo.py"}],
        )
        out = h.handle("pull_request", self._payload())
        self.assertTrue(out.handled)
        self.assertEqual(out.conclusion, "neutral")
        self.assertEqual(len(client.creates), 1)
        self.assertEqual(client.creates[0]["status"], "completed")

    def test_model_file_triggers_pending_then_completion(self):
        h, client = self._handler(
            files=[{"filename": "weights/model.safetensors"},
                   {"filename": "README.md"}],
        )
        out = h.handle("pull_request", self._payload())
        self.assertTrue(out.handled)
        self.assertEqual(out.conclusion, "success")
        # Two API calls: in_progress + completed
        self.assertEqual(len(client.creates), 1)
        self.assertEqual(client.creates[0]["status"], "in_progress")
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.updates[0]["conclusion"], "success")

    def test_failure_conclusion(self):
        from squash.github_app import GitHubAppConfig, WebhookHandler
        cfg = GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )
        client = _FakeClient(
            files=[{"filename": "weights/model.safetensors"}],
        )
        h = WebhookHandler.__new__(WebhookHandler)
        h._config = cfg
        from squash.github_app import ModelFileMatcher
        h._matcher = ModelFileMatcher(cfg.model_patterns)
        h._auth = None
        h._client = client
        h._runner = _fake_runner_factory(
            passed=False, summary="bad",
        )(cfg)
        h._cloner = _fake_cloner

        out = h.handle("pull_request", self._payload())
        self.assertEqual(out.conclusion, "failure")
        self.assertEqual(client.updates[-1]["conclusion"], "failure")

    def test_missing_fields_skips(self):
        h, client = self._handler(files=[])
        bad = self._payload()
        bad["pull_request"]["head"]["sha"] = ""
        out = h.handle("pull_request", bad)
        self.assertFalse(out.handled)
        self.assertEqual(out.skipped_reason, "missing_required_fields")


class TestWebhookHandlerPush(unittest.TestCase):
    def _handler(self):
        from squash.github_app import (
            GitHubAppConfig, WebhookHandler, ModelFileMatcher,
        )
        cfg = GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )
        client = _FakeClient()
        h = WebhookHandler.__new__(WebhookHandler)
        h._config = cfg
        h._matcher = ModelFileMatcher(cfg.model_patterns)
        h._auth = None
        h._client = client
        h._runner = _fake_runner_factory(passed=True)(cfg)
        h._cloner = _fake_cloner
        return h, client

    def _payload(self, files):
        return {
            "after": "1234abcd",
            "installation": {"id": 7},
            "repository": {
                "name": "repo",
                "owner": {"login": "oct"},
                "clone_url": "https://github.com/oct/repo.git",
            },
            "commits": [{"added": [], "modified": files, "removed": []}],
            "head_commit": {"added": [], "modified": files, "removed": []},
        }

    def test_push_with_model_file(self):
        h, client = self._handler()
        out = h.handle("push", self._payload(["weights/model.safetensors"]))
        self.assertTrue(out.handled)
        self.assertEqual(out.conclusion, "success")
        self.assertEqual(client.creates[0]["head_sha"], "1234abcd")

    def test_push_without_model_file(self):
        h, client = self._handler()
        out = h.handle("push", self._payload(["docs/x.md"]))
        self.assertTrue(out.handled)
        self.assertEqual(out.conclusion, "neutral")

    def test_push_deleted_branch_skipped(self):
        h, client = self._handler()
        p = self._payload(["model.safetensors"])
        p["deleted"] = True
        out = h.handle("push", p)
        self.assertTrue(out.handled)
        self.assertEqual(out.skipped_reason, "branch_deleted")
        self.assertEqual(client.creates, [])


class TestWebhookHandlerEvents(unittest.TestCase):
    def _h(self):
        from squash.github_app import (
            GitHubAppConfig, WebhookHandler, ModelFileMatcher,
        )
        cfg = GitHubAppConfig(
            app_id=1, private_key_path="/dev/null", webhook_secret="x",
        )
        h = WebhookHandler.__new__(WebhookHandler)
        h._config = cfg
        h._matcher = ModelFileMatcher(cfg.model_patterns)
        h._auth = None
        h._client = _FakeClient()
        h._runner = _fake_runner_factory(True)(cfg)
        h._cloner = _fake_cloner
        return h

    def test_ping_acknowledged(self):
        out = self._h().handle("ping", {"zen": "wow"})
        self.assertTrue(out.handled)
        self.assertIn("ping", out.detail)

    def test_unsupported_event(self):
        out = self._h().handle("issues", {})
        self.assertFalse(out.handled)
        self.assertTrue(out.skipped_reason.startswith("unsupported_event"))


# ── Config round-trip ─────────────────────────────────────────────────────────


def _has_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_has_yaml(), "PyYAML not installed")
class TestConfigRoundTrip(unittest.TestCase):
    def test_template_loadable(self):
        from squash.github_app import dump_config_template, load_config

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "app.yaml"
            dump_config_template(cfg_path)
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.app_id, 0)
            self.assertGreater(len(cfg.model_patterns), 5)
            errors = cfg.validate()
            # Default template intentionally has placeholders, so it should
            # surface validation errors.
            self.assertTrue(any("app_id" in e for e in errors))

    def test_load_real_config(self):
        from squash.github_app import load_config

        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "key.pem"
            key_path.write_bytes(b"--- placeholder ---")
            cfg_path = Path(tmp) / "real.yaml"
            cfg_path.write_text(
                "app_id: 12345\n"
                f"private_key_path: {key_path}\n"
                "webhook_secret: my-secret\n"
                "policies:\n  - enterprise-strict\n"
                "model_patterns:\n  - '*.gguf'\n",
            )
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.app_id, 12345)
            self.assertEqual(cfg.webhook_secret, "my-secret")
            self.assertEqual(cfg.model_patterns, ["*.gguf"])
            self.assertEqual(cfg.validate(), [])

    def test_validate_missing_key(self):
        from squash.github_app import GitHubAppConfig
        cfg = GitHubAppConfig(
            app_id=1, private_key_path="/no/such/file.pem",
            webhook_secret="x",
        )
        errors = cfg.validate()
        self.assertTrue(any("private_key_path" in e for e in errors))


# ── Outcome rendering ─────────────────────────────────────────────────────────


class TestAttestationOutcome(unittest.TestCase):
    def test_check_run_output_passed(self):
        from squash.github_app import AttestationOutcome
        out = AttestationOutcome(
            passed=True, model_id="m", summary="ok", detail_md="d",
        )
        body = out.to_check_run_output()
        self.assertIn("passed", body["title"])
        self.assertEqual(out.conclusion, "success")

    def test_check_run_output_failed(self):
        from squash.github_app import AttestationOutcome
        out = AttestationOutcome(
            passed=False, model_id="m", summary="bad", detail_md="d",
        )
        body = out.to_check_run_output()
        self.assertIn("FAILED", body["title"])
        self.assertEqual(out.conclusion, "failure")


# ── HTTP server (in-process) ──────────────────────────────────────────────────


class TestHttpServer(unittest.TestCase):
    def setUp(self):
        from squash.github_app import (
            GitHubAppConfig, WebhookHandler, ModelFileMatcher,
            WebhookOutcome, serve,
        )
        # Build a config with a real (placeholder) key file so validate() passes.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        key = Path(self._tmp.name) / "k.pem"
        key.write_bytes(b"placeholder")
        cfg = GitHubAppConfig(
            app_id=1, private_key_path=str(key), webhook_secret="topsecret",
        )

        class _StubHandler(WebhookHandler):
            def __init__(self, cfg):
                self._config = cfg
                self._matcher = ModelFileMatcher(cfg.model_patterns)
                self._auth = None
                self._client = _FakeClient()
                self._runner = _fake_runner_factory(True)(cfg)
                self._cloner = _fake_cloner

        self.handler = _StubHandler(cfg)
        self.cfg = cfg

        self.server = serve(cfg, handler=self.handler, host="127.0.0.1", port=0)
        self.addCleanup(self.server.server_close)
        self.t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.t.start()
        self.addCleanup(self.server.shutdown)
        self.host, self.port = self.server.server_address[:2]

    def _post(self, body: bytes, sig: str | None, event: str = "ping"):
        req = urllib.request.Request(
            f"http://{self.host}:{self.port}/webhook", method="POST", data=body,
        )
        req.add_header("Content-Type", "application/json")
        if sig is not None:
            req.add_header("X-Hub-Signature-256", sig)
        req.add_header("X-GitHub-Event", event)
        req.add_header("X-GitHub-Delivery", "abc-123")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _sig(self, body: bytes) -> str:
        import hashlib, hmac
        return "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()

    def test_health_endpoint(self):
        with urllib.request.urlopen(
            f"http://{self.host}:{self.port}/healthz", timeout=5,
        ) as r:
            body = json.loads(r.read())
        self.assertTrue(body.get("ok"))

    def test_invalid_signature_rejected(self):
        body = b'{"zen": "x"}'
        status, _ = self._post(body, sig="sha256=deadbeef", event="ping")
        self.assertEqual(status, 401)

    def test_missing_signature_rejected(self):
        status, _ = self._post(b"{}", sig=None, event="ping")
        self.assertEqual(status, 401)

    def test_ping_handled(self):
        body = b'{"zen": "x"}'
        status, payload = self._post(body, self._sig(body), event="ping")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["handled"])

    def test_invalid_json_rejected(self):
        body = b"{not json"
        status, _ = self._post(body, self._sig(body), event="ping")
        self.assertEqual(status, 400)


# ── CLI handler ───────────────────────────────────────────────────────────────


class TestCli(unittest.TestCase):
    def test_config_init_writes_template(self):
        from squash.cli import _cmd_github_app
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.yaml"
            ns = argparse.Namespace(
                gha_command="config",
                gha_cfg_init=str(target),
                gha_cfg_check=None,
                gha_cfg_show=False,
            )
            rc = _cmd_github_app(ns, quiet=True)
            self.assertEqual(rc, 0)
            self.assertTrue(target.exists())
            self.assertIn("model_patterns", target.read_text())

    def test_config_check_invalid_returns_two(self):
        from squash.cli import _cmd_github_app
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "bad.yaml"
            cfg_path.write_text(
                "app_id: 0\nprivate_key_path: ''\nwebhook_secret: ''\n"
            )
            ns = argparse.Namespace(
                gha_command="config",
                gha_cfg_init=None,
                gha_cfg_check=str(cfg_path),
                gha_cfg_show=False,
            )
            rc = _cmd_github_app(ns, quiet=True)
            self.assertEqual(rc, 2)

    def test_verify_webhook_valid_signature(self):
        from squash.cli import _cmd_github_app
        body = b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(b"S", body, hashlib.sha256).hexdigest()
        ns = argparse.Namespace(
            gha_command="verify-webhook",
            gha_v_secret="S", gha_v_sig=sig,
            gha_v_body=body.decode(), gha_v_body_file=None,
        )
        self.assertEqual(_cmd_github_app(ns, quiet=True), 0)

    def test_verify_webhook_invalid_signature(self):
        from squash.cli import _cmd_github_app
        ns = argparse.Namespace(
            gha_command="verify-webhook",
            gha_v_secret="S", gha_v_sig="sha256=00",
            gha_v_body="{}", gha_v_body_file=None,
        )
        self.assertEqual(_cmd_github_app(ns, quiet=True), 1)

    def test_unknown_subcommand_returns_two(self):
        from squash.cli import _cmd_github_app
        ns = argparse.Namespace(gha_command=None)
        self.assertEqual(_cmd_github_app(ns, quiet=True), 2)


# ── CLI parser registration ───────────────────────────────────────────────────


class TestCliRegistration(unittest.TestCase):
    def test_dispatch_branch_present(self):
        cli_src = (Path(__file__).parent.parent / "squash" / "cli.py").read_text()
        self.assertIn('args.command == "github-app"', cli_src)
        self.assertIn("_cmd_github_app", cli_src)


if __name__ == "__main__":
    unittest.main()
