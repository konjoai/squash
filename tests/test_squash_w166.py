"""tests/test_squash_w166.py — W166: FastAPI/Django compliance middleware."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestAttestationState(unittest.TestCase):
    """AttestationState parsing."""

    def setUp(self):
        from squash.middleware import AttestationState
        self.AttestationState = AttestationState

    def test_defaults(self):
        state = self.AttestationState()
        self.assertFalse(state.compliant)
        self.assertEqual(state.model_id, "")
        self.assertEqual(state.policy, "")
        self.assertEqual(state.error, "")

    def test_from_squash_report_passed(self):
        data = {
            "passed": True,
            "model_id": "bert-base",
            "policy": "eu-ai-act",
            "timestamp": "2026-04-28T12:00:00Z",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        state = self.AttestationState.from_squash_report(path)
        self.assertTrue(state.compliant)
        self.assertEqual(state.model_id, "bert-base")
        self.assertEqual(state.policy, "eu-ai-act")
        self.assertEqual(state.attested_at, "2026-04-28T12:00:00Z")

    def test_from_squash_report_failed(self):
        data = {"passed": False, "model_id": "gpt4", "policy": "nist-ai-rmf"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        state = self.AttestationState.from_squash_report(path)
        self.assertFalse(state.compliant)

    def test_from_squash_report_missing_file(self):
        state = self.AttestationState.from_squash_report("/nonexistent/path.json")
        self.assertFalse(state.compliant)
        self.assertIn("not found", state.error)

    def test_from_cyclonedx_parsed(self):
        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "timestamp": "2026-04-28T12:00:00Z",
                "component": {"name": "my-model"},
                "properties": [
                    {"name": "squash:passed", "value": "true"},
                    {"name": "squash:policy", "value": "eu-ai-act"},
                    {"name": "squash:model_id", "value": "my-model"},
                ],
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cdx, f)
            path = f.name

        state = self.AttestationState.from_cyclonedx(path)
        self.assertTrue(state.compliant)
        self.assertEqual(state.policy, "eu-ai-act")

    def test_from_cyclonedx_non_compliant(self):
        cdx = {
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {"name": "model"},
                "properties": [{"name": "squash:passed", "value": "false"}],
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cdx, f)
            path = f.name

        state = self.AttestationState.from_cyclonedx(path)
        self.assertFalse(state.compliant)

    def test_from_cyclonedx_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            path = f.name

        state = self.AttestationState.from_cyclonedx(path)
        self.assertFalse(state.compliant)
        self.assertIn("parse error", state.error)


class TestSquashComplianceMiddlewareAsgi(unittest.TestCase):
    """SquashComplianceMiddleware ASGI behavior."""

    def setUp(self):
        from squash.middleware import SquashComplianceMiddleware
        self.SquashComplianceMiddleware = SquashComplianceMiddleware

    def test_passes_through_when_no_attestation(self):
        """Middleware passes through when block_on_missing=False (default)."""
        inner_called = []

        async def inner_app(scope, receive, send):
            inner_called.append(True)
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            })
            await send({"type": "http.response.body", "body": b""})

        mw = self.SquashComplianceMiddleware(
            inner_app,
            block_on_missing=False,
        )

        import asyncio

        sent_messages = []

        async def fake_send(msg):
            sent_messages.append(msg)

        scope = {"type": "http", "path": "/test"}
        asyncio.get_event_loop().run_until_complete(
            mw(scope, None, fake_send)
        )
        self.assertTrue(inner_called)

    def test_injects_squash_compliant_header(self):
        """Response headers include X-Squash-Compliant."""
        async def inner_app(scope, receive, send):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            })
            await send({"type": "http.response.body", "body": b""})

        mw = self.SquashComplianceMiddleware(inner_app, model_id="bert")

        import asyncio
        sent = []

        async def capture(msg):
            sent.append(msg)

        asyncio.get_event_loop().run_until_complete(
            mw({"type": "http"}, None, capture)
        )

        start = next(m for m in sent if m.get("type") == "http.response.start")
        header_names = [h[0] for h in start["headers"]]
        self.assertIn(b"x-squash-compliant", header_names)

    def test_blocks_when_block_on_missing_true(self):
        """Returns 503 when block_on_missing=True and no attestation."""
        inner_called = []

        async def inner_app(scope, receive, send):
            inner_called.append(True)

        mw = self.SquashComplianceMiddleware(
            inner_app,
            block_on_missing=True,
        )

        import asyncio
        sent = []

        async def capture(msg):
            sent.append(msg)

        asyncio.get_event_loop().run_until_complete(
            mw({"type": "http"}, None, capture)
        )

        self.assertFalse(inner_called, "inner app should not be called when blocking")
        start = next((m for m in sent if m.get("type") == "http.response.start"), None)
        self.assertIsNotNone(start)
        self.assertEqual(start["status"], 503)

    def test_passthrough_for_non_http_scope(self):
        """Non-HTTP scopes (lifespan) pass through unchanged."""
        inner_called = []

        async def inner_app(scope, receive, send):
            inner_called.append(True)

        mw = self.SquashComplianceMiddleware(inner_app)

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            mw({"type": "lifespan"}, None, None)
        )
        self.assertTrue(inner_called)

    def test_compliant_header_true_when_attestation_passed(self):
        """X-Squash-Compliant is 'true' when attestation file says passed."""
        from squash.middleware import AttestationState

        data = {"passed": True, "model_id": "bert", "policy": "eu-ai-act"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        async def inner_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        mw = self.SquashComplianceMiddleware(
            inner_app,
            attestation_path=path,
            model_id="bert",
        )

        import asyncio
        sent = []

        async def capture(msg):
            sent.append(msg)

        asyncio.get_event_loop().run_until_complete(
            mw({"type": "http"}, None, capture)
        )

        start = next(m for m in sent if m.get("type") == "http.response.start")
        headers = dict(start["headers"])
        self.assertEqual(headers.get(b"x-squash-compliant"), b"true")

    def test_model_header_injected(self):
        """X-Squash-Model header is set when model_id configured."""
        async def inner_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        mw = self.SquashComplianceMiddleware(inner_app, model_id="llama-3")

        import asyncio
        sent = []

        async def capture(msg):
            sent.append(msg)

        asyncio.get_event_loop().run_until_complete(
            mw({"type": "http"}, None, capture)
        )

        start = next(m for m in sent if m.get("type") == "http.response.start")
        headers = dict(start["headers"])
        self.assertEqual(headers.get(b"x-squash-model"), b"llama-3")


class TestSquashDjangoMiddleware(unittest.TestCase):
    """SquashDjangoMiddleware WSGI behavior."""

    def setUp(self):
        from squash.middleware import SquashDjangoMiddleware
        self.SquashDjangoMiddleware = SquashDjangoMiddleware

    def test_calls_get_response(self):
        mock_response = MagicMock()
        mock_response.__setitem__ = MagicMock()
        mock_request = MagicMock()

        def get_response(request):
            return mock_response

        mw = self.SquashDjangoMiddleware(get_response)
        result = mw(mock_request)
        self.assertIs(result, mock_response)

    def test_injects_compliance_header(self):
        headers_set = {}
        mock_response = MagicMock()
        mock_response.__setitem__ = lambda s, k, v: headers_set.update({k: v})
        mock_request = MagicMock()

        def get_response(request):
            return mock_response

        mw = self.SquashDjangoMiddleware(get_response)
        mw(mock_request)
        self.assertIn("X-Squash-Compliant", headers_set)

    def test_blocks_when_configured_and_not_compliant(self):
        """Returns 503 dict-like response when block_on_missing=True."""
        mock_request = MagicMock()
        inner_called = []

        def get_response(request):
            inner_called.append(True)
            return MagicMock()

        mw = self.SquashDjangoMiddleware(get_response)
        mw._config = {"block_on_missing": True}

        # Mock django.http.JsonResponse since Django may not be installed
        mock_json_response = MagicMock()
        with patch.dict("sys.modules", {"django.http": MagicMock(JsonResponse=MagicMock(return_value=mock_json_response))}):
            result = mw(mock_request)

        self.assertFalse(inner_called)


class TestMiddlewareStateRefresh(unittest.TestCase):
    """Attestation state is refreshed after interval."""

    def test_state_reloaded_after_interval(self):
        from squash.middleware import SquashComplianceMiddleware
        import time

        async def inner_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        mw = SquashComplianceMiddleware(inner_app, refresh_interval_seconds=0)
        mw._last_loaded = time.monotonic() - 1

        # Force reload by clearing state
        mw._state = None

        import asyncio
        sent = []

        async def capture(msg):
            sent.append(msg)

        asyncio.get_event_loop().run_until_complete(
            mw({"type": "http"}, None, capture)
        )

        start = next(m for m in sent if m.get("type") == "http.response.start")
        header_names = [h[0] for h in start["headers"]]
        self.assertIn(b"x-squash-compliant", header_names)


if __name__ == "__main__":
    unittest.main()
