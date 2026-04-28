"""tests/test_squash_w165.py — W165: JIRA/Linear/GitHub auto-ticketing module."""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestTicketConfig(unittest.TestCase):
    """TicketConfig auto-detection and env var fallback."""

    def setUp(self):
        from squash.ticketing import TicketConfig
        self.TicketConfig = TicketConfig

    def test_explicit_backend(self):
        cfg = self.TicketConfig(backend="github", github_token="tok", github_repo="a/b")
        self.assertEqual(cfg.backend, "github")

    def test_auto_detect_github_from_env(self):
        with patch.dict(os.environ, {
            "SQUASH_GITHUB_TOKEN": "ghp_test",
            "SQUASH_GITHUB_REPO": "acme/ml",
        }, clear=False):
            cfg = self.TicketConfig()
        self.assertEqual(cfg.backend, "github")
        self.assertEqual(cfg.github_token, "ghp_test")
        self.assertEqual(cfg.github_repo, "acme/ml")

    def test_auto_detect_jira_from_env(self):
        with patch.dict(os.environ, {
            "SQUASH_JIRA_URL": "https://acme.atlassian.net",
            "SQUASH_JIRA_USER": "user@acme.com",
            "SQUASH_JIRA_TOKEN": "jira_token",
            "SQUASH_JIRA_PROJECT": "AI",
        }, clear=False):
            cfg = self.TicketConfig()
        self.assertEqual(cfg.backend, "jira")

    def test_auto_detect_linear_from_env(self):
        with patch.dict(os.environ, {
            "SQUASH_LINEAR_TOKEN": "lin_api_test",
            "SQUASH_LINEAR_TEAM_ID": "team-123",
        }, clear=False):
            cfg = self.TicketConfig()
        self.assertEqual(cfg.backend, "linear")

    def test_is_configured_github_valid(self):
        cfg = self.TicketConfig(backend="github", github_token="tok", github_repo="a/b")
        self.assertTrue(cfg.is_configured)

    def test_is_configured_github_missing_token(self):
        cfg = self.TicketConfig(backend="github", github_repo="a/b")
        self.assertFalse(cfg.is_configured)

    def test_is_configured_jira_valid(self):
        cfg = self.TicketConfig(
            backend="jira",
            jira_url="https://acme.atlassian.net",
            jira_user="u",
            jira_token="t",
            jira_project="AI",
        )
        self.assertTrue(cfg.is_configured)

    def test_is_configured_linear_valid(self):
        cfg = self.TicketConfig(
            backend="linear", linear_token="tok", linear_team_id="team-1"
        )
        self.assertTrue(cfg.is_configured)

    def test_is_configured_no_backend(self):
        cfg = self.TicketConfig()
        self.assertFalse(cfg.is_configured)

    def test_timeout_default(self):
        cfg = self.TicketConfig()
        self.assertEqual(cfg.timeout_seconds, 15)


class TestTicketResult(unittest.TestCase):
    """TicketResult dataclass."""

    def setUp(self):
        from squash.ticketing import TicketResult
        self.TicketResult = TicketResult

    def test_success_defaults_false(self):
        r = self.TicketResult()
        self.assertFalse(r.success)

    def test_fields_set(self):
        r = self.TicketResult(
            success=True,
            ticket_id="PROJ-123",
            ticket_url="https://example.com/PROJ-123",
            backend="jira",
        )
        self.assertTrue(r.success)
        self.assertEqual(r.ticket_id, "PROJ-123")
        self.assertEqual(r.backend, "jira")


class TestTicketDispatcherNotConfigured(unittest.TestCase):
    """TicketDispatcher returns graceful result when not configured."""

    def test_no_config_returns_not_success(self):
        from squash.ticketing import TicketDispatcher, TicketConfig
        dispatcher = TicketDispatcher(TicketConfig())
        result = dispatcher.create_ticket("Test", "body")
        self.assertFalse(result.success)
        self.assertIn("not configured", result.error)


class TestTicketDispatcherGitHub(unittest.TestCase):
    """GitHub Issues backend."""

    def _make_dispatcher(self):
        from squash.ticketing import TicketDispatcher, TicketConfig
        cfg = TicketConfig(backend="github", github_token="ghp_test", github_repo="acme/ml")
        return TicketDispatcher(cfg)

    def test_creates_github_issue(self):
        dispatcher = self._make_dispatcher()
        mock_resp = json.dumps({"number": 42, "html_url": "https://github.com/acme/ml/issues/42"}).encode()
        mock_resp_obj = MagicMock()
        mock_resp_obj.getcode.return_value = 201
        mock_resp_obj.read.return_value = mock_resp
        mock_resp_obj.__enter__ = lambda s: s
        mock_resp_obj.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp_obj):
            result = dispatcher.create_ticket(
                "EU AI Act violation",
                "Policy score: 42",
                labels=["compliance"],
                priority="high",
                model_id="bert-base",
                policy="eu-ai-act",
            )

        self.assertTrue(result.success)
        self.assertEqual(result.ticket_id, "42")
        self.assertIn("42", result.ticket_url)
        self.assertEqual(result.backend, "github")

    def test_github_request_has_auth_header(self):
        dispatcher = self._make_dispatcher()
        captured_req = {}
        mock_resp_obj = MagicMock()
        mock_resp_obj.getcode.return_value = 201
        mock_resp_obj.read.return_value = b'{"number": 1, "html_url": "https://github.com/x"}'
        mock_resp_obj.__enter__ = lambda s: s
        mock_resp_obj.__exit__ = MagicMock(return_value=False)

        def fake_urlopen(req, timeout=None):
            captured_req["headers"] = dict(req.headers)
            return mock_resp_obj

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            dispatcher.create_ticket("T", "B")

        auth = captured_req.get("headers", {}).get("Authorization", "")
        self.assertIn("token ghp_test", auth)

    def test_github_http_error_returns_failed_result(self):
        dispatcher = self._make_dispatcher()
        with patch("squash.ticketing._http_post", side_effect=RuntimeError("HTTP 422")):
            result = dispatcher.create_ticket("T", "B")
        self.assertFalse(result.success)
        self.assertIn("422", result.error)


class TestTicketDispatcherJira(unittest.TestCase):
    """JIRA backend."""

    def _make_dispatcher(self):
        from squash.ticketing import TicketDispatcher, TicketConfig
        cfg = TicketConfig(
            backend="jira",
            jira_url="https://acme.atlassian.net",
            jira_user="user@acme.com",
            jira_token="api_token",
            jira_project="AI",
        )
        return TicketDispatcher(cfg)

    def test_creates_jira_issue(self):
        dispatcher = self._make_dispatcher()
        mock_resp_data = {"key": "AI-42", "self": "https://acme.atlassian.net/rest/api/3/issue/1"}

        with patch("squash.ticketing._http_post", return_value=mock_resp_data):
            result = dispatcher.create_ticket("JIRA Test", "body", priority="high")

        self.assertTrue(result.success)
        self.assertEqual(result.ticket_id, "AI-42")
        self.assertIn("AI-42", result.ticket_url)
        self.assertEqual(result.backend, "jira")

    def test_jira_priority_mapping(self):
        from squash.ticketing import _JIRA_PRIORITY_MAP
        self.assertEqual(_JIRA_PRIORITY_MAP["critical"], "Highest")
        self.assertEqual(_JIRA_PRIORITY_MAP["high"], "High")
        self.assertEqual(_JIRA_PRIORITY_MAP["medium"], "Medium")
        self.assertEqual(_JIRA_PRIORITY_MAP["low"], "Low")


class TestTicketDispatcherLinear(unittest.TestCase):
    """Linear backend."""

    def _make_dispatcher(self):
        from squash.ticketing import TicketDispatcher, TicketConfig
        cfg = TicketConfig(
            backend="linear",
            linear_token="lin_api_test",
            linear_team_id="team-abc",
        )
        return TicketDispatcher(cfg)

    def test_creates_linear_issue(self):
        dispatcher = self._make_dispatcher()
        mock_resp_data = {
            "data": {
                "issueCreate": {
                    "success": True,
                    "issue": {
                        "id": "uuid-123",
                        "identifier": "ENG-42",
                        "url": "https://linear.app/team/issue/ENG-42",
                    }
                }
            }
        }

        with patch("squash.ticketing._http_post", return_value=mock_resp_data):
            result = dispatcher.create_ticket("Linear Test", "body")

        self.assertTrue(result.success)
        self.assertEqual(result.ticket_id, "ENG-42")
        self.assertIn("ENG-42", result.ticket_url)
        self.assertEqual(result.backend, "linear")

    def test_linear_priority_mapping(self):
        from squash.ticketing import _LINEAR_PRIORITY_MAP
        self.assertEqual(_LINEAR_PRIORITY_MAP["critical"], 1)
        self.assertEqual(_LINEAR_PRIORITY_MAP["high"], 2)
        self.assertEqual(_LINEAR_PRIORITY_MAP["medium"], 3)
        self.assertEqual(_LINEAR_PRIORITY_MAP["low"], 4)


class TestTicketBodyBuilder(unittest.TestCase):
    """_build_body helper."""

    def test_body_with_model_and_policy(self):
        from squash.ticketing import _build_body
        result = _build_body("violation details", model_id="bert", policy="eu-ai-act")
        self.assertIn("bert", result)
        self.assertIn("eu-ai-act", result)
        self.assertIn("violation details", result)

    def test_body_without_metadata(self):
        from squash.ticketing import _build_body
        result = _build_body("plain body")
        self.assertEqual(result, "plain body")

    def test_body_model_only(self):
        from squash.ticketing import _build_body
        result = _build_body("details", model_id="llama-3")
        self.assertIn("llama-3", result)
        self.assertNotIn("Policy", result)


class TestTicketingHttpPost(unittest.TestCase):
    """_http_post in ticketing module."""

    def test_raises_on_non_2xx(self):
        from squash.ticketing import _http_post
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 422
        mock_resp.read.return_value = b'{"errors": []}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                _http_post("https://example.com", {}, 5)
        self.assertIn("422", str(ctx.exception))

    def test_returns_parsed_json(self):
        from squash.ticketing import _http_post
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps({"number": 1}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _http_post("https://example.com", {}, 5)
        self.assertEqual(result["number"], 1)

    def test_non_json_response_returns_empty_dict(self):
        from squash.ticketing import _http_post
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b"OK"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _http_post("https://example.com", {}, 5)
        self.assertEqual(result, {})


class TestTicketingSingleton(unittest.TestCase):
    """Module-level singleton helpers."""

    def test_get_dispatcher_singleton(self):
        from squash.ticketing import get_dispatcher, reset_dispatcher
        d1 = reset_dispatcher()
        d2 = get_dispatcher()
        self.assertIs(d1, d2)

    def test_create_ticket_convenience(self):
        from squash.ticketing import create_ticket, reset_dispatcher
        reset_dispatcher()
        result = create_ticket("T", "B")
        self.assertFalse(result.success)
        self.assertIn("not configured", result.error)


if __name__ == "__main__":
    unittest.main()
