"""squash/ticketing.py — Auto-ticketing adapter for JIRA, Linear, and GitHub Issues.

When a squash attestation fails or a policy violation is detected, this module
can automatically create a tracking ticket in the team's issue tracker so that
violations flow into existing engineering workflows without manual triage.

Supported backends
------------------
``jira``          — Atlassian JIRA Cloud / Server REST API v3.
``linear``        — Linear GraphQL API.
``github``        — GitHub Issues REST API.

Usage::

    from squash.ticketing import TicketConfig, TicketDispatcher

    config = TicketConfig(
        backend="github",
        github_token="ghp_...",
        github_repo="acme/ml-models",
    )
    dispatcher = TicketDispatcher(config)
    result = dispatcher.create_ticket(
        title="EU AI Act violation: bert-base-uncased",
        body="Policy score: 42/100. Violations: data_governance, transparency.",
        labels=["compliance", "ai-act"],
        priority="high",
    )
    print(result.ticket_url)

Environment variables (alternative to explicit config)::

    SQUASH_JIRA_URL            — e.g. https://acme.atlassian.net
    SQUASH_JIRA_USER           — Atlassian account email
    SQUASH_JIRA_TOKEN          — Atlassian API token
    SQUASH_JIRA_PROJECT        — JIRA project key (e.g. "AI")
    SQUASH_LINEAR_TOKEN        — Linear API key
    SQUASH_LINEAR_TEAM_ID      — Linear team ID
    SQUASH_GITHUB_TOKEN        — GitHub personal access token
    SQUASH_GITHUB_REPO         — owner/repo slug
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ── Priority mapping ───────────────────────────────────────────────────────────

_JIRA_PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

_LINEAR_PRIORITY_MAP = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 0,
}


# ── Configuration ──────────────────────────────────────────────────────────────


@dataclass
class TicketConfig:
    """Configuration for the ticketing dispatcher.

    All fields fall back to environment variables when not set explicitly.
    """

    backend: str = ""           # "jira" | "linear" | "github"
    timeout_seconds: int = 15

    # JIRA
    jira_url: str = ""          # https://acme.atlassian.net
    jira_user: str = ""
    jira_token: str = ""
    jira_project: str = ""

    # Linear
    linear_token: str = ""
    linear_team_id: str = ""

    # GitHub
    github_token: str = ""
    github_repo: str = ""       # "owner/repo"

    def __post_init__(self) -> None:
        if not self.jira_url:
            self.jira_url = os.environ.get("SQUASH_JIRA_URL", "")
        if not self.jira_user:
            self.jira_user = os.environ.get("SQUASH_JIRA_USER", "")
        if not self.jira_token:
            self.jira_token = os.environ.get("SQUASH_JIRA_TOKEN", "")
        if not self.jira_project:
            self.jira_project = os.environ.get("SQUASH_JIRA_PROJECT", "")
        if not self.linear_token:
            self.linear_token = os.environ.get("SQUASH_LINEAR_TOKEN", "")
        if not self.linear_team_id:
            self.linear_team_id = os.environ.get("SQUASH_LINEAR_TEAM_ID", "")
        if not self.github_token:
            self.github_token = os.environ.get("SQUASH_GITHUB_TOKEN", "")
        if not self.github_repo:
            self.github_repo = os.environ.get("SQUASH_GITHUB_REPO", "")

        if not self.backend:
            if self.jira_url and self.jira_token:
                self.backend = "jira"
            elif self.linear_token:
                self.backend = "linear"
            elif self.github_token:
                self.backend = "github"

    @property
    def is_configured(self) -> bool:
        if self.backend == "jira":
            return bool(self.jira_url and self.jira_user and self.jira_token and self.jira_project)
        if self.backend == "linear":
            return bool(self.linear_token and self.linear_team_id)
        if self.backend == "github":
            return bool(self.github_token and self.github_repo)
        return False


# ── Ticket result ──────────────────────────────────────────────────────────────


@dataclass
class TicketResult:
    """Result of a ticket creation attempt."""

    success: bool = False
    ticket_id: str = ""
    ticket_url: str = ""
    backend: str = ""
    error: str = ""


# ── Dispatcher ────────────────────────────────────────────────────────────────


class TicketDispatcher:
    """Create compliance tickets in JIRA, Linear, or GitHub Issues.

    Thread-safe; all state is in the config object.
    """

    def __init__(self, config: TicketConfig | None = None) -> None:
        self.config = config or TicketConfig()

    def create_ticket(
        self,
        title: str,
        body: str,
        *,
        labels: list[str] | None = None,
        priority: str = "medium",
        model_id: str = "",
        policy: str = "",
    ) -> TicketResult:
        """Create a compliance ticket in the configured backend.

        Parameters
        ----------
        title:
            Short issue title.
        body:
            Full markdown body / description.
        labels:
            List of label strings to apply.
        priority:
            Severity: critical | high | medium | low | info.
        model_id:
            Model identifier to include in the ticket body.
        policy:
            Policy framework name.

        Returns
        -------
        TicketResult
        """
        if not self.config.is_configured:
            log.debug("ticketing: backend not configured, skipping")
            return TicketResult(success=False, error="backend not configured")

        full_body = _build_body(body, model_id=model_id, policy=policy)
        labels = labels or ["squash", "compliance"]

        try:
            if self.config.backend == "jira":
                return self._create_jira(title, full_body, labels, priority)
            if self.config.backend == "linear":
                return self._create_linear(title, full_body, labels, priority)
            if self.config.backend == "github":
                return self._create_github(title, full_body, labels, priority)
        except Exception as exc:  # noqa: BLE001
            log.warning("ticketing: failed to create ticket: %s", exc)
            return TicketResult(success=False, backend=self.config.backend, error=str(exc))

        return TicketResult(success=False, error=f"unknown backend: {self.config.backend}")

    # ── JIRA ──────────────────────────────────────────────────────────────────

    def _create_jira(
        self,
        title: str,
        body: str,
        labels: list[str],
        priority: str,
    ) -> TicketResult:
        url = f"{self.config.jira_url.rstrip('/')}/rest/api/3/issue"
        jira_priority = _JIRA_PRIORITY_MAP.get(priority, "Medium")

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": self.config.jira_project},
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": body}]}
                    ],
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": jira_priority},
                "labels": labels,
            }
        }

        creds = base64.b64encode(
            f"{self.config.jira_user}:{self.config.jira_token}".encode()
        ).decode()
        headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        resp_data = _http_post(url, payload, self.config.timeout_seconds, headers=headers)
        ticket_id = resp_data.get("key", "")
        ticket_url = f"{self.config.jira_url}/browse/{ticket_id}" if ticket_id else ""
        return TicketResult(
            success=bool(ticket_id),
            ticket_id=ticket_id,
            ticket_url=ticket_url,
            backend="jira",
        )

    # ── Linear ────────────────────────────────────────────────────────────────

    def _create_linear(
        self,
        title: str,
        body: str,
        labels: list[str],
        priority: str,
    ) -> TicketResult:
        url = "https://api.linear.app/graphql"
        linear_priority = _LINEAR_PRIORITY_MAP.get(priority, 3)

        mutation = """
        mutation CreateIssue($teamId: String!, $title: String!, $description: String!, $priority: Int) {
          issueCreate(input: {
            teamId: $teamId
            title: $title
            description: $description
            priority: $priority
          }) {
            success
            issue {
              id
              identifier
              url
            }
          }
        }
        """

        payload = {
            "query": mutation,
            "variables": {
                "teamId": self.config.linear_team_id,
                "title": title,
                "description": body,
                "priority": linear_priority,
            },
        }

        headers = {
            "Authorization": self.config.linear_token,
            "Content-Type": "application/json",
        }

        resp_data = _http_post(url, payload, self.config.timeout_seconds, headers=headers)
        issue = resp_data.get("data", {}).get("issueCreate", {}).get("issue", {})
        ticket_id = issue.get("identifier", "")
        ticket_url = issue.get("url", "")
        return TicketResult(
            success=bool(ticket_id),
            ticket_id=ticket_id,
            ticket_url=ticket_url,
            backend="linear",
        )

    # ── GitHub Issues ─────────────────────────────────────────────────────────

    def _create_github(
        self,
        title: str,
        body: str,
        labels: list[str],
        priority: str,
    ) -> TicketResult:
        repo = self.config.github_repo.strip("/")
        url = f"https://api.github.com/repos/{repo}/issues"

        payload: dict[str, Any] = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        headers = {
            "Authorization": f"token {self.config.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }

        resp_data = _http_post(url, payload, self.config.timeout_seconds, headers=headers)
        ticket_id = str(resp_data.get("number", ""))
        ticket_url = resp_data.get("html_url", "")
        return TicketResult(
            success=bool(ticket_id),
            ticket_id=ticket_id,
            ticket_url=ticket_url,
            backend="github",
        )


# ── Module-level singleton ─────────────────────────────────────────────────────

_dispatcher: TicketDispatcher | None = None


def get_dispatcher(config: TicketConfig | None = None) -> TicketDispatcher:
    """Return the module-level singleton, creating it if needed."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = TicketDispatcher(config)
    return _dispatcher


def reset_dispatcher() -> TicketDispatcher:
    """Reset the singleton (for test isolation)."""
    global _dispatcher
    _dispatcher = TicketDispatcher()
    return _dispatcher


def create_ticket(
    title: str,
    body: str,
    *,
    labels: list[str] | None = None,
    priority: str = "medium",
    model_id: str = "",
    policy: str = "",
) -> TicketResult:
    """Convenience function using the module-level singleton."""
    return get_dispatcher().create_ticket(
        title, body,
        labels=labels,
        priority=priority,
        model_id=model_id,
        policy=policy,
    )


# ── Internal helpers ───────────────────────────────────────────────────────────


def _build_body(body: str, *, model_id: str = "", policy: str = "") -> str:
    parts = []
    if model_id:
        parts.append(f"**Model:** `{model_id}`")
    if policy:
        parts.append(f"**Policy:** {policy}")
    if parts:
        return "\n".join(parts) + "\n\n" + body
    return body


def _http_post(
    url: str,
    payload: dict,
    timeout: int,
    *,
    headers: dict[str, str] | None = None,
) -> dict:
    """POST JSON payload; return parsed JSON response. Raises on non-2xx."""
    data = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", "User-Agent": "squash-ai/ticketing"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = resp.getcode()
        raw = resp.read()
        if not (200 <= status < 300):
            raise RuntimeError(f"HTTP {status} from {url}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
