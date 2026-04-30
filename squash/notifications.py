"""squash/notifications.py — Slack, Teams, and generic webhook notification adapter.

Fires structured JSON payloads to Slack, Microsoft Teams, or any outbound
webhook URL when squash attestation events occur.

Supported event types
---------------------
``attestation.passed``   — CI/pipeline attestation completed successfully.
``attestation.failed``   — Policy violation detected.
``drift.detected``       — Model drifted from its attested baseline.
``vex.new_cve``          — New CVE matched a deployed model's VEX feed.
``quota.exhausted``      — Monthly attestation quota reached.

Usage::

    from squash.notifications import NotificationConfig, NotificationDispatcher

    config = NotificationConfig(
        slack_webhook_url="https://hooks.slack.com/services/T.../B.../...",
        teams_webhook_url="https://acme.webhook.office.com/...",
    )
    dispatcher = NotificationDispatcher(config)

    dispatcher.notify(
        event="attestation.failed",
        model_id="llama-3-8b",
        details={"policy": "eu-ai-act", "violations": 3, "score": 42},
        link="https://dashboard.getsquash.dev/attestations/abc123",
    )

Environment variables (alternative to explicit config)::

    SQUASH_SLACK_WEBHOOK_URL
    SQUASH_TEAMS_WEBHOOK_URL
    SQUASH_WEBHOOK_URL          — generic outbound webhook
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ── Event type registry ────────────────────────────────────────────────────────

ATTESTATION_PASSED = "attestation.passed"
ATTESTATION_FAILED = "attestation.failed"
DRIFT_DETECTED = "drift.detected"
VEX_NEW_CVE = "vex.new_cve"
QUOTA_EXHAUSTED = "quota.exhausted"

_EVENT_EMOJI: dict[str, str] = {
    ATTESTATION_PASSED: "✅",
    ATTESTATION_FAILED: "❌",
    DRIFT_DETECTED: "⚠️",
    VEX_NEW_CVE: "🔴",
    QUOTA_EXHAUSTED: "🚫",
}

_EVENT_COLOR: dict[str, str] = {
    ATTESTATION_PASSED: "#2eb886",   # green
    ATTESTATION_FAILED: "#e01e5a",   # red
    DRIFT_DETECTED: "#f4a100",       # amber
    VEX_NEW_CVE: "#e01e5a",          # red
    QUOTA_EXHAUSTED: "#888888",      # grey
}


# ── Configuration ──────────────────────────────────────────────────────────────


@dataclass
class NotificationConfig:
    """Configuration for the notification dispatcher.

    All fields are optional; missing fields fall back to environment variables.
    """

    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    generic_webhook_url: str = ""
    timeout_seconds: int = 10
    # Only fire notifications for these event types; empty = all events
    event_filter: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.slack_webhook_url:
            self.slack_webhook_url = os.environ.get("SQUASH_SLACK_WEBHOOK_URL", "")
        if not self.teams_webhook_url:
            self.teams_webhook_url = os.environ.get("SQUASH_TEAMS_WEBHOOK_URL", "")
        if not self.generic_webhook_url:
            self.generic_webhook_url = os.environ.get("SQUASH_WEBHOOK_URL", "")

    @property
    def has_any_target(self) -> bool:
        return bool(self.slack_webhook_url or self.teams_webhook_url or self.generic_webhook_url)


# ── Notification result ────────────────────────────────────────────────────────


@dataclass
class NotificationResult:
    """Aggregated result of a notification dispatch."""

    event: str
    targets_attempted: int = 0
    targets_succeeded: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def all_succeeded(self) -> bool:
        return self.targets_attempted > 0 and self.targets_succeeded == self.targets_attempted

    @property
    def any_succeeded(self) -> bool:
        return self.targets_succeeded > 0


# ── Dispatcher ────────────────────────────────────────────────────────────────


class NotificationDispatcher:
    """Fire structured notifications to Slack, Teams, and generic webhooks.

    Thread-safe; creates one persistent config object, fires per-event.
    """

    def __init__(self, config: NotificationConfig | None = None) -> None:
        self.config = config or NotificationConfig()

    def notify(
        self,
        event: str,
        *,
        model_id: str = "",
        details: dict[str, Any] | None = None,
        link: str = "",
        title: str = "",
        plan: str = "",
    ) -> NotificationResult:
        """Fire a notification to all configured targets.

        Parameters
        ----------
        event:
            Event type string, e.g. ``"attestation.failed"``.
        model_id:
            Identifier of the model involved (e.g. ``"llama-3-8b"``).
        details:
            Arbitrary dict of event-specific metadata (violations count, score, etc.).
        link:
            URL to the full report or dashboard.
        title:
            Optional override for the notification title.

        Returns
        -------
        NotificationResult
        """
        result = NotificationResult(event=event)

        if not self.config.has_any_target:
            log.debug("notifications: no targets configured, skipping event=%s", event)
            return result

        if self.config.event_filter and event not in self.config.event_filter:
            log.debug("notifications: event=%s filtered out", event)
            return result

        details = details or {}
        auto_title = title or _make_title(event, model_id)

        # Sprint 13 (W203) — entitlement gating. When `plan` is provided
        # but does not grant the channel's entitlement, the dispatch is
        # silently skipped and recorded as a no-op (plan="" preserves
        # backward-compatible un-gated behaviour for CLI / library callers).
        from squash.auth import (
            has_entitlement,
            ENTITLEMENT_SLACK_DELIVERY,
            ENTITLEMENT_TEAMS_DELIVERY,
        )
        gate_slack = bool(plan) and not has_entitlement(plan, ENTITLEMENT_SLACK_DELIVERY)
        gate_teams = bool(plan) and not has_entitlement(plan, ENTITLEMENT_TEAMS_DELIVERY)

        # ── Slack ──────────────────────────────────────────────────────────────
        if self.config.slack_webhook_url:
            if gate_slack:
                log.debug(
                    "notifications: slack delivery requires entitlement %s "
                    "(plan=%s) — skipping", ENTITLEMENT_SLACK_DELIVERY, plan,
                )
            else:
                result.targets_attempted += 1
                try:
                    self._post_slack(auto_title, event, model_id, details, link)
                    result.targets_succeeded += 1
                except Exception as exc:  # noqa: BLE001
                    err = f"slack: {exc}"
                    result.errors.append(err)
                    log.warning("notifications: %s", err)

        # ── Teams ──────────────────────────────────────────────────────────────
        if self.config.teams_webhook_url:
            if gate_teams:
                log.debug(
                    "notifications: teams delivery requires entitlement %s "
                    "(plan=%s) — skipping", ENTITLEMENT_TEAMS_DELIVERY, plan,
                )
            else:
                result.targets_attempted += 1
                try:
                    self._post_teams(auto_title, event, model_id, details, link)
                    result.targets_succeeded += 1
                except Exception as exc:  # noqa: BLE001
                    err = f"teams: {exc}"
                    result.errors.append(err)
                    log.warning("notifications: %s", err)

        # ── Generic webhook ────────────────────────────────────────────────────
        if self.config.generic_webhook_url:
            result.targets_attempted += 1
            try:
                self._post_generic(event, model_id, details, link, auto_title)
                result.targets_succeeded += 1
            except Exception as exc:  # noqa: BLE001
                err = f"generic: {exc}"
                result.errors.append(err)
                log.warning("notifications: %s", err)

        return result

    # ── Slack Block Kit payload ────────────────────────────────────────────────

    def _post_slack(
        self,
        title: str,
        event: str,
        model_id: str,
        details: dict[str, Any],
        link: str,
    ) -> None:
        emoji = _EVENT_EMOJI.get(event, "🔔")
        color = _EVENT_COLOR.get(event, "#888888")

        fields = []
        if model_id:
            fields.append({"type": "mrkdwn", "text": f"*Model:*\n`{model_id}`"})
        for k, v in list(details.items())[:8]:
            fields.append({"type": "mrkdwn", "text": f"*{k.replace('_', ' ').title()}:*\n{v}"})

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True},
            },
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields[:10]})
        if link:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Report"},
                    "url": link,
                    "style": "primary",
                }],
            })

        payload = {
            "attachments": [{"color": color, "blocks": blocks}],
        }
        _http_post(self.config.slack_webhook_url, payload, self.config.timeout_seconds)

    # ── Teams Adaptive Card payload ────────────────────────────────────────────

    def _post_teams(
        self,
        title: str,
        event: str,
        model_id: str,
        details: dict[str, Any],
        link: str,
    ) -> None:
        emoji = _EVENT_EMOJI.get(event, "🔔")
        color = _EVENT_COLOR.get(event, "default").lstrip("#")

        facts = []
        if model_id:
            facts.append({"name": "Model", "value": model_id})
        for k, v in list(details.items())[:8]:
            facts.append({"name": k.replace("_", " ").title(), "value": str(v)})

        body: list[dict] = [
            {"type": "TextBlock", "size": "Large", "weight": "Bolder",
             "text": f"{emoji} {title}"},
        ]
        if facts:
            body.append({
                "type": "FactSet",
                "facts": facts,
            })

        actions = []
        if link:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Report",
                "url": link,
            })

        card: dict[str, Any] = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": actions,
                    "themeColor": color,
                },
            }],
        }
        _http_post(self.config.teams_webhook_url, card, self.config.timeout_seconds)

    # ── Generic webhook payload ────────────────────────────────────────────────

    def _post_generic(
        self,
        event: str,
        model_id: str,
        details: dict[str, Any],
        link: str,
        title: str,
    ) -> None:
        import datetime
        payload = {
            "event": event,
            "title": title,
            "model_id": model_id,
            "details": details,
            "link": link,
            "source": "squash-ai",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        _http_post(self.config.generic_webhook_url, payload, self.config.timeout_seconds)


# ── Module-level singleton helpers ─────────────────────────────────────────────

_dispatcher: NotificationDispatcher | None = None


def get_dispatcher(config: NotificationConfig | None = None) -> NotificationDispatcher:
    """Return the module-level dispatcher singleton, creating it if needed."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = NotificationDispatcher(config)
    return _dispatcher


def reset_dispatcher() -> NotificationDispatcher:
    """Reset the module-level singleton (for test isolation)."""
    global _dispatcher
    _dispatcher = NotificationDispatcher()
    return _dispatcher


def notify(
    event: str,
    *,
    model_id: str = "",
    details: dict[str, Any] | None = None,
    link: str = "",
    title: str = "",
) -> NotificationResult:
    """Convenience function using the module-level dispatcher singleton."""
    return get_dispatcher().notify(
        event,
        model_id=model_id,
        details=details,
        link=link,
        title=title,
    )


# ── Internal helpers ───────────────────────────────────────────────────────────


def _make_title(event: str, model_id: str) -> str:
    templates = {
        ATTESTATION_PASSED: "Attestation passed{model}",
        ATTESTATION_FAILED: "Attestation failed{model} — policy violation",
        DRIFT_DETECTED: "Model drift detected{model}",
        VEX_NEW_CVE: "New CVE affects{model}",
        QUOTA_EXHAUSTED: "Monthly attestation quota exhausted{model}",
    }
    model_suffix = f": {model_id}" if model_id else ""
    return templates.get(event, f"Squash event: {event}").format(model=model_suffix)


def _http_post(url: str, payload: dict, timeout: int) -> None:
    """POST JSON payload to url, raising on non-2xx response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "squash-ai/notifications"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = resp.getcode()
        if not (200 <= status < 300):
            raise RuntimeError(f"HTTP {status} from {url}")
