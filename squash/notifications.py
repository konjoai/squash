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
ATTESTATION_FROZEN = "attestation.frozen"
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
        ATTESTATION_FROZEN: "EMERGENCY FREEZE{model} — attestation revoked",
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


# ─────────────────────────────────────────────────────────────────────────────
# B3 — W209/W210: Compliance Digest (weekly / monthly portfolio email)
# ─────────────────────────────────────────────────────────────────────────────

# Brief design:
#   - ComplianceDigestBuilder.build() consumes the existing dashboard.Dashboard
#     to produce a structured ComplianceDigest with:
#       1. five-metric summary panel
#       2. top-5 worst-scoring models ("risk movers" — ranked by lowest score
#          and most violations; cross-period deltas opportunistic when an
#          attestation history exists in registry)
#       3. regulatory deadline countdown (EU AI Act Aug 2 + Colorado Jun 1)
#       4. HTML body (inlined CSS, email-client safe — no <style> blocks)
#       5. plain-text body (Markdown-shaped fallback for the same content)
#   - send_email_digest() is a stdlib-only smtplib wrapper. PRs that want to
#     route digests via Resend / Mailgun / SES point a smarthost SMTP at the
#     provider — no provider-specific code in squash.
#   - The digest is also delivery-routable via NotificationDispatcher events
#     for orgs that prefer Slack/Teams summaries over email.
#
# Why no new module: notifications is already the home for all outbound
# events. A second module would be a graveyard.
#
# Foundation: dashboard.Dashboard already computes the five-metric panel
# and the deadline countdown — the digest is a render layer over that.

import datetime as _dt


_DEFAULT_DEADLINES: tuple[tuple[str, _dt.date], ...] = (
    ("EU AI Act enforcement", _dt.date(2026, 8, 2)),
    ("Colorado AI Act", _dt.date(2026, 6, 1)),
    ("ISO 42001 review window", _dt.date(2027, 1, 1)),
)


@dataclass
class DigestMover:
    """One entry in the top-5 risk-mover panel."""

    model_id: str
    compliance_score: float | None
    open_violations: int
    open_cves: int
    risk_tier: str
    drift_detected: bool
    last_attested: str = ""
    score_delta: float | None = None  # positive = improved; None = no history

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "compliance_score": self.compliance_score,
            "open_violations": self.open_violations,
            "open_cves": self.open_cves,
            "risk_tier": self.risk_tier,
            "drift_detected": self.drift_detected,
            "last_attested": self.last_attested,
            "score_delta": self.score_delta,
        }


@dataclass
class DigestDeadline:
    """Regulatory deadline countdown row."""

    label: str
    date: str  # YYYY-MM-DD
    days_remaining: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "date": self.date,
            "days_remaining": self.days_remaining,
        }


@dataclass
class ComplianceDigest:
    """Renderable compliance-portfolio digest.

    The single source of truth for the email AND any structured webhook
    payload version. Both ``html_body`` and ``text_body`` are computed
    eagerly so callers can branch on delivery channel without re-rendering.
    """

    period: str  # "weekly" | "monthly"
    generated_at: str
    subject: str
    summary: dict[str, Any]            # 5-metric panel
    top_movers: list[DigestMover]
    deadlines: list[DigestDeadline]
    html_body: str
    text_body: str
    # Optional pointer to a host that renders a richer view (sent in email
    # footer + included in webhook payloads).
    dashboard_url: str = ""
    org_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "squash_version": "compliance_digest_v1",
            "period": self.period,
            "generated_at": self.generated_at,
            "subject": self.subject,
            "summary": dict(self.summary),
            "top_movers": [m.to_dict() for m in self.top_movers],
            "deadlines": [d.to_dict() for d in self.deadlines],
            "dashboard_url": self.dashboard_url,
            "org_name": self.org_name,
        }


class ComplianceDigestBuilder:
    """Build a :class:`ComplianceDigest` from the live attestation portfolio.

    Foundation: ``squash.dashboard.Dashboard.build()`` already computes the
    five-metric panel + per-model rows + deadline countdown. The builder
    layers the digest concerns on top: subject line, top-5 ranking, score
    deltas (when history is available), HTML / plain-text rendering.

    Usage::

        from squash.notifications import ComplianceDigestBuilder
        digest = ComplianceDigestBuilder().build(
            period="weekly",
            models_dir=Path("./models"),
            org_name="Acme ML Platform",
        )
        print(digest.text_body)        # cron-friendly stdout dump
        print(digest.html_body)        # MIMEMultipart payload
    """

    def build(
        self,
        *,
        period: str = "weekly",
        models_dir: "Any | None" = None,
        model_paths: "list[Any] | None" = None,
        dashboard: "Any | None" = None,
        org_name: str = "",
        dashboard_url: str = "",
        score_history: dict[str, float] | None = None,
        deadlines: tuple[tuple[str, _dt.date], ...] | None = None,
        now: _dt.datetime | None = None,
    ) -> ComplianceDigest:
        """Render the digest.

        Args:
            period:        ``"weekly"`` or ``"monthly"``.
            models_dir:    Forwarded to ``Dashboard.build``.
            model_paths:   Forwarded to ``Dashboard.build``.
            dashboard:     Pre-built :class:`squash.dashboard.Dashboard`. When
                           supplied, ``models_dir`` / ``model_paths`` are
                           ignored — useful for tests + cached calls.
            org_name:      Recipient-facing org label. Empty → omits header.
            dashboard_url: URL to the live dashboard (footer link).
            score_history: Map of ``model_id → previous_score``. When
                           supplied, score deltas are computed for each
                           top-mover row. Empty → deltas elided.
            deadlines:     Override the deadline rows. Default: EU Aug 2,
                           Colorado Jun 1, ISO 42001 review window.
            now:           Inject a deterministic clock. Default: now (UTC).
        """
        if period not in ("weekly", "monthly"):
            raise ValueError(f"period must be 'weekly' or 'monthly', got {period!r}")

        if dashboard is None:
            from squash.dashboard import Dashboard  # local import — no hard dep
            dashboard = Dashboard.build(
                models_dir=models_dir, model_paths=model_paths,
            )

        now = now or _dt.datetime.now(_dt.timezone.utc)

        movers = self._top_movers(dashboard, score_history or {}, limit=5)
        deadline_rows = self._deadlines(deadlines or _DEFAULT_DEADLINES, now)

        summary = {
            "total_models": int(getattr(dashboard, "total_models", 0)),
            "models_passing": int(getattr(dashboard, "models_passing", 0)),
            "models_failing": int(getattr(dashboard, "models_failing", 0)),
            "overall_score": getattr(dashboard, "overall_score", None),
            "total_violations": int(getattr(dashboard, "total_violations", 0)),
            "total_cves": int(getattr(dashboard, "total_cves", 0)),
            "portfolio_trend": getattr(dashboard, "portfolio_trend", "stable"),
        }
        subject = self._subject(period, summary, deadline_rows, org_name)
        text_body = _render_digest_text(
            period, summary, movers, deadline_rows, org_name, dashboard_url,
        )
        html_body = _render_digest_html(
            period, summary, movers, deadline_rows, org_name, dashboard_url,
        )

        return ComplianceDigest(
            period=period,
            generated_at=now.isoformat(),
            subject=subject,
            summary=summary,
            top_movers=movers,
            deadlines=deadline_rows,
            html_body=html_body,
            text_body=text_body,
            dashboard_url=dashboard_url,
            org_name=org_name,
        )

    # ── Internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _top_movers(
        dashboard: "Any",
        score_history: dict[str, float],
        *,
        limit: int = 5,
    ) -> list[DigestMover]:
        rows = list(getattr(dashboard, "model_rows", []) or [])

        def _rank_key(r: "Any") -> tuple[int, float, int]:
            # Worst-first: violations DESC, score ASC, cves DESC.
            score = float(getattr(r, "compliance_score", 0) or 0)
            viol = int(getattr(r, "open_violations", 0) or 0)
            cves = int(getattr(r, "open_cves", 0) or 0)
            return (-viol, score, -cves)

        rows.sort(key=_rank_key)
        out: list[DigestMover] = []
        for r in rows[:limit]:
            mid = str(getattr(r, "model_id", "") or "")
            score = getattr(r, "compliance_score", None)
            prev = score_history.get(mid)
            delta: float | None = None
            if prev is not None and score is not None:
                delta = round(float(score) - float(prev), 1)
            out.append(DigestMover(
                model_id=mid,
                compliance_score=score,
                open_violations=int(getattr(r, "open_violations", 0) or 0),
                open_cves=int(getattr(r, "open_cves", 0) or 0),
                risk_tier=str(getattr(r, "risk_tier", "") or "unknown"),
                drift_detected=bool(getattr(r, "drift_detected", False)),
                last_attested=str(getattr(r, "last_attested", "") or ""),
                score_delta=delta,
            ))
        return out

    @staticmethod
    def _deadlines(
        rows: tuple[tuple[str, _dt.date], ...],
        now: _dt.datetime,
    ) -> list[DigestDeadline]:
        out: list[DigestDeadline] = []
        today = now.date()
        for label, date in rows:
            days = (date - today).days
            out.append(DigestDeadline(
                label=label,
                date=date.isoformat(),
                days_remaining=days,
            ))
        # Sort soonest-first; bury already-elapsed deadlines at the end.
        out.sort(key=lambda d: (d.days_remaining < 0, abs(d.days_remaining)))
        return out

    @staticmethod
    def _subject(
        period: str,
        summary: dict[str, Any],
        deadlines: list[DigestDeadline],
        org_name: str,
    ) -> str:
        period_word = "weekly" if period == "weekly" else "monthly"
        org = f"{org_name}: " if org_name else ""
        score = summary.get("overall_score")
        score_str = f"{score:.0f}%" if isinstance(score, (int, float)) else "—"
        viol = summary.get("total_violations", 0)
        deadline_tail = ""
        for d in deadlines:
            if 0 <= d.days_remaining <= 60:
                deadline_tail = f" · {d.label} in {d.days_remaining}d"
                break
        return (
            f"[squash] {org}{period_word.capitalize()} compliance digest — "
            f"score {score_str} · {viol} violations{deadline_tail}"
        )


def _render_digest_text(
    period: str,
    summary: dict[str, Any],
    movers: list[DigestMover],
    deadlines: list[DigestDeadline],
    org_name: str,
    dashboard_url: str,
) -> str:
    lines: list[str] = []
    if org_name:
        lines.append(f"# {org_name} · {period.capitalize()} compliance digest")
    else:
        lines.append(f"# {period.capitalize()} compliance digest")
    lines.append("")
    lines.append("## Portfolio summary")
    lines.append("")
    score = summary.get("overall_score")
    score_str = f"{score:.1f}%" if isinstance(score, (int, float)) else "N/A"
    lines.append(f"- Overall score: **{score_str}**")
    lines.append(f"- Models: {summary.get('total_models', 0)} "
                 f"({summary.get('models_passing', 0)} passing, "
                 f"{summary.get('models_failing', 0)} failing)")
    lines.append(f"- Open violations: {summary.get('total_violations', 0)}")
    lines.append(f"- Open CVEs: {summary.get('total_cves', 0)}")
    lines.append(f"- Trend: {summary.get('portfolio_trend', 'stable')}")
    lines.append("")

    lines.append("## Top 5 risk movers")
    lines.append("")
    if movers:
        for i, m in enumerate(movers, start=1):
            score_str = f"{m.compliance_score:.0f}%" \
                if isinstance(m.compliance_score, (int, float)) else "N/A"
            delta_str = ""
            if m.score_delta is not None:
                arrow = "▲" if m.score_delta > 0 else ("▼" if m.score_delta < 0 else "→")
                delta_str = f" {arrow} {m.score_delta:+.1f}"
            drift_tag = " · drift" if m.drift_detected else ""
            lines.append(
                f"{i}. {m.model_id} — {score_str}{delta_str} · "
                f"{m.open_violations} violations · {m.open_cves} CVEs · "
                f"{m.risk_tier}{drift_tag}"
            )
    else:
        lines.append("_No models tracked. Run `squash attest ./model` to add one._")
    lines.append("")

    lines.append("## Regulatory deadlines")
    lines.append("")
    for d in deadlines:
        if d.days_remaining < 0:
            lines.append(f"- {d.label} ({d.date}) — past")
        elif d.days_remaining == 0:
            lines.append(f"- {d.label} ({d.date}) — today")
        else:
            lines.append(f"- {d.label} ({d.date}) — {d.days_remaining}d")
    lines.append("")
    if dashboard_url:
        lines.append(f"View live dashboard: {dashboard_url}")
        lines.append("")
    lines.append(
        "— squash · `pip install squash-ai` · https://getsquash.dev"
    )
    return "\n".join(lines) + "\n"


def _render_digest_html(
    period: str,
    summary: dict[str, Any],
    movers: list[DigestMover],
    deadlines: list[DigestDeadline],
    org_name: str,
    dashboard_url: str,
) -> str:
    """Email-client-safe HTML — inlined styles only, no <style>/<link>.

    Renders defensively: no flexbox, no grid, no JS, no remote images.
    Tables for layout (Outlook still doesn't accept much else in 2026).
    """
    score = summary.get("overall_score")
    score_str = f"{score:.1f}%" if isinstance(score, (int, float)) else "N/A"
    score_color = (
        "#10b981" if isinstance(score, (int, float)) and score >= 80 else
        "#f59e0b" if isinstance(score, (int, float)) and score >= 60 else
        "#ef4444"
    )
    org_header = (
        f"<div style='color:#666;font-size:13px;margin-bottom:4px'>{_html_escape(org_name)}</div>"
        if org_name else ""
    )

    movers_rows: list[str] = []
    if movers:
        for m in movers:
            mscore = (
                f"{m.compliance_score:.0f}%"
                if isinstance(m.compliance_score, (int, float)) else "N/A"
            )
            delta_html = ""
            if m.score_delta is not None:
                if m.score_delta > 0:
                    delta_html = (
                        f" <span style='color:#10b981'>▲ {m.score_delta:+.1f}</span>"
                    )
                elif m.score_delta < 0:
                    delta_html = (
                        f" <span style='color:#ef4444'>▼ {m.score_delta:+.1f}</span>"
                    )
                else:
                    delta_html = " <span style='color:#666'>→ 0.0</span>"
            drift_pill = (
                "<span style='background:#fef3c7;color:#92400e;padding:1px 6px;"
                "border-radius:3px;font-size:11px;margin-left:6px'>drift</span>"
                if m.drift_detected else ""
            )
            movers_rows.append(
                f"<tr>"
                f"<td style='padding:8px 12px;border-bottom:1px solid #eee'>"
                f"<code style='background:#f6f6f6;padding:2px 6px;border-radius:3px'>"
                f"{_html_escape(m.model_id)}</code>{drift_pill}</td>"
                f"<td style='padding:8px 12px;border-bottom:1px solid #eee;"
                f"text-align:right;font-weight:600'>{mscore}{delta_html}</td>"
                f"<td style='padding:8px 12px;border-bottom:1px solid #eee;"
                f"text-align:right;color:#666'>"
                f"{m.open_violations} viol · {m.open_cves} CVEs</td>"
                f"</tr>"
            )
    else:
        movers_rows.append(
            "<tr><td colspan='3' style='padding:12px;color:#666'>"
            "No models tracked. Run <code>squash attest ./model</code> to add one."
            "</td></tr>"
        )

    deadline_rows: list[str] = []
    for d in deadlines:
        if d.days_remaining < 0:
            badge = "<span style='color:#666'>past</span>"
        elif d.days_remaining == 0:
            badge = "<span style='color:#ef4444;font-weight:600'>today</span>"
        elif d.days_remaining <= 30:
            badge = (
                f"<span style='color:#ef4444;font-weight:600'>"
                f"{d.days_remaining}d</span>"
            )
        elif d.days_remaining <= 90:
            badge = f"<span style='color:#f59e0b'>{d.days_remaining}d</span>"
        else:
            badge = f"<span style='color:#10b981'>{d.days_remaining}d</span>"
        deadline_rows.append(
            f"<tr>"
            f"<td style='padding:6px 12px'>{_html_escape(d.label)}</td>"
            f"<td style='padding:6px 12px;color:#666'>{d.date}</td>"
            f"<td style='padding:6px 12px;text-align:right'>{badge}</td>"
            f"</tr>"
        )

    dashboard_link = (
        f"<p style='margin:24px 0 0 0;font-size:13px'>"
        f"<a href='{_html_escape(dashboard_url)}' "
        f"style='color:#3b82f6;text-decoration:none'>"
        f"View live dashboard →</a></p>"
        if dashboard_url else ""
    )

    return (
        "<!doctype html><html><body style='font-family:-apple-system,Segoe UI,"
        "Helvetica,Arial,sans-serif;color:#222;background:#fafafa;margin:0;"
        "padding:24px'>"
        "<table cellpadding='0' cellspacing='0' role='presentation' width='100%' "
        "style='max-width:640px;margin:0 auto;background:#fff;border:1px solid "
        "#e5e7eb;border-radius:8px;padding:32px'>"
        "<tr><td>"
        f"{org_header}"
        f"<h1 style='margin:0 0 16px 0;font-size:22px;color:#111'>"
        f"{period.capitalize()} compliance digest</h1>"

        # Summary
        "<h2 style='margin:8px 0 8px 0;font-size:16px;color:#111'>"
        "Portfolio summary</h2>"
        "<table cellpadding='0' cellspacing='0' role='presentation' width='100%' "
        "style='margin:16px 0 24px 0'>"
        f"<tr><td style='padding:12px 0'>Overall score</td>"
        f"<td style='padding:12px 0;text-align:right;font-size:24px;"
        f"font-weight:700;color:{score_color}'>{score_str}</td></tr>"
        f"<tr><td style='padding:6px 0;color:#666'>Models</td>"
        f"<td style='padding:6px 0;text-align:right'>"
        f"<strong>{summary.get('total_models', 0)}</strong> total · "
        f"{summary.get('models_passing', 0)} passing · "
        f"{summary.get('models_failing', 0)} failing</td></tr>"
        f"<tr><td style='padding:6px 0;color:#666'>Open violations</td>"
        f"<td style='padding:6px 0;text-align:right'>"
        f"<strong>{summary.get('total_violations', 0)}</strong></td></tr>"
        f"<tr><td style='padding:6px 0;color:#666'>Open CVEs</td>"
        f"<td style='padding:6px 0;text-align:right'>"
        f"<strong>{summary.get('total_cves', 0)}</strong></td></tr>"
        f"<tr><td style='padding:6px 0;color:#666'>Trend</td>"
        f"<td style='padding:6px 0;text-align:right'>"
        f"{_html_escape(str(summary.get('portfolio_trend', 'stable')))}</td></tr>"
        "</table>"

        # Movers
        "<h2 style='margin:24px 0 8px 0;font-size:16px;color:#111'>"
        "Top 5 risk movers</h2>"
        "<table cellpadding='0' cellspacing='0' role='presentation' width='100%' "
        "style='border-top:1px solid #eee'>"
        + "".join(movers_rows) +
        "</table>"

        # Deadlines
        "<h2 style='margin:24px 0 8px 0;font-size:16px;color:#111'>"
        "Regulatory deadlines</h2>"
        "<table cellpadding='0' cellspacing='0' role='presentation' width='100%'>"
        + "".join(deadline_rows) +
        "</table>"

        + dashboard_link +

        "<p style='margin:24px 0 0 0;font-size:11px;color:#999;border-top:1px "
        "solid #eee;padding-top:16px'>"
        "Sent by squash · <code>pip install squash-ai</code> · "
        "<a href='https://getsquash.dev' style='color:#999'>getsquash.dev</a>"
        "</p>"
        "</td></tr></table></body></html>"
    )


def _html_escape(s: str) -> str:
    """Stdlib-only HTML escape (avoids the html.escape import for hot paths)."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


@dataclass
class SmtpConfig:
    """SMTP connection settings for ``send_email_digest``.

    All fields fall back to environment variables on construction:

    ============================  =================================
    Field                         Env var
    ============================  =================================
    ``host``                      ``SQUASH_SMTP_HOST``
    ``port``                      ``SQUASH_SMTP_PORT``  (default 587)
    ``username``                  ``SQUASH_SMTP_USER``
    ``password``                  ``SQUASH_SMTP_PASSWORD``
    ``from_addr``                 ``SQUASH_SMTP_FROM``
    ``use_tls``                   ``SQUASH_SMTP_TLS`` (truthy = TLS)
    ============================  =================================

    Resend / Mailgun / SES are supported by pointing host+port+credentials
    at the provider's SMTP relay — no provider-specific code in squash.
    """

    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    use_tls: bool = True
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.host:
            self.host = os.environ.get("SQUASH_SMTP_HOST", "")
        env_port = os.environ.get("SQUASH_SMTP_PORT", "")
        if env_port and self.port == 587:
            try:
                self.port = int(env_port)
            except ValueError:
                pass
        if not self.username:
            self.username = os.environ.get("SQUASH_SMTP_USER", "")
        if not self.password:
            self.password = os.environ.get("SQUASH_SMTP_PASSWORD", "")
        if not self.from_addr:
            self.from_addr = os.environ.get("SQUASH_SMTP_FROM", "")
        env_tls = os.environ.get("SQUASH_SMTP_TLS")
        if env_tls is not None:
            self.use_tls = env_tls.strip().lower() in ("1", "true", "yes", "on")

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.from_addr)


@dataclass
class DigestSendResult:
    """Outcome of a digest send attempt."""

    success: bool
    recipients: list[str] = field(default_factory=list)
    delivered: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "recipients": list(self.recipients),
            "delivered": self.delivered,
            "error": self.error,
        }


def send_email_digest(
    digest: ComplianceDigest,
    recipients: list[str],
    *,
    smtp: SmtpConfig | None = None,
    dry_run: bool = False,
) -> DigestSendResult:
    """Send the rendered digest as a multipart MIME email.

    Args:
        digest:     Fully rendered :class:`ComplianceDigest`.
        recipients: Non-empty list of RFC-822 email addresses.
        smtp:       :class:`SmtpConfig`. Default: read from environment.
        dry_run:    If ``True``, returns the result with ``success=True``
                    without opening any network connection. Use for CI
                    smoke tests + cron-friendly previews.

    Returns:
        :class:`DigestSendResult`. ``success=False`` always populates
        ``error``; transient SMTP failures roll up into the same shape.
    """
    if not recipients:
        return DigestSendResult(success=False, error="no recipients supplied")
    cfg = smtp or SmtpConfig()
    if dry_run:
        return DigestSendResult(
            success=True, recipients=list(recipients), delivered=len(recipients),
        )
    if not cfg.is_configured:
        return DigestSendResult(
            success=False, recipients=list(recipients),
            error="SMTP not configured (set SQUASH_SMTP_HOST + SQUASH_SMTP_FROM)",
        )

    # Build the MIME message — multipart/alternative so clients pick the
    # richer body when supported, plain-text otherwise.
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    msg = MIMEMultipart("alternative")
    msg["Subject"] = digest.subject
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(digest.text_body, "plain", "utf-8"))
    msg.attach(MIMEText(digest.html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout_seconds) as srv:
            srv.ehlo()
            if cfg.use_tls:
                srv.starttls()
                srv.ehlo()
            if cfg.username and cfg.password:
                srv.login(cfg.username, cfg.password)
            srv.sendmail(cfg.from_addr, recipients, msg.as_string())
    except Exception as exc:  # noqa: BLE001 — surface any SMTP error verbatim
        log.warning("digest: SMTP send failed: %s", exc)
        return DigestSendResult(
            success=False, recipients=list(recipients), error=str(exc),
        )

    log.info("digest: emailed %d recipient(s) via %s",
             len(recipients), cfg.host)
    return DigestSendResult(
        success=True, recipients=list(recipients), delivered=len(recipients),
    )
