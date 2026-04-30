"""squash/regulatory_watch.py — Sprint 27 W243–W245 (Track C / C4).

Continuous Regulatory Watch Daemon: real-time monitoring of primary
regulatory sources. Polls SEC.gov, NIST.gov, EUR-Lex, and generic
state-legislature RSS feeds; deduplicates against a local SQLite store;
runs gap analysis against the squash policy framework and the user's
attested model portfolio; routes structured alerts through
``squash.notifications``.

The **through-line**: regulatory change is the constant. The org that
learns about a new AI governance requirement on Day 1 instead of Day 90
has a 90-day moat. Squash turns that mailing list / RSS-refresh ritual
into a command and a cron job.

Architecture
============

::

    Source adapters (per-feed)
        └─ RegulatoryWatcher.poll()
               ├─ fetch() each adapter (graceful per-source failure)
               ├─ deduplicate against SQLite seen-events store
               └─ gap_analysis() maps new events → squash controls
                       └─ GapAnalysisResult per event

    CLI daemon (squash watch-regulatory)
        ├─ --once: single poll + print / notify
        ├─ --interval Nh: cron-friendly loop (sleep N hours)
        └─ --alert-channel {slack,teams,webhook,stdout}

Source adapters
===============

``SecAdapter``
    SEC EDGAR AI-governance RSS + SEC press-releases feed.
    Looks for enforcement actions and guidance mentioning AI.

``NistAdapter``
    NIST CSRC publications RSS — catches new SP 800-* and AI RMF updates.

``EurLexAdapter``
    EUR-Lex Official Journal RSS — catches AI Act delegated acts, Commission
    implementing decisions, and related OJ publications.

``GenericRssAdapter``
    Handles any RSS 2.0 or Atom feed (state legislatures, IAPP tracker,
    ISO/IEC news). Configurable keyword filter.

Gap analysis
============

Maps each new ``RegulatoryEvent`` to:

1. Which squash regulatory framework IDs (from ``regulatory_feed.py``) are
   affected — matched by keyword scan on title + summary.
2. Which squash CLI controls the org should run (pulled from the framework
   database).
3. Severity: ``HIGH`` / ``MEDIUM`` / ``LOW`` based on source authority +
   keyword patterns (enforcement actions → HIGH; guidance → MEDIUM; news →
   LOW).

Persistence
===========

Event IDs are stored in a SQLite database at
``~/.squash/regulatory_events.db`` (overridable). A seen event is never
re-alerted. The schema is minimal: ``(id TEXT PRIMARY KEY, fetched_at TEXT,
source TEXT, url TEXT, title TEXT)``.

Stdlib-only: ``urllib.request`` for HTTP, ``xml.etree.ElementTree`` for
RSS/Atom, ``sqlite3`` for persistence. ``notifications.py`` is imported
lazily for alert routing.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
import sqlite3
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger(__name__)

# Default paths
_DEFAULT_DB_PATH = Path.home() / ".squash" / "regulatory_events.db"

# Feed URLs used by built-in adapters
_SEC_PRESS_RSS = (
    "https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type="
    "AI&dateb=&owner=include&count=40&search_text=&output=atom"
)
_SEC_NEWS_RSS = "https://www.sec.gov/rss/news/press-releases.rss"
_NIST_RSS = "https://www.nist.gov/news-events/cybersecurity-topics.rss"
_NIST_CSRC_RSS = "https://csrc.nist.gov/publications/all/rss"
_EURLEX_OJ_RSS = "https://eur-lex.europa.eu/RSSOJ.do?ojType=ALL"
_EURLEX_PROC_RSS = "https://eur-lex.europa.eu/oj/direct-access.html?ojType=L&year=2026"

# Keyword sets used for AI-relevance filtering and severity scoring
_AI_KEYWORDS: frozenset[str] = frozenset({
    "artificial intelligence", "machine learning", "ai system", "large language",
    "llm", "generative ai", "foundation model", "ai act", "ai risk",
    "automated decision", "algorithmic", "ai governance", "ai compliance",
    "ai disclosure", "ai safety", "ai audit", "ai bias",
})
_HIGH_SEVERITY_PATTERNS: tuple[str, ...] = (
    "enforcement", "penalty", "fine", "violation", "cease", "sanction",
    "mandatory", "requirement", "deadline", "effective date",
)
_MEDIUM_SEVERITY_PATTERNS: tuple[str, ...] = (
    "guidance", "framework", "rule", "regulation", "directive", "standard",
    "amendment", "update", "revised", "final rule",
)

# Mapping from keyword fragments → regulatory framework IDs in regulatory_feed.py
_KEYWORD_TO_REG_ID: list[tuple[str, str]] = [
    ("eu ai act", "EU_AI_ACT"),
    ("artificial intelligence act", "EU_AI_ACT"),
    ("regulation 2024/1689", "EU_AI_ACT"),
    ("annex iv", "EU_AI_ACT"),
    ("nist ai rmf", "NIST_AI_RMF"),
    ("nist ai risk management", "NIST_AI_RMF"),
    ("ai 100-1", "NIST_AI_RMF"),
    ("iso 42001", "ISO_42001"),
    ("iso/iec 42001", "ISO_42001"),
    ("colorado ai", "COLORADO_AI_ACT"),
    ("sb 205", "COLORADO_AI_ACT"),
    ("nyc local law 144", "NYC_LL144"),
    ("local law 144", "NYC_LL144"),
    ("sec ai", "SEC_AI"),
    ("securities ai", "SEC_AI"),
    ("investment adviser ai", "SEC_AI"),
    ("ftc ai", "FTC_GUIDANCE"),
    ("ftc", "FTC_GUIDANCE"),
    ("fda ai", "FDA_AI_ML"),
    ("software as medical device", "FDA_AI_ML"),
    ("samd", "FDA_AI_ML"),
    ("cmmc", "CMMC"),
    ("fedramp", "FEDRAMP_AI"),
    ("gdpr", "EU_GDPR"),
    ("bipa", "ILLINOIS_BIPA"),
    ("biometric", "ILLINOIS_BIPA"),
]


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class RegulatoryEvent:
    """A single item fetched from a live regulatory source.

    Attributes:
        event_id:      Stable unique ID derived from source + URL hash.
        source:        Human-readable source label (e.g. ``"SEC Press"``,
                       ``"EUR-Lex OJ"``).
        title:         Publication title as returned by the feed.
        url:           Canonical URL for the full text.
        published:     ISO-8601 publication date (best effort; feed-dependent).
        summary:       Short text summary or abstract.
        severity:      Derived severity: ``"HIGH"`` / ``"MEDIUM"`` / ``"LOW"``.
        fetched_at:    ISO-8601 timestamp when squash first saw this event.
        raw_tags:      Raw category/label tags from the feed entry.
    """

    event_id: str
    source: str
    title: str
    url: str
    published: str
    summary: str
    severity: str = "LOW"
    fetched_at: str = ""
    raw_tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.fetched_at:
            self.fetched_at = _utc_now_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "title": self.title,
            "url": self.url,
            "published": self.published,
            "summary": self.summary,
            "severity": self.severity,
            "fetched_at": self.fetched_at,
            "raw_tags": list(self.raw_tags),
        }


@dataclass
class GapAnalysisResult:
    """Gap analysis for a single regulatory event.

    Maps the incoming event to the squash policy framework and surfaces
    which models in the local attestation registry may need re-attestation.

    Attributes:
        event:                  The triggering ``RegulatoryEvent``.
        matched_reg_ids:        Framework IDs from ``regulatory_feed.py``
                                whose text matched this event.
        squash_controls:        CLI commands the user should run (sourced
                                from the matched regulations' ``squash_controls``
                                field).
        models_to_re_attest:    Model IDs from the local registry that have
                                attestations covering the matched regulations.
        recommended_actions:    Plain-language remediation steps.
        days_to_act:            Urgency estimate — derived from matched
                                regulation enforcement deadlines.
    """

    event: RegulatoryEvent
    matched_reg_ids: list[str] = field(default_factory=list)
    squash_controls: list[str] = field(default_factory=list)
    models_to_re_attest: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    days_to_act: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "matched_reg_ids": list(self.matched_reg_ids),
            "squash_controls": list(self.squash_controls),
            "models_to_re_attest": list(self.models_to_re_attest),
            "recommended_actions": list(self.recommended_actions),
            "days_to_act": self.days_to_act,
        }

    def summary_text(self) -> str:
        lines = [
            f"[{self.event.severity}] {self.event.source}: {self.event.title}",
            f"  URL: {self.event.url}",
        ]
        if self.matched_reg_ids:
            lines.append(f"  Affects: {', '.join(self.matched_reg_ids)}")
        if self.models_to_re_attest:
            lines.append(f"  Re-attest: {', '.join(self.models_to_re_attest)}")
        if self.squash_controls:
            lines.append("  Run:")
            for c in self.squash_controls[:3]:
                lines.append(f"    $ {c}")
        if self.days_to_act is not None:
            lines.append(f"  Days to act: {self.days_to_act}")
        return "\n".join(lines)


@dataclass
class WatcherConfig:
    """Configuration for ``RegulatoryWatcher``.

    Attributes:
        db_path:         SQLite store for seen event IDs. Created on first use.
        sources:         Which built-in source adapters to poll. Default: all.
        extra_feeds:     Extra ``GenericRssAdapter`` configs — list of dicts
                         with keys ``name``, ``url``, and optional ``keywords``.
        timeout_seconds: Per-request HTTP timeout.
        max_events:      Max events returned per poll cycle (oldest first).
        alert_on_new:    Notify through ``squash.notifications`` on new events.
        alert_channel:   ``"slack"`` / ``"teams"`` / ``"webhook"`` / ``"stdout"``.
    """

    db_path: Path = field(default_factory=lambda: _DEFAULT_DB_PATH)
    sources: list[str] = field(default_factory=lambda: ["sec", "nist", "eurlex"])
    extra_feeds: list[dict[str, Any]] = field(default_factory=list)
    timeout_seconds: int = 15
    max_events: int = 50
    alert_on_new: bool = True
    alert_channel: str = "stdout"

    def __post_init__(self) -> None:
        self.db_path = Path(self.db_path)


# ── Source adapters ───────────────────────────────────────────────────────────


class SecAdapter:
    """SEC.gov regulatory intelligence adapter.

    Polls the SEC press-release RSS feed and filters for AI-governance
    relevant items (enforcement actions, guidance, rule proposals).
    """

    name = "sec"
    label = "SEC Press"

    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout

    def fetch(self) -> list[RegulatoryEvent]:
        events: list[RegulatoryEvent] = []
        for url, source_label in [
            (_SEC_NEWS_RSS, "SEC Press"),
        ]:
            try:
                events.extend(self._fetch_rss(url, source_label))
            except Exception as exc:  # noqa: BLE001
                log.warning("regulatory_watch: SEC adapter failed (%s): %s", url, exc)
        return events

    def _fetch_rss(self, url: str, label: str) -> list[RegulatoryEvent]:
        raw = _http_get(url, self._timeout)
        return _parse_rss(raw, source_label=label, ai_filter=True)


class NistAdapter:
    """NIST.gov regulatory intelligence adapter.

    Polls NIST CSRC publications RSS for new AI RMF, SP 800-*, and AI
    governance publications.
    """

    name = "nist"
    label = "NIST CSRC"

    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout

    def fetch(self) -> list[RegulatoryEvent]:
        events: list[RegulatoryEvent] = []
        for url, label in [
            (_NIST_CSRC_RSS, "NIST CSRC"),
            (_NIST_RSS, "NIST News"),
        ]:
            try:
                events.extend(_parse_rss(_http_get(url, self._timeout),
                                         source_label=label, ai_filter=True))
            except Exception as exc:  # noqa: BLE001
                log.warning("regulatory_watch: NIST adapter failed (%s): %s", url, exc)
        return events


class EurLexAdapter:
    """EUR-Lex Official Journal adapter.

    Polls the EUR-Lex OJ RSS feed for new EU publications. Filters for
    AI Act, GDPR, and related instruments.
    """

    name = "eurlex"
    label = "EUR-Lex OJ"

    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout

    def fetch(self) -> list[RegulatoryEvent]:
        events: list[RegulatoryEvent] = []
        try:
            raw = _http_get(_EURLEX_OJ_RSS, self._timeout)
            events.extend(_parse_rss(raw, source_label="EUR-Lex OJ", ai_filter=True))
        except Exception as exc:  # noqa: BLE001
            log.warning("regulatory_watch: EUR-Lex adapter failed: %s", exc)
        return events


class GenericRssAdapter:
    """Generic RSS 2.0 / Atom adapter for arbitrary regulatory feeds.

    Used for state legislature tracking, IAPP news, ISO TC 42, etc.
    Configurable keyword filter; AI-only filtering is disabled by default
    so all items are returned (caller is responsible for relevance).

    Example::

        adapter = GenericRssAdapter(
            name="legiscan",
            url="https://legiscan.com/feeds/bills/AI/2026",
            keywords=["artificial intelligence", "ai act"],
        )
        events = adapter.fetch()
    """

    def __init__(
        self,
        name: str,
        url: str,
        keywords: list[str] | None = None,
        timeout: int = 15,
    ) -> None:
        self.name = name
        self.label = name
        self._url = url
        self._keywords = {k.lower() for k in (keywords or [])}
        self._timeout = timeout

    def fetch(self) -> list[RegulatoryEvent]:
        try:
            raw = _http_get(self._url, self._timeout)
            events = _parse_rss(raw, source_label=self.label, ai_filter=False)
            if self._keywords:
                events = [
                    e for e in events
                    if any(kw in e.title.lower() or kw in e.summary.lower()
                           for kw in self._keywords)
                ]
            return events
        except Exception as exc:  # noqa: BLE001
            log.warning("regulatory_watch: %s adapter failed (%s): %s",
                        self.name, self._url, exc)
            return []


# ── Core watcher ─────────────────────────────────────────────────────────────


class RegulatoryWatcher:
    """Poll live regulatory sources and run gap analysis.

    Manages deduplication via a local SQLite store and routes alerts
    through the squash notification dispatcher.

    Usage::

        cfg = WatcherConfig(sources=["sec", "nist", "eurlex"])
        watcher = RegulatoryWatcher(cfg)
        new_events, gap_results = watcher.poll()
        for gap in gap_results:
            print(gap.summary_text())
    """

    def __init__(self, config: WatcherConfig | None = None) -> None:
        self.config = config or WatcherConfig()
        self._ensure_db()

    # ── Public API ────────────────────────────────────────────────────────

    def poll(
        self,
        models_dir: Path | None = None,
    ) -> tuple[list[RegulatoryEvent], list[GapAnalysisResult]]:
        """Fetch from all configured sources and run gap analysis.

        Args:
            models_dir: Path to a directory of attested model subdirectories.
                        When supplied, ``gap_analysis`` identifies which
                        local models need re-attestation.

        Returns:
            ``(new_events, gap_results)`` — events not previously seen +
            the gap analysis results for each new event.  Both lists are
            empty when all events were already known.
        """
        all_events = self._fetch_all()
        new_events = self._filter_new(all_events)
        if new_events:
            self._mark_seen(new_events)
        gap_results = [
            self.gap_analysis(e, models_dir=models_dir) for e in new_events
        ]
        return new_events, gap_results

    def gap_analysis(
        self,
        event: RegulatoryEvent,
        models_dir: Path | None = None,
    ) -> GapAnalysisResult:
        """Map a regulatory event to squash controls and affected models.

        Args:
            event:      The regulatory event to analyse.
            models_dir: Directory of attested model subdirectories.

        Returns:
            ``GapAnalysisResult`` with matched framework IDs, recommended
            squash controls, and models needing re-attestation.
        """
        # 1. Match to framework IDs
        matched_ids = _match_regulatory_ids(event)

        # 2. Pull squash controls from the static feed
        controls: list[str] = []
        days_to_act: int | None = None
        try:
            from squash.regulatory_feed import RegulatoryFeed
            feed = RegulatoryFeed()
            for reg_id in matched_ids:
                reg = feed.get_regulation(reg_id)
                if reg:
                    controls.extend(reg.squash_controls)
                    if reg.enforcement_date and days_to_act is None:
                        try:
                            d = datetime.date.fromisoformat(reg.enforcement_date)
                            days_to_act = (d - datetime.date.today()).days
                        except ValueError:
                            pass
        except ImportError:
            pass

        # 3. Identify attested models that should be re-checked
        models_to_re_attest = _find_attested_models(models_dir) if models_dir else []

        # 4. Build recommended actions
        actions: list[str] = []
        if matched_ids:
            actions.append(
                f"Review the full text at {event.url} and assess impact on "
                f"your {', '.join(matched_ids)} compliance posture."
            )
        if controls:
            actions.append(f"Run: {controls[0]} to update attestation records.")
        if models_to_re_attest:
            actions.append(
                f"Re-attest {len(models_to_re_attest)} model(s) with "
                f"the affected policies."
            )
        if not actions:
            actions.append(
                "Monitor this development. No direct squash control mapping found — "
                "manual review recommended."
            )

        return GapAnalysisResult(
            event=event,
            matched_reg_ids=list(matched_ids),
            squash_controls=list(dict.fromkeys(controls))[:6],  # deduplicate, cap
            models_to_re_attest=models_to_re_attest,
            recommended_actions=actions,
            days_to_act=days_to_act if (days_to_act is not None and days_to_act >= 0) else None,
        )

    def notify(
        self,
        gap_results: list[GapAnalysisResult],
        channel: str = "stdout",
    ) -> None:
        """Dispatch gap-analysis alerts through the configured channel.

        Args:
            gap_results: Output of :meth:`poll` or individual
                         :meth:`gap_analysis` calls.
            channel:     ``"stdout"`` (print to terminal), ``"slack"``,
                         ``"teams"``, or ``"webhook"``.
        """
        if not gap_results:
            return
        if channel == "stdout":
            for gap in gap_results:
                print(gap.summary_text())
            return
        try:
            from squash.notifications import notify as _notify
        except ImportError:
            log.warning("regulatory_watch: notifications unavailable; printing to stdout")
            for gap in gap_results:
                print(gap.summary_text())
            return

        for gap in gap_results:
            details = {
                "matched_frameworks": gap.matched_reg_ids,
                "models_affected": len(gap.models_to_re_attest),
                "days_to_act": gap.days_to_act,
                "recommended_action": gap.recommended_actions[0] if gap.recommended_actions else "",
            }
            _notify(
                event="regulatory.new_guidance",
                model_id="",
                title=f"[{gap.event.severity}] {gap.event.source}: {gap.event.title[:80]}",
                details=details,
                link=gap.event.url,
            )

    def mark_all_seen(self, events: list[RegulatoryEvent]) -> None:
        """Persist event IDs so they are never re-surfaced.

        Useful when the user wants to catch up without being flooded by
        historical items on first run.
        """
        self._mark_seen(events)

    def load_history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent seen events from the persistent store."""
        with _open_db(self.config.db_path) as con:
            cur = con.execute(
                "SELECT id, fetched_at, source, title, url "
                "FROM regulatory_events ORDER BY fetched_at DESC LIMIT ?",
                (limit,),
            )
            return [
                {"id": r[0], "fetched_at": r[1], "source": r[2],
                 "title": r[3], "url": r[4]}
                for r in cur.fetchall()
            ]

    # ── Internal ──────────────────────────────────────────────────────────

    def _fetch_all(self) -> list[RegulatoryEvent]:
        """Fetch from every configured adapter (failures are logged and skipped)."""
        adapters = self._build_adapters()
        events: list[RegulatoryEvent] = []
        for adapter in adapters:
            try:
                fetched = adapter.fetch()
                log.info(
                    "regulatory_watch: %s → %d event(s)",
                    adapter.label, len(fetched),
                )
                events.extend(fetched)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "regulatory_watch: adapter %s failed: %s", adapter.name, exc,
                )
        # Cap total
        return events[: self.config.max_events * 3]  # generous pre-dedup cap

    def _build_adapters(self) -> list[Any]:
        adapters: list[Any] = []
        timeout = self.config.timeout_seconds
        for src in self.config.sources:
            src_lo = src.lower()
            if src_lo == "sec":
                adapters.append(SecAdapter(timeout=timeout))
            elif src_lo == "nist":
                adapters.append(NistAdapter(timeout=timeout))
            elif src_lo in ("eurlex", "eur-lex"):
                adapters.append(EurLexAdapter(timeout=timeout))
            else:
                log.warning("regulatory_watch: unknown source %r — skipping", src)
        for extra in self.config.extra_feeds:
            try:
                adapters.append(GenericRssAdapter(
                    name=extra["name"],
                    url=extra["url"],
                    keywords=extra.get("keywords"),
                    timeout=timeout,
                ))
            except (KeyError, TypeError) as exc:
                log.warning("regulatory_watch: bad extra_feed config: %s", exc)
        return adapters

    def _filter_new(self, events: list[RegulatoryEvent]) -> list[RegulatoryEvent]:
        if not events:
            return []
        ids = {e.event_id for e in events}
        with _open_db(self.config.db_path) as con:
            placeholders = ",".join("?" * len(ids))
            cur = con.execute(
                f"SELECT id FROM regulatory_events WHERE id IN ({placeholders})",
                tuple(ids),
            )
            already_seen = {row[0] for row in cur.fetchall()}
        new = [e for e in events if e.event_id not in already_seen]
        return new[: self.config.max_events]

    def _mark_seen(self, events: list[RegulatoryEvent]) -> None:
        if not events:
            return
        with _open_db(self.config.db_path) as con:
            con.executemany(
                "INSERT OR IGNORE INTO regulatory_events "
                "(id, fetched_at, source, title, url) VALUES (?,?,?,?,?)",
                [
                    (e.event_id, e.fetched_at, e.source,
                     e.title[:500], e.url[:1000])
                    for e in events
                ],
            )
            con.commit()

    def _ensure_db(self) -> None:
        self.config.db_path.parent.mkdir(parents=True, exist_ok=True)
        with _open_db(self.config.db_path) as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS regulatory_events ("
                "  id TEXT PRIMARY KEY, "
                "  fetched_at TEXT, "
                "  source TEXT, "
                "  title TEXT, "
                "  url TEXT"
                ")"
            )
            con.commit()


# ── RSS parsing utilities ─────────────────────────────────────────────────────


def _parse_rss(
    raw: bytes,
    source_label: str,
    ai_filter: bool = True,
) -> list[RegulatoryEvent]:
    """Parse RSS 2.0 or Atom bytes into ``RegulatoryEvent`` objects.

    Applies AI-relevance keyword filtering when ``ai_filter=True``.
    Each event gets a stable ID derived from the URL hash.
    """
    events: list[RegulatoryEvent] = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        log.debug("regulatory_watch: XML parse error: %s", exc)
        return events

    ns = _detect_ns(root)
    items = _iter_items(root, ns)

    for item in items:
        title = _text(item, ns, "title") or "Untitled"
        link = _text(item, ns, "link") or _attr_link(item)
        published = _extract_date(item, ns)
        summary = _text(item, ns, "summary") or _text(item, ns, "description") or ""
        # Strip HTML tags from summary
        summary = re.sub(r"<[^>]+>", " ", summary)
        summary = " ".join(summary.split())[:500]
        raw_tags = _extract_tags(item, ns)

        if ai_filter and not _is_ai_relevant(title, summary, raw_tags):
            continue

        event_id = _make_event_id(source_label, link or title)
        severity = _compute_severity(title, summary, source_label)

        events.append(RegulatoryEvent(
            event_id=event_id,
            source=source_label,
            title=title,
            url=link or "",
            published=published,
            summary=summary,
            severity=severity,
            raw_tags=raw_tags,
        ))

    return events


def _detect_ns(root: ET.Element) -> dict[str, str]:
    """Extract the Atom namespace URI from the root element tag, if present."""
    tag = root.tag
    m = re.match(r"^\{([^}]+)\}", tag)
    if m:
        ns_uri = m.group(1)
        if "atom" in ns_uri.lower() or "w3.org/2005" in ns_uri:
            return {"atom": ns_uri}
    return {}


def _iter_items(root: ET.Element, ns: dict[str, str]) -> Iterator[ET.Element]:
    """Yield RSS <item> or Atom <entry> elements (namespace-aware)."""
    atom_ns = ns.get("atom", "")
    # Atom feed
    if atom_ns:
        for entry in root.iter(f"{{{atom_ns}}}entry"):
            yield entry
        return
    # RSS 2.0 — bare tags; also handle unexpected namespaced item tags
    for child in root.iter():
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if local == "item":
            yield child


def _text(node: ET.Element, ns: dict[str, str], tag: str) -> str:
    """Extract text from a child element, trying bare and all-namespace forms."""
    # Bare tag first (RSS 2.0)
    el = node.find(tag)
    if el is not None and el.text:
        return el.text.strip()
    # Namespaced (Atom and mixed feeds)
    atom_ns = ns.get("atom", "")
    if atom_ns:
        el = node.find(f"{{{atom_ns}}}{tag}")
        if el is not None and el.text:
            return el.text.strip()
    # Walk direct children by local name (handles any unknown namespace)
    for child in node:
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if local == tag and child.text:
            return child.text.strip()
    return ""


def _attr_link(node: ET.Element) -> str:
    """Extract href from <link href="..."/> (Atom style)."""
    for child in node:
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if local == "link":
            href = child.get("href")
            if href:
                return href
    return ""


def _extract_date(node: ET.Element, ns: dict[str, str]) -> str:
    """Extract publication date, trying common RSS/Atom date tags."""
    for tag in ("pubDate", "published", "updated", "date"):
        val = _text(node, ns, tag)
        if val:
            # Normalise: just return as-is; consumers parse if needed
            return val[:25]
    return _utc_now_iso()[:10]


def _extract_tags(node: ET.Element, ns: dict[str, str]) -> list[str]:
    tags: list[str] = []
    for child in node:
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if local in ("category", "subject"):
            val = child.get("term") or child.text or ""
            if val:
                tags.append(val.strip())
    return tags


def _is_ai_relevant(title: str, summary: str, tags: list[str]) -> bool:
    """Return True if this item mentions AI-governance concepts."""
    haystack = (title + " " + summary + " " + " ".join(tags)).lower()
    return any(kw in haystack for kw in _AI_KEYWORDS)


def _compute_severity(title: str, summary: str, source: str) -> str:
    """Derive HIGH / MEDIUM / LOW severity from content + source."""
    text = (title + " " + summary).lower()
    if any(p in text for p in _HIGH_SEVERITY_PATTERNS):
        return "HIGH"
    # SEC and EUR-Lex final rules default to MEDIUM
    if source in ("SEC Press", "EUR-Lex OJ") and any(
        p in text for p in _MEDIUM_SEVERITY_PATTERNS
    ):
        return "MEDIUM"
    if any(p in text for p in _MEDIUM_SEVERITY_PATTERNS):
        return "MEDIUM"
    return "LOW"


def _match_regulatory_ids(event: RegulatoryEvent) -> list[str]:
    """Map an event's title + summary to regulatory framework IDs."""
    haystack = (event.title + " " + event.summary).lower()
    matched: list[str] = []
    for keyword, reg_id in _KEYWORD_TO_REG_ID:
        if keyword in haystack and reg_id not in matched:
            matched.append(reg_id)
    return matched


def _find_attested_models(models_dir: Path) -> list[str]:
    """Return model IDs that have attestation records in ``models_dir``."""
    out: list[str] = []
    if not models_dir.is_dir():
        return out
    for child in sorted(models_dir.iterdir()):
        if child.is_dir() and (child / "squash-attest.json").exists():
            try:
                data = json.loads((child / "squash-attest.json").read_text())
                model_id = data.get("model_id") or child.name
            except (json.JSONDecodeError, OSError):
                model_id = child.name
            out.append(model_id)
    return out


# ── Utilities ─────────────────────────────────────────────────────────────────


def _make_event_id(source: str, url_or_title: str) -> str:
    """Stable, short event ID — SHA-256 prefix of source + URL/title."""
    raw = f"{source}::{url_or_title}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _http_get(url: str, timeout: int = 15) -> bytes:
    """Fetch URL and return raw bytes. Raises on HTTP errors."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "squash-regulatory-watch/1.0 (AI compliance tool; "
                          "contact: getsquash.dev)",
            "Accept": "application/rss+xml, application/atom+xml, "
                      "application/xml, text/xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(path))


def parse_interval(interval_str: str) -> int:
    """Parse a human-readable interval string to seconds.

    Supports ``'6h'``, ``'1d'``, ``'30m'``, bare integer seconds,
    or ``'0'`` / empty (meaning "once").
    """
    import re as _re
    s = str(interval_str).strip().lower()
    if not s or s == "0":
        return 0
    m = _re.match(r"^(\d+)([smhd]?)$", s)
    if not m:
        return 0
    val, unit = int(m.group(1)), m.group(2)
    return val * {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}[unit]


__all__ = [
    "RegulatoryEvent",
    "GapAnalysisResult",
    "WatcherConfig",
    "RegulatoryWatcher",
    "SecAdapter",
    "NistAdapter",
    "EurLexAdapter",
    "GenericRssAdapter",
    "parse_interval",
]
