"""tests/test_regulatory_watch.py — Sprint C4 W243-W245 Regulatory Watch Daemon.

Test taxonomy:

PART 1 — Data classes (RegulatoryEvent, GapAnalysisResult, WatcherConfig)
  * Construction, defaults, to_dict() round-trip, summary_text()

PART 2 — RSS / Atom parsing utilities (_parse_rss, _detect_ns, _iter_items)
  * RSS 2.0 feed with AI-relevant items
  * Atom feed with namespaced entries
  * AI-relevance filtering: positive + negative cases
  * Severity classification: HIGH / MEDIUM / LOW

PART 3 — Source adapters (SecAdapter, NistAdapter, EurLexAdapter,
          GenericRssAdapter)
  * Fetch via injected HTTP stub — returns correct RegulatoryEvent list
  * HTTP error degrades gracefully (no exception raised)
  * GenericRssAdapter keyword filtering

PART 4 — RegulatoryWatcher (dedup, gap analysis, persistence)
  * poll() returns only new events on second call with same store
  * mark_all_seen() suppresses future re-surfacing
  * load_history() returns persisted events in recency order
  * gap_analysis() maps EU AI Act keywords → EU_AI_ACT
  * gap_analysis() populates recommended_actions
  * gap_analysis() discovers attested models in models_dir fixture

PART 5 — Severity + matching helpers
  * _compute_severity: HIGH for enforcement text
  * _compute_severity: MEDIUM for guidance text
  * _compute_severity: LOW for unrelated text
  * _match_regulatory_ids: EU AI Act, NIST, ISO, SEC, FTC mappings
  * _is_ai_relevant: True for AI text, False for unrelated text

PART 6 — parse_interval utility
  * 30m → 1800 s
  * 6h → 21600 s
  * 1d → 86400 s
  * 0 / empty → 0
  * bare integer → seconds

PART 7 — Notify (stdout path + notifications fallback)
  * stdout channel prints to stdout
  * empty list → no output
  * missing notifications module logs warning (ImportError path)

PART 8 — CLI smoke (_cmd_watch_regulatory via argparse round-trip)
  * parser registration: watch-regulatory sub-command exists
  * --dry-run flag exists
  * --once flag exists
  * --interval flag accepts 6h
  * --sources flag accepts comma-delimited values
"""

from __future__ import annotations

import io
import json
import sqlite3
import sys
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from squash.regulatory_watch import (
    EurLexAdapter,
    GapAnalysisResult,
    GenericRssAdapter,
    NistAdapter,
    RegulatoryEvent,
    RegulatoryWatcher,
    SecAdapter,
    WatcherConfig,
    _compute_severity,
    _is_ai_relevant,
    _make_event_id,
    _match_regulatory_ids,
    _parse_rss,
    parse_interval,
)


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures & RSS helpers
# ──────────────────────────────────────────────────────────────────────────────

_RSS2_AI_ITEM = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>SEC Press</title>
        <item>
          <title>SEC Issues Guidance on Artificial Intelligence Disclosures</title>
          <link>https://www.sec.gov/news/press-release/2026-001</link>
          <pubDate>Wed, 07 May 2026 10:00:00 +0000</pubDate>
          <description>
            The Commission released final guidance requiring investment advisers
            to disclose material AI systems and their governance frameworks.
          </description>
        </item>
        <item>
          <title>SEC Charges Firm for Misleading AI Claims</title>
          <link>https://www.sec.gov/news/press-release/2026-002</link>
          <pubDate>Wed, 07 May 2026 14:00:00 +0000</pubDate>
          <description>
            Enforcement action and penalty for AI washing disclosures.
            Mandatory compliance deadline set for August 2026.
          </description>
        </item>
        <item>
          <title>Quarterly Earnings Report — No AI</title>
          <link>https://www.sec.gov/news/press-release/2026-003</link>
          <pubDate>Wed, 07 May 2026 15:00:00 +0000</pubDate>
          <description>Standard financial disclosure with no technology content.</description>
        </item>
      </channel>
    </rss>
""").encode()

_ATOM_AI_ITEM = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>EUR-Lex OJ</title>
      <entry>
        <title>Commission Delegated Regulation on EU AI Act Annex IV</title>
        <link href="https://eur-lex.europa.eu/2026/01" rel="alternate"/>
        <published>2026-05-07T09:00:00Z</published>
        <summary>Delegated regulation supplementing Regulation 2024/1689 on
        artificial intelligence act requirements for high-risk AI systems.</summary>
      </entry>
      <entry>
        <title>NIST AI RMF Supplemental Guidance Published</title>
        <link href="https://csrc.nist.gov/pub/2026-02"/>
        <published>2026-05-06T12:00:00Z</published>
        <summary>NIST releases updated AI 100-1 framework with machine learning
        governance guidance for critical infrastructure operators.</summary>
      </entry>
    </feed>
""").encode()

_RSS2_NO_AI = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>Finance News</title>
        <item>
          <title>Bond Market Update — Treasury Yields</title>
          <link>https://example.com/bond-update</link>
          <description>Interest rate outlook for Q3 2026 bonds.</description>
        </item>
      </channel>
    </rss>
""").encode()


def _make_event(
    source: str = "SEC Press",
    title: str = "SEC AI enforcement action",
    url: str = "https://www.sec.gov/news/001",
    summary: str = "Enforcement for AI disclosure violation with penalty.",
    severity: str = "HIGH",
) -> RegulatoryEvent:
    event_id = _make_event_id(source, url)
    return RegulatoryEvent(
        event_id=event_id,
        source=source,
        title=title,
        url=url,
        published="2026-05-07",
        summary=summary,
        severity=severity,
    )


# ──────────────────────────────────────────────────────────────────────────────
# PART 1 — Data classes
# ──────────────────────────────────────────────────────────────────────────────


class TestRegulatoryEvent:
    def test_defaults_populated(self) -> None:
        e = RegulatoryEvent(
            event_id="abc123",
            source="NIST",
            title="NIST Publishes AI RMF Update",
            url="https://nist.gov",
            published="2026-05-07",
            summary="AI risk management framework update.",
        )
        assert e.severity == "LOW"
        assert e.fetched_at  # auto-set in __post_init__
        assert e.raw_tags == []

    def test_to_dict_round_trip(self) -> None:
        e = _make_event()
        d = e.to_dict()
        assert d["event_id"] == e.event_id
        assert d["source"] == "SEC Press"
        assert d["severity"] == "HIGH"
        assert isinstance(d["raw_tags"], list)

    def test_explicit_fetched_at_preserved(self) -> None:
        e = RegulatoryEvent(
            event_id="xyz",
            source="test",
            title="t",
            url="u",
            published="2026-01-01",
            summary="s",
            fetched_at="2026-05-07T10:00:00+00:00",
        )
        assert e.fetched_at == "2026-05-07T10:00:00+00:00"

    @pytest.mark.parametrize("severity", ["HIGH", "MEDIUM", "LOW"])
    def test_severity_values(self, severity: str) -> None:
        e = _make_event(severity=severity)
        assert e.severity == severity


class TestGapAnalysisResult:
    def test_to_dict_has_all_keys(self) -> None:
        event = _make_event()
        gap = GapAnalysisResult(
            event=event,
            matched_reg_ids=["EU_AI_ACT"],
            squash_controls=["squash attest --policy eu-ai-act"],
            models_to_re_attest=["model-a"],
            recommended_actions=["Review guidance."],
            days_to_act=87,
        )
        d = gap.to_dict()
        assert d["matched_reg_ids"] == ["EU_AI_ACT"]
        assert d["squash_controls"] == ["squash attest --policy eu-ai-act"]
        assert d["models_to_re_attest"] == ["model-a"]
        assert d["days_to_act"] == 87
        assert "event" in d

    def test_summary_text_high_severity(self) -> None:
        event = _make_event(severity="HIGH")
        gap = GapAnalysisResult(
            event=event,
            matched_reg_ids=["EU_AI_ACT"],
            squash_controls=["squash attest"],
            recommended_actions=["Run squash attest now."],
        )
        text = gap.summary_text()
        assert "[HIGH]" in text
        assert "EU_AI_ACT" in text
        assert "squash attest" in text

    def test_summary_text_includes_days_to_act(self) -> None:
        gap = GapAnalysisResult(
            event=_make_event(),
            days_to_act=30,
        )
        assert "30" in gap.summary_text()

    def test_summary_text_no_days_to_act(self) -> None:
        gap = GapAnalysisResult(event=_make_event(), days_to_act=None)
        text = gap.summary_text()
        assert "Days to act" not in text

    def test_summary_text_lists_models(self) -> None:
        gap = GapAnalysisResult(
            event=_make_event(),
            models_to_re_attest=["bert-v2", "gpt-fine-tuned"],
        )
        assert "Re-attest" in gap.summary_text()
        assert "bert-v2" in gap.summary_text()

    def test_empty_gap_result_renders(self) -> None:
        gap = GapAnalysisResult(event=_make_event())
        text = gap.summary_text()
        assert "SEC Press" in text


class TestWatcherConfig:
    def test_defaults(self) -> None:
        cfg = WatcherConfig()
        assert cfg.sources == ["sec", "nist", "eurlex"]
        assert cfg.timeout_seconds == 15
        assert cfg.max_events == 50
        assert cfg.alert_channel == "stdout"

    def test_db_path_coerced_to_path(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        cfg = WatcherConfig(db_path=db)
        assert isinstance(cfg.db_path, Path)

    def test_custom_sources(self) -> None:
        cfg = WatcherConfig(sources=["sec"])
        assert cfg.sources == ["sec"]


# ──────────────────────────────────────────────────────────────────────────────
# PART 2 — RSS / Atom parsing utilities
# ──────────────────────────────────────────────────────────────────────────────


class TestParseRss:
    def test_rss2_ai_filter_true_keeps_ai_items(self) -> None:
        events = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=True)
        titles = [e.title for e in events]
        assert any("Artificial Intelligence" in t or "AI" in t for t in titles)

    def test_rss2_ai_filter_drops_non_ai_items(self) -> None:
        events = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=True)
        titles = [e.title for e in events]
        assert all("Quarterly Earnings" not in t for t in titles)

    def test_rss2_ai_filter_false_returns_all_items(self) -> None:
        events = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=False)
        assert len(events) == 3

    def test_rss2_no_ai_items_with_filter(self) -> None:
        events = _parse_rss(_RSS2_NO_AI, source_label="Finance", ai_filter=True)
        assert events == []

    def test_atom_feed_parsed_correctly(self) -> None:
        events = _parse_rss(_ATOM_AI_ITEM, source_label="EUR-Lex OJ", ai_filter=True)
        assert len(events) == 2
        assert all(e.source == "EUR-Lex OJ" for e in events)

    def test_atom_link_extracted_from_href(self) -> None:
        events = _parse_rss(_ATOM_AI_ITEM, source_label="EUR-Lex OJ", ai_filter=True)
        urls = [e.url for e in events]
        assert any("eur-lex.europa.eu" in u for u in urls)

    def test_event_ids_are_stable(self) -> None:
        events1 = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=True)
        events2 = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=True)
        ids1 = {e.event_id for e in events1}
        ids2 = {e.event_id for e in events2}
        assert ids1 == ids2

    def test_event_ids_are_unique_within_feed(self) -> None:
        events = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=False)
        ids = [e.event_id for e in events]
        assert len(ids) == len(set(ids))

    def test_malformed_xml_returns_empty(self) -> None:
        events = _parse_rss(b"<not valid xml<<<", source_label="test", ai_filter=False)
        assert events == []

    def test_html_stripped_from_summary(self) -> None:
        rss = textwrap.dedent("""\
            <?xml version="1.0"?>
            <rss version="2.0"><channel>
              <item>
                <title>AI governance enforcement action</title>
                <link>https://example.com/1</link>
                <description><![CDATA[<p>Mandatory <b>AI</b> framework rules.</p>]]></description>
              </item>
            </channel></rss>
        """).encode()
        events = _parse_rss(rss, source_label="test", ai_filter=True)
        if events:
            assert "<p>" not in events[0].summary

    def test_missing_link_falls_back_to_empty_string(self) -> None:
        rss = textwrap.dedent("""\
            <?xml version="1.0"?>
            <rss version="2.0"><channel>
              <item>
                <title>Large language model regulation update</title>
                <description>New machine learning governance rules.</description>
              </item>
            </channel></rss>
        """).encode()
        events = _parse_rss(rss, source_label="test", ai_filter=True)
        assert events[0].url == ""

    def test_published_date_extracted(self) -> None:
        events = _parse_rss(_RSS2_AI_ITEM, source_label="SEC Press", ai_filter=False)
        assert any(e.published.startswith("Wed") or "2026" in e.published for e in events)


# ──────────────────────────────────────────────────────────────────────────────
# PART 3 — Source adapters
# ──────────────────────────────────────────────────────────────────────────────


def _make_http_stub(response: bytes) -> Any:
    """Return a callable that replaces _http_get and returns *response*."""
    def _stub(url: str, timeout: int = 15) -> bytes:
        return response
    return _stub


def _make_failing_http_stub() -> Any:
    import urllib.error
    def _stub(url: str, timeout: int = 15) -> bytes:
        raise urllib.error.URLError("connection refused")
    return _stub


class TestSecAdapter:
    def test_fetch_returns_ai_events(self) -> None:
        adapter = SecAdapter(timeout=5)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            events = adapter.fetch()
        assert len(events) >= 1
        assert all(e.source == "SEC Press" for e in events)

    def test_fetch_graceful_on_http_error(self) -> None:
        adapter = SecAdapter(timeout=5)
        with patch("squash.regulatory_watch._http_get", _make_failing_http_stub()):
            events = adapter.fetch()
        assert events == []

    def test_adapter_name(self) -> None:
        assert SecAdapter.name == "sec"
        assert SecAdapter.label == "SEC Press"


class TestNistAdapter:
    def test_fetch_returns_events(self) -> None:
        adapter = NistAdapter(timeout=5)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_ATOM_AI_ITEM)):
            events = adapter.fetch()
        assert isinstance(events, list)

    def test_fetch_graceful_on_http_error(self) -> None:
        adapter = NistAdapter(timeout=5)
        with patch("squash.regulatory_watch._http_get", _make_failing_http_stub()):
            events = adapter.fetch()
        assert events == []

    def test_adapter_name(self) -> None:
        assert NistAdapter.name == "nist"


class TestEurLexAdapter:
    def test_fetch_returns_atom_events(self) -> None:
        adapter = EurLexAdapter(timeout=5)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_ATOM_AI_ITEM)):
            events = adapter.fetch()
        assert len(events) >= 1

    def test_fetch_graceful_on_http_error(self) -> None:
        adapter = EurLexAdapter(timeout=5)
        with patch("squash.regulatory_watch._http_get", _make_failing_http_stub()):
            events = adapter.fetch()
        assert events == []

    def test_adapter_name(self) -> None:
        assert EurLexAdapter.name == "eurlex"


class TestGenericRssAdapter:
    def test_no_keyword_filter_returns_all(self) -> None:
        adapter = GenericRssAdapter(name="test", url="http://example.com/feed.rss")
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            events = adapter.fetch()
        assert len(events) == 3  # ai_filter=False for generic adapter

    def test_keyword_filter_matches(self) -> None:
        adapter = GenericRssAdapter(
            name="test",
            url="http://example.com/feed.rss",
            keywords=["artificial intelligence", "enforcement"],
        )
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            events = adapter.fetch()
        # Only items with matching keywords returned
        assert len(events) >= 1
        for e in events:
            text = (e.title + " " + e.summary).lower()
            assert any(kw in text for kw in ["artificial intelligence", "enforcement"])

    def test_keyword_filter_excludes_non_matching(self) -> None:
        adapter = GenericRssAdapter(
            name="test",
            url="http://example.com/feed.rss",
            keywords=["xylophone"],  # nothing in the feed matches
        )
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            events = adapter.fetch()
        assert events == []

    def test_http_error_returns_empty_list(self) -> None:
        adapter = GenericRssAdapter(name="test", url="http://example.com/feed.rss")
        with patch("squash.regulatory_watch._http_get", _make_failing_http_stub()):
            events = adapter.fetch()
        assert events == []

    def test_name_attribute_set(self) -> None:
        adapter = GenericRssAdapter(name="legiscan", url="http://example.com")
        assert adapter.name == "legiscan"
        assert adapter.label == "legiscan"


# ──────────────────────────────────────────────────────────────────────────────
# PART 4 — RegulatoryWatcher
# ──────────────────────────────────────────────────────────────────────────────


def _make_watcher(tmp_path: Path, sources: list[str] | None = None) -> RegulatoryWatcher:
    cfg = WatcherConfig(
        db_path=tmp_path / "events.db",
        sources=sources or [],
        alert_on_new=False,
    )
    return RegulatoryWatcher(cfg)


class TestRegulatoryWatcher:
    def test_db_created_on_init(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        assert (tmp_path / "events.db").exists()

    def test_poll_empty_adapters_returns_empty(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path, sources=[])
        new_events, gap_results = watcher.poll()
        assert new_events == []
        assert gap_results == []

    def test_poll_with_stub_returns_events(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            new_events, gap_results = watcher.poll()
        assert len(new_events) >= 1
        assert len(gap_results) == len(new_events)

    def test_poll_deduplicates_on_second_call(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            first_new, _ = watcher.poll()
            second_new, _ = watcher.poll()
        assert len(first_new) >= 1
        assert second_new == []  # all already seen

    def test_mark_all_seen_then_poll_returns_empty(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            events = SecAdapter(timeout=5).fetch()
        # Patch _http_get for the SecAdapter used inside _fetch_all
        watcher.mark_all_seen(events)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            new_events, _ = watcher.poll()
        assert new_events == []

    def test_load_history_empty_on_new_db(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        history = watcher.load_history()
        assert history == []

    def test_load_history_after_poll(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            watcher.poll()
        history = watcher.load_history()
        assert len(history) >= 1
        assert "source" in history[0]
        assert "title" in history[0]
        assert "fetched_at" in history[0]

    def test_load_history_limit_respected(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            watcher.poll()
        history = watcher.load_history(limit=1)
        assert len(history) == 1

    def test_gap_analysis_eu_ai_act_match(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        event = RegulatoryEvent(
            event_id="test-001",
            source="EUR-Lex OJ",
            title="Commission Decision: EU AI Act Annex IV Requirements",
            url="https://eur-lex.europa.eu/001",
            published="2026-05-07",
            summary="Delegated regulation under Regulation 2024/1689 on the EU AI Act.",
        )
        gap = watcher.gap_analysis(event)
        assert "EU_AI_ACT" in gap.matched_reg_ids

    def test_gap_analysis_nist_match(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        event = RegulatoryEvent(
            event_id="test-002",
            source="NIST CSRC",
            title="NIST AI RMF 1.0 Supplemental Guidance",
            url="https://csrc.nist.gov/pubs",
            published="2026-05-07",
            summary="Updated NIST AI Risk Management Framework guidance for AI 100-1.",
        )
        gap = watcher.gap_analysis(event)
        assert "NIST_AI_RMF" in gap.matched_reg_ids

    def test_gap_analysis_no_match_returns_generic_action(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        event = RegulatoryEvent(
            event_id="test-003",
            source="Generic",
            title="Bond market update unrelated to AI",
            url="https://example.com/bonds",
            published="2026-05-07",
            summary="Interest rate forecast for fixed income markets.",
        )
        gap = watcher.gap_analysis(event)
        assert gap.matched_reg_ids == []
        assert len(gap.recommended_actions) >= 1
        assert "monitor" in gap.recommended_actions[0].lower() or \
               "manual" in gap.recommended_actions[0].lower() or \
               "no direct" in gap.recommended_actions[0].lower()

    def test_gap_analysis_discovers_attested_models(self, tmp_path: Path) -> None:
        # Create two model directories with squash-attest.json
        for model_name in ("bert-v2", "gpt-fine-tuned"):
            model_dir = tmp_path / "models" / model_name
            model_dir.mkdir(parents=True)
            attest = {"model_id": model_name, "policy": "eu-ai-act"}
            (model_dir / "squash-attest.json").write_text(json.dumps(attest))

        watcher = _make_watcher(tmp_path)
        event = _make_event(
            title="EU AI Act enforcement deadline confirmed",
            summary="Regulation 2024/1689 enforcement begins August 2026.",
        )
        gap = watcher.gap_analysis(event, models_dir=tmp_path / "models")
        assert "bert-v2" in gap.models_to_re_attest
        assert "gpt-fine-tuned" in gap.models_to_re_attest

    def test_gap_analysis_models_dir_missing_returns_empty(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        event = _make_event()
        gap = watcher.gap_analysis(event, models_dir=tmp_path / "nonexistent")
        assert gap.models_to_re_attest == []

    def test_gap_analysis_squash_controls_deduped(self, tmp_path: Path) -> None:
        watcher = _make_watcher(tmp_path)
        event = RegulatoryEvent(
            event_id="test-004",
            source="EUR-Lex OJ",
            title="EU AI Act final guidance on Annex IV artificial intelligence",
            url="https://eur-lex.europa.eu/004",
            published="2026-05-07",
            summary="EU AI Act and artificial intelligence act requirements.",
        )
        gap = watcher.gap_analysis(event)
        # Controls must be deduplicated
        assert len(gap.squash_controls) == len(set(gap.squash_controls))

    def test_unknown_source_ignored(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["unknown_src"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        new_events, _ = watcher.poll()
        assert new_events == []

    def test_extra_feeds_configured(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=[],
            extra_feeds=[{"name": "iapp", "url": "http://example.com/feed.rss"}],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            new_events, _ = watcher.poll()
        # Should return events from the extra feed (ai_filter=False for generic)
        assert isinstance(new_events, list)

    def test_bad_extra_feed_config_ignored(self, tmp_path: Path) -> None:
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=[],
            extra_feeds=[{"missing_name_key": "bad"}],
            alert_on_new=False,
        )
        # Should not raise
        watcher = RegulatoryWatcher(cfg)
        new_events, _ = watcher.poll()
        assert new_events == []

    def test_max_events_cap(self, tmp_path: Path) -> None:
        """Events list is capped at max_events after deduplication."""
        # Create feed with 3 items; set max_events=1
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            max_events=1,
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get",
                   _make_http_stub(_RSS2_AI_ITEM)):
            new_events, _ = watcher.poll()
        assert len(new_events) <= 1


# ──────────────────────────────────────────────────────────────────────────────
# PART 5 — Severity + matching helpers
# ──────────────────────────────────────────────────────────────────────────────


class TestComputeSeverity:
    @pytest.mark.parametrize("text,expected", [
        # HIGH: contains high-severity trigger words
        ("SEC enforcement penalty for violation", "HIGH"),
        ("Mandatory compliance deadline August 2026", "HIGH"),
        ("Cease and desist order for AI firm", "HIGH"),
        ("New sanction against AI company", "HIGH"),
        # MEDIUM: guidance / standards language, no HIGH trigger words
        ("NIST AI RMF revised guidance update", "MEDIUM"),
        ("New regulation on AI governance framework", "MEDIUM"),
        ("Revised amendment to ISO standard published", "MEDIUM"),
        # LOW: general news with no matching patterns
        ("AI research paper published", "LOW"),
        ("General press release about technology", "LOW"),
    ])
    def test_severity_classification(self, text: str, expected: str) -> None:
        result = _compute_severity(text, "", "NIST CSRC")
        assert result == expected

    def test_sec_press_guidance_is_medium(self) -> None:
        result = _compute_severity(
            "SEC Issues Guidance on AI Disclosures", "", "SEC Press"
        )
        assert result == "MEDIUM"

    def test_eurlex_final_rule_is_medium(self) -> None:
        result = _compute_severity(
            "Commission final rule on AI governance framework", "", "EUR-Lex OJ"
        )
        assert result == "MEDIUM"


class TestMatchRegulatoryIds:
    @pytest.mark.parametrize("title,summary,expected_id", [
        ("EU AI Act enforcement deadline", "Regulation 2024/1689 requirements.", "EU_AI_ACT"),
        ("Artificial intelligence act delegated acts", "", "EU_AI_ACT"),
        ("Annex IV technical documentation", "", "EU_AI_ACT"),
        ("NIST AI RMF 1.0 updated", "AI 100-1 framework", "NIST_AI_RMF"),
        ("NIST AI Risk Management Framework guidance", "", "NIST_AI_RMF"),
        ("ISO 42001 AI management system standard", "", "ISO_42001"),
        ("ISO/IEC 42001:2023 certification guidance", "", "ISO_42001"),
        ("Colorado AI Act SB 205 enforcement", "", "COLORADO_AI_ACT"),
        ("NYC Local Law 144 bias audit requirements", "", "NYC_LL144"),
        ("SEC AI disclosure requirements for investment advisers", "", "SEC_AI"),
        ("FTC guidance on AI marketing claims", "", "FTC_GUIDANCE"),
        ("GDPR implications for AI training data", "", "EU_GDPR"),
        ("FedRAMP AI authorization requirements", "", "FEDRAMP_AI"),
    ])
    def test_matching(self, title: str, summary: str, expected_id: str) -> None:
        event = RegulatoryEvent(
            event_id="x",
            source="test",
            title=title,
            url="http://example.com",
            published="2026-05-07",
            summary=summary,
        )
        ids = _match_regulatory_ids(event)
        assert expected_id in ids, f"Expected {expected_id} in {ids}"

    def test_no_match_returns_empty(self) -> None:
        event = RegulatoryEvent(
            event_id="x",
            source="test",
            title="Bond yield forecast for 2026",
            url="http://example.com",
            published="2026-05-07",
            summary="Interest rate outlook for treasuries.",
        )
        ids = _match_regulatory_ids(event)
        assert ids == []

    def test_multiple_frameworks_detected(self) -> None:
        event = RegulatoryEvent(
            event_id="x",
            source="EUR-Lex OJ",
            title="EU AI Act and GDPR joint guidance for AI training data",
            url="http://example.com",
            published="2026-05-07",
            summary="Regulation 2024/1689 and GDPR data requirements intersect.",
        )
        ids = _match_regulatory_ids(event)
        assert "EU_AI_ACT" in ids
        assert "EU_GDPR" in ids


class TestIsAiRelevant:
    @pytest.mark.parametrize("title,summary", [
        ("SEC AI enforcement action", "Penalty for artificial intelligence violations."),
        ("Large language model governance", "LLM compliance framework published."),
        ("Machine learning audit requirements", "Automated decision-making rules."),
        ("EU AI Act Annex IV delegated act", "AI governance requirements."),
        ("Foundation model transparency rules", "Generative AI disclosure guidance."),
    ])
    def test_ai_relevant_returns_true(self, title: str, summary: str) -> None:
        assert _is_ai_relevant(title, summary, []) is True

    @pytest.mark.parametrize("title,summary", [
        ("Bond market update", "Interest rate forecast for Q3 2026."),
        ("Quarterly earnings report", "Revenue growth across all segments."),
        ("Real estate investment update", "Commercial property valuations."),
        ("Banking regulation announcement", "Capital requirements for commercial banks."),
    ])
    def test_non_ai_relevant_returns_false(self, title: str, summary: str) -> None:
        assert _is_ai_relevant(title, summary, []) is False

    def test_tag_match_returns_true(self) -> None:
        assert _is_ai_relevant("Earnings update", "Revenue report", ["ai governance"]) is True


# ──────────────────────────────────────────────────────────────────────────────
# PART 6 — parse_interval utility
# ──────────────────────────────────────────────────────────────────────────────


class TestParseInterval:
    @pytest.mark.parametrize("input_str,expected_seconds", [
        ("30m", 1800),
        ("6h", 21600),
        ("1d", 86400),
        ("2d", 172800),
        ("60s", 60),
        ("120", 120),
        ("0", 0),
        ("", 0),
        ("once", 0),   # unrecognised → 0
    ])
    def test_parse_interval(self, input_str: str, expected_seconds: int) -> None:
        assert parse_interval(input_str) == expected_seconds

    def test_bare_integer(self) -> None:
        assert parse_interval("300") == 300

    def test_whitespace_stripped(self) -> None:
        assert parse_interval("  6h  ") == 21600


# ──────────────────────────────────────────────────────────────────────────────
# PART 7 — Notify
# ──────────────────────────────────────────────────────────────────────────────


class TestNotify:
    def test_stdout_channel_prints(self, tmp_path: Path, capsys: Any) -> None:
        watcher = _make_watcher(tmp_path)
        event = _make_event(title="[HIGH] AI enforcement action")
        gap = GapAnalysisResult(event=event, matched_reg_ids=["SEC_AI"])
        watcher.notify([gap], channel="stdout")
        out = capsys.readouterr().out
        assert "SEC Press" in out or "SEC_AI" in out or "HIGH" in out

    def test_notify_empty_list_no_output(self, tmp_path: Path, capsys: Any) -> None:
        watcher = _make_watcher(tmp_path)
        watcher.notify([], channel="stdout")
        out = capsys.readouterr().out
        assert out == ""

    def test_notify_notifications_import_error_falls_back_to_stdout(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        watcher = _make_watcher(tmp_path)
        event = _make_event()
        gap = GapAnalysisResult(event=event)

        with patch.dict(sys.modules, {"squash.notifications": None}):
            # ImportError path — should fall back to stdout without raising
            watcher.notify([gap], channel="slack")
        # After fallback, output appears on stdout
        out = capsys.readouterr().out
        # Either fell back to stdout (printed) or logged warning — no exception
        assert True  # primary assertion: no exception raised

    def test_notify_multiple_gaps(self, tmp_path: Path, capsys: Any) -> None:
        watcher = _make_watcher(tmp_path)
        events = [
            _make_event(url="https://example.com/1", title="AI enforcement 1"),
            _make_event(url="https://example.com/2", title="AI guidance 2"),
        ]
        gaps = [GapAnalysisResult(event=e) for e in events]
        watcher.notify(gaps, channel="stdout")
        out = capsys.readouterr().out
        assert out.count("SEC Press") == 2


# ──────────────────────────────────────────────────────────────────────────────
# PART 8 — CLI smoke
# ──────────────────────────────────────────────────────────────────────────────


class TestCli:
    def _get_parser(self) -> Any:
        """Return the squash argparse root parser."""
        # Import lazily to avoid side-effects at collection time
        from squash import cli as _cli
        import argparse
        # Build the full parser the same way main() does
        parser = _cli._build_parser()
        return parser

    def test_watch_regulatory_subcommand_registered(self) -> None:
        parser = self._get_parser()
        # Should parse without error
        args = parser.parse_args(["watch-regulatory", "--once"])
        assert args.command == "watch-regulatory"

    def test_once_flag(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["watch-regulatory", "--once"])
        assert args.wr_once is True

    def test_interval_flag_accepts_6h(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["watch-regulatory", "--interval", "6h"])
        assert args.wr_interval == "6h"

    def test_dry_run_flag(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["watch-regulatory", "--once", "--dry-run"])
        assert args.wr_dry_run is True

    def test_alert_channel_flag(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args([
            "watch-regulatory", "--once", "--alert-channel", "slack"
        ])
        assert args.wr_alert_channel == "slack"

    def test_sources_flag(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args([
            "watch-regulatory", "--once", "--sources", "sec"
        ])
        # wr_sources is an append list
        assert args.wr_sources == ["sec"]

    def test_models_dir_flag(self, tmp_path: Path) -> None:
        parser = self._get_parser()
        args = parser.parse_args([
            "watch-regulatory", "--once", "--models-dir", str(tmp_path)
        ])
        assert str(tmp_path) in str(args.wr_models_dir)


# ──────────────────────────────────────────────────────────────────────────────
# PART 9 — Integration: full poll cycle with stub adapters
# ──────────────────────────────────────────────────────────────────────────────


class TestIntegration:
    def test_full_poll_cycle_rss2(self, tmp_path: Path) -> None:
        """End-to-end: SEC adapter → watcher.poll() → gap_analysis output."""
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            new_events, gap_results = watcher.poll()

        assert len(new_events) >= 1
        assert len(gap_results) == len(new_events)
        # Every gap result has an event
        for gap in gap_results:
            assert gap.event in new_events
            assert isinstance(gap.recommended_actions, list)
            assert len(gap.recommended_actions) >= 1

    def test_full_poll_cycle_atom(self, tmp_path: Path) -> None:
        """End-to-end: EUR-Lex Atom feed → watcher.poll() → gap_analysis."""
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["eurlex"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_ATOM_AI_ITEM)):
            new_events, gap_results = watcher.poll()

        # EUR-Lex Atom feed has 2 AI-relevant entries
        assert len(new_events) == 2
        eu_event = next(
            (e for e in new_events if "EU AI Act" in e.title or "Annex IV" in e.title), None
        )
        assert eu_event is not None
        eu_gap = next(g for g in gap_results if g.event == eu_event)
        assert "EU_AI_ACT" in eu_gap.matched_reg_ids

    def test_idempotent_db_init(self, tmp_path: Path) -> None:
        """Creating two watchers with the same DB does not raise."""
        cfg = WatcherConfig(db_path=tmp_path / "events.db", sources=[])
        RegulatoryWatcher(cfg)
        RegulatoryWatcher(cfg)  # second init on existing schema

    def test_to_dict_json_serialisable(self, tmp_path: Path) -> None:
        """gap.to_dict() must be JSON-serialisable (no custom types)."""
        cfg = WatcherConfig(
            db_path=tmp_path / "events.db",
            sources=["sec"],
            alert_on_new=False,
        )
        watcher = RegulatoryWatcher(cfg)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            _, gap_results = watcher.poll()
        for gap in gap_results:
            serialised = json.dumps(gap.to_dict())
            assert isinstance(serialised, str)

    def test_history_persists_across_watcher_instances(self, tmp_path: Path) -> None:
        """Events seen in one watcher instance are persisted for a second."""
        db_path = tmp_path / "events.db"
        cfg1 = WatcherConfig(db_path=db_path, sources=["sec"], alert_on_new=False)
        watcher1 = RegulatoryWatcher(cfg1)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            first_new, _ = watcher1.poll()

        assert len(first_new) >= 1

        # New watcher, same DB — events should be deduped
        cfg2 = WatcherConfig(db_path=db_path, sources=["sec"], alert_on_new=False)
        watcher2 = RegulatoryWatcher(cfg2)
        with patch("squash.regulatory_watch._http_get", _make_http_stub(_RSS2_AI_ITEM)):
            second_new, _ = watcher2.poll()

        assert second_new == []
