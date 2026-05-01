"""tests/test_squash_sprint27.py — Sprint 27 W243–W245 (Track C / C4).

Continuous Regulatory Watch Daemon: squash/regulatory_watch.py.

W243 — RegulatoryEvent dataclass, source adapters (SEC, NIST, EUR-Lex,
       GenericRss), RSS parse engine, AI-relevance filter, severity scoring
W244 — RegulatoryWatcher: poll, gap_analysis, deduplication via SQLite,
       GapAnalysisResult, regulatory ID mapping
W245 — `squash watch-regulatory` CLI: --once, --dry-run, --interval,
       --sources, --extra-feed, --json, --alert-channel, --models-dir

All network calls are mocked at the `urllib.request.urlopen` boundary.
No live HTTP calls occur during testing.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
    parse_interval as _parse_interval,
    _parse_rss,
)


# ── Shared fixtures ──────────────────────────────────────────────────────────


_RSS_AI = b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>EU AI Act Annex IV requirements update</title>
      <link>https://eur-lex.europa.eu/test1</link>
      <pubDate>Wed, 30 Apr 2026 12:00:00 GMT</pubDate>
      <description>New implementing regulation for the EU AI Act Annex IV documentation.</description>
    </item>
    <item>
      <title>NIST AI RMF Profile published for healthcare</title>
      <link>https://csrc.nist.gov/test2</link>
      <pubDate>Tue, 29 Apr 2026 09:00:00 GMT</pubDate>
      <description>NIST AI Risk Management Framework healthcare sector profile.</description>
    </item>
  </channel>
</rss>"""

_RSS_NONAI = b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Weather News</title>
    <item>
      <title>Storm warning for the north-east coast</title>
      <link>https://weather.example.com/1</link>
      <description>Heavy rain expected through the weekend.</description>
    </item>
  </channel>
</rss>"""

_ATOM_AI = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>SEC AI Guidance</title>
  <entry>
    <title>SEC enforcement action on AI disclosure in fund prospectus</title>
    <link href="https://sec.gov/enforcement/test3"/>
    <published>2026-04-28T15:00:00Z</published>
    <summary>SEC issues enforcement action related to artificial intelligence disclosure.</summary>
  </entry>
</feed>"""


def _make_event(
    title: str = "EU AI Act update",
    source: str = "EUR-Lex OJ",
    severity: str = "HIGH",
    url: str = "https://eur-lex.europa.eu/test",
) -> RegulatoryEvent:
    return RegulatoryEvent(
        event_id=_make_event_id(source, url),
        source=source,
        title=title,
        url=url,
        published="2026-04-30",
        summary="Test regulatory event for eu ai act.",
        severity=severity,
    )


# ── W243 — RSS parsing + utility functions ───────────────────────────────────


class TestRssParsing(unittest.TestCase):
    def test_parse_rss_ai_filter_on(self) -> None:
        events = _parse_rss(_RSS_AI, source_label="Test", ai_filter=True)
        self.assertEqual(len(events), 2)
        all_text = " ".join(e.title.lower() + " " + e.summary.lower() for e in events)
        self.assertTrue(
            any(kw in all_text for kw in ("ai act", "nist ai", "machine learning")),
            msg=f"Expected AI keyword in combined text, got: {all_text[:200]}",
        )

    def test_parse_rss_ai_filter_off_returns_all(self) -> None:
        events = _parse_rss(_RSS_NONAI, source_label="Test", ai_filter=False)
        self.assertEqual(len(events), 1)
        self.assertIn("Storm", events[0].title)

    def test_parse_rss_nonai_filtered_out(self) -> None:
        events = _parse_rss(_RSS_NONAI, source_label="Test", ai_filter=True)
        self.assertEqual(len(events), 0)

    def test_parse_atom_feed(self) -> None:
        events = _parse_rss(_ATOM_AI, source_label="SEC", ai_filter=True)
        self.assertEqual(len(events), 1)
        self.assertIn("enforcement", events[0].title.lower())
        self.assertIn("sec.gov", events[0].url)

    def test_event_id_is_stable(self) -> None:
        events1 = _parse_rss(_RSS_AI, source_label="Test", ai_filter=True)
        events2 = _parse_rss(_RSS_AI, source_label="Test", ai_filter=True)
        self.assertEqual(events1[0].event_id, events2[0].event_id)

    def test_event_id_differs_by_source_label(self) -> None:
        e1 = _parse_rss(_RSS_AI, source_label="A", ai_filter=True)[0]
        e2 = _parse_rss(_RSS_AI, source_label="B", ai_filter=True)[0]
        self.assertNotEqual(e1.event_id, e2.event_id)

    def test_bad_xml_returns_empty(self) -> None:
        events = _parse_rss(b"not xml", source_label="X", ai_filter=False)
        self.assertEqual(events, [])


class TestAiRelevance(unittest.TestCase):
    def test_ai_keyword_triggers(self) -> None:
        self.assertTrue(_is_ai_relevant("artificial intelligence disclosure", "", []))
        self.assertTrue(_is_ai_relevant("LLM governance update", "", []))
        self.assertTrue(_is_ai_relevant("", "machine learning framework", []))
        self.assertTrue(_is_ai_relevant("", "", ["ai governance"]))

    def test_non_ai_not_triggered(self) -> None:
        self.assertFalse(_is_ai_relevant("Weather forecast", "Rain expected", []))
        self.assertFalse(_is_ai_relevant("Stock market update", "Dow Jones index", []))


class TestSeverityScoring(unittest.TestCase):
    def test_enforcement_keyword_gives_high(self) -> None:
        self.assertEqual(_compute_severity("enforcement action on AI", "", "SEC"), "HIGH")

    def test_penalty_gives_high(self) -> None:
        self.assertEqual(_compute_severity("AI penalty imposed", "", "Test"), "HIGH")

    def test_guidance_gives_medium(self) -> None:
        self.assertEqual(_compute_severity("New AI guidance issued", "", "NIST CSRC"), "MEDIUM")

    def test_sec_rule_gives_medium(self) -> None:
        self.assertEqual(_compute_severity("Final rule on AI disclosure", "", "SEC Press"), "MEDIUM")

    def test_generic_news_gives_low(self) -> None:
        self.assertEqual(_compute_severity("AI working group meets", "", "State News"), "LOW")


class TestMakeEventId(unittest.TestCase):
    def test_returns_24_char_hex(self) -> None:
        eid = _make_event_id("SEC", "https://sec.gov/example")
        self.assertEqual(len(eid), 24)
        int(eid, 16)  # must be valid hex

    def test_stable_given_same_inputs(self) -> None:
        a = _make_event_id("X", "Y")
        b = _make_event_id("X", "Y")
        self.assertEqual(a, b)

    def test_differs_on_different_source(self) -> None:
        self.assertNotEqual(_make_event_id("A", "Y"), _make_event_id("B", "Y"))


class TestParseInterval(unittest.TestCase):
    def test_zero_means_once(self) -> None:
        self.assertEqual(_parse_interval("0"), 0)

    def test_hours(self) -> None:
        self.assertEqual(_parse_interval("6h"), 6 * 3600)

    def test_days(self) -> None:
        self.assertEqual(_parse_interval("1d"), 86400)

    def test_minutes(self) -> None:
        self.assertEqual(_parse_interval("30m"), 1800)

    def test_plain_integer_seconds(self) -> None:
        self.assertEqual(_parse_interval("3600"), 3600)

    def test_empty_string(self) -> None:
        self.assertEqual(_parse_interval(""), 0)

    def test_invalid(self) -> None:
        self.assertEqual(_parse_interval("bad"), 0)


# ── W243 — Source adapters (network mocked) ──────────────────────────────────


def _mock_http_get(content: bytes):
    return mock.patch(
        "squash.regulatory_watch._http_get", return_value=content
    )


class TestSecAdapter(unittest.TestCase):
    def test_fetch_parses_rss(self) -> None:
        with _mock_http_get(_RSS_AI):
            events = SecAdapter(timeout=1).fetch()
        self.assertGreater(len(events), 0)
        for e in events:
            self.assertEqual(e.source, "SEC Press")

    def test_fetch_silently_survives_http_error(self) -> None:
        with mock.patch(
            "squash.regulatory_watch._http_get",
            side_effect=Exception("connection refused"),
        ):
            events = SecAdapter(timeout=1).fetch()
        self.assertEqual(events, [])


class TestNistAdapter(unittest.TestCase):
    def test_fetch_parses_rss(self) -> None:
        with _mock_http_get(_RSS_AI):
            events = NistAdapter(timeout=1).fetch()
        self.assertGreater(len(events), 0)

    def test_fetch_survives_error(self) -> None:
        with mock.patch(
            "squash.regulatory_watch._http_get",
            side_effect=Exception("timeout"),
        ):
            events = NistAdapter(timeout=1).fetch()
        self.assertEqual(events, [])


class TestEurLexAdapter(unittest.TestCase):
    def test_fetch_parses_rss(self) -> None:
        with _mock_http_get(_RSS_AI):
            events = EurLexAdapter(timeout=1).fetch()
        self.assertGreater(len(events), 0)
        for e in events:
            self.assertEqual(e.source, "EUR-Lex OJ")

    def test_fetch_survives_error(self) -> None:
        with mock.patch(
            "squash.regulatory_watch._http_get", side_effect=OSError("DNS")):
            events = EurLexAdapter(timeout=1).fetch()
        self.assertEqual(events, [])


class TestGenericRssAdapter(unittest.TestCase):
    def test_no_keyword_filter_returns_all(self) -> None:
        with _mock_http_get(_RSS_NONAI):
            events = GenericRssAdapter("test", "http://x.com/rss", timeout=1).fetch()
        self.assertEqual(len(events), 1)

    def test_keyword_filter_excludes_non_matching(self) -> None:
        with _mock_http_get(_RSS_NONAI):
            events = GenericRssAdapter(
                "test", "http://x.com/rss", keywords=["artificial intelligence"], timeout=1
            ).fetch()
        self.assertEqual(events, [])

    def test_keyword_filter_includes_matching(self) -> None:
        with _mock_http_get(_RSS_AI):
            events = GenericRssAdapter(
                "test", "http://x.com/rss", keywords=["eu ai act"], timeout=1
            ).fetch()
        self.assertGreater(len(events), 0)

    def test_fetch_survives_error(self) -> None:
        with mock.patch("squash.regulatory_watch._http_get", side_effect=Exception("x")):
            events = GenericRssAdapter("test", "http://x.com/rss", timeout=1).fetch()
        self.assertEqual(events, [])


# ── W244 — RegulatoryWatcher: deduplication + persistence + gap analysis ──────


class TestRegulatoryWatcher(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        self.cfg = WatcherConfig(
            db_path=self.tmp / "events.db",
            sources=["sec"],
        )
        self.watcher = RegulatoryWatcher(self.cfg)

    def _patch_adapters(self, events: list[RegulatoryEvent]):
        """Patch all adapter fetch methods to return the given events."""
        fake = mock.MagicMock()
        fake.fetch.return_value = list(events)
        fake.name = "sec"
        fake.label = "SEC Press"
        return mock.patch.object(
            self.watcher, "_build_adapters", return_value=[fake]
        )

    def test_first_poll_returns_all_events(self) -> None:
        events = [_make_event(url=f"https://x/{i}") for i in range(3)]
        with self._patch_adapters(events):
            new, _ = self.watcher.poll()
        self.assertEqual(len(new), 3)

    def test_second_poll_deduplicates(self) -> None:
        events = [_make_event()]
        with self._patch_adapters(events):
            self.watcher.poll()
            new2, _ = self.watcher.poll()
        self.assertEqual(len(new2), 0)

    def test_new_event_on_second_poll_surfaced(self) -> None:
        e1 = _make_event(url="https://x/1")
        e2 = _make_event(url="https://x/2")
        with self._patch_adapters([e1]):
            self.watcher.poll()
        with self._patch_adapters([e1, e2]):
            new2, _ = self.watcher.poll()
        self.assertEqual(len(new2), 1)
        self.assertEqual(new2[0].url, "https://x/2")

    def test_mark_all_seen_prevents_re_surfacing(self) -> None:
        events = [_make_event()]
        self.watcher.mark_all_seen(events)
        with self._patch_adapters(events):
            new, _ = self.watcher.poll()
        self.assertEqual(len(new), 0)

    def test_load_history_returns_persisted_events(self) -> None:
        events = [_make_event()]
        with self._patch_adapters(events):
            self.watcher.poll()
        history = self.watcher.load_history()
        self.assertEqual(len(history), 1)
        self.assertIn("source", history[0])

    def test_poll_returns_gap_results_per_event(self) -> None:
        events = [_make_event(
            title="EU AI Act Annex IV implementing regulation",
            source="EUR-Lex OJ",
        )]
        with self._patch_adapters(events):
            _, gaps = self.watcher.poll()
        self.assertEqual(len(gaps), 1)
        self.assertIsInstance(gaps[0], GapAnalysisResult)

    def test_poll_survives_total_adapter_failure(self) -> None:
        with mock.patch.object(
            self.watcher, "_build_adapters",
            return_value=[mock.MagicMock(
                name="bad", label="bad",
                fetch=mock.MagicMock(side_effect=Exception("net fail"))
            )],
        ):
            new, gaps = self.watcher.poll()
        self.assertEqual(new, [])
        self.assertEqual(gaps, [])


class TestGapAnalysis(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        cfg = WatcherConfig(db_path=Path(self._tmp) / "e.db", sources=[])
        self.watcher = RegulatoryWatcher(cfg)

    def test_gap_analysis_matches_eu_ai_act(self) -> None:
        e = _make_event(title="EU AI Act Annex IV update", source="EUR-Lex OJ")
        gap = self.watcher.gap_analysis(e)
        self.assertIn("EU_AI_ACT", gap.matched_reg_ids)

    def test_gap_analysis_includes_squash_controls(self) -> None:
        e = _make_event(title="EU AI Act enforcement guidance 2026")
        gap = self.watcher.gap_analysis(e)
        # squash controls populated from regulatory_feed.py
        self.assertGreater(len(gap.squash_controls), 0)

    def test_gap_analysis_with_no_match_has_actions(self) -> None:
        e = _make_event(title="Generic data-center energy efficiency report", source="DOE")
        gap = self.watcher.gap_analysis(e)
        self.assertGreater(len(gap.recommended_actions), 0)

    def test_gap_analysis_finds_attested_models(self) -> None:
        model_dir = Path(self._tmp) / "models" / "my-bert"
        model_dir.mkdir(parents=True)
        (model_dir / "squash-attest.json").write_text(
            json.dumps({"model_id": "acme/bert-v2", "passed": True})
        )
        e = _make_event(title="NIST AI RMF GOVERN profile update")
        gap = self.watcher.gap_analysis(
            e, models_dir=Path(self._tmp) / "models",
        )
        self.assertIn("acme/bert-v2", gap.models_to_re_attest)

    def test_gap_analysis_no_models_dir(self) -> None:
        gap = self.watcher.gap_analysis(_make_event())
        self.assertEqual(gap.models_to_re_attest, [])

    def test_gap_summary_text_is_non_empty(self) -> None:
        gap = self.watcher.gap_analysis(
            _make_event(title="EU AI Act Annex IV final implementing decision")
        )
        text = gap.summary_text()
        self.assertGreater(len(text), 20)
        self.assertIn("EUR-Lex OJ", text)

    def test_gap_to_dict_round_trip(self) -> None:
        gap = self.watcher.gap_analysis(_make_event())
        d = gap.to_dict()
        self.assertIn("event", d)
        self.assertIn("matched_reg_ids", d)
        self.assertIn("squash_controls", d)
        self.assertIn("recommended_actions", d)


class TestMatchRegulatoryIds(unittest.TestCase):
    def test_eu_ai_act_keyword(self) -> None:
        e = _make_event("EU AI Act implementing decision")
        self.assertIn("EU_AI_ACT", _match_regulatory_ids(e))

    def test_nist_ai_rmf_keyword(self) -> None:
        e = RegulatoryEvent(
            event_id="x", source="NIST", title="NIST AI RMF profile update",
            url="https://csrc.nist.gov/x", published="2026-04-30",
            summary="NIST AI risk management framework.", severity="MEDIUM",
        )
        self.assertIn("NIST_AI_RMF", _match_regulatory_ids(e))

    def test_multiple_regs_matched(self) -> None:
        e = RegulatoryEvent(
            event_id="x", source="T", title="EU AI Act and GDPR alignment",
            url="https://eur-lex.europa.eu/x", published="2026-04-30",
            summary="eu ai act and gdpr joint guidance.", severity="MEDIUM",
        )
        matched = _match_regulatory_ids(e)
        self.assertIn("EU_AI_ACT", matched)
        self.assertIn("EU_GDPR", matched)

    def test_no_keywords_returns_empty(self) -> None:
        # Create an event with no regulatory keywords in title or summary
        e = RegulatoryEvent(
            event_id="xyz",
            source="Weather",
            title="Storm warning for the north-east coast",
            url="https://weather.example.com",
            published="2026-04-30",
            summary="Heavy rain expected through the weekend.",
            severity="LOW",
        )
        self.assertEqual(_match_regulatory_ids(e), [])


# ── W245 — CLI: `squash watch-regulatory` ─────────────────────────────────────


class TestCLIWatchRegulatory(unittest.TestCase):
    """CLI tests for `squash watch-regulatory`.

    Network-free: adapter fetch methods are patched to return synthetic events.
    Three test shapes:
      - subprocess: validates help surface and misconfig exit codes (no network needed)
      - subprocess shim: injects mocked adapters at the module level before CLI runs
      - direct (_cmd_watch_regulatory): fastest, avoids subprocess overhead for most logic
    """

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    # ── Help surface ──────────────────────────────────────────────────────────

    def test_help_surface(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "watch-regulatory", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--once", "--interval", "--sources", "--extra-feed",
                     "--models-dir", "--alert-channel", "--dry-run", "--json",
                     "--db-path", "--quiet"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing from help")

    # ── misconfig exit codes (subprocess, no real network needed) ─────────────

    def test_invalid_extra_feed_returns_2(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "watch-regulatory",
             "--once", "--extra-feed", "noequals",
             "--db-path", str(self.tmp / "e.db"), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)

    # ── Direct function tests (fastest; adapters mocked in-process) ───────────

    def _make_args(self, **kwargs) -> "mock.MagicMock":
        """Build a minimal argparse Namespace for _cmd_watch_regulatory."""
        defaults = {
            "wr_once": True,
            "wr_interval": "0",
            "wr_sources": None,
            "wr_extra_feeds": None,
            "wr_models_dir": None,
            "wr_alert_channel": "stdout",
            "wr_db_path": str(self.tmp / "e.db"),
            "wr_dry_run": False,
            "wr_json": False,
            "wr_max_events": 50,
            "quiet": False,
        }
        defaults.update(kwargs)
        return mock.MagicMock(**defaults)

    def _patch_watcher(self, events, gaps=None):
        """Patch RegulatoryWatcher.poll to return synthetic (events, gaps)."""
        if gaps is None:
            gaps = [
                GapAnalysisResult(
                    event=e,
                    matched_reg_ids=["EU_AI_ACT"],
                    squash_controls=["squash attest --policy eu-ai-act"],
                    recommended_actions=["Review at " + e.url],
                )
                for e in events
            ]
        m = mock.MagicMock()
        m.poll.return_value = (list(events), list(gaps))
        m.notify = mock.MagicMock()
        return mock.patch(
            "squash.regulatory_watch.RegulatoryWatcher", return_value=m
        )

    def test_once_no_events_returns_0(self) -> None:
        from squash.cli import _cmd_watch_regulatory
        args = self._make_args(quiet=True)
        with self._patch_watcher([]):
            rc = _cmd_watch_regulatory(args, quiet=True)
        self.assertEqual(rc, 0)

    def test_once_with_new_event_prints_summary(self) -> None:
        from squash.cli import _cmd_watch_regulatory
        import io, contextlib
        e = _make_event("EU AI Act Annex IV update")
        args = self._make_args()
        buf = io.StringIO()
        with self._patch_watcher([e]):
            with contextlib.redirect_stdout(buf):
                rc = _cmd_watch_regulatory(args, quiet=False)
        self.assertEqual(rc, 0)
        self.assertIn("1 new regulatory event", buf.getvalue())

    def test_json_output_structure(self) -> None:
        from squash.cli import _cmd_watch_regulatory
        import io, contextlib
        e = _make_event("NIST AI RMF profile released")
        args = self._make_args(wr_json=True, quiet=False)
        buf = io.StringIO()
        with self._patch_watcher([e]):
            with contextlib.redirect_stdout(buf):
                rc = _cmd_watch_regulatory(args, quiet=False)
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("new_events", payload)
        self.assertIn("gap_results", payload)
        self.assertEqual(payload["new_events"], 1)

    def test_dry_run_notes_not_persisted(self) -> None:
        from squash.cli import _cmd_watch_regulatory
        import io, contextlib
        e = _make_event("EU AI Act enforcement")
        args = self._make_args(wr_dry_run=True)
        buf = io.StringIO()
        with self._patch_watcher([e]):
            with contextlib.redirect_stdout(buf):
                rc = _cmd_watch_regulatory(args, quiet=False)
        self.assertEqual(rc, 0)
        self.assertIn("dry-run", buf.getvalue())

    def test_sources_none_defaults_to_all_three(self) -> None:
        from squash.cli import _cmd_watch_regulatory
        args = self._make_args(wr_sources=None, quiet=True)
        with self._patch_watcher([]) as m_cls:
            _cmd_watch_regulatory(args, quiet=True)
        cfg = m_cls.call_args.args[0] if m_cls.call_args.args else m_cls.call_args.kwargs.get("config") or m_cls.call_args[0][0]
        self.assertIn("sec", cfg.sources)
        self.assertIn("nist", cfg.sources)
        self.assertIn("eurlex", cfg.sources)


# ── WatcherConfig defaults ────────────────────────────────────────────────────


class TestWatcherConfig(unittest.TestCase):
    def test_default_sources(self) -> None:
        cfg = WatcherConfig()
        self.assertEqual(set(cfg.sources), {"sec", "nist", "eurlex"})

    def test_db_path_coerced(self) -> None:
        cfg = WatcherConfig(db_path="/tmp/x.db")
        self.assertIsInstance(cfg.db_path, Path)

    def test_default_max_events(self) -> None:
        self.assertEqual(WatcherConfig().max_events, 50)


# ── Module count gate ─────────────────────────────────────────────────────────


class TestModuleCountAfterSprint27(unittest.TestCase):
    """Sprint 27 adds regulatory_watch.py → count 75 → 76."""

    def test_module_count_is_76(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        self.assertEqual(
            len(py_files), 80,
            msg=f"squash/ has {len(py_files)} files (expected 80 after Sprint 22). "
                "If you added a file, update this gate.",
        )


if __name__ == "__main__":
    unittest.main()
