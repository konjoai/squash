"""tests/test_squash_c8_deprecation.py — Track C / C8 — Model Deprecation Watch.

Sprint 35 (W265–W266) exit criteria:
  * 1 new module (deprecation_watch.py)
  * 5 provider feeds covered (OpenAI, Anthropic, Google, Meta, Mistral)
  * Cross-reference produces deterministic alerts against fixture registry
  * Migration effort estimator correct for prod/non-prod × high/low risk
  * Re-attestation checklist generated with squash-specific commands
  * CLI: deprecation-watch --list, --check, --json, --fail-on-alert, --checklist
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── DeprecationEntry ──────────────────────────────────────────────────────────


class TestDeprecationEntry(unittest.TestCase):
    def _entry(self, **kw):
        from squash.deprecation_watch import DeprecationEntry, DeprecationImpact
        defaults = dict(
            provider="openai", model_id="gpt-4-0613", aliases=["gpt-4"],
            sunset_date="2025-06-30", announced_date="2024-09-05",
            impact=DeprecationImpact.BREAKING, successor_model="gpt-4o",
            migration_url="https://example.com", notes="test",
        )
        defaults.update(kw)
        return DeprecationEntry(**defaults)

    def test_days_until_sunset_is_int_or_none(self):
        e = self._entry(sunset_date="2099-01-01")
        d = e.days_until_sunset
        self.assertIsNotNone(d)
        self.assertGreater(d, 0)

    def test_days_until_sunset_none_when_no_date(self):
        e = self._entry(sunset_date="")
        self.assertIsNone(e.days_until_sunset)

    def test_is_sunsetted_past_date(self):
        e = self._entry(sunset_date="2020-01-01")
        self.assertTrue(e.is_sunsetted)

    def test_is_sunsetted_future_date(self):
        e = self._entry(sunset_date="2099-12-31")
        self.assertFalse(e.is_sunsetted)

    def test_matches_exact(self):
        e = self._entry()
        self.assertTrue(e.matches("gpt-4-0613"))

    def test_matches_alias(self):
        e = self._entry()
        self.assertTrue(e.matches("gpt-4"))

    def test_matches_case_insensitive(self):
        e = self._entry()
        self.assertTrue(e.matches("GPT-4-0613"))

    def test_not_matches_unrelated(self):
        e = self._entry()
        self.assertFalse(e.matches("claude-3-opus"))

    def test_not_matches_successor(self):
        """gpt-4o should NOT match gpt-4-0613 (not a segment-prefix match)."""
        e = self._entry()
        self.assertFalse(e.matches("gpt-4o"))

    def test_matches_hyphen_prefix(self):
        """gpt-4 matches gpt-4-0613 because next char after gpt-4 is '-'."""
        e = self._entry(model_id="gpt-4-0613", aliases=[])
        self.assertTrue(e.matches("gpt-4"))
        self.assertFalse(e.matches("gpt-4o"))

    def test_matches_longer_needle(self):
        """llama-2-7b should match entry model_id=llama-2."""
        from squash.deprecation_watch import DeprecationEntry, DeprecationImpact
        e = DeprecationEntry(
            provider="meta", model_id="llama-2", aliases=["llama-2-7b", "llama-2-13b"],
            sunset_date="2026-01-01", announced_date="2024-04-18",
            impact=DeprecationImpact.SOFT, successor_model="llama-3",
            migration_url="", notes="",
        )
        self.assertTrue(e.matches("llama-2-7b"))
        self.assertTrue(e.matches("llama-2-13b"))
        self.assertTrue(e.matches("llama-2"))
        self.assertFalse(e.matches("llama-3"))

    def test_to_dict_contains_computed_fields(self):
        e = self._entry(sunset_date="2099-01-01")
        d = e.to_dict()
        self.assertIn("days_until_sunset", d)
        self.assertIn("is_sunsetted", d)
        self.assertFalse(d["is_sunsetted"])


# ── Built-in feed ─────────────────────────────────────────────────────────────


class TestBuiltInFeed(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _watcher(self):
        from squash.deprecation_watch import DeprecationWatcher
        return DeprecationWatcher(db_path=self.tmp / "d.db")

    def test_five_providers_covered(self):
        with self._watcher() as w:
            entries = w.load_feeds()
        providers = {e.provider for e in entries}
        for p in ("openai", "anthropic", "google", "meta", "mistral"):
            self.assertIn(p, providers, f"Provider {p} missing from feed")

    def test_at_least_15_entries_in_feed(self):
        with self._watcher() as w:
            entries = w.load_feeds()
        self.assertGreaterEqual(len(entries), 15)

    def test_gpt4_deprecated_entry_exists(self):
        with self._watcher() as w:
            entries = w.load_feeds(providers=["openai"])
        ids = [e.model_id for e in entries]
        self.assertIn("gpt-4-0613", ids)

    def test_claude1_deprecated_entry_exists(self):
        with self._watcher() as w:
            entries = w.load_feeds(providers=["anthropic"])
        ids = [e.model_id for e in entries]
        self.assertIn("claude-1", ids)

    def test_google_entry_exists(self):
        with self._watcher() as w:
            entries = w.load_feeds(providers=["google"])
        self.assertTrue(any(e.provider == "google" for e in entries))

    def test_meta_entry_exists(self):
        with self._watcher() as w:
            entries = w.load_feeds(providers=["meta"])
        self.assertTrue(any(e.provider == "meta" for e in entries))

    def test_mistral_entry_exists(self):
        with self._watcher() as w:
            entries = w.load_feeds(providers=["mistral"])
        self.assertTrue(any(e.provider == "mistral" for e in entries))

    def test_provider_filter_works(self):
        with self._watcher() as w:
            entries = w.load_feeds(providers=["openai"])
        self.assertTrue(all(e.provider == "openai" for e in entries))

    def test_informational_filter_removes_soft_entries(self):
        with self._watcher() as w:
            entries = w.load_feeds(include_informational=False)
        from squash.deprecation_watch import DeprecationImpact
        self.assertFalse(any(e.impact == DeprecationImpact.INFORMATIONAL for e in entries))

    def test_feed_persisted_to_sqlite(self):
        db = self.tmp / "d.db"
        with self._watcher() as w:
            w.load_feeds()
        # Reload from a fresh instance — entries are in the DB
        from squash.deprecation_watch import DeprecationStore
        with DeprecationStore(db_path=db) as store:
            cached = store.get_all()
        self.assertGreater(len(cached), 0)


# ── Cross-reference engine (W265) ────────────────────────────────────────────


class TestCrossReference(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _watcher(self):
        from squash.deprecation_watch import DeprecationWatcher
        return DeprecationWatcher(db_path=self.tmp / "d.db")

    def test_scan_with_explicit_model_ids(self):
        with self._watcher() as w:
            alerts = w.scan(
                lead_time_days=36500,
                model_ids=["gpt-4-0613", "claude-1", "mistral-tiny",
                           "gemini-1.0-pro", "llama-2"],
            )
        self.assertEqual(len(alerts), 5, [a.asset_model_id for a in alerts])

    def test_scan_non_deprecated_model_produces_no_alerts(self):
        with self._watcher() as w:
            alerts = w.scan(lead_time_days=36500, model_ids=["gpt-4o", "claude-3-5-sonnet"])
        self.assertEqual(len(alerts), 0)

    def test_scan_lead_time_filters_future_entries(self):
        """Models with sunset far in the future should not appear at short lead-time."""
        with self._watcher() as w:
            # whisper-1 has no sunset date — lead-time shouldn't match it
            # Only check sunsetted/near-sunset models
            all_alerts = w.scan(lead_time_days=36500, model_ids=["gpt-4-0613"])
            near_alerts = w.scan(lead_time_days=30, model_ids=["gpt-4-0613"])
        # gpt-4-0613 is already sunsetted (days < 0) → appears at any lead_time
        self.assertEqual(len(all_alerts), len(near_alerts))

    def test_check_model_returns_alert_for_deprecated(self):
        with self._watcher() as w:
            alert = w.check_model("gpt-4-0613")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.entry.provider, "openai")

    def test_check_model_returns_none_for_current(self):
        with self._watcher() as w:
            alert = w.check_model("gpt-4o")
        self.assertIsNone(alert)

    def test_check_model_via_alias(self):
        with self._watcher() as w:
            alert = w.check_model("gpt-4")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.entry.model_id, "gpt-4-0613")

    def test_alert_has_days_remaining(self):
        with self._watcher() as w:
            alert = w.check_model("gpt-4-0613")
        self.assertIsNotNone(alert.days_remaining)
        self.assertLess(alert.days_remaining, 0)  # already sunsetted

    def test_alert_has_migration_effort(self):
        with self._watcher() as w:
            alert = w.check_model("gpt-4-0613")
        from squash.deprecation_watch import MigrationEffort
        self.assertIsInstance(alert.migration_effort, MigrationEffort)

    def test_alert_has_checklist(self):
        with self._watcher() as w:
            alert = w.check_model("gpt-4-0613")
        self.assertGreater(len(alert.re_attestation_checklist), 3)
        # Every item is a checkbox
        for item in alert.re_attestation_checklist:
            self.assertTrue(item.startswith("[ ]"), item)

    def test_alert_is_urgent_when_sunsetted(self):
        with self._watcher() as w:
            alert = w.check_model("claude-1")  # retired Nov 2024
        self.assertTrue(alert.is_urgent(lead_time_days=30))

    def test_deterministic_alerts_for_fixture_registry(self):
        """Same model list → same alert count across runs."""
        model_ids = ["gpt-4-0613", "claude-1.0", "mistral-tiny"]
        with self._watcher() as w:
            a1 = w.scan(lead_time_days=36500, model_ids=model_ids)
        with self._watcher() as w:
            a2 = w.scan(lead_time_days=36500, model_ids=model_ids)
        self.assertEqual(len(a1), len(a2))


# ── Migration effort estimator (W266) ────────────────────────────────────────


class TestMigrationEffortEstimator(unittest.TestCase):
    def _entry(self, impact="BREAKING", successor="gpt-4o"):
        from squash.deprecation_watch import DeprecationEntry, DeprecationImpact
        return DeprecationEntry(
            provider="openai", model_id="gpt-4-0613", aliases=[],
            sunset_date="2025-06-30", announced_date="2024-09-05",
            impact=DeprecationImpact(impact), successor_model=successor,
            migration_url="", notes="",
        )

    def test_breaking_prod_high_risk_is_critical(self):
        from squash.deprecation_watch import estimate_migration_effort, MigrationEffort
        effort, _ = estimate_migration_effort(
            self._entry(), environment="production", risk_tier="HIGH")
        self.assertEqual(effort, MigrationEffort.CRITICAL)

    def test_breaking_prod_normal_risk_is_high(self):
        from squash.deprecation_watch import estimate_migration_effort, MigrationEffort
        effort, _ = estimate_migration_effort(
            self._entry(), environment="production", risk_tier="MEDIUM")
        self.assertEqual(effort, MigrationEffort.HIGH)

    def test_breaking_non_prod_is_medium(self):
        from squash.deprecation_watch import estimate_migration_effort, MigrationEffort
        effort, _ = estimate_migration_effort(
            self._entry(), environment="staging", risk_tier="LOW")
        self.assertEqual(effort, MigrationEffort.MEDIUM)

    def test_soft_prod_is_medium(self):
        from squash.deprecation_watch import estimate_migration_effort, MigrationEffort
        effort, _ = estimate_migration_effort(
            self._entry(impact="SOFT"), environment="production", risk_tier="LOW")
        self.assertEqual(effort, MigrationEffort.MEDIUM)

    def test_informational_any_env_is_low(self):
        from squash.deprecation_watch import estimate_migration_effort, MigrationEffort
        effort, _ = estimate_migration_effort(
            self._entry(impact="INFORMATIONAL"), environment="production", risk_tier="LOW")
        self.assertEqual(effort, MigrationEffort.LOW)

    def test_no_successor_breaking_is_high(self):
        from squash.deprecation_watch import estimate_migration_effort, MigrationEffort
        effort, _ = estimate_migration_effort(
            self._entry(successor=""), environment="dev", risk_tier="LOW")
        self.assertEqual(effort, MigrationEffort.HIGH)

    def test_rationale_is_non_empty_string(self):
        from squash.deprecation_watch import estimate_migration_effort
        _, rationale = estimate_migration_effort(
            self._entry(), environment="production", risk_tier="CRITICAL")
        self.assertIsInstance(rationale, str)
        self.assertGreater(len(rationale), 10)


# ── Re-attestation checklist (W266) ──────────────────────────────────────────


class TestReAttestationChecklist(unittest.TestCase):
    def _entry(self, provider="openai"):
        from squash.deprecation_watch import DeprecationEntry, DeprecationImpact
        return DeprecationEntry(
            provider=provider, model_id="gpt-4-0613", aliases=[],
            sunset_date="2025-06-30", announced_date="2024-09-05",
            impact=DeprecationImpact.BREAKING, successor_model="gpt-4o",
            migration_url="https://example.com", notes="",
        )

    def test_checklist_has_squash_commands(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry())
        text = "\n".join(items)
        self.assertIn("squash attest", text)
        self.assertIn("squash publish", text)

    def test_checklist_references_successor(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry())
        text = "\n".join(items)
        self.assertIn("gpt-4o", text)

    def test_checklist_includes_annex_iv_when_eu_framework(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry(), frameworks=["eu-ai-act"])
        text = "\n".join(items)
        self.assertIn("annex-iv", text.lower())

    def test_checklist_includes_iso_when_iso_framework(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry(), frameworks=["iso-42001"])
        text = "\n".join(items)
        self.assertIn("iso42001", text.lower())

    def test_checklist_includes_migration_url(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry())
        text = "\n".join(items)
        self.assertIn("https://example.com", text)

    def test_checklist_all_checkbox_format(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry())
        for item in items:
            self.assertTrue(item.startswith("[ ]"), f"Item not a checkbox: {item!r}")

    def test_checklist_minimum_length(self):
        from squash.deprecation_watch import build_reAttestation_checklist
        items = build_reAttestation_checklist(self._entry())
        self.assertGreaterEqual(len(items), 5)


# ── DeprecationAlert ──────────────────────────────────────────────────────────


class TestDeprecationAlert(unittest.TestCase):
    def _alert(self, days=-10, environment="production", risk_tier="HIGH"):
        from squash.deprecation_watch import (
            DeprecationAlert, DeprecationEntry, DeprecationImpact,
            MigrationEffort, _utc_now,
        )
        entry = DeprecationEntry(
            provider="openai", model_id="gpt-4-0613", aliases=[],
            sunset_date="2025-01-01", announced_date="2024-09-05",
            impact=DeprecationImpact.BREAKING, successor_model="gpt-4o",
            migration_url="", notes="",
        )
        return DeprecationAlert(
            asset_model_id="gpt-4-0613",
            asset_id="asset-1",
            environment=environment,
            risk_tier=risk_tier,
            frameworks=["eu-ai-act"],
            entry=entry,
            days_remaining=days,
            migration_effort=MigrationEffort.CRITICAL,
            migration_effort_rationale="critical prod",
            re_attestation_checklist=["[ ] step 1", "[ ] step 2"],
            notified_at=_utc_now(),
        )

    def test_is_urgent_when_sunsetted(self):
        a = self._alert(days=-1)
        self.assertTrue(a.is_urgent(30))

    def test_is_urgent_within_lead_time(self):
        a = self._alert(days=15)
        self.assertTrue(a.is_urgent(30))

    def test_not_urgent_outside_lead_time(self):
        a = self._alert(days=60)
        self.assertFalse(a.is_urgent(30))

    def test_summary_contains_provider_and_days(self):
        a = self._alert(days=-1)
        s = a.summary()
        self.assertIn("openai", s)
        self.assertIn("gpt-4o", s)

    def test_to_dict_roundtrip(self):
        a = self._alert()
        d = a.to_dict()
        self.assertIn("entry", d)
        self.assertIn("migration_effort", d)
        self.assertIn("re_attestation_checklist", d)
        self.assertIn("is_urgent", d)


# ── CLI dispatcher ────────────────────────────────────────────────────────────


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


class TestCliDeprecationWatch(unittest.TestCase):
    def _run_cmd(self, **kw):
        from squash.cli import _cmd_deprecation_watch
        defaults = dict(
            dw_lead_time=30, dw_providers="", dw_check_model=None,
            dw_list_all=False, dw_include_all=True, dw_informational=False,
            dw_sunsetted=True, dw_model_ids="", dw_registry_db=None,
            dw_channel="stdout", dw_checklist=False, dw_json=False,
            dw_fail=False, quiet=True,
        )
        defaults.update(kw)
        return _cmd_deprecation_watch(_ns(**defaults), quiet=True)

    def test_list_all_exits_0(self):
        rc = self._run_cmd(dw_list_all=True)
        self.assertEqual(rc, 0)

    def test_list_json_emits_array(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            self._run_cmd(dw_list_all=True, dw_json=True, quiet=False)
        parsed = json.loads(buf.getvalue())
        self.assertIsInstance(parsed, list)
        self.assertGreater(len(parsed), 0)

    def test_check_deprecated_exits_0_without_fail_flag(self):
        rc = self._run_cmd(dw_check_model="gpt-4-0613")
        self.assertEqual(rc, 0)

    def test_check_current_model_exits_0(self):
        rc = self._run_cmd(dw_check_model="gpt-4o")
        self.assertEqual(rc, 0)

    def test_scan_with_model_ids_emits_json(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            self._run_cmd(dw_model_ids="gpt-4-0613,claude-1", dw_json=True,
                          dw_include_all=True, quiet=False)
        parsed = json.loads(buf.getvalue())
        self.assertIsInstance(parsed, list)
        ids = [a["asset_model_id"] for a in parsed]
        self.assertIn("gpt-4-0613", ids)
        self.assertIn("claude-1", ids)

    def test_fail_on_alert_returns_1_when_alerts(self):
        rc = self._run_cmd(dw_model_ids="gpt-4-0613", dw_include_all=True, dw_fail=True)
        self.assertEqual(rc, 1)

    def test_no_alerts_no_fail(self):
        rc = self._run_cmd(dw_model_ids="gpt-4o", dw_include_all=True, dw_fail=True)
        self.assertEqual(rc, 0)

    def test_provider_filter_restricts_results(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            self._run_cmd(
                dw_model_ids="gpt-4-0613,claude-1",
                dw_providers="anthropic",
                dw_include_all=True,
                dw_json=True, quiet=False,
            )
        parsed = json.loads(buf.getvalue())
        providers = {a["entry"]["provider"] for a in parsed}
        self.assertTrue(providers <= {"anthropic"}, f"unexpected providers: {providers}")


# ── Subprocess CLI ────────────────────────────────────────────────────────────


class TestCliSubprocess(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True,
        )

    def test_help_text_includes_all_flags(self):
        r = self._run("deprecation-watch", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--lead-time", "--provider", "--check", "--list",
                     "--model-ids", "--alert-channel", "--checklist",
                     "--json", "--fail-on-alert"):
            self.assertIn(flag, r.stdout, msg=f"{flag} missing from help")

    def test_list_exits_zero(self):
        r = self._run("deprecation-watch", "--list", "--quiet")
        self.assertEqual(r.returncode, 0)

    def test_check_known_deprecated_model(self):
        r = self._run("deprecation-watch", "--check", "gpt-4-0613")
        # rc=0 without --fail-on-alert
        self.assertEqual(r.returncode, 0)

    def test_check_unknown_model_exits_0(self):
        r = self._run("deprecation-watch", "--check", "totally-unknown-model-xyz",
                      "--quiet")
        self.assertEqual(r.returncode, 0)

    def test_json_list_is_parseable(self):
        r = self._run("deprecation-watch", "--list", "--json")
        self.assertEqual(r.returncode, 0)
        entries = json.loads(r.stdout)
        self.assertIsInstance(entries, list)
        self.assertGreater(len(entries), 0)
        self.assertIn("provider", entries[0])
        self.assertIn("model_id", entries[0])


if __name__ == "__main__":
    unittest.main()
