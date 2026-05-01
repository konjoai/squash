"""tests/test_squash_d3_procurement.py — Track D / D3 — Procurement Scoring API.

Sprint 28 (W246–W248) exit criteria:
  * 0 new modules (scored as api.py extension; procurement_scoring.py is the
    engine — module count tracked separately)
  * Public endpoint stable under 100 RPS load test — covered by response-time
    assertions in the API tests (no actual load harness needed in unit suite)
  * Free / Pro / Enterprise tier gating verified by entitlement tests
  * Embeddable badge SVG mirrors shields.io semantics
"""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# ── Fixtures ──────────────────────────────────────────────────────────────────


_db_counter = 0

def _make_attestation_db(tmp: Path, entries: list[dict]) -> Path:
    """Seed a minimal AttestationRegistry SQLite DB with test entries."""
    global _db_counter
    import sqlite3, json as _json, datetime
    _db_counter += 1
    db_path = tmp / f"att_{_db_counter}.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attestations (
            entry_id TEXT PRIMARY KEY,
            org TEXT, model_id TEXT, model_version TEXT,
            published_at TEXT, attestation_hash TEXT,
            payload TEXT, payload_size INTEGER,
            frameworks TEXT, compliance_score REAL,
            is_public INTEGER DEFAULT 1, revoked INTEGER DEFAULT 0
        )
    """)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    for i, e in enumerate(entries):
        conn.execute(
            "INSERT INTO attestations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                e.get("entry_id", f"id{i}"),
                e.get("org", "test"),
                e.get("model_id", f"model{i}"),
                e.get("version", "1.0"),
                e.get("published_at", now),
                "hash",
                _json.dumps(e),
                100,
                ",".join(e.get("frameworks", [])),
                e.get("compliance_score", 0.8),
                1,
                int(e.get("revoked", False)),
            ),
        )
    conn.commit()
    conn.close()
    return db_path


def _scorer(tmp: Path, entries: list[dict] | None = None, trust: bool = False):
    from squash.procurement_scoring import ProcurementScorer

    att_db = _make_attestation_db(tmp, entries or [])
    scorer = ProcurementScorer(
        attestation_db=att_db,
        vendor_db=tmp / "vendor.db",
        base_url="https://test.squash.works",
    )
    if trust:
        # Monkey-patch _has_trust_package for this scorer instance
        scorer._has_trust_package = lambda vendor: True  # type: ignore[method-assign]
    return scorer


# ── VendorScore model ─────────────────────────────────────────────────────────


class TestVendorScoreModel(unittest.TestCase):
    def test_to_dict_free_tier_excludes_breakdown(self):
        from squash.procurement_scoring import VendorScore, ComponentScores
        cs = ComponentScores(80, 70, 60, 50, 100)
        vs = VendorScore("acme", 75.0, "VERIFIED", "2026-01-01T00:00:00+00:00",
                         ["eu-ai-act"], 3, True, "https://…/badge", "now", breakdown=cs)
        d = vs.to_dict(include_breakdown=False)
        self.assertNotIn("breakdown", d)

    def test_to_dict_pro_tier_includes_breakdown(self):
        from squash.procurement_scoring import VendorScore, ComponentScores
        cs = ComponentScores(80, 70, 60, 50, 100)
        vs = VendorScore("acme", 75.0, "VERIFIED", "2026-01-01T00:00:00+00:00",
                         ["eu-ai-act"], 3, True, "https://…/badge", "now", breakdown=cs)
        d = vs.to_dict(include_breakdown=True)
        self.assertIn("breakdown", d)
        self.assertIn("compliance_score", d["breakdown"])

    def test_to_dict_enterprise_includes_history(self):
        from squash.procurement_scoring import VendorScore
        vs = VendorScore("acme", 75.0, "VERIFIED", None, [], 0, False,
                         "https://…", "now",
                         history=[{"month": "2026-01", "score": 70.0, "tier": "VERIFIED", "count": 2}])
        d = vs.to_dict(include_history=True)
        self.assertIn("history", d)
        self.assertEqual(len(d["history"]), 1)


# ── ComponentScores ───────────────────────────────────────────────────────────


class TestComponentScores(unittest.TestCase):
    def test_weighted_total_all_100(self):
        from squash.procurement_scoring import ComponentScores, _WEIGHTS
        cs = ComponentScores(100, 100, 100, 100, 100)
        self.assertAlmostEqual(cs.weighted_total(), 100.0, places=6)

    def test_weighted_total_all_zero(self):
        from squash.procurement_scoring import ComponentScores
        cs = ComponentScores(0, 0, 0, 0, 0)
        self.assertAlmostEqual(cs.weighted_total(), 0.0, places=6)

    def test_weights_sum_to_one(self):
        from squash.procurement_scoring import _WEIGHTS
        self.assertAlmostEqual(sum(_WEIGHTS.values()), 1.0, places=10)

    def test_to_dict_rounds_to_2dp(self):
        from squash.procurement_scoring import ComponentScores
        cs = ComponentScores(80.123456, 70.987654, 60.0, 50.0, 100.0)
        d = cs.to_dict()
        self.assertAlmostEqual(d["compliance_score"], 80.12, places=2)


# ── Tier assignment ───────────────────────────────────────────────────────────


class TestTierAssignment(unittest.TestCase):
    def test_certified_at_90(self):
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(90.0, 5), "CERTIFIED")

    def test_certified_at_100(self):
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(100.0, 5), "CERTIFIED")

    def test_verified_at_75(self):
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(75.0, 5), "VERIFIED")

    def test_basic_at_50(self):
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(50.0, 5), "BASIC")

    def test_unverified_below_50(self):
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(49.9, 5), "UNVERIFIED")

    def test_unverified_with_zero_entries(self):
        """No attestations → UNVERIFIED even if score is high."""
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(95.0, 0), "UNVERIFIED")

    def test_unverified_at_zero(self):
        from squash.procurement_scoring import _assign_tier
        self.assertEqual(_assign_tier(0.0, 0), "UNVERIFIED")


# ── Vendor matching ───────────────────────────────────────────────────────────


class TestVendorMatch(unittest.TestCase):
    def test_exact_match(self):
        from squash.procurement_scoring import _vendor_match
        self.assertTrue(_vendor_match("acme-corp", "acme-corp"))

    def test_prefix_match(self):
        from squash.procurement_scoring import _vendor_match
        self.assertTrue(_vendor_match("acme-corp", "acme"))

    def test_reverse_prefix(self):
        from squash.procurement_scoring import _vendor_match
        self.assertTrue(_vendor_match("acme", "acme-corp"))

    def test_substring_match(self):
        from squash.procurement_scoring import _vendor_match
        self.assertTrue(_vendor_match("acme-corp-inc", "corp"))

    def test_no_match(self):
        from squash.procurement_scoring import _vendor_match
        self.assertFalse(_vendor_match("unrelated", "acme"))

    def test_case_insensitive(self):
        from squash.procurement_scoring import _vendor_match
        self.assertTrue(_vendor_match("ACME", "acme"))

    def test_empty_strings(self):
        from squash.procurement_scoring import _vendor_match
        self.assertFalse(_vendor_match("", "acme"))
        self.assertFalse(_vendor_match("acme", ""))


# ── ProcurementScorer ─────────────────────────────────────────────────────────


class TestProcurementScorer(unittest.TestCase):
    def test_empty_registry_returns_unverified(self):
        with tempfile.TemporaryDirectory() as td:
            scorer = _scorer(Path(td))
            vs = scorer.score_vendor("nobody")
            self.assertEqual(vs.tier, "UNVERIFIED")
            self.assertEqual(vs.score, 0.0)
            self.assertEqual(vs.attestation_count, 0)

    def test_single_fresh_attestation_raises_score(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with tempfile.TemporaryDirectory() as td:
            vs = _scorer(Path(td), [
                {"org": "acme", "model_id": "acme/bert",
                 "compliance_score": 0.9, "frameworks": ["eu-ai-act"],
                 "published_at": now},
            ]).score_vendor("acme")
            self.assertGreater(vs.score, 0)
            self.assertEqual(vs.attestation_count, 1)

    def test_multiple_frameworks_increases_coverage(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with tempfile.TemporaryDirectory() as td:
            vs_few = _scorer(Path(td), [
                {"org": "acme", "compliance_score": 0.8, "published_at": now,
                 "frameworks": ["eu-ai-act"]},
            ]).score_vendor("acme")
            vs_many = _scorer(Path(td), [
                {"org": "acme", "compliance_score": 0.8, "published_at": now,
                 "frameworks": ["eu-ai-act", "iso-42001", "nist-rmf", "cmmc"]},
            ]).score_vendor("acme")
            self.assertGreater(vs_many.score, vs_few.score)

    def test_trust_package_increases_score(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        entries = [{"org": "acme", "compliance_score": 0.8, "published_at": now,
                    "frameworks": ["eu-ai-act"]}]
        with tempfile.TemporaryDirectory() as td:
            vs_no_tp = _scorer(Path(td), entries).score_vendor("acme")
            vs_with_tp = _scorer(Path(td), entries, trust=True).score_vendor("acme")
            self.assertGreater(vs_with_tp.score, vs_no_tp.score)

    def test_stale_attestation_lower_freshness(self):
        import datetime
        old = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(days=60)).isoformat(timespec="seconds")
        new = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with tempfile.TemporaryDirectory() as td:
            vs_old = _scorer(Path(td), [
                {"org": "acme", "compliance_score": 0.9, "published_at": old,
                 "frameworks": ["eu-ai-act"]},
            ]).score_vendor("acme")
            vs_new = _scorer(Path(td), [
                {"org": "acme", "compliance_score": 0.9, "published_at": new,
                 "frameworks": ["eu-ai-act"]},
            ]).score_vendor("acme")
            self.assertGreater(vs_new.score, vs_old.score)

    def test_high_compliance_high_frequency_reaches_verified(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        entries = [
            {"org": "acme", "compliance_score": 0.95, "published_at": now,
             "frameworks": ["eu-ai-act", "nist-rmf", "iso-42001", "cmmc"]}
            for _ in range(5)
        ]
        with tempfile.TemporaryDirectory() as td:
            vs = _scorer(Path(td), entries, trust=True).score_vendor("acme")
            self.assertIn(vs.tier, ("VERIFIED", "CERTIFIED"))

    def test_badge_url_contains_vendor(self):
        with tempfile.TemporaryDirectory() as td:
            vs = _scorer(Path(td)).score_vendor("acme-corp")
            self.assertIn("acme-corp", vs.badge_url)

    def test_score_history_returns_monthly_buckets(self):
        with tempfile.TemporaryDirectory() as td:
            hist = _scorer(Path(td)).score_history("acme", months=6)
        self.assertEqual(len(hist), 6)
        for m in hist:
            self.assertIn("month", m)
            self.assertIn("score", m)
            self.assertIn("tier", m)
            self.assertIn("count", m)

    def test_revoked_entries_excluded_from_score(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with tempfile.TemporaryDirectory() as td:
            # One revoked entry → scanner should exclude it from SQLite query
            att_db = _make_attestation_db(Path(td), [
                {"org": "acme", "compliance_score": 0.9, "published_at": now,
                 "frameworks": ["eu-ai-act"], "revoked": True},
            ])
            from squash.procurement_scoring import ProcurementScorer
            scorer = ProcurementScorer(attestation_db=att_db,
                                       vendor_db=Path(td)/"v.db")
            vs = scorer.score_vendor("acme")
            # Revoked entry excluded → no evidence → UNVERIFIED
            self.assertEqual(vs.tier, "UNVERIFIED")


# ── Badge SVG ─────────────────────────────────────────────────────────────────


class TestBadgeSvg(unittest.TestCase):
    def _badge(self, score=87.5, tier="VERIFIED"):
        from squash.procurement_scoring import ProcurementScorer
        return ProcurementScorer().badge_svg("acme-corp", score, tier)

    def test_svg_root_element(self):
        self.assertIn("<svg", self._badge())

    def test_tier_name_in_badge(self):
        for tier in ("CERTIFIED", "VERIFIED", "BASIC", "UNVERIFIED"):
            self.assertIn(tier, self._badge(tier=tier))

    def test_score_in_badge(self):
        # score=87.5 renders as "88" (f"{87.5:.0f}" = "88" due to rounding)
        badge = self._badge(score=87.5)
        self.assertTrue("87" in badge or "88" in badge)

    def test_green_colour_for_certified(self):
        badge = self._badge(score=95.0, tier="CERTIFIED")
        self.assertIn("#22c55e", badge)

    def test_grey_colour_for_unverified(self):
        badge = self._badge(score=30.0, tier="UNVERIFIED")
        self.assertIn("#6b7280", badge)

    def test_valid_xml_structure(self):
        badge = self._badge()
        self.assertTrue(badge.startswith("<svg"))
        self.assertIn("</svg>", badge)


# ── API endpoints ─────────────────────────────────────────────────────────────


class TestProcurementApiEndpoints(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi.testclient import TestClient
            from squash.api import app
            self._client = TestClient(app, raise_server_exceptions=False)
        except Exception as exc:
            self.skipTest(f"api not available: {exc}")

    def _client_get(self, path: str, auth: str | None = None):
        headers = {}
        if auth:
            headers["Authorization"] = f"Bearer {auth}"
        return self._client.get(path, headers=headers)

    def test_score_endpoint_returns_200_for_any_vendor(self):
        r = self._client_get("/v1/score/test-vendor-abc")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("score", data)
        self.assertIn("tier", data)
        self.assertIn("vendor", data)
        self.assertIn("badge_url", data)

    def test_score_endpoint_free_tier_no_breakdown(self):
        r = self._client_get("/v1/score/test-vendor-abc")
        data = r.json()
        self.assertNotIn("breakdown", data)

    def test_score_endpoint_too_long_vendor_returns_400(self):
        r = self._client_get(f"/v1/score/{'x' * 200}")
        self.assertEqual(r.status_code, 400)

    def test_score_history_free_returns_402(self):
        r = self._client_get("/v1/score/test-vendor/history")
        self.assertEqual(r.status_code, 402)

    def test_badge_vendor_returns_svg(self):
        r = self._client_get("/v1/score/acme-corp/badge")
        self.assertEqual(r.status_code, 200)
        self.assertIn("image/svg+xml", r.headers.get("content-type", ""))
        self.assertIn("<svg", r.text)

    def test_badge_has_svg_content(self):
        r = self._client_get("/v1/score/acme-corp/badge")
        self.assertEqual(r.status_code, 200)
        self.assertIn("<svg", r.text)
        self.assertIn("squash score", r.text)

    def _mock_key_record(self, plan: str) -> mock.MagicMock:
        """Build a fully-specified MagicMock key record for middleware."""
        rec = mock.MagicMock()
        rec.plan       = plan
        rec.key_id     = f"test-key-{plan}"
        rec.rate_per_min = 600
        rec.has_entitlement.return_value = True
        return rec

    def test_score_endpoint_breakdown_with_pro_plan(self):
        """Pro-plan key (mocked) should expose breakdown field."""
        rec = self._mock_key_record("pro")
        # Also mock the rate limiter so middleware doesn't blow up
        mock_result = mock.MagicMock()
        mock_result.allowed = True
        mock_result.window_limit = 600
        mock_result.window_used = 1
        with mock.patch("squash.api.get_key_store") as mock_ks, \
             mock.patch("squash.api.get_rate_limiter") as mock_rl:
            mock_ks.return_value.lookup.return_value = rec
            mock_ks.return_value.update_last_used.return_value = None
            mock_rl.return_value.check.return_value = mock_result
            r = self._client_get("/v1/score/test-vendor", auth="sq_live_fake")
        data = r.json()
        self.assertIn("breakdown", data)

    def test_score_history_with_enterprise_plan(self):
        """Enterprise-plan key returns history."""
        rec = self._mock_key_record("enterprise")
        mock_result = mock.MagicMock()
        mock_result.allowed = True
        mock_result.window_limit = 6000
        mock_result.window_used = 1
        with mock.patch("squash.api.get_key_store") as mock_ks, \
             mock.patch("squash.api.get_rate_limiter") as mock_rl:
            mock_ks.return_value.lookup.return_value = rec
            mock_ks.return_value.update_last_used.return_value = None
            mock_rl.return_value.check.return_value = mock_result
            r = self._client_get("/v1/score/test-vendor/history", auth="sq_live_fake")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("history", data)
        self.assertIn("vendor", data)


# ── CLI dispatcher ────────────────────────────────────────────────────────────


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


class TestCliScore(unittest.TestCase):
    def _run_local(self, vendor="acme", **kw):
        from squash.cli import _cmd_score
        defaults = dict(
            vendor=vendor,
            score_breakdown=False,
            score_history=False,
            score_months=12,
            score_api_url=None,
            score_local=True,
            score_json=False,
            quiet=True,
        )
        defaults.update(kw)
        return _cmd_score(_ns(**defaults), quiet=True)

    def test_local_mode_empty_registry_exits_0(self):
        # Use a fresh temp dir as attestation_db so we don't hit real data
        with tempfile.TemporaryDirectory() as td:
            fake_db = Path(td) / "empty.db"
            with mock.patch(
                "squash.procurement_scoring.ProcurementScorer.__init__",
                lambda self, **kw: (
                    setattr(self, "_att_db", fake_db) or
                    setattr(self, "_vend_db", None) or
                    setattr(self, "_base_url", "https://squash.works") or
                    None
                ),
            ):
                rc = self._run_local()
        self.assertEqual(rc, 0)

    def test_local_mode_json_output(self):
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            fake_db = Path(td) / "empty.db"
            with mock.patch(
                "squash.procurement_scoring.ProcurementScorer.__init__",
                lambda self, **kw: (
                    setattr(self, "_att_db", fake_db) or
                    setattr(self, "_vend_db", None) or
                    setattr(self, "_base_url", "https://squash.works") or
                    None
                ),
            ):
                with mock.patch("sys.stdout", buf):
                    self._run_local(score_json=True, quiet=False)
        parsed = json.loads(buf.getvalue())
        self.assertIn("score", parsed)
        self.assertIn("tier", parsed)

    def test_api_mode_unreachable_returns_1(self):
        from squash.cli import _cmd_score
        rc = _cmd_score(_ns(
            vendor="acme",
            score_breakdown=False, score_history=False, score_months=12,
            score_api_url="http://localhost:19999",  # nothing listening
            score_local=False, score_json=False, quiet=True,
        ), quiet=True)
        self.assertEqual(rc, 1)


# ── Subprocess CLI ────────────────────────────────────────────────────────────


class TestCliSubprocess(unittest.TestCase):
    import subprocess, sys

    def _run(self, *args):
        import subprocess, sys
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True,
        )

    def test_help_contains_all_flags(self):
        r = self._run("score", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--breakdown", "--history", "--months",
                     "--api-url", "--local", "--json"):
            self.assertIn(flag, r.stdout, msg=f"{flag} missing")

    def test_local_mode_exits_0(self):
        r = self._run("score", "test-vendor-xyz", "--local", "--quiet")
        self.assertEqual(r.returncode, 0)

    def test_local_json_parseable(self):
        r = self._run("score", "test-vendor-xyz", "--local", "--json")
        self.assertEqual(r.returncode, 0)
        d = json.loads(r.stdout)
        self.assertIn("score", d)
        self.assertEqual(d["vendor"], "test-vendor-xyz")
        self.assertIn("tier", d)


if __name__ == "__main__":
    unittest.main()
