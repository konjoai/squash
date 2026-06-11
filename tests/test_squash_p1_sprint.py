"""tests/test_squash_p1_sprint.py — P1 sprint (v3.8.0).

Covers three new modules + two new API routes:
  * squash.financial_risk       — clause-id -> USD exposure band + aggregate
  * squash.clause_remediation   — RemediationReport / RemediationEntry
  * squash.scan_history         — append-only SQLite ledger + sparkline
  * GET /r/{hash}/remediation   — wired in squash/api.py
  * GET /history                — wired in squash/api.py

CLI / fetch boundaries are exercised via Starlette's TestClient. The
SQLite store is always rerouted to an in-memory database per-test so
the global singleton never leaks across runs.
"""

from __future__ import annotations

import json
import time
import unittest
from typing import Any
from unittest import mock


# ──────────────────────────────────────────────────────────────────────────────
# financial_risk
# ──────────────────────────────────────────────────────────────────────────────


class TestFinancialRisk(unittest.TestCase):
    def test_public_surface(self):
        from squash import financial_risk
        for name in (
            "RISK_TABLE", "RiskBand", "AggregateExposure",
            "quantify", "aggregate_exposure", "covered_clause_ids",
            "format_usd",
        ):
            self.assertIn(name, financial_risk.__all__, msg=name)
            self.assertTrue(hasattr(financial_risk, name), msg=name)

    def test_table_covers_every_clause_severity_etc(self):
        from squash.financial_risk import RISK_TABLE
        for cid, band in RISK_TABLE.items():
            self.assertGreater(band.low_usd, 0, msg=cid)
            self.assertGreaterEqual(band.high_usd, band.low_usd, msg=cid)
            self.assertIn(band.risk_level,
                          {"low", "medium", "high", "critical"}, msg=cid)
            self.assertTrue(band.rationale, msg=cid)
            self.assertTrue(band.citation, msg=cid)

    def test_quantify_known_and_unknown(self):
        from squash.financial_risk import quantify
        band = quantify("GDPR-LAWFUL-BASIS")
        self.assertIsNotNone(band)
        self.assertEqual(band.risk_level, "critical")
        self.assertIsNone(quantify("DOES-NOT-EXIST"))
        self.assertIsNone(quantify(None))  # type: ignore[arg-type]

    def test_aggregate_exposure(self):
        from squash.financial_risk import aggregate_exposure
        agg = aggregate_exposure(["GDPR-LAWFUL-BASIS", "AIA-RISK-CLASS"])
        self.assertEqual(agg.count, 2)
        self.assertGreater(agg.low_usd, 0)
        self.assertGreater(agg.high_usd, agg.low_usd)
        self.assertIn("critical", agg.by_risk_level)

    def test_aggregate_skips_unknown_ids(self):
        from squash.financial_risk import aggregate_exposure
        agg = aggregate_exposure(["GDPR-LAWFUL-BASIS", "NOT-A-CLAUSE"])
        self.assertEqual(agg.count, 1)

    def test_format_usd_buckets(self):
        from squash.financial_risk import format_usd
        self.assertEqual(format_usd(2_500), "$2K")
        self.assertEqual(format_usd(50_000), "$50K")
        self.assertEqual(format_usd(1_200_000), "$1.2M")
        self.assertEqual(format_usd(1_200_000_000), "$1.2B")
        self.assertEqual(format_usd(500), "$500")

    def test_aggregate_empty_is_zero(self):
        from squash.financial_risk import aggregate_exposure
        agg = aggregate_exposure([])
        self.assertEqual((agg.count, agg.low_usd, agg.high_usd), (0, 0, 0))


# ──────────────────────────────────────────────────────────────────────────────
# clause_remediation
# ──────────────────────────────────────────────────────────────────────────────


class TestClauseRemediation(unittest.TestCase):
    def test_public_surface(self):
        from squash import clause_remediation as cr
        for n in ("RemediationEntry", "RemediationReport",
                  "build_remediation", "covered_clause_ids"):
            self.assertIn(n, cr.__all__, msg=n)
            self.assertTrue(hasattr(cr, n), msg=n)

    def test_catalog_matches_financial_table(self):
        # Every clause-id in the financial-risk table must have a
        # remediation entry — symmetry guarantees the demo never shows
        # an exposure number without a paired fix to apply.
        from squash.financial_risk import RISK_TABLE
        from squash.clause_remediation import covered_clause_ids
        rem = set(covered_clause_ids())
        fin = set(RISK_TABLE.keys())
        self.assertEqual(rem, fin, msg=f"diff: {rem ^ fin}")

    def test_build_remediation_from_dicts(self):
        from squash.clause_remediation import build_remediation
        report = build_remediation([
            {"id": "GDPR-LAWFUL-BASIS"},
            {"id": "AIA-RISK-CLASS"},
        ])
        d = report.to_dict()
        self.assertEqual(d["count"], 2)
        self.assertEqual(len(d["entries"]), 2)
        first = d["entries"][0]
        for key in ("clause_id", "label", "issue", "original",
                    "suggested_fix", "risk_level", "dollar_low_usd",
                    "dollar_high_usd", "citation"):
            self.assertIn(key, first, msg=key)
        self.assertGreater(first["dollar_high_usd"], first["dollar_low_usd"])
        self.assertIn(first["risk_level"],
                      {"low", "medium", "high", "critical"})

    def test_build_remediation_from_strings(self):
        from squash.clause_remediation import build_remediation
        report = build_remediation(["GDPR-RETENTION"])
        self.assertEqual(report.entries[0].clause_id, "GDPR-RETENTION")

    def test_build_remediation_unknown_id_falls_back(self):
        from squash.clause_remediation import build_remediation
        report = build_remediation([{"id": "MADE-UP", "label": "Custom"}])
        self.assertEqual(report.entries[0].clause_id, "MADE-UP")
        self.assertEqual(report.entries[0].label, "Custom")
        self.assertIn("No remediation guidance", report.entries[0].issue)
        self.assertEqual(report.entries[0].dollar_high_usd, 0)  # not in table

    def test_aggregate_display_renders(self):
        from squash.clause_remediation import build_remediation
        report = build_remediation([{"id": "GDPR-LAWFUL-BASIS"}])
        d = report.to_dict()
        self.assertTrue(d["aggregate_display"])
        self.assertIn("$", d["aggregate_display"])
        self.assertIn("–", d["aggregate_display"])

    def test_remediation_includes_suggested_fix_text(self):
        from squash.clause_remediation import build_remediation
        report = build_remediation([{"id": "CCPA-OPT-OUT"}])
        e = report.entries[0]
        self.assertGreater(len(e.suggested_fix), 60,
                           msg="suggested_fix should be a real paste-ready clause")
        self.assertIn("California", e.suggested_fix)


# ──────────────────────────────────────────────────────────────────────────────
# scan_history
# ──────────────────────────────────────────────────────────────────────────────


class TestScanHistory(unittest.TestCase):
    def _store(self):
        from squash.scan_history import ScanHistory
        return ScanHistory(path=":memory:")

    def test_public_surface(self):
        from squash import scan_history
        for n in ("ScanHistory", "ScanRecord",
                  "global_history", "reset_global_history"):
            self.assertIn(n, scan_history.__all__, msg=n)
            self.assertTrue(hasattr(scan_history, n), msg=n)

    def test_record_round_trip(self):
        s = self._store()
        rec = s.record(text="hello world",
                       framework="gdpr", verdict="pass", score=92)
        self.assertEqual(rec.framework, "gdpr")
        self.assertEqual(rec.verdict, "pass")
        self.assertEqual(rec.score, 92)
        self.assertEqual(len(rec.input_hash), 16)
        self.assertEqual(s.count(), 1)
        listed = s.list(limit=10)
        self.assertEqual(listed[0].input_hash, rec.input_hash)

    def test_validation(self):
        s = self._store()
        with self.assertRaises(ValueError):
            s.record(text="x", framework="", verdict="pass", score=50)
        with self.assertRaises(ValueError):
            s.record(text="x", framework="gdpr", verdict="bogus", score=50)
        with self.assertRaises(ValueError):
            s.record(text="x", framework="gdpr", verdict="pass", score=150)

    def test_list_newest_first(self):
        s = self._store()
        s.record(text="a", framework="gdpr", verdict="pass", score=90)
        s.record(text="b", framework="ccpa", verdict="fail", score=20)
        out = s.list(limit=10)
        self.assertEqual(out[0].framework, "ccpa")

    def test_list_filter_by_framework_and_verdict(self):
        s = self._store()
        s.record(text="a", framework="gdpr", verdict="pass", score=90)
        s.record(text="b", framework="gdpr", verdict="fail", score=20)
        s.record(text="c", framework="ccpa", verdict="fail", score=10)
        self.assertEqual(len(s.list(framework="gdpr", limit=10)), 2)
        self.assertEqual(len(s.list(framework="gdpr", verdict="fail", limit=10)), 1)

    def test_pagination(self):
        s = self._store()
        for i in range(5):
            s.record(text=f"t{i}", framework="gdpr",
                     verdict="pass", score=80 + i)
        self.assertEqual(len(s.list(limit=2, offset=0)), 2)
        self.assertEqual(len(s.list(limit=2, offset=4)), 1)

    def test_capacity_evicts_oldest(self):
        from squash.scan_history import ScanHistory
        s = ScanHistory(path=":memory:", capacity=3)
        for i in range(5):
            s.record(text=f"t{i}", framework="gdpr",
                     verdict="pass", score=50 + i)
        self.assertEqual(s.count(), 3)
        # newest three remain
        scores = sorted(r.score for r in s.list(limit=10))
        self.assertEqual(scores, [52, 53, 54])

    def test_sparkline_length_and_bounds(self):
        s = self._store()
        for v in ("pass", "fail", "pass", "warn"):
            s.record(text=v, framework="gdpr", verdict=v, score=70)
        spark = s.pass_rate_sparkline(points=12, bucket_seconds=3600)
        self.assertEqual(len(spark), 12)
        for v in spark:
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)

    def test_stats(self):
        s = self._store()
        s.record(text="a", framework="gdpr", verdict="pass", score=80)
        s.record(text="b", framework="gdpr", verdict="fail", score=20)
        st = s.stats()
        self.assertEqual(st["total"], 2)
        self.assertEqual(st["by_verdict"]["pass"], 1)
        self.assertEqual(st["by_verdict"]["fail"], 1)
        self.assertEqual(st["avg_score"], 50.0)

    def test_singleton_reset(self):
        from squash.scan_history import (
            ScanHistory, global_history, reset_global_history,
        )
        try:
            mem = ScanHistory(path=":memory:")
            reset_global_history(mem)
            self.assertIs(global_history(), mem)
            mem.record(text="x", framework="gdpr", verdict="pass", score=80)
            self.assertEqual(global_history().count(), 1)
        finally:
            reset_global_history(None)


# ──────────────────────────────────────────────────────────────────────────────
# API endpoints — exercised via Starlette TestClient
# ──────────────────────────────────────────────────────────────────────────────


def _has_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        from starlette.testclient import TestClient  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_has_fastapi(), "fastapi / starlette not installed")
class TestApiEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reroute the scan-history singleton to in-memory so tests are isolated.
        from squash.scan_history import ScanHistory, reset_global_history
        cls._mem = ScanHistory(path=":memory:")
        reset_global_history(cls._mem)

        from starlette.testclient import TestClient
        from squash.api import app
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        from squash.scan_history import reset_global_history
        reset_global_history(None)

    def _post_quick_check(self, text: str, framework: str = "general") -> dict[str, Any]:
        r = self.client.post(
            "/quick-check",
            json={"text": text, "framework": framework, "share": True},
        )
        self.assertEqual(r.status_code, 200, msg=r.text)
        return r.json()

    def test_quick_check_records_into_history(self):
        before = self.__class__._mem.count()
        self._post_quick_check(
            "This privacy policy describes data collection and your rights. "
            "Contact privacy@example.com for any concerns.",
            framework="general",
        )
        after = self.__class__._mem.count()
        self.assertEqual(after, before + 1)

    def test_remediation_returns_entries_for_known_share(self):
        body = self._post_quick_check(
            "Short and uninformative policy.",
            framework="gdpr",
        )
        share_hash = body.get("share_hash")
        self.assertIsNotNone(share_hash)
        r = self.client.get(f"/r/{share_hash}/remediation")
        self.assertEqual(r.status_code, 200, msg=r.text)
        payload = r.json()
        self.assertIn("entries", payload)
        self.assertGreater(payload["count"], 0)
        self.assertIn("aggregate", payload)
        self.assertIn("aggregate_display", payload)
        first = payload["entries"][0]
        for key in ("clause_id", "issue", "original",
                    "suggested_fix", "risk_level",
                    "dollar_low_usd", "dollar_high_usd"):
            self.assertIn(key, first, msg=key)

    def test_remediation_unknown_share_404(self):
        r = self.client.get("/r/" + "0" * 16 + "/remediation")
        self.assertEqual(r.status_code, 404)

    def test_remediation_malformed_share_400(self):
        r = self.client.get("/r/not-a-hash/remediation")
        self.assertEqual(r.status_code, 400)

    def test_history_returns_entries(self):
        self._post_quick_check("Some text " * 5, framework="general")
        r = self.client.get("/history?limit=5&sparkline=true")
        self.assertEqual(r.status_code, 200, msg=r.text)
        data = r.json()
        self.assertIn("entries", data)
        self.assertIn("total", data)
        self.assertIn("pass_rate_sparkline", data)
        self.assertIn("stats", data)
        self.assertEqual(len(data["pass_rate_sparkline"]), 24)

    def test_history_pagination_validation(self):
        r = self.client.get("/history?limit=0")
        self.assertEqual(r.status_code, 400)
        r = self.client.get("/history?offset=-1")
        self.assertEqual(r.status_code, 400)

    def test_history_filter_by_verdict(self):
        self._post_quick_check("a" * 2000, framework="general")
        self._post_quick_check("b" * 2000, framework="general")
        r = self.client.get("/history?verdict=fail&limit=50")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        for entry in data["entries"]:
            self.assertEqual(entry["verdict"], "fail")

    def test_history_unknown_verdict_400(self):
        r = self.client.get("/history?verdict=bogus")
        self.assertEqual(r.status_code, 400)


# ──────────────────────────────────────────────────────────────────────────────
# Version bump assertion (anchors the sprint to v3.8.0)
# ──────────────────────────────────────────────────────────────────────────────


class TestVersionBump(unittest.TestCase):
    def test_version_is_3_8_x(self):
        from squash import __version__
        major, minor, *_ = __version__.split(".")
        self.assertEqual(major, "3")
        self.assertGreaterEqual(int(minor), 8)


# ──────────────────────────────────────────────────────────────────────────────
# Demo HTML structural smoke
# ──────────────────────────────────────────────────────────────────────────────


class TestDemoHtml(unittest.TestCase):
    def test_new_dom_anchors_present(self):
        from pathlib import Path
        # The v2 compliance-lab rebuild moved the single-page demo (with these
        # anchors) to legacy.html; index.html now hosts the tabbed lab.
        src = (Path(__file__).parent.parent / "demo" / "legacy.html").read_text()
        for anchor in (
            'id="sqRedline"',
            'id="sqExposureChip"',
            'id="sqHistory"',
            'id="sqSparkline"',
            'id="sqHistoryList"',
            'id="sqExposureAmount"',
            'id="sqAvgScore"',
            "/r/${shareHash}/remediation",
            "/history?limit=10",
        ):
            self.assertIn(anchor, src, msg=anchor)


if __name__ == "__main__":
    unittest.main()
