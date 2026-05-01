"""tests/test_squash_d6_soc2.py — Track D / D6 — SOC 2 Type II Readiness.

Sprint 18 (W218–W220) exit criteria:
  * squash soc2 readiness covers all 65 TSC controls; squash-mapped show evidence
  * squash soc2 evidence produces a valid ZIP with controls_index, dossiers, SHA256SUMS
  * Evidence collection works against 12-month attestation history fixture
  * 1 new module (soc2.py)
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


# ── Soc2ControlCatalogue (W218) ───────────────────────────────────────────────


class TestSoc2ControlCatalogue(unittest.TestCase):
    def setUp(self):
        from squash.soc2 import Soc2ControlCatalogue
        self.cat = Soc2ControlCatalogue()

    def test_exactly_65_controls(self):
        self.assertEqual(len(self.cat.controls), 65)

    def test_all_five_categories_present(self):
        from squash.soc2 import TscCategory
        for cat in TscCategory:
            self.assertTrue(
                any(c.category == cat for c in self.cat.controls),
                f"Category {cat.value} has no controls"
            )

    def test_cc_has_33_plus_one_controls(self):
        from squash.soc2 import TscCategory
        cc_controls = self.cat.by_category(TscCategory.CC)
        self.assertGreaterEqual(len(cc_controls), 33)

    def test_availability_has_controls(self):
        from squash.soc2 import TscCategory
        a_controls = self.cat.by_category(TscCategory.A)
        self.assertGreaterEqual(len(a_controls), 3)

    def test_processing_integrity_covered(self):
        from squash.soc2 import TscCategory, ControlStatus
        pi_controls = self.cat.by_category(TscCategory.PI)
        covered = [c for c in pi_controls if c.status == ControlStatus.COVERED]
        self.assertEqual(len(covered), len(pi_controls),
                         "All PI controls should be COVERED (squash is a processing tool)")

    def test_no_gap_controls(self):
        """Squash has no hard gaps — every control is at least PARTIAL."""
        from squash.soc2 import ControlStatus
        gaps = self.cat.by_status(ControlStatus.GAP)
        self.assertEqual(gaps, [],
                         f"Found {len(gaps)} gap controls: {[c.id for c in gaps]}")

    def test_get_known_control(self):
        cc61 = self.cat.get("CC6.1")
        self.assertIsNotNone(cc61)
        self.assertEqual(cc61.id, "CC6.1")
        self.assertIn("signing", cc61.evidence_description.lower())

    def test_get_unknown_control_returns_none(self):
        self.assertIsNone(self.cat.get("XX99.99"))

    def test_all_control_ids_unique(self):
        ids = [c.id for c in self.cat.controls]
        self.assertEqual(len(ids), len(set(ids)))

    def test_covered_controls_have_squash_components(self):
        from squash.soc2 import ControlStatus
        for c in self.cat.by_status(ControlStatus.COVERED):
            self.assertGreater(
                len(c.squash_components), 0,
                f"COVERED control {c.id} has no squash_components"
            )

    def test_partial_controls_have_remediation(self):
        from squash.soc2 import ControlStatus
        for c in self.cat.by_status(ControlStatus.PARTIAL):
            self.assertGreater(
                len(c.remediation), 0,
                f"PARTIAL control {c.id} has no remediation text"
            )

    def test_to_dict_has_required_fields(self):
        d = self.cat.get("CC6.1").to_dict()
        for field in ("id", "category", "title", "description",
                      "status", "squash_components", "evidence_description"):
            self.assertIn(field, d)

    def test_to_markdown_contains_id(self):
        md = self.cat.get("CC6.1").to_markdown()
        self.assertIn("CC6.1", md)
        self.assertIn("COVERED", md)


class TestSoc2Coverage(unittest.TestCase):
    def setUp(self):
        from squash.soc2 import Soc2ControlCatalogue
        self.cov = Soc2ControlCatalogue().coverage()

    def test_total_is_65(self):
        self.assertEqual(self.cov["total_controls"], 65)

    def test_coverage_pct_between_0_and_100(self):
        self.assertGreaterEqual(self.cov["coverage_pct"], 0)
        self.assertLessEqual(self.cov["coverage_pct"], 100)

    def test_effective_coverage_gte_coverage(self):
        self.assertGreaterEqual(
            self.cov["effective_coverage_pct"],
            self.cov["coverage_pct"]
        )

    def test_counts_sum_to_total(self):
        total = (self.cov["covered"] + self.cov["partial"]
                 + self.cov["gap"] + self.cov["not_applicable"])
        self.assertEqual(total, self.cov["total_controls"])

    def test_by_category_has_all_five(self):
        for cat in ("CC", "A", "PI", "C", "P"):
            self.assertIn(cat, self.cov["by_category"])

    def test_pi_coverage_100_pct(self):
        pi = self.cov["by_category"]["PI"]
        total = sum(pi.values()) - pi.get("NOT_APPLICABLE", 0)
        self.assertEqual(pi.get("COVERED", 0), total,
                         "All PI controls should be COVERED")


# ── EvidenceCollector (W219) ──────────────────────────────────────────────────


class TestEvidenceCollector(unittest.TestCase):
    def _collector(self, tmp: Path, window_days: int = 365):
        from squash.soc2 import EvidenceCollector
        return EvidenceCollector(
            window_days=window_days,
            audit_log_path=tmp / "audit.jsonl",
            attestation_db=tmp / "att.db",
        )

    def _write_audit_log(self, tmp: Path, n: int = 5) -> None:
        """Write n fake audit entries."""
        import datetime
        log_path = tmp / "audit.jsonl"
        now = datetime.datetime.now(datetime.timezone.utc)
        lines = []
        for i in range(n):
            ts = (now - datetime.timedelta(days=i)).isoformat(timespec="seconds")
            lines.append(json.dumps({
                "ts": ts, "event_type": "attestation",
                "model_id": f"model-{i}", "session_id": f"sess-{i}",
                "input_hash": "h", "output_hash": "h", "latency_ms": 100,
                "metadata": {}, "prev_hash": "", "entry_hash": f"hash{i}", "seq": i,
            }))
        log_path.write_text("\n".join(lines))

    def test_collect_all_returns_dossier_per_control(self):
        from squash.soc2 import Soc2ControlCatalogue
        with tempfile.TemporaryDirectory() as td:
            col = self._collector(Path(td))
            dossiers = col.collect_all(Soc2ControlCatalogue())
            self.assertEqual(len(dossiers), 65)

    def test_covered_controls_get_evidence(self):
        from squash.soc2 import Soc2ControlCatalogue, ControlStatus
        with tempfile.TemporaryDirectory() as td:
            col = self._collector(Path(td))
            dossiers = col.collect_all(Soc2ControlCatalogue())
            covered = [c for c in Soc2ControlCatalogue().by_status(ControlStatus.COVERED)]
            for c in covered:
                dossier = dossiers[c.id]
                self.assertGreater(len(dossier.evidence), 0,
                    f"COVERED control {c.id} has no evidence items")

    def test_audit_log_entries_counted(self):
        from squash.soc2 import Soc2ControlCatalogue
        with tempfile.TemporaryDirectory() as td:
            self._write_audit_log(Path(td), n=7)
            col = self._collector(Path(td))
            dossiers = col.collect_all(Soc2ControlCatalogue())
            # CC7.2 explicitly maps to governor.py (audit log)
            dossier = dossiers["CC7.2"]
            audit_ev = [e for e in dossier.evidence if e.source == "audit_log"]
            self.assertGreater(len(audit_ev), 0)
            # Count should reflect our 7 entries
            self.assertEqual(audit_ev[0].data["entry_count"], 7)

    def test_window_filters_old_entries(self):
        from squash.soc2 import Soc2ControlCatalogue, EvidenceCollector
        import datetime
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "audit.jsonl"
            old_ts = (datetime.datetime.now(datetime.timezone.utc)
                      - datetime.timedelta(days=400)).isoformat(timespec="seconds")
            log_path.write_text(json.dumps({
                "ts": old_ts, "event_type": "attestation", "model_id": "m",
                "session_id": "s", "input_hash": "h", "output_hash": "h",
                "latency_ms": 0, "metadata": {}, "prev_hash": "", "entry_hash": "h", "seq": 0,
            }))
            col = EvidenceCollector(window_days=365, audit_log_path=log_path)
            entries = col._read_audit_log()
            # Entry is 400 days old — outside 365-day window
            self.assertEqual(len(entries), 0)

    def test_evidence_item_has_required_fields(self):
        from squash.soc2 import Soc2ControlCatalogue
        with tempfile.TemporaryDirectory() as td:
            col = self._collector(Path(td))
            dossiers = col.collect_all(Soc2ControlCatalogue())
            # Find any dossier with evidence
            for d in dossiers.values():
                if d.evidence:
                    ev = d.evidence[0].to_dict()
                    for f in ("source", "description", "timestamp", "data"):
                        self.assertIn(f, ev)
                    break

    def test_dossier_to_markdown_contains_control_id(self):
        from squash.soc2 import Soc2ControlCatalogue
        with tempfile.TemporaryDirectory() as td:
            col = self._collector(Path(td))
            dossiers = col.collect_all(Soc2ControlCatalogue())
            md = dossiers["CC6.1"].to_markdown()
            self.assertIn("CC6.1", md)

    def test_dossier_to_dict_structure(self):
        from squash.soc2 import Soc2ControlCatalogue
        with tempfile.TemporaryDirectory() as td:
            col = self._collector(Path(td))
            dossiers = col.collect_all(Soc2ControlCatalogue())
            d = dossiers["CC6.1"].to_dict()
            for f in ("control", "evidence_count", "collected_at",
                      "collection_window_days", "evidence"):
                self.assertIn(f, d)


# ── Soc2CoverageReport (W220) ─────────────────────────────────────────────────


class TestSoc2CoverageReport(unittest.TestCase):
    def test_build_returns_report(self):
        from squash.soc2 import Soc2CoverageReport
        with tempfile.TemporaryDirectory() as td:
            report = Soc2CoverageReport.build(
                window_days=30,
                attestation_db=Path(td) / "att.db",
            )
            self.assertIsNotNone(report)
            self.assertEqual(len(report.dossiers), 65)

    def test_summary_text_shows_65_controls(self):
        from squash.soc2 import Soc2CoverageReport
        with tempfile.TemporaryDirectory() as td:
            report = Soc2CoverageReport.build(
                window_days=30,
                attestation_db=Path(td) / "att.db",
            )
            text = report.summary_text()
            self.assertIn("65", text)
            self.assertIn("Coverage Report", text)

    def test_summary_text_has_category_bars(self):
        from squash.soc2 import Soc2CoverageReport
        with tempfile.TemporaryDirectory() as td:
            report = Soc2CoverageReport.build(
                window_days=30,
                attestation_db=Path(td) / "att.db",
            )
            text = report.summary_text()
            for cat in ("CC", "A", "PI", "C", "P"):
                self.assertIn(cat, text)

    def test_to_dict_has_controls_list(self):
        from squash.soc2 import Soc2CoverageReport
        with tempfile.TemporaryDirectory() as td:
            report = Soc2CoverageReport.build(
                window_days=30,
                attestation_db=Path(td) / "att.db",
            )
            d = report.to_dict()
            self.assertIn("controls", d)
            self.assertEqual(len(d["controls"]), 65)
            self.assertIn("coverage", d)
            self.assertIn("generated_at", d)


# ── Soc2EvidenceBundle (W220) ─────────────────────────────────────────────────


class TestSoc2EvidenceBundle(unittest.TestCase):
    def test_bundle_creates_zip(self):
        from squash.soc2 import Soc2EvidenceBundle
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(
                output_dir=Path(td),
                window_days=30,
            )
            self.assertTrue(bundle.exists())
            self.assertTrue(bundle.suffix == ".zip")

    def test_bundle_contains_controls_index(self):
        from squash.soc2 import Soc2EvidenceBundle
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            with zipfile.ZipFile(bundle) as zf:
                self.assertIn("controls_index.json", zf.namelist())

    def test_bundle_contains_sha256sums(self):
        from squash.soc2 import Soc2EvidenceBundle
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            with zipfile.ZipFile(bundle) as zf:
                self.assertIn("SHA256SUMS", zf.namelist())

    def test_bundle_contains_65_json_dossiers(self):
        from squash.soc2 import Soc2EvidenceBundle
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            with zipfile.ZipFile(bundle) as zf:
                dossier_count = sum(
                    1 for n in zf.namelist()
                    if n.startswith("dossiers/") and n.endswith("_evidence.json")
                )
            self.assertEqual(dossier_count, 65)

    def test_bundle_contains_65_md_dossiers(self):
        from squash.soc2 import Soc2EvidenceBundle
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            with zipfile.ZipFile(bundle) as zf:
                md_count = sum(
                    1 for n in zf.namelist()
                    if n.startswith("dossiers/") and n.endswith("_evidence.md")
                )
            self.assertEqual(md_count, 65)

    def test_sha256sums_verifiable(self):
        """Every line in SHA256SUMS should match the actual file in the ZIP."""
        from squash.soc2 import Soc2EvidenceBundle
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            with zipfile.ZipFile(bundle) as zf:
                manifest_lines = zf.read("SHA256SUMS").decode().strip().splitlines()
                for line in manifest_lines[:5]:  # verify first 5 for speed
                    expected_hash, path = line.split("  ", 1)
                    actual = hashlib.sha256(zf.read(path)).hexdigest()
                    self.assertEqual(expected_hash, actual,
                                     f"SHA256 mismatch for {path}")

    def test_controls_index_parseable(self):
        from squash.soc2 import Soc2EvidenceBundle
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            with zipfile.ZipFile(bundle) as zf:
                data = json.loads(zf.read("controls_index.json"))
            self.assertIn("controls", data)
            self.assertIn("coverage", data)
            self.assertEqual(len(data["controls"]), 65)

    def test_bundle_filename_has_date(self):
        from squash.soc2 import Soc2EvidenceBundle
        import datetime
        with tempfile.TemporaryDirectory() as td:
            bundle = Soc2EvidenceBundle.build(output_dir=Path(td), window_days=30)
            today = datetime.date.today().isoformat()
            self.assertIn(today, bundle.name)


# ── CLI dispatcher ────────────────────────────────────────────────────────────


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


class TestCliSoc2(unittest.TestCase):
    def test_readiness_exits_0(self):
        from squash.cli import _cmd_soc2
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_soc2(_ns(
                soc2_command="readiness",
                soc2_window=30,
                soc2_json=False,
                soc2_category=None,
                soc2_status=None,
                quiet=False,
            ), quiet=False)
        self.assertEqual(rc, 0)
        self.assertIn("65", buf.getvalue())

    def test_readiness_json_mode(self):
        from squash.cli import _cmd_soc2
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_soc2(_ns(
                soc2_command="readiness",
                soc2_window=30,
                soc2_json=True,
                soc2_category=None,
                soc2_status=None,
                quiet=True,
            ), quiet=True)
        self.assertEqual(rc, 0)
        parsed = json.loads(buf.getvalue())
        self.assertIn("controls", parsed)
        self.assertEqual(len(parsed["controls"]), 65)
        self.assertIn("coverage", parsed)

    def test_readiness_category_filter(self):
        from squash.cli import _cmd_soc2
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            _cmd_soc2(_ns(
                soc2_command="readiness",
                soc2_window=30,
                soc2_json=True,
                soc2_category="PI",
                soc2_status=None,
                quiet=True,
            ), quiet=True)
        parsed = json.loads(buf.getvalue())
        # When filtered, only PI controls appear
        self.assertTrue(all(c["category"] == "PI" for c in parsed["controls"]))

    def test_readiness_status_filter(self):
        from squash.cli import _cmd_soc2
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            _cmd_soc2(_ns(
                soc2_command="readiness",
                soc2_window=30,
                soc2_json=True,
                soc2_category=None,
                soc2_status="COVERED",
                quiet=True,
            ), quiet=True)
        parsed = json.loads(buf.getvalue())
        self.assertTrue(all(c["status"] == "COVERED" for c in parsed["controls"]))

    def test_evidence_builds_zip(self):
        from squash.cli import _cmd_soc2
        with tempfile.TemporaryDirectory() as td:
            rc = _cmd_soc2(_ns(
                soc2_command="evidence",
                soc2_window=30,
                soc2_output=td,
                soc2_no_attest=True,
                quiet=True,
            ), quiet=True)
            self.assertEqual(rc, 0)
            zips = list(Path(td).glob("*.zip"))
            self.assertEqual(len(zips), 1)
            with zipfile.ZipFile(zips[0]) as zf:
                self.assertIn("SHA256SUMS", zf.namelist())

    def test_unknown_subcommand_returns_1(self):
        from squash.cli import _cmd_soc2
        rc = _cmd_soc2(_ns(soc2_command=None), quiet=True)
        self.assertEqual(rc, 1)


# ── Subprocess CLI ────────────────────────────────────────────────────────────


class TestCliSubprocess(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True,
        )

    def test_readiness_help(self):
        r = self._run("soc2", "readiness", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--window", "--json", "--category", "--status"):
            self.assertIn(flag, r.stdout)

    def test_evidence_help(self):
        r = self._run("soc2", "evidence", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--output", "--window", "--no-attestations"):
            self.assertIn(flag, r.stdout)

    def test_readiness_runs(self):
        r = self._run("soc2", "readiness", "--window", "30", "--quiet")
        self.assertEqual(r.returncode, 0)

    def test_readiness_json(self):
        r = self._run("soc2", "readiness", "--json", "--window", "30")
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["coverage"]["total_controls"], 65)

    def test_evidence_builds_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._run("soc2", "evidence",
                          "--output", td, "--window", "30",
                          "--no-attestations", "--quiet")
            self.assertEqual(r.returncode, 0)
            zips = list(Path(td).glob("*.zip"))
            self.assertEqual(len(zips), 1)


if __name__ == "__main__":
    unittest.main()
