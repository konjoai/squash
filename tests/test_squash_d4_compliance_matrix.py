"""tests/test_squash_d4_compliance_matrix.py — Track D / D4.

Sprint 26 (W240–W242) exit criteria:
  * 1 new module (compliance_matrix.py)
  * Matrix correctly cross-references at least 5 jurisdictions × 9 frameworks
  * HTML output renders without JavaScript dependencies
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Module surface ────────────────────────────────────────────────────────────


class TestModuleSurface(unittest.TestCase):
    def test_public_api_exposed(self):
        from squash import compliance_matrix as cm
        for n in (
            "ComplianceMatrix", "Jurisdiction", "Requirement", "MatrixCell",
            "MatrixSummary", "CellStatus", "GapAnalyser", "RemediationStep",
            "EvidenceCheck", "render_html", "parse_region", "parse_regions",
            "builtin_requirements", "load_attestation_dir",
        ):
            self.assertIn(n, cm.__all__, msg=n)
            self.assertTrue(hasattr(cm, n), msg=n)

    def test_jurisdiction_enum_has_required_members(self):
        from squash.compliance_matrix import Jurisdiction
        for code in ("global", "eu", "us", "us-fed", "us-co", "us-nyc",
                     "uk", "sg", "ca", "au", "cn"):
            Jurisdiction(code)  # raises if missing


# ── Region parsing ────────────────────────────────────────────────────────────


class TestRegionParsing(unittest.TestCase):
    def test_parse_canonical(self):
        from squash.compliance_matrix import Jurisdiction, parse_region
        self.assertEqual(parse_region("eu"), Jurisdiction.EU)
        self.assertEqual(parse_region("US-FED"), Jurisdiction.US_FED)

    def test_parse_aliases(self):
        from squash.compliance_matrix import Jurisdiction, parse_region
        self.assertEqual(parse_region("usa"), Jurisdiction.US)
        self.assertEqual(parse_region("Singapore"), Jurisdiction.SG)
        self.assertEqual(parse_region("colorado"), Jurisdiction.US_CO)

    def test_parse_unknown_raises(self):
        from squash.compliance_matrix import parse_region
        with self.assertRaises(ValueError):
            parse_region("mars")

    def test_parse_regions_csv(self):
        from squash.compliance_matrix import Jurisdiction, parse_regions
        out = parse_regions("eu, us, uk, sg, ca")
        self.assertEqual(out, [
            Jurisdiction.EU, Jurisdiction.US, Jurisdiction.UK,
            Jurisdiction.SG, Jurisdiction.CA,
        ])

    def test_parse_regions_dedupes(self):
        from squash.compliance_matrix import parse_regions
        self.assertEqual(len(parse_regions("eu,eu,uk,uk,eu")), 2)


# ── Catalogue coverage ────────────────────────────────────────────────────────


class TestCatalogueCoverage(unittest.TestCase):
    def test_at_least_15_requirements(self):
        from squash.compliance_matrix import builtin_requirements
        reqs = builtin_requirements()
        self.assertGreaterEqual(len(reqs), 15)

    def test_at_least_9_frameworks(self):
        from squash.compliance_matrix import builtin_requirements
        regs = set()
        for r in builtin_requirements():
            regs.update(r.regulations)
        # 9 frameworks expected per master plan
        self.assertGreaterEqual(len(regs), 9, msg=f"got {regs}")

    def test_covers_5_plus_jurisdictions(self):
        from squash.compliance_matrix import Jurisdiction, builtin_requirements
        seen = set()
        for r in builtin_requirements():
            seen.update(r.jurisdictions)
        # Strip GLOBAL — count distinct regional jurisdictions.
        regional = seen - {Jurisdiction.GLOBAL}
        self.assertGreaterEqual(len(regional), 5)

    def test_each_requirement_has_squash_control(self):
        from squash.compliance_matrix import builtin_requirements
        for r in builtin_requirements():
            self.assertTrue(r.squash_control.startswith("squash "),
                            msg=r.requirement_id)

    def test_each_requirement_has_evidence(self):
        from squash.compliance_matrix import builtin_requirements
        for r in builtin_requirements():
            self.assertTrue(
                r.evidence_files or r.evidence_paths,
                msg=f"{r.requirement_id} has no evidence sources",
            )


# ── Matrix construction ──────────────────────────────────────────────────────


class TestMatrixBuild(unittest.TestCase):
    def test_cell_count_is_jurisdictions_times_requirements(self):
        from squash.compliance_matrix import (
            ComplianceMatrix, builtin_requirements,
        )
        m = ComplianceMatrix.build("eu,us,uk,sg,ca")
        self.assertEqual(
            len(m.cells),
            len(m.jurisdictions) * len(builtin_requirements()),
        )

    def test_empty_attestation_yields_failures(self):
        from squash.compliance_matrix import ComplianceMatrix, CellStatus
        m = ComplianceMatrix.build("eu,us,uk")
        # All applicable cells should be FAIL (or NOT_APPLICABLE).
        statuses = {c.status for c in m.cells}
        self.assertIn(CellStatus.FAIL, statuses)
        self.assertIn(CellStatus.NOT_APPLICABLE, statuses)

    def test_attestation_with_evidence_path_passes(self):
        from squash.compliance_matrix import ComplianceMatrix, CellStatus
        attestation = {
            "risk": {"score": 88},
            "policies": {"human_oversight": True},
        }
        m = ComplianceMatrix.build("eu", attestation=attestation)
        risk_cells = m.cells_for_requirement("risk_management")
        self.assertEqual(risk_cells[0].status, CellStatus.PASS)
        oversight_cells = m.cells_for_requirement("human_oversight")
        self.assertEqual(oversight_cells[0].status, CellStatus.PASS)

    def test_evidence_file_satisfies_requirement(self):
        from squash.compliance_matrix import ComplianceMatrix, CellStatus
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "annex_iv_documentation.json").write_text("{}")
            m = ComplianceMatrix.build("eu", attestation={}, model_dir=d)
            cells = m.cells_for_requirement("annex_iv_docs")
            self.assertEqual(cells[0].status, CellStatus.PASS)

    def test_not_applicable_for_us_co_only_requirement(self):
        from squash.compliance_matrix import (
            ComplianceMatrix, CellStatus, Jurisdiction,
        )
        m = ComplianceMatrix.build("eu,us-co")
        bias_cells = {c.jurisdiction: c for c in m.cells_for_requirement("bias_audit")}
        # bias_audit applies to EU + US-CO + US-NYC + UK
        self.assertEqual(bias_cells[Jurisdiction.US_CO].status,
                         CellStatus.FAIL)  # applies, no evidence
        # SEC AI disclosure does NOT apply to EU
        sec_cells = {c.jurisdiction: c for c in m.cells_for_requirement("financial_disclosure")}
        self.assertEqual(sec_cells[Jurisdiction.EU].status,
                         CellStatus.NOT_APPLICABLE)

    def test_global_requirement_applies_everywhere(self):
        from squash.compliance_matrix import ComplianceMatrix, CellStatus
        m = ComplianceMatrix.build(
            "eu,us,uk,sg,ca,au,cn",
            attestation={"risk": {"score": 80}},
        )
        risk_cells = m.cells_for_requirement("risk_management")
        # risk_management is GLOBAL → applies to every jurisdiction
        statuses = [c.status for c in risk_cells]
        self.assertNotIn(CellStatus.NOT_APPLICABLE, statuses)

    def test_must_be_at_least_partial(self):
        from squash.compliance_matrix import (
            ComplianceMatrix, CellStatus, Requirement, Jurisdiction,
        )
        req = Requirement(
            requirement_id="x_threshold", title="X", description="",
            jurisdictions=[Jurisdiction.EU], regulations=[],
            squash_control="squash test",
            evidence_paths=["score"], rule="must_be_at_least", threshold=80.0,
        )
        m = ComplianceMatrix.build(
            "eu", attestation={"score": 50}, requirements=[req],
        )
        self.assertEqual(m.cells[0].status, CellStatus.PARTIAL)
        m2 = ComplianceMatrix.build(
            "eu", attestation={"score": 95}, requirements=[req],
        )
        self.assertEqual(m2.cells[0].status, CellStatus.PASS)

    def test_summary_counts_match(self):
        from squash.compliance_matrix import ComplianceMatrix
        m = ComplianceMatrix.build("eu,us,uk,sg,ca")
        s = m.summary
        self.assertEqual(
            s.total_cells,
            s.pass_count + s.fail_count + s.partial_count
            + s.not_applicable_count + s.unknown_count,
        )

    def test_coverage_by_jurisdiction(self):
        from squash.compliance_matrix import ComplianceMatrix
        m = ComplianceMatrix.build(
            "eu,us",
            attestation={
                "risk": {"score": 80},
                "policies": {"human_oversight": True},
            },
        )
        cov = m.coverage_by_jurisdiction()
        self.assertEqual(len(cov), 2)
        for v in cov.values():
            self.assertGreaterEqual(v, 0)
            self.assertLessEqual(v, 100)


# ── Gap analyser ──────────────────────────────────────────────────────────────


class TestGapAnalyser(unittest.TestCase):
    def test_plan_is_sorted_by_coverage(self):
        from squash.compliance_matrix import (
            ComplianceMatrix, GapAnalyser,
        )
        m = ComplianceMatrix.build("eu,us,uk,sg,ca")
        plan = GapAnalyser(m).plan()
        # First step should have the largest coverage_count.
        for i in range(len(plan) - 1):
            self.assertGreaterEqual(plan[i].coverage_count,
                                    plan[i + 1].coverage_count)

    def test_plan_addresses_all_failures(self):
        from squash.compliance_matrix import (
            ComplianceMatrix, GapAnalyser, CellStatus,
        )
        m = ComplianceMatrix.build("eu,us")
        plan = GapAnalyser(m).plan()
        addressed = {
            (rid, j) for s in plan
            for rid in s.addresses_requirement_ids
            for j in s.addresses_jurisdictions
        }
        for c in m.cells:
            if c.status.is_failing:
                self.assertIn(
                    (c.requirement_id, c.jurisdiction), addressed,
                    msg=f"{c.requirement_id}/{c.jurisdiction.value} not in plan",
                )

    def test_plan_empty_when_no_failures(self):
        from squash.compliance_matrix import (
            ComplianceMatrix, GapAnalyser, Requirement, Jurisdiction,
        )
        # Construct a matrix with one always-passing requirement
        req = Requirement(
            requirement_id="ok", title="OK", description="",
            jurisdictions=[Jurisdiction.EU], regulations=[],
            squash_control="squash noop",
            evidence_paths=["x"],
        )
        m = ComplianceMatrix.build(
            "eu", attestation={"x": "yes"}, requirements=[req],
        )
        self.assertEqual(GapAnalyser(m).plan(), [])


# ── Renderers ─────────────────────────────────────────────────────────────────


class TestRenderers(unittest.TestCase):
    def test_text_contains_jurisdictions(self):
        from squash.compliance_matrix import ComplianceMatrix
        out = ComplianceMatrix.build("eu,us,uk").to_text()
        self.assertIn("eu", out)
        self.assertIn("us", out)
        self.assertIn("uk", out)

    def test_markdown_table_header(self):
        from squash.compliance_matrix import ComplianceMatrix
        md = ComplianceMatrix.build("eu,us").to_markdown()
        self.assertIn("| Requirement |", md)
        self.assertIn("| eu |", md)

    def test_html_no_javascript(self):
        from squash.compliance_matrix import ComplianceMatrix
        html_text = ComplianceMatrix.build("eu,us,uk,sg,ca").to_html()
        self.assertNotIn("<script", html_text.lower())
        self.assertNotIn("javascript:", html_text.lower())
        self.assertNotIn("onclick", html_text.lower())
        self.assertNotIn("onload", html_text.lower())

    def test_html_has_status_classes(self):
        from squash.compliance_matrix import ComplianceMatrix
        html_text = ComplianceMatrix.build(
            "eu,us",
            attestation={"risk": {"score": 90}},
        ).to_html()
        self.assertIn("cell pass", html_text)
        self.assertIn("cell fail", html_text)
        self.assertIn("cell na", html_text)

    def test_html_includes_remediation_when_failing(self):
        from squash.compliance_matrix import ComplianceMatrix
        html_text = ComplianceMatrix.build("eu,us,uk").to_html()
        self.assertIn("Remediation plan", html_text)

    def test_json_round_trip(self):
        from squash.compliance_matrix import ComplianceMatrix
        m = ComplianceMatrix.build("eu,us")
        body = json.loads(m.to_json())
        self.assertEqual(body["jurisdictions"], ["eu", "us"])
        self.assertIn("cells", body)
        self.assertIn("summary", body)


# ── load_attestation_dir ──────────────────────────────────────────────────────


class TestLoadAttestationDir(unittest.TestCase):
    def test_loads_json_files(self):
        from squash.compliance_matrix import load_attestation_dir
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "risk.json").write_text(json.dumps({"score": 80}))
            (d / "policies.json").write_text(json.dumps({"human_oversight": True}))
            out = load_attestation_dir(d)
            self.assertIn("risk", out)
            self.assertEqual(out["risk"]["score"], 80)

    def test_missing_dir_returns_empty(self):
        from squash.compliance_matrix import load_attestation_dir
        self.assertEqual(load_attestation_dir("/no/such/dir"), {})

    def test_invalid_json_skipped(self):
        from squash.compliance_matrix import load_attestation_dir
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "bad.json").write_text("{not json")
            (d / "good.json").write_text('{"x": 1}')
            out = load_attestation_dir(d)
            self.assertNotIn("bad", out)
            self.assertEqual(out["good"], {"x": 1})


# ── CLI handler ───────────────────────────────────────────────────────────────


def _ns(**kw):
    defaults = dict(
        cm_regions="",
        cm_models=None,
        cm_attestation=None,
        cm_model_id="",
        cm_output=None,
        cm_format="text",
        cm_remediation=False,
        cm_fail_on_gap=False,
        cm_list_reqs=False,
        cm_list_jurs=False,
    )
    defaults.update(kw)
    return argparse.Namespace(**defaults)


class TestCli(unittest.TestCase):
    def test_missing_regions_returns_two(self):
        from squash.cli import _cmd_compliance_matrix
        rc = _cmd_compliance_matrix(_ns(), quiet=True)
        self.assertEqual(rc, 2)

    def test_unknown_region_returns_two(self):
        from squash.cli import _cmd_compliance_matrix
        rc = _cmd_compliance_matrix(_ns(cm_regions="mars"), quiet=True)
        self.assertEqual(rc, 2)

    def test_text_output_default(self):
        from squash.cli import _cmd_compliance_matrix
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.txt"
            rc = _cmd_compliance_matrix(
                _ns(cm_regions="eu,us", cm_format="text",
                    cm_output=str(target)),
                quiet=True,
            )
            self.assertEqual(rc, 0)
            content = target.read_text()
            self.assertIn("SQUASH COMPLIANCE MATRIX", content)
            self.assertIn("eu", content)

    def test_html_output_writes_html(self):
        from squash.cli import _cmd_compliance_matrix
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.html"
            rc = _cmd_compliance_matrix(
                _ns(cm_regions="eu,us,uk", cm_format="html",
                    cm_output=str(target)),
                quiet=True,
            )
            self.assertEqual(rc, 0)
            content = target.read_text()
            self.assertIn("<!doctype html>", content)
            self.assertNotIn("<script", content.lower())

    def test_json_output_remediation(self):
        from squash.cli import _cmd_compliance_matrix
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.json"
            rc = _cmd_compliance_matrix(
                _ns(cm_regions="eu", cm_format="json",
                    cm_output=str(target), cm_remediation=True),
                quiet=True,
            )
            self.assertEqual(rc, 0)
            data = json.loads(target.read_text())
            self.assertIn("remediation_plan", data)
            self.assertIn("cells", data)

    def test_fail_on_gap_returns_one(self):
        from squash.cli import _cmd_compliance_matrix
        rc = _cmd_compliance_matrix(
            _ns(cm_regions="eu,us", cm_fail_on_gap=True),
            quiet=True,
        )
        self.assertEqual(rc, 1)

    def test_list_jurisdictions(self):
        from squash.cli import _cmd_compliance_matrix
        from io import StringIO
        buf = StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_compliance_matrix(
                _ns(cm_regions="ignored", cm_list_jurs=True),
                quiet=True,
            )
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("eu", out)
        self.assertIn("us", out)

    def test_list_requirements_emits_json(self):
        from squash.cli import _cmd_compliance_matrix
        from io import StringIO
        buf = StringIO()
        with mock.patch("sys.stdout", buf):
            rc = _cmd_compliance_matrix(
                _ns(cm_regions="ignored", cm_list_reqs=True),
                quiet=True,
            )
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertIsInstance(out, list)
        self.assertGreaterEqual(len(out), 15)

    def test_attestation_file_loaded(self):
        from squash.cli import _cmd_compliance_matrix
        with tempfile.TemporaryDirectory() as tmp:
            att = Path(tmp) / "att.json"
            att.write_text(json.dumps({
                "risk": {"score": 88},
                "policies": {"human_oversight": True},
            }))
            target = Path(tmp) / "out.json"
            rc = _cmd_compliance_matrix(
                _ns(
                    cm_regions="eu",
                    cm_attestation=str(att),
                    cm_format="json",
                    cm_output=str(target),
                ),
                quiet=True,
            )
            self.assertEqual(rc, 0)
            data = json.loads(target.read_text())
            self.assertGreater(data["summary"]["pass"], 0)


# ── CLI parser registration ───────────────────────────────────────────────────


class TestCliRegistration(unittest.TestCase):
    def test_dispatch_branch_present(self):
        cli_src = (Path(__file__).parent.parent / "squash" / "cli.py").read_text()
        self.assertIn('args.command == "compliance-matrix"', cli_src)
        self.assertIn("_cmd_compliance_matrix", cli_src)


if __name__ == "__main__":
    unittest.main()
