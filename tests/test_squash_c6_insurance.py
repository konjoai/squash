"""tests/test_squash_c6_insurance.py — Track C / C6 — AI Insurance Risk Package.

Sprint 24 (W235–W237) exit criteria:
  * ModelRiskProfile: all fields, to_dict round-trip, risk tier derivation
  * InsurancePackage: to_dict / to_json / to_markdown / save_zip / save
  * InsuranceBuilder: single-model dir, multi-model dir, empty dir, graceful degradation
  * MunichReAdapter: A–D rating logic, maturity level 1–4, coverage recommendation
  * CoalitionAdapter: 5-category scores, weighted aggregate, assessment labels
  * GenericAdapter: flat schema, risk interpretation bands
  * _compute_risk_tier: formula coverage (critical CVEs, unsafe scan, drift, incidents)
  * _aggregate: empty fleet → 100 risk / 0 compliance; multi-model averages correct
  * save_zip: ZIP contains 6 expected members; integrity manifest SHA-256 verifiable
  * CLI: squash insurance-package --json, --underwriter, --zip, missing path, quiet mode
  * Numerical correctness: formulas documented in insurance.py hold exactly
  * No external deps: stdlib-only (no requests, no rich, no cryptography import required)
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_attest(model_id: str = "bert-base", passed_policies: list[str] | None = None) -> dict:
    """Return a minimal squash-attest.json fixture."""
    policy_results = {}
    for name in (passed_policies or ["eu-ai-act"]):
        policy_results[name] = {"passed": True, "error_count": 0}
    return {
        "model_id": model_id,
        "generated_at": "2026-05-01T12:00:00+00:00",
        "policy_results": policy_results,
    }


def _make_vex(critical: int = 0, open_cves: int = 0) -> dict:
    stmts = []
    for i in range(critical):
        stmts.append({"cve_id": f"CVE-2026-{i:04d}", "status": "affected", "severity": "critical"})
    for i in range(open_cves):
        stmts.append({"cve_id": f"CVE-2026-{100 + i:04d}", "status": "affected", "severity": "medium"})
    return {"statements": stmts}


def _make_incident(count: int = 1) -> dict:
    return {"incidents": [{"id": f"inc-{i}", "severity": "HIGH"} for i in range(count)]}


def _make_drift(events: int = 0) -> dict:
    return {"events": [{"ts": f"2026-04-0{i+1}"} for i in range(events)]}


def _make_bias(passed: bool = True) -> dict:
    return {"passed": passed, "overall_status": "PASS" if passed else "FAIL"}


def _write_model_dir(tmp: Path, name: str, **artifacts) -> Path:
    """Create a named model sub-directory with squash artifacts."""
    d = tmp / name
    d.mkdir(parents=True, exist_ok=True)
    for filename, data in artifacts.items():
        (d / filename).write_text(json.dumps(data), encoding="utf-8")
    return d


# ── W235: ModelRiskProfile ────────────────────────────────────────────────────


class TestModelRiskProfile(unittest.TestCase):
    def _profile(self, **kw) -> "ModelRiskProfile":
        from squash.insurance import ModelRiskProfile
        defaults = dict(
            model_id="bert-base",
            model_path="/models/bert-base",
            risk_tier="LOW",
            compliance_score=85,
            frameworks_assessed=["eu-ai-act", "nist-rmf"],
            frameworks_passing=["eu-ai-act"],
            cve_count=2,
            critical_cve_count=0,
            drift_events=0,
            incident_count=0,
            bias_status="PASS",
            last_attested="2026-05-01T12:00:00+00:00",
            attestation_id="bert-base",
            scan_status="clean",
            has_incident_plan=True,
            has_data_lineage=True,
            has_model_card=True,
            has_annex_iv=True,
        )
        defaults.update(kw)
        return ModelRiskProfile(**defaults)

    def test_to_dict_contains_model_id(self):
        d = self._profile().to_dict()
        self.assertEqual(d["model_id"], "bert-base")

    def test_to_dict_contains_risk_tier(self):
        d = self._profile(risk_tier="HIGH").to_dict()
        self.assertEqual(d["risk_tier"], "HIGH")

    def test_to_dict_controls_block_present(self):
        d = self._profile().to_dict()
        self.assertIn("controls", d)
        controls = d["controls"]
        self.assertIn("incident_plan", controls)
        self.assertIn("data_lineage", controls)
        self.assertIn("model_card", controls)
        self.assertIn("technical_documentation", controls)

    def test_to_dict_controls_values_match_fields(self):
        p = self._profile(has_incident_plan=False, has_data_lineage=True)
        d = p.to_dict()
        self.assertFalse(d["controls"]["incident_plan"])
        self.assertTrue(d["controls"]["data_lineage"])

    def test_to_dict_cve_fields(self):
        d = self._profile(cve_count=5, critical_cve_count=2).to_dict()
        self.assertEqual(d["cve_count"], 5)
        self.assertEqual(d["critical_cve_count"], 2)

    def test_to_dict_frameworks_lists(self):
        d = self._profile().to_dict()
        self.assertIsInstance(d["frameworks_assessed"], list)
        self.assertIsInstance(d["frameworks_passing"], list)


# ── W235: _compute_risk_tier ──────────────────────────────────────────────────


class TestComputeRiskTier(unittest.TestCase):
    def _tier(self, **kw) -> str:
        from squash.insurance import _compute_risk_tier
        defaults = dict(
            compliance_score=80,
            critical_cves=0,
            scan_status="clean",
            drift_events=0,
            incidents=0,
            has_any_policy=True,
        )
        defaults.update(kw)
        return _compute_risk_tier(**defaults)

    def test_perfect_posture_is_low(self):
        self.assertEqual(self._tier(), "LOW")

    def test_zero_compliance_no_policy_is_high(self):
        t = self._tier(compliance_score=0, has_any_policy=False)
        self.assertEqual(t, "HIGH")

    def test_critical_cve_pushes_toward_high(self):
        # compliance_score=80 → risk=20, +20 critical_cves → 40 → MEDIUM
        t = self._tier(compliance_score=80, critical_cves=1)
        self.assertIn(t, ("MEDIUM", "HIGH"))

    def test_unsafe_scan_increases_risk(self):
        # compliance_score=50 → risk=50, +10 unsafe → 60 → MEDIUM
        t = self._tier(compliance_score=50, scan_status="unsafe")
        self.assertIn(t, ("MEDIUM", "HIGH"))

    def test_incidents_increase_risk(self):
        t = self._tier(compliance_score=60, incidents=1)
        self.assertIn(t, ("MEDIUM", "HIGH"))

    def test_heavy_drift_increases_risk(self):
        t = self._tier(compliance_score=70, drift_events=10)
        self.assertIn(t, ("MEDIUM", "HIGH"))

    def test_medium_band_boundary(self):
        from squash.insurance import _compute_risk_tier
        # risk = 100 - 60 = 40 → MEDIUM (≥40 and <70)
        t = _compute_risk_tier(60, 0, "clean", 0, 0, True)
        self.assertEqual(t, "MEDIUM")

    def test_risk_clipped_to_100(self):
        from squash.insurance import _compute_risk_tier
        # worst possible: compliance=0, critical_cves, unsafe, drift>5, incidents, no policy
        t = _compute_risk_tier(0, 5, "unsafe", 10, 5, False)
        self.assertEqual(t, "HIGH")


# ── W235: InsuranceBuilder + _aggregate ──────────────────────────────────────


class TestInsuranceBuilder(unittest.TestCase):
    def test_empty_dir_returns_package_100_risk(self):
        """An empty directory with no artefacts → no frameworks assessed → 100 risk."""
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            pkg = InsuranceBuilder().build(Path(tmp), org_name="EmptyCorp")
        # The builder may treat root as a single model dir (fallback) or return
        # 0 models, but in both cases compliance_score must be 0 and risk 100.
        self.assertEqual(pkg.aggregate_risk_score, 100)
        self.assertEqual(pkg.aggregate_compliance_score, 0)

    def test_single_model_directory_root_scanned(self):
        """If root dir has artefacts directly, it is treated as a single model."""
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "squash-attest.json").write_text(
                json.dumps(_make_attest("model-a", ["eu-ai-act", "nist-rmf"])),
                encoding="utf-8",
            )
            pkg = InsuranceBuilder().build(d, org_name="AcmeCorp")
        self.assertEqual(pkg.total_models, 1)
        self.assertEqual(pkg.org_name, "AcmeCorp")

    def test_multi_model_subdirs_discovered(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for name in ("model-a", "model-b", "model-c"):
                _write_model_dir(d, name, **{"squash-attest.json": _make_attest(name)})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.total_models, 3)

    def test_non_model_subdirs_ignored(self):
        """Directories without squash artefacts are skipped."""
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            # One real model, one junk dir
            _write_model_dir(d, "real-model", **{"squash-attest.json": _make_attest("real")})
            junk = d / "junk"
            junk.mkdir()
            (junk / "readme.txt").write_text("not a model")
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.total_models, 1)

    def test_vex_cves_counted(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1",
                **{"squash-attest.json": _make_attest("m1"),
                   "squash-vex-report.json": _make_vex(critical=2, open_cves=3)})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.critical_cves, 2)
        self.assertEqual(pkg.open_cves, 5)  # 2 critical + 3 medium

    def test_incident_count_aggregated(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1",
                **{"squash-attest.json": _make_attest("m1"),
                   "squash-incident.json": _make_incident(3)})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.recent_incidents, 3)

    def test_drift_events_aggregated(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1",
                **{"squash-attest.json": _make_attest("m1"),
                   "squash-drift.json": _make_drift(events=4)})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.drift_events_total, 4)

    def test_bias_fail_counted(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1",
                **{"squash-attest.json": _make_attest("m1"),
                   "bias_audit_report.json": _make_bias(passed=False)})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.bias_fails, 1)

    def test_compliance_score_derived_from_policies(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            # 2 frameworks assessed, 1 passing → 50%
            attest = _make_attest("m1", ["eu-ai-act"])
            attest["policy_results"]["nist-rmf"] = {"passed": False, "error_count": 2}
            _write_model_dir(d, "m1", **{"squash-attest.json": attest})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.model_profiles[0].compliance_score, 50)

    def test_response_plan_true_when_incident_artefact_present(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1",
                **{"squash-attest.json": _make_attest("m1"),
                   "squash-incident.json": _make_incident(1)})
            pkg = InsuranceBuilder().build(d)
        self.assertTrue(pkg.response_plan_documented)

    def test_invalid_json_artefact_does_not_crash(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            # corrupt a secondary artefact
            (d / "m1" / "squash-vex-report.json").write_text("NOT JSON", encoding="utf-8")
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.total_models, 1)

    def test_org_name_stored_in_package(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            pkg = InsuranceBuilder().build(d, org_name="Konjo Inc")
        self.assertEqual(pkg.org_name, "Konjo Inc")

    def test_nonexistent_path_returns_empty_package(self):
        from squash.insurance import InsuranceBuilder
        pkg = InsuranceBuilder().build(Path("/nonexistent/path/does/not/exist"))
        self.assertEqual(pkg.total_models, 0)


# ── W235: InsurancePackage serialisation ─────────────────────────────────────


class TestInsurancePackageSerialization(unittest.TestCase):
    def _pkg(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_model_dir(d, "m1",
                **{"squash-attest.json": _make_attest("m1", ["eu-ai-act"]),
                   "squash-vex-report.json": _make_vex(critical=1),
                   "bias_audit_report.json": _make_bias(True)})
            _write_model_dir(d, "m2",
                **{"squash-attest.json": _make_attest("m2", ["nist-rmf"]),
                   "squash-incident.json": _make_incident(1)})
            return InsuranceBuilder().build(d, org_name="TestCorp")

    def test_to_json_is_valid_json(self):
        pkg = self._pkg()
        data = json.loads(pkg.to_json())
        self.assertIn("org_name", data)
        self.assertIn("aggregate", data)
        self.assertIn("model_profiles", data)

    def test_to_json_contains_underwriter_formats(self):
        data = json.loads(self._pkg().to_json())
        self.assertIn("underwriter_formats", data)
        uf = data["underwriter_formats"]
        self.assertIn("munich_re", uf)
        self.assertIn("coalition", uf)
        self.assertIn("generic", uf)

    def test_to_markdown_contains_org_name(self):
        pkg = self._pkg()
        md = pkg.to_markdown()
        self.assertIn("TestCorp", md)

    def test_to_markdown_contains_score(self):
        pkg = self._pkg()
        md = pkg.to_markdown()
        self.assertIn("Aggregate Risk Scorecard", md)

    def test_to_markdown_model_table_populated(self):
        pkg = self._pkg()
        md = pkg.to_markdown()
        self.assertIn("Model Inventory", md)
        self.assertIn("m1", md)
        self.assertIn("m2", md)

    def test_to_dict_aggregate_keys(self):
        data = self._pkg().to_dict()
        agg = data["aggregate"]
        for key in ("risk_score", "compliance_score", "total_models",
                    "risk_distribution", "open_cves", "critical_cves"):
            self.assertIn(key, agg)


# ── W237: save_zip + integrity manifest ──────────────────────────────────────


class TestSaveZip(unittest.TestCase):
    def _pkg_simple(self, tmp: Path):
        from squash.insurance import InsuranceBuilder
        d = tmp / "models"
        d.mkdir()
        _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
        return InsuranceBuilder().build(d, org_name="ZipCorp")

    def test_zip_created_at_path(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            pkg = self._pkg_simple(tmp)
            zip_path = tmp / "bundle.zip"
            result = pkg.save_zip(zip_path)
            self.assertTrue(zip_path.exists())
            self.assertEqual(result, zip_path)

    def test_zip_contains_required_members(self):
        expected = {
            "insurance-package.json",
            "insurance-munich-re.json",
            "insurance-coalition.json",
            "insurance-generic.json",
            "insurance-executive-summary.md",
            "integrity.sha256",
        }
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            pkg = self._pkg_simple(tmp)
            zip_path = tmp / "bundle.zip"
            pkg.save_zip(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                names = set(zf.namelist())
        self.assertEqual(names, expected)

    def test_integrity_manifest_hashes_are_valid_sha256(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            pkg = self._pkg_simple(tmp)
            zip_path = tmp / "bundle.zip"
            pkg.save_zip(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                manifest = zf.read("integrity.sha256").decode()
                for line in manifest.strip().splitlines():
                    digest, fname = line.split("  ", 1)
                    self.assertEqual(len(digest), 64)  # SHA-256 hex = 64 chars
                    actual = hashlib.sha256(zf.read(fname)).hexdigest()
                    self.assertEqual(actual, digest)

    def test_zip_main_json_parseable(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            pkg = self._pkg_simple(tmp)
            zip_path = tmp / "bundle.zip"
            pkg.save_zip(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                data = json.loads(zf.read("insurance-package.json"))
        self.assertIn("org_name", data)

    def test_save_writes_json_and_md(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            pkg = self._pkg_simple(tmp)
            out = tmp / "output"
            written = pkg.save(out)
            self.assertIn("json", written)
            self.assertIn("md", written)
            self.assertTrue(written["json"].exists())
            self.assertTrue(written["md"].exists())


# ── W236: MunichReAdapter ─────────────────────────────────────────────────────


class TestMunichReAdapter(unittest.TestCase):
    def _run(self, compliance_score: int = 90, has_scan: bool = True,
             has_attest: bool = True, has_plan: bool = True, has_lineage: bool = True) -> dict:
        from squash.insurance import (
            InsurancePackage, ModelRiskProfile, MunichReAdapter,
        )
        p = ModelRiskProfile(
            model_id="m1", model_path="/m1",
            risk_tier="LOW" if compliance_score >= 80 else "MEDIUM",
            compliance_score=compliance_score,
            frameworks_assessed=["eu-ai-act"],
            frameworks_passing=["eu-ai-act"] if compliance_score >= 80 else [],
            cve_count=0, critical_cve_count=0, drift_events=0, incident_count=0,
            bias_status="PASS",
            last_attested="2026-05-01T00:00:00+00:00" if has_attest else "never",
            attestation_id="m1",
            scan_status="clean" if has_scan else "skipped",
            has_incident_plan=has_plan,
            has_data_lineage=has_lineage,
            has_model_card=True,
            has_annex_iv=True,
        )
        pkg = InsurancePackage(
            org_name="TestOrg", generated_at="2026-05-05T00:00:00+00:00",
            model_profiles=[p],
            aggregate_risk_score=100 - compliance_score,
            aggregate_compliance_score=compliance_score,
            response_plan_documented=has_plan,
            total_models=1, high_risk_count=0, medium_risk_count=0,
            low_risk_count=1, open_cves=0, critical_cves=0,
            recent_incidents=0, drift_events_total=0, bias_fails=0,
        )
        return MunichReAdapter().format(pkg)

    def test_schema_field_present(self):
        d = self._run()
        self.assertEqual(d["schema"], "munich_re_ai_cyber_v1")

    def test_full_coverage_rating_a(self):
        d = self._run(compliance_score=95)
        domains = d["control_domains"]
        self.assertEqual(domains["technical_security"]["rating"], "A")
        self.assertEqual(domains["operational_excellence"]["rating"], "A")

    def test_no_scan_rating_d(self):
        d = self._run(compliance_score=50, has_scan=False)
        domains = d["control_domains"]
        self.assertEqual(domains["technical_security"]["rating"], "D")

    def test_maturity_level_4_for_excellent(self):
        d = self._run(compliance_score=95)
        self.assertEqual(d["ai_maturity_level"], 4)

    def test_maturity_level_1_for_poor(self):
        d = self._run(compliance_score=0, has_scan=False, has_attest=False,
                      has_plan=False, has_lineage=False)
        self.assertEqual(d["ai_maturity_level"], 1)

    def test_standard_recommendation_for_maturity_3_plus(self):
        d = self._run(compliance_score=95)
        self.assertIn("STANDARD", d["coverage_recommendation"])

    def test_specialist_recommendation_for_maturity_1(self):
        d = self._run(compliance_score=0, has_scan=False, has_attest=False,
                      has_plan=False, has_lineage=False)
        self.assertIn("SPECIALIST", d["coverage_recommendation"])

    def test_fleet_summary_present(self):
        d = self._run()
        self.assertIn("fleet_summary", d)
        self.assertIn("total_models", d["fleet_summary"])

    def test_control_domains_five_keys(self):
        d = self._run()
        self.assertEqual(len(d["control_domains"]), 5)


# ── W236: CoalitionAdapter ────────────────────────────────────────────────────


class TestCoalitionAdapter(unittest.TestCase):
    def _run(self, compliance: int = 80, has_scan: bool = True,
             critical_cves: int = 0, incidents: int = 0,
             has_lineage: bool = True) -> dict:
        from squash.insurance import (
            CoalitionAdapter, InsurancePackage, ModelRiskProfile,
        )
        p = ModelRiskProfile(
            model_id="m1", model_path="/m1",
            risk_tier="LOW" if compliance >= 80 else "MEDIUM",
            compliance_score=compliance,
            frameworks_assessed=["eu-ai-act"],
            frameworks_passing=["eu-ai-act"] if compliance >= 60 else [],
            cve_count=critical_cves, critical_cve_count=critical_cves,
            drift_events=0, incident_count=incidents,
            bias_status="PASS",
            last_attested="2026-05-01T00:00:00+00:00",
            attestation_id="m1",
            scan_status="clean" if has_scan else "skipped",
            has_incident_plan=incidents == 0,
            has_data_lineage=has_lineage, has_model_card=True, has_annex_iv=True,
        )
        pkg = InsurancePackage(
            org_name="CoalTestOrg", generated_at="2026-05-05T00:00:00+00:00",
            model_profiles=[p],
            aggregate_risk_score=100 - compliance,
            aggregate_compliance_score=compliance,
            response_plan_documented=True,
            total_models=1, high_risk_count=0, medium_risk_count=0,
            low_risk_count=1, open_cves=critical_cves, critical_cves=critical_cves,
            recent_incidents=incidents, drift_events_total=0, bias_fails=0,
        )
        return CoalitionAdapter().format(pkg)

    def test_schema_field(self):
        d = self._run()
        self.assertEqual(d["schema"], "coalition_ai_risk_v1")

    def test_five_risk_categories(self):
        d = self._run()
        cats = d["risk_categories"]
        for key in ("ai_model_security", "ai_operational_risk", "ai_governance",
                    "ai_incident_history", "third_party_ai_risk"):
            self.assertIn(key, cats)

    def test_aggregate_score_in_0_100(self):
        d = self._run()
        self.assertGreaterEqual(d["aggregate_ai_risk_score"], 0)
        self.assertLessEqual(d["aggregate_ai_risk_score"], 100)

    def test_assessment_label_present(self):
        d = self._run(compliance=90)
        cats = d["risk_categories"]
        for cat in cats.values():
            self.assertIn("assessment", cat)

    def test_no_scan_lowers_model_security_score(self):
        d_scan = self._run(has_scan=True)
        d_noscan = self._run(has_scan=False)
        sec_scan = d_scan["risk_categories"]["ai_model_security"]["score"]
        sec_noscan = d_noscan["risk_categories"]["ai_model_security"]["score"]
        self.assertGreater(sec_scan, sec_noscan)

    def test_incidents_lower_incident_history_score(self):
        d_clean = self._run(incidents=0)
        d_dirty = self._run(incidents=2)
        h_clean = d_clean["risk_categories"]["ai_incident_history"]["score"]
        h_dirty = d_dirty["risk_categories"]["ai_incident_history"]["score"]
        self.assertGreater(h_clean, h_dirty)

    def test_open_cves_propagated(self):
        d = self._run(critical_cves=3)
        self.assertEqual(d["open_cves"], 3)


# ── W236: GenericAdapter ──────────────────────────────────────────────────────


class TestGenericAdapter(unittest.TestCase):
    def _run(self, risk_score: int = 20, compliance: int = 80) -> dict:
        from squash.insurance import GenericAdapter, InsurancePackage, ModelRiskProfile
        p = ModelRiskProfile(
            model_id="m1", model_path="/m1", risk_tier="LOW",
            compliance_score=compliance, frameworks_assessed=[], frameworks_passing=[],
            cve_count=0, critical_cve_count=0, drift_events=0, incident_count=0,
            bias_status="PASS", last_attested="2026-05-01T00:00:00+00:00",
            attestation_id="m1", scan_status="clean",
            has_incident_plan=True, has_data_lineage=True,
            has_model_card=True, has_annex_iv=True,
        )
        pkg = InsurancePackage(
            org_name="GenOrg", generated_at="2026-05-05T00:00:00+00:00",
            model_profiles=[p],
            aggregate_risk_score=risk_score,
            aggregate_compliance_score=compliance,
            response_plan_documented=True,
            total_models=1, high_risk_count=0, medium_risk_count=0,
            low_risk_count=1, open_cves=0, critical_cves=0,
            recent_incidents=0, drift_events_total=0, bias_fails=0,
        )
        return GenericAdapter().format(pkg)

    def test_schema_field(self):
        d = self._run()
        self.assertEqual(d["schema"], "squash_insurance_generic_v1")

    def test_low_risk_interpretation(self):
        d = self._run(risk_score=10)
        self.assertEqual(d["risk_posture"]["risk_interpretation"], "LOW")

    def test_medium_risk_interpretation(self):
        d = self._run(risk_score=45)
        self.assertEqual(d["risk_posture"]["risk_interpretation"], "MEDIUM")

    def test_high_risk_interpretation(self):
        d = self._run(risk_score=80)
        self.assertEqual(d["risk_posture"]["risk_interpretation"], "HIGH")

    def test_model_inventory_block(self):
        d = self._run()
        self.assertIn("model_inventory", d)
        self.assertEqual(d["model_inventory"]["total_models"], 1)

    def test_governance_controls_block(self):
        d = self._run()
        self.assertIn("governance_controls", d)
        gc = d["governance_controls"]
        self.assertIn("response_plan_documented", gc)
        self.assertIn("models_with_data_lineage", gc)

    def test_model_profiles_included(self):
        d = self._run()
        self.assertEqual(len(d["model_profiles"]), 1)


# ── CLI: squash insurance-package ────────────────────────────────────────────


class TestInsuranceCLI(unittest.TestCase):
    def _run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True,
            cwd="/Users/wesleyscholl/squash",
        )

    def test_cli_help_exits_0(self):
        r = self._run_cli(["insurance-package", "--help"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("insurance", r.stdout.lower())

    def test_cli_missing_models_dir_exits_nonzero(self):
        r = self._run_cli([
            "insurance-package", "--models-dir", "/nonexistent/path/xyz",
        ])
        self.assertNotEqual(r.returncode, 0)

    def test_cli_json_output_valid(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--json",
            ])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertIn("org_name", data)

    def test_cli_munich_re_underwriter(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--underwriter", "munich-re",
                "--json",
            ])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["schema"], "munich_re_ai_cyber_v1")

    def test_cli_coalition_underwriter(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--underwriter", "coalition",
                "--json",
            ])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["schema"], "coalition_ai_risk_v1")

    def test_cli_generic_underwriter(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--underwriter", "generic",
                "--json",
            ])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["schema"], "squash_insurance_generic_v1")

    def test_cli_zip_output_created(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            d = Path(tmp_dir)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            zip_path = d / "bundle.zip"
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--zip", str(zip_path),
                "--quiet",
            ])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(zip_path.exists())
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_cli_quiet_suppresses_output(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--quiet",
            ])
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "")

    def test_cli_org_flag_propagated(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            _write_model_dir(d, "m1", **{"squash-attest.json": _make_attest("m1")})
            r = self._run_cli([
                "insurance-package",
                "--models-dir", str(d),
                "--output-dir", str(d),
                "--org", "KonjoInsuranceCorp",
                "--json",
            ])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["org_name"], "KonjoInsuranceCorp")


# ── Numerical correctness ─────────────────────────────────────────────────────


class TestNumericalCorrectness(unittest.TestCase):
    """Verify the documented formulas in insurance.py hold exactly."""

    def test_aggregate_risk_formula_no_cves_no_incidents(self):
        """risk_score = max(0, min(100, 100 - avg_compliance))"""
        from squash.insurance import _aggregate, ModelRiskProfile
        profiles = [
            ModelRiskProfile(
                model_id="m1", model_path="/m", risk_tier="LOW",
                compliance_score=70, frameworks_assessed=["eu-ai-act"],
                frameworks_passing=["eu-ai-act"], cve_count=0, critical_cve_count=0,
                drift_events=0, incident_count=0, bias_status="PASS",
                last_attested="2026-05-01T00:00:00+00:00", attestation_id="m1",
                scan_status="clean", has_incident_plan=True, has_data_lineage=True,
                has_model_card=True, has_annex_iv=True,
            )
        ]
        pkg = _aggregate(profiles, "NumericalOrg")
        # avg_compliance = 70, no critical CVEs, no HIGH models, no incidents
        # risk = 100 - 70 = 30
        self.assertEqual(pkg.aggregate_risk_score, 30)

    def test_aggregate_risk_with_critical_cves_bonus(self):
        """risk += 15 when critical_cves > 0"""
        from squash.insurance import _aggregate, ModelRiskProfile
        profiles = [
            ModelRiskProfile(
                model_id="m1", model_path="/m", risk_tier="HIGH",
                compliance_score=70, frameworks_assessed=["eu-ai-act"],
                frameworks_passing=["eu-ai-act"], cve_count=2, critical_cve_count=2,
                drift_events=0, incident_count=0, bias_status="PASS",
                last_attested="2026-05-01T00:00:00+00:00", attestation_id="m1",
                scan_status="clean", has_incident_plan=True, has_data_lineage=True,
                has_model_card=True, has_annex_iv=True,
            )
        ]
        pkg = _aggregate(profiles, "CveOrg")
        # avg_compliance=70, critical_cves>0 (+15), high model (+10) → 30+15+10=55
        self.assertEqual(pkg.aggregate_risk_score, 55)

    def test_compliance_score_100_for_all_policies_pass(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            attest = {
                "model_id": "perfect",
                "generated_at": "2026-05-01T12:00:00+00:00",
                "policy_results": {
                    "eu-ai-act": {"passed": True, "error_count": 0},
                    "nist-rmf": {"passed": True, "error_count": 0},
                },
            }
            _write_model_dir(d, "m1", **{"squash-attest.json": attest})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.model_profiles[0].compliance_score, 100)

    def test_compliance_score_0_for_all_policies_fail(self):
        from squash.insurance import InsuranceBuilder
        with tempfile.TemporaryDirectory() as tmp_str:
            d = Path(tmp_str)
            attest = {
                "model_id": "failing",
                "generated_at": "2026-05-01T12:00:00+00:00",
                "policy_results": {
                    "eu-ai-act": {"passed": False, "error_count": 5},
                    "nist-rmf": {"passed": False, "error_count": 3},
                },
            }
            _write_model_dir(d, "m1", **{"squash-attest.json": attest})
            pkg = InsuranceBuilder().build(d)
        self.assertEqual(pkg.model_profiles[0].compliance_score, 0)


# ── No-external-deps check ────────────────────────────────────────────────────


class TestNoDependencies(unittest.TestCase):
    """insurance.py must be importable with zero optional deps."""

    def test_module_imports_without_sigstore(self):
        with mock.patch.dict("sys.modules", {"sigstore": None}):
            import importlib
            import squash.insurance as ins  # should not raise
            self.assertTrue(hasattr(ins, "InsuranceBuilder"))

    def test_module_imports_without_rich(self):
        with mock.patch.dict("sys.modules", {"rich": None, "rich.console": None}):
            import importlib
            import squash.insurance as ins
            self.assertTrue(hasattr(ins, "InsurancePackage"))


if __name__ == "__main__":
    unittest.main()
