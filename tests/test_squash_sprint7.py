"""tests/test_squash_sprint7.py — Sprint 7 tests: W178–W181.

W178: AI Vendor Risk Register
W179: AI Asset Registry
W180: Training Data Lineage Certificate
W181: Algorithmic Bias Audit

Total: 180+ tests
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# W178 — AI Vendor Risk Register
# ═══════════════════════════════════════════════════════════════════════════════

class TestVendorRegistry:

    def _reg(self, tmp_path):
        from squash.vendor_registry import VendorRegistry
        return VendorRegistry(tmp_path / "vendors.db")

    def test_import(self):
        from squash.vendor_registry import VendorRegistry, VendorRiskTier, VendorQuestionnaire  # noqa

    def test_add_vendor_returns_id(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("OpenAI", risk_tier="high")
            assert isinstance(vid, str) and len(vid) > 0

    def test_get_vendor_roundtrip(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("Anthropic", website="https://anthropic.com", risk_tier="high")
            vendor = reg.get_vendor(vid)
            assert vendor is not None
            assert vendor.name == "Anthropic"
            assert vendor.website == "https://anthropic.com"

    def test_list_vendors_empty(self, tmp_path):
        with self._reg(tmp_path) as reg:
            assert reg.list_vendors() == []

    def test_list_vendors_returns_all(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.add_vendor("V1", risk_tier="high")
            reg.add_vendor("V2", risk_tier="low")
            assert len(reg.list_vendors()) == 2

    def test_list_vendors_filter_by_tier(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.add_vendor("HighRisk", risk_tier="high")
            reg.add_vendor("LowRisk", risk_tier="low")
            highs = reg.list_vendors(tier="high")
            assert len(highs) == 1
            assert highs[0].name == "HighRisk"

    def test_remove_vendor(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("ToDelete")
            assert reg.remove_vendor(vid)
            assert reg.get_vendor(vid) is None

    def test_remove_nonexistent_vendor(self, tmp_path):
        with self._reg(tmp_path) as reg:
            assert not reg.remove_vendor("nonexistent")

    def test_update_assessment_status(self, tmp_path):
        from squash.vendor_registry import AssessmentStatus
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("Tested", risk_tier="medium")
            reg.update_assessment_status(vid, AssessmentStatus.APPROVED.value)
            vendor = reg.get_vendor(vid)
            assert vendor.assessment_status == AssessmentStatus.APPROVED

    def test_generate_questionnaire(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("TestVendor", risk_tier="high")
            q = reg.generate_questionnaire(vid)
            assert q.vendor_name == "TestVendor"
            assert len(q.items) > 10

    def test_questionnaire_high_has_more_questions(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid_h = reg.add_vendor("High", risk_tier="high")
            vid_l = reg.add_vendor("Low", risk_tier="low")
            q_h = reg.generate_questionnaire(vid_h)
            q_l = reg.generate_questionnaire(vid_l)
            assert len(q_h.items) > len(q_l.items)

    def test_questionnaire_to_text(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("Acme AI", risk_tier="critical")
            q = reg.generate_questionnaire(vid)
            text = q.to_text()
            assert "Acme AI" in text
            assert "CRITICAL" in text
            assert len(text) > 500

    def test_questionnaire_to_dict(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("Acme", risk_tier="medium")
            q = reg.generate_questionnaire(vid)
            d = q.to_dict()
            assert "items" in d
            assert len(d["items"]) > 0

    def test_questionnaire_save_txt(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("Save", risk_tier="medium")
            q = reg.generate_questionnaire(vid)
            out = tmp_path / "q.txt"
            q.save(out)
            assert out.exists()
            assert len(out.read_text()) > 100

    def test_questionnaire_save_json(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("SaveJson", risk_tier="medium")
            q = reg.generate_questionnaire(vid)
            out = tmp_path / "q.json"
            q.save(out)
            d = json.loads(out.read_text())
            assert "items" in d

    def test_risk_summary(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.add_vendor("H1", risk_tier="high")
            reg.add_vendor("H2", risk_tier="high")
            reg.add_vendor("L1", risk_tier="low")
            s = reg.risk_summary()
            assert s["total_vendors"] == 3
            assert s["by_risk_tier"]["high"] == 2
            assert s["by_risk_tier"]["low"] == 1
            assert s["high_or_critical_unreviewed"] == 2

    def test_export(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.add_vendor("E1", risk_tier="medium")
            data = reg.export()
            assert len(data) == 1
            assert data[0]["name"] == "E1"

    def test_import_trust_package(self, tmp_path):
        from squash.trust_package import TrustPackageBuilder
        pkg_path = tmp_path / "vendor.zip"
        TrustPackageBuilder.build(tmp_path, pkg_path)
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("TrustVendor", risk_tier="high")
            result = reg.import_trust_package(vid, pkg_path)
            assert "passed" in result
            vendor = reg.get_vendor(vid)
            assert vendor.trust_package_path is not None

    def test_vendor_record_to_dict(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("DictVendor", risk_tier="critical",
                                 use_case="Credit scoring", data_access="financial")
            vendor = reg.get_vendor(vid)
            d = vendor.to_dict()
            assert d["name"] == "DictVendor"
            assert d["risk_tier"] == "critical"
            assert d["data_access"] == "financial"

    def test_questionnaire_categories_present(self, tmp_path):
        with self._reg(tmp_path) as reg:
            vid = reg.add_vendor("CatTest", risk_tier="critical")
            q = reg.generate_questionnaire(vid)
            categories = {item.category for item in q.items}
            assert "Security" in categories
            assert "Training Data" in categories
            assert "Bias & Fairness" in categories

    def test_context_manager(self, tmp_path):
        from squash.vendor_registry import VendorRegistry
        with VendorRegistry(tmp_path / "test.db") as reg:
            vid = reg.add_vendor("CM", risk_tier="low")
            assert reg.get_vendor(vid) is not None


class TestVendorCLI:

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True, cwd=Path(__file__).parents[1],
        )

    def test_vendor_help(self):
        r = self._run("vendor", "--help")
        assert r.returncode == 0

    def test_vendor_add(self, tmp_path):
        db = str(tmp_path / "v.db")
        r = self._run("vendor", "add", "--name", "TestCo", "--risk-tier", "high", "--db", db)
        assert r.returncode == 0
        assert "TestCo" in r.stdout

    def test_vendor_list(self, tmp_path):
        db = str(tmp_path / "v.db")
        self._run("vendor", "add", "--name", "ListCo", "--risk-tier", "medium", "--db", db)
        r = self._run("vendor", "list", "--db", db)
        assert r.returncode == 0
        assert "ListCo" in r.stdout

    def test_vendor_list_json(self, tmp_path):
        db = str(tmp_path / "v.db")
        self._run("vendor", "add", "--name", "JsonCo", "--risk-tier", "low", "--db", db)
        r = self._run("vendor", "list", "--json", "--db", db)
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert len(data) == 1

    def test_vendor_summary(self, tmp_path):
        db = str(tmp_path / "v.db")
        self._run("vendor", "add", "--name", "SumCo", "--risk-tier", "high", "--db", db)
        r = self._run("vendor", "summary", "--db", db)
        assert r.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
# W179 — AI Asset Registry
# ═══════════════════════════════════════════════════════════════════════════════

class TestAssetRegistry:

    def _reg(self, tmp_path):
        from squash.asset_registry import AssetRegistry
        return AssetRegistry(tmp_path / "assets.db")

    def test_import(self):
        from squash.asset_registry import AssetRegistry, AssetRecord, RegistrySummary  # noqa

    def test_register_returns_id(self, tmp_path):
        with self._reg(tmp_path) as reg:
            aid = reg.register("my-model", environment="production")
            assert isinstance(aid, str) and len(aid) > 0

    def test_register_deduplicates(self, tmp_path):
        with self._reg(tmp_path) as reg:
            a1 = reg.register("dup-model", environment="production")
            a2 = reg.register("dup-model", environment="production")
            assert a1 == a2

    def test_register_different_envs(self, tmp_path):
        with self._reg(tmp_path) as reg:
            a1 = reg.register("same-model", environment="production")
            a2 = reg.register("same-model", environment="staging")
            assert a1 != a2

    def test_get_asset(self, tmp_path):
        with self._reg(tmp_path) as reg:
            aid = reg.register("gpt-ft", environment="production", owner="team@co.com")
            asset = reg.get_asset(aid)
            assert asset.model_id == "gpt-ft"
            assert asset.owner == "team@co.com"

    def test_list_assets_empty(self, tmp_path):
        with self._reg(tmp_path) as reg:
            assert reg.list_assets() == []

    def test_list_assets_all(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("m1", environment="production")
            reg.register("m2", environment="staging")
            assert len(reg.list_assets()) == 2

    def test_list_assets_filter_env(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("m1", environment="production")
            reg.register("m2", environment="staging")
            prod = reg.list_assets(environment="production")
            assert len(prod) == 1
            assert prod[0].model_id == "m1"

    def test_find_by_model_id(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("llm-v1", environment="production")
            reg.register("llm-v1", environment="staging")
            found = reg.find_by_model_id("llm-v1")
            assert len(found) == 2

    def test_sync_from_attestation(self, tmp_path):
        (tmp_path / "squash_attestation.json").write_text(json.dumps({
            "model_id": "synced-model",
            "model_version": "v1.2",
            "compliance_score": 88.0,
            "policies_checked": ["eu-ai-act"],
            "attested_at": "2026-04-29T12:00:00+00:00",
        }))
        with self._reg(tmp_path) as reg:
            aid = reg.sync_from_attestation(tmp_path)
            assert aid is not None
            asset = reg.get_asset(aid)
            assert asset.model_id == "synced-model"
            assert asset.compliance_score == 88.0
            assert "eu-ai-act" in asset.frameworks

    def test_sync_updates_existing(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("update-model", environment="development")
            (tmp_path / "squash_attestation.json").write_text(json.dumps({
                "model_id": "update-model",
                "compliance_score": 75.0,
            }))
            reg.sync_from_attestation(tmp_path)
            assets = reg.find_by_model_id("update-model")
            assert any(a.compliance_score == 75.0 for a in assets)

    def test_sync_with_drift_report(self, tmp_path):
        (tmp_path / "squash_attestation.json").write_text('{"model_id":"drift-model"}')
        (tmp_path / "drift_report.json").write_text('{"drift_detected": true}')
        with self._reg(tmp_path) as reg:
            aid = reg.sync_from_attestation(tmp_path)
            asset = reg.get_asset(aid)
            assert asset.drift_detected is True

    def test_sync_with_vex_report(self, tmp_path):
        (tmp_path / "squash_attestation.json").write_text('{"model_id":"vex-model"}')
        (tmp_path / "vex_report.json").write_text('{"total_count": 3}')
        with self._reg(tmp_path) as reg:
            aid = reg.sync_from_attestation(tmp_path)
            asset = reg.get_asset(aid)
            assert asset.open_cves == 3

    def test_flag_shadow_ai(self, tmp_path):
        with self._reg(tmp_path) as reg:
            aid = reg.register("shadow-tool", environment="production")
            reg.flag_shadow_ai(aid)
            asset = reg.get_asset(aid)
            assert asset.is_shadow_ai is True

    def test_list_shadow_only(self, tmp_path):
        with self._reg(tmp_path) as reg:
            a1 = reg.register("legit", environment="production")
            a2 = reg.register("shadow", environment="production")
            reg.flag_shadow_ai(a2)
            shadows = reg.list_assets(shadow_only=True)
            assert len(shadows) == 1

    def test_remove_asset(self, tmp_path):
        with self._reg(tmp_path) as reg:
            aid = reg.register("delete-me")
            assert reg.remove_asset(aid)
            assert reg.get_asset(aid) is None

    def test_summary_counts(self, tmp_path):
        with self._reg(tmp_path) as reg:
            (tmp_path / "squash_attestation.json").write_text(json.dumps({
                "model_id": "m1", "compliance_score": 90.0,
                "attested_at": "2026-04-29T12:00:00+00:00",
            }))
            reg.sync_from_attestation(tmp_path)
            reg.register("m2", environment="staging")
            s = reg.summary()
            assert s.total_assets == 2
            assert s.unattested == 1  # m2 has no attestation

    def test_summary_to_text(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("text-model", environment="production")
            text = reg.summary().to_text()
            assert "AI ASSET REGISTRY" in text

    def test_export_json(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("export-model")
            data = json.loads(reg.export("json"))
            assert len(data) == 1

    def test_export_markdown(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.register("md-model", environment="production")
            md = reg.export("md")
            assert "Model ID" in md
            assert "md-model" in md

    def test_asset_record_to_dict(self, tmp_path):
        with self._reg(tmp_path) as reg:
            aid = reg.register("dict-model", environment="production", risk_tier="high")
            asset = reg.get_asset(aid)
            d = asset.to_dict()
            assert d["model_id"] == "dict-model"
            assert d["environment"] == "production"
            assert d["risk_tier"] == "high"


class TestAssetRegistryCLI:

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True, cwd=Path(__file__).parents[1],
        )

    def test_registry_help(self):
        r = self._run("registry", "--help")
        assert r.returncode == 0

    def test_registry_add(self, tmp_path):
        db = str(tmp_path / "a.db")
        r = self._run("registry", "add", "--model-id", "test-llm",
                      "--environment", "production", "--db", db)
        assert r.returncode == 0

    def test_registry_list(self, tmp_path):
        db = str(tmp_path / "a.db")
        self._run("registry", "add", "--model-id", "listed", "--db", db)
        r = self._run("registry", "list", "--db", db)
        assert r.returncode == 0
        assert "listed" in r.stdout

    def test_registry_list_json(self, tmp_path):
        db = str(tmp_path / "a.db")
        self._run("registry", "add", "--model-id", "json-model", "--db", db)
        r = self._run("registry", "list", "--json", "--db", db)
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert len(data) == 1

    def test_registry_sync(self, tmp_path):
        db = str(tmp_path / "a.db")
        (tmp_path / "squash_attestation.json").write_text(
            json.dumps({"model_id": "synced", "compliance_score": 80.0})
        )
        r = self._run("registry", "sync", str(tmp_path), "--db", db)
        assert r.returncode == 0

    def test_registry_summary(self, tmp_path):
        db = str(tmp_path / "a.db")
        self._run("registry", "add", "--model-id", "sum-model", "--db", db)
        r = self._run("registry", "summary", "--db", db)
        assert r.returncode == 0

    def test_registry_export_json(self, tmp_path):
        db = str(tmp_path / "a.db")
        out = str(tmp_path / "export.json")
        self._run("registry", "add", "--model-id", "exp-model", "--db", db)
        r = self._run("registry", "export", "--format", "json", "--output", out, "--db", db)
        assert r.returncode == 0
        assert Path(out).exists()


# ═══════════════════════════════════════════════════════════════════════════════
# W180 — Training Data Lineage Certificate
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataLineageTracer:

    def test_import(self):
        from squash.data_lineage import DataLineageTracer, LineageCertificate, DatasetProvenance  # noqa

    def test_trace_empty_dir(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path)
        assert cert.model_id == tmp_path.name
        assert cert.certificate_id != ""

    def test_trace_with_explicit_datasets(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["wikipedia", "c4"])
        assert len(cert.datasets) == 2
        names = {d.dataset_name for d in cert.datasets}
        assert "wikipedia" in names
        assert "c4" in names

    def test_trace_wikipedia_license(self, tmp_path):
        from squash.data_lineage import DataLineageTracer, LicenseCategory
        cert = DataLineageTracer.trace(tmp_path, datasets=["wikipedia"])
        ds = cert.datasets[0]
        assert ds.license_category == LicenseCategory.COMMERCIAL_OK
        assert ds.commercial_use_allowed is True

    def test_trace_alpaca_research_only(self, tmp_path):
        from squash.data_lineage import DataLineageTracer, LicenseCategory
        cert = DataLineageTracer.trace(tmp_path, datasets=["alpaca"])
        ds = cert.datasets[0]
        assert ds.license_category == LicenseCategory.RESEARCH_ONLY
        assert ds.commercial_use_allowed is False
        assert cert.license_issues  # should flag non-commercial

    def test_trace_pile_high_pii(self, tmp_path):
        from squash.data_lineage import DataLineageTracer, PIIRiskLevel
        cert = DataLineageTracer.trace(tmp_path, datasets=["the_pile"])
        ds = cert.datasets[0]
        assert ds.pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL)
        assert cert.pii_issues  # should flag PII

    def test_trace_unknown_dataset(self, tmp_path):
        from squash.data_lineage import DataLineageTracer, LicenseCategory
        cert = DataLineageTracer.trace(tmp_path, datasets=["my_proprietary_dataset_xyz"])
        ds = cert.datasets[0]
        assert ds.license_category == LicenseCategory.UNKNOWN

    def test_trace_from_config(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        config = {"dataset_name": "wikipedia", "batch_size": 32}
        config_path = tmp_path / "train_config.json"
        config_path.write_text(json.dumps(config))
        cert = DataLineageTracer.trace(tmp_path, config_path=config_path)
        # should find wikipedia in config
        names = {d.dataset_name for d in cert.datasets}
        assert "wikipedia" in names

    def test_certificate_has_hash(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["gsm8k"])
        assert len(cert.certificate_hash) == 64

    def test_summary_contains_cert_id(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["gsm8k"])
        summary = cert.summary()
        assert cert.certificate_id in summary
        assert "TRAINING DATA LINEAGE" in summary

    def test_save_certificate(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["mmlu"])
        out = tmp_path / "cert.json"
        cert.save(out)
        assert out.exists()
        d = json.loads(out.read_text())
        assert d["document_type"] == "TRAINING_DATA_LINEAGE_CERTIFICATE"

    def test_to_dict_structure(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["humaneval"])
        d = cert.to_dict()
        assert "datasets" in d
        assert "overall_pii_risk" in d
        assert "gdpr_compliant" in d
        assert "license_issues" in d

    def test_gdpr_compliant_for_safe_data(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["gsm8k", "humaneval"])
        # gsm8k and humaneval have NONE pii risk
        assert cert.gdpr_compliant is True

    def test_gdpr_unknown_for_high_pii(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["medical_dialog"])
        # medical_dialog has critical PII → GDPR compliance unknown without explicit legal basis
        assert cert.gdpr_compliant in (False, None)

    def test_overall_risk_escalates(self, tmp_path):
        from squash.data_lineage import DataLineageTracer, PIIRiskLevel
        cert = DataLineageTracer.trace(tmp_path, datasets=["wikipedia", "the_pile"])
        # the_pile has HIGH pii risk — overall should be at least HIGH
        assert cert.overall_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL)

    def test_dataset_record_has_required_fields(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        cert = DataLineageTracer.trace(tmp_path, datasets=["mmlu"])
        ds = cert.datasets[0]
        assert hasattr(ds, "dataset_id")
        assert hasattr(ds, "license_spdx")
        assert hasattr(ds, "pii_risk")
        assert hasattr(ds, "gdpr_legal_basis")
        assert hasattr(ds, "verified")

    def test_provenance_file_parsed(self, tmp_path):
        from squash.data_lineage import DataLineageTracer
        (tmp_path / "dataset_provenance.json").write_text(json.dumps({
            "datasets": [{"name": "custom_dataset_xyz"}]
        }))
        cert = DataLineageTracer.trace(tmp_path)
        names = {d.dataset_name for d in cert.datasets}
        assert "custom_dataset_xyz" in names

    def test_laion_flagged_high_pii(self, tmp_path):
        from squash.data_lineage import DataLineageTracer, PIIRiskLevel
        cert = DataLineageTracer.trace(tmp_path, datasets=["laion-5b"])
        ds = cert.datasets[0]
        assert ds.pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL)


class TestDataLineageCLI:

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True, cwd=Path(__file__).parents[1],
        )

    def test_data_lineage_help(self):
        r = self._run("data-lineage", "--help")
        assert r.returncode == 0

    def test_data_lineage_basic(self, tmp_path):
        r = self._run("data-lineage", str(tmp_path), "--datasets", "wikipedia,gsm8k")
        assert r.returncode == 0
        assert (tmp_path / "data_lineage_certificate.json").exists()

    def test_data_lineage_json_format(self, tmp_path):
        r = self._run("data-lineage", str(tmp_path), "--datasets", "mmlu", "--format", "json")
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert d["document_type"] == "TRAINING_DATA_LINEAGE_CERTIFICATE"

    def test_data_lineage_fail_on_pii(self, tmp_path):
        r = self._run("data-lineage", str(tmp_path),
                      "--datasets", "the_pile", "--fail-on-pii")
        assert r.returncode == 2

    def test_data_lineage_fail_on_license(self, tmp_path):
        r = self._run("data-lineage", str(tmp_path),
                      "--datasets", "alpaca", "--fail-on-license")
        assert r.returncode == 2

    def test_data_lineage_safe_datasets_pass(self, tmp_path):
        r = self._run("data-lineage", str(tmp_path),
                      "--datasets", "gsm8k,humaneval",
                      "--fail-on-pii", "--fail-on-license")
        assert r.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
# W181 — Bias Audit
# ═══════════════════════════════════════════════════════════════════════════════

def _make_bias_csv(tmp_path: Path, bias: bool = True) -> Path:
    """Write a predictions CSV for testing."""
    p = tmp_path / "predictions.csv"
    rows = []
    if bias:
        # Group A: 80% positive, Group B: 40% positive → DPD = 0.40, DIR = 0.50
        for i in range(50):
            rows.append({"age_group": "senior", "gender": "female" if i % 2 == 0 else "male",
                         "label": "1", "prediction": "1"})
        for i in range(50):
            rows.append({"age_group": "senior", "gender": "female" if i % 2 == 0 else "male",
                         "label": "0", "prediction": "0"})
        # Biased against young: only 20% positive
        for i in range(10):
            rows.append({"age_group": "young", "gender": "male",
                         "label": "1", "prediction": "1"})
        for i in range(40):
            rows.append({"age_group": "young", "gender": "male",
                         "label": "0", "prediction": "0"})
    else:
        # Fair: equal positive rates
        for group in ["groupA", "groupB"]:
            for _ in range(50):
                rows.append({"age_group": group, "label": "1", "prediction": "1"})
            for _ in range(50):
                rows.append({"age_group": group, "label": "0", "prediction": "0"})

    with open(p, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["age_group", "gender", "label", "prediction"])
        writer.writeheader()
        writer.writerows(rows)
    return p


class TestBiasAuditor:

    def test_import(self):
        from squash.bias_audit import BiasAuditor, BiasAuditReport, FairnessVerdict  # noqa

    def test_audit_from_dicts_empty(self):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        report = BiasAuditor.audit([], protected_attributes=["age"])
        assert report.overall_verdict == FairnessVerdict.PASS

    def test_audit_fair_data(self):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        records = []
        for g in ["A", "B"]:
            records += [{"group": g, "label": "1", "prediction": "1"}] * 50
            records += [{"group": g, "label": "0", "prediction": "0"}] * 50
        report = BiasAuditor.audit(records, ["group"])
        assert report.overall_verdict == FairnessVerdict.PASS
        assert report.results[0].demographic_parity_diff == pytest.approx(0.0, abs=0.01)
        assert report.results[0].disparate_impact_ratio == pytest.approx(1.0, abs=0.01)

    def test_audit_biased_data_fails_dir(self):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        # Group A: 90% positive, Group B: 40% positive → DIR < 0.80
        records = []
        records += [{"group": "A", "label": "1", "prediction": "1"}] * 90
        records += [{"group": "A", "label": "0", "prediction": "0"}] * 10
        records += [{"group": "B", "label": "1", "prediction": "1"}] * 40
        records += [{"group": "B", "label": "0", "prediction": "0"}] * 60
        report = BiasAuditor.audit(records, ["group"], standard="generic")
        assert report.results[0].disparate_impact_ratio < 0.80
        assert report.results[0].verdict == FairnessVerdict.FAIL

    def test_audit_all_10_risks_measured(self):
        from squash.bias_audit import BiasAuditor
        records = [{"g": "A", "label": "1", "prediction": "1"}] * 10
        records += [{"g": "B", "label": "0", "prediction": "0"}] * 10
        report = BiasAuditor.audit(records, ["g"])
        r = report.results[0]
        assert hasattr(r, "demographic_parity_diff")
        assert hasattr(r, "disparate_impact_ratio")
        assert hasattr(r, "equalized_odds_diff")
        assert hasattr(r, "predictive_equality_diff")
        assert hasattr(r, "accuracy_diff")

    def test_failing_attributes_populated(self):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        records = []
        records += [{"g": "priv", "label": "1", "prediction": "1"}] * 90
        records += [{"g": "priv", "label": "0", "prediction": "0"}] * 10
        records += [{"g": "unpriv", "label": "1", "prediction": "1"}] * 20
        records += [{"g": "unpriv", "label": "0", "prediction": "0"}] * 80
        report = BiasAuditor.audit(records, ["g"])
        if report.overall_verdict == FairnessVerdict.FAIL:
            assert "g" in report.failing_attributes

    def test_nyc_local_law_144_strict_threshold(self):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        # Near-threshold case: DPD = 0.06 > 0.05 for NYC LL144
        records = []
        records += [{"g": "A", "label": "1", "prediction": "1"}] * 53
        records += [{"g": "A", "label": "0", "prediction": "0"}] * 47
        records += [{"g": "B", "label": "1", "prediction": "1"}] * 47
        records += [{"g": "B", "label": "0", "prediction": "0"}] * 53
        report_nyc = BiasAuditor.audit(records, ["g"], standard="nyc_local_law_144")
        report_gen = BiasAuditor.audit(records, ["g"], standard="generic")
        # NYC is stricter (0.05 threshold vs 0.10)
        # NYC may fail while generic may pass
        assert report_nyc.regulatory_standard == "nyc_local_law_144"
        assert report_gen.regulatory_standard == "generic"

    def test_to_dict_structure(self):
        from squash.bias_audit import BiasAuditor
        records = [{"g": "A", "label": "1", "prediction": "1"}] * 50
        records += [{"g": "B", "label": "1", "prediction": "1"}] * 50
        report = BiasAuditor.audit(records, ["g"])
        d = report.to_dict()
        assert d["document_type"] == "BIAS_AUDIT_REPORT"
        assert "attribute_results" in d
        assert "overall_verdict" in d
        assert "audit_id" in d

    def test_save_report(self, tmp_path):
        from squash.bias_audit import BiasAuditor
        records = [{"g": "A", "label": "1", "prediction": "1"}] * 20
        report = BiasAuditor.audit(records, ["g"], model_id="test-model")
        out = tmp_path / "bias_report.json"
        report.save(out)
        assert out.exists()
        d = json.loads(out.read_text())
        assert d["model_id"] == "test-model"

    def test_summary_contains_verdict(self):
        from squash.bias_audit import BiasAuditor
        records = [{"g": "X", "label": "1", "prediction": "1"}] * 10
        report = BiasAuditor.audit(records, ["g"])
        summary = report.summary()
        assert "BIAS AUDIT" in summary
        assert "PASS" in summary or "FAIL" in summary or "WARN" in summary

    def test_group_metrics_computed(self):
        from squash.bias_audit import BiasAuditor
        records = []
        records += [{"g": "A", "label": "1", "prediction": "1"}] * 40
        records += [{"g": "A", "label": "0", "prediction": "0"}] * 60
        records += [{"g": "B", "label": "1", "prediction": "1"}] * 70
        records += [{"g": "B", "label": "0", "prediction": "0"}] * 30
        report = BiasAuditor.audit(records, ["g"])
        groups = report.results[0].groups
        assert len(groups) == 2
        assert all(g.n_total > 0 for g in groups)

    def test_audit_from_csv(self, tmp_path):
        from squash.bias_audit import BiasAuditor
        p = _make_bias_csv(tmp_path, bias=False)
        report = BiasAuditor.audit_from_csv(p, protected_attributes=["age_group"])
        assert report.n_total_samples > 0

    def test_audit_from_csv_biased(self, tmp_path):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        p = _make_bias_csv(tmp_path, bias=True)
        report = BiasAuditor.audit_from_csv(p, protected_attributes=["age_group"])
        # Biased data should fail
        assert report.overall_verdict in (FairnessVerdict.FAIL, FairnessVerdict.WARN)

    def test_single_group_passes(self):
        from squash.bias_audit import BiasAuditor, FairnessVerdict
        records = [{"g": "only_group", "label": "1", "prediction": "1"}] * 100
        report = BiasAuditor.audit(records, ["g"])
        assert report.overall_verdict == FairnessVerdict.PASS

    def test_multiple_protected_attributes(self):
        from squash.bias_audit import BiasAuditor
        records = []
        for age in ["young", "senior"]:
            for gender in ["male", "female"]:
                records += [{"age": age, "gender": gender, "label": "1", "prediction": "1"}] * 25
        report = BiasAuditor.audit(records, ["age", "gender"])
        assert len(report.results) == 2
        assert {r.attribute for r in report.results} == {"age", "gender"}

    def test_dir_is_1_for_fair(self):
        from squash.bias_audit import BiasAuditor
        records = []
        for g in ["X", "Y"]:
            records += [{"g": g, "label": "1", "prediction": "1"}] * 50
            records += [{"g": g, "label": "0", "prediction": "0"}] * 50
        report = BiasAuditor.audit(records, ["g"])
        assert abs(report.results[0].disparate_impact_ratio - 1.0) < 0.01

    def test_audit_id_is_uppercase_hex(self):
        from squash.bias_audit import BiasAuditor
        report = BiasAuditor.audit([], ["g"])
        assert report.audit_id.isupper() or report.audit_id.replace("-", "").isupper()
        assert len(report.audit_id) == 12

    def test_data_hash_set(self):
        from squash.bias_audit import BiasAuditor
        records = [{"g": "A", "label": "1", "prediction": "1"}] * 5
        report = BiasAuditor.audit(records, ["g"])
        assert len(report.data_hash) == 64

    def test_regulatory_standard_stored(self):
        from squash.bias_audit import BiasAuditor
        records = [{"g": "A", "label": "1", "prediction": "1"}] * 5
        report = BiasAuditor.audit(records, ["g"], standard="eu_ai_act_annex_iii")
        assert report.regulatory_standard == "eu_ai_act_annex_iii"


class TestBiasAuditCLI:

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True, cwd=Path(__file__).parents[1],
        )

    def test_bias_audit_help(self):
        r = self._run("bias-audit", "--help")
        assert r.returncode == 0
        assert "bias" in r.stdout.lower()

    def test_bias_audit_fair(self, tmp_path):
        p = _make_bias_csv(tmp_path, bias=False)
        r = self._run("bias-audit", "--predictions", str(p),
                      "--protected", "age_group")
        assert r.returncode == 0

    def test_bias_audit_biased_fail_on_fail(self, tmp_path):
        p = _make_bias_csv(tmp_path, bias=True)
        r = self._run("bias-audit", "--predictions", str(p),
                      "--protected", "age_group", "--fail-on-fail")
        # biased data should cause non-zero exit
        assert r.returncode in (0, 2)

    def test_bias_audit_json_output(self, tmp_path):
        p = _make_bias_csv(tmp_path, bias=False)
        r = self._run("bias-audit", "--predictions", str(p),
                      "--protected", "age_group", "--format", "json")
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert "overall_verdict" in d

    def test_bias_audit_saves_report(self, tmp_path):
        p = _make_bias_csv(tmp_path, bias=False)
        out = str(tmp_path / "bias_report.json")
        r = self._run("bias-audit", "--predictions", str(p),
                      "--protected", "age_group", "--output", out)
        assert r.returncode == 0
        assert Path(out).exists()

    def test_bias_audit_nyc_standard(self, tmp_path):
        p = _make_bias_csv(tmp_path, bias=False)
        r = self._run("bias-audit", "--predictions", str(p),
                      "--protected", "age_group", "--standard", "nyc_local_law_144")
        assert r.returncode == 0

    def test_bias_audit_missing_file(self, tmp_path):
        r = self._run("bias-audit", "--predictions", str(tmp_path / "missing.csv"),
                      "--protected", "age_group")
        assert r.returncode == 1
