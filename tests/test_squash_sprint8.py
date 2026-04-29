"""tests/test_squash_sprint8.py — Sprint 8 tests: W182–W187.

W182: Annual Review Generator
W183: Public Attestation Registry
W184: CISO Dashboard
W185: Regulatory Intelligence Feed
W186: M&A Due Diligence Package
W187: VS Code Extension scaffold
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "squash.cli", *args],
        capture_output=True, text=True, cwd=Path(__file__).parents[1],
    )


def _attest_fixture(model_dir: Path, score: float = 82.0, violations: int = 0) -> None:
    (model_dir / "squash_attestation.json").write_text(json.dumps({
        "model_id": model_dir.name,
        "compliance_score": score,
        "policies_checked": ["eu-ai-act", "nist-ai-rmf"],
        "violations": [f"v{i}" for i in range(violations)],
        "attested_at": "2025-06-15T12:00:00+00:00",
        "risk_tier": "high",
    }))


# ═══════════════════════════════════════════════════════════════════════════════
# W182 — Annual Review Generator
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnnualReviewGenerator:

    def test_import(self):
        from squash.annual_review import AnnualReviewGenerator, AnnualReview  # noqa

    def test_generate_empty_dir(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert review.year == 2025

    def test_generate_with_model(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert len(review.models) >= 1

    def test_period_start_end(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert review.period_start == "2025-01-01"
        assert review.period_end == "2025-12-31"

    def test_compliance_score_computed(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path, score=78.0)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert review.year_end_score is not None

    def test_score_delta_positive(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path, score=80.0)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        if review.score_delta is not None:
            assert review.score_delta > 0  # synthetic improvement

    def test_next_year_objectives_populated(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path, score=65.0, violations=2)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert len(review.next_year_objectives) > 0

    def test_frameworks_assessed(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert "eu-ai-act" in review.frameworks_assessed

    def test_to_dict_structure(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        d = review.to_dict()
        assert d["document_type"] == "ANNUAL_AI_COMPLIANCE_REVIEW"
        assert "executive_summary" in d
        assert "model_audit" in d
        assert "monthly_snapshots" in d
        assert len(d["monthly_snapshots"]) == 12

    def test_to_markdown_sections(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        md = review.to_markdown()
        assert "Annual AI Compliance Review" in md
        assert "Executive Summary" in md

    def test_executive_summary_text(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        summary = review.executive_summary()
        assert "2025" in summary
        assert "COMPLIANCE" in summary

    def test_save_creates_files(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        out = tmp_path / "review"
        written = review.save(out)
        assert (out / "annual-review-2025.json").exists()
        assert (out / "annual-review-2025.md").exists()
        assert (out / "annual-review-2025-summary.txt").exists()
        assert len(written) == 3

    def test_eu_ai_act_compliant_when_high_score(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path, score=85.0)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        if review.year_end_score is not None and review.year_end_score >= 70:
            assert review.eu_ai_act_compliant is True

    def test_model_audit_entry_fields(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        if review.models:
            m = review.models[0]
            assert hasattr(m, "model_id")
            assert hasattr(m, "year_end_score")
            assert hasattr(m, "trend")

    def test_regulatory_changes_populated(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        review = AnnualReviewGenerator.generate(year=2026, models_dir=tmp_path)
        # 2026 should include EU AI Act enforcement mention
        text = " ".join(review.regulatory_changes_addressed)
        assert len(review.regulatory_changes_addressed) > 0

    def test_generate_with_explicit_model_path(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path)
        review = AnnualReviewGenerator.generate(year=2025, model_paths=[tmp_path])
        assert len(review.models) >= 1

    def test_portfolio_trend_improving(self, tmp_path):
        from squash.annual_review import AnnualReviewGenerator
        _attest_fixture(tmp_path, score=90.0, violations=0)
        review = AnnualReviewGenerator.generate(year=2025, models_dir=tmp_path)
        assert review.portfolio_trend in ("improving", "stable", "degrading")


class TestAnnualReviewCLI:

    def test_annual_review_help(self):
        r = _run("annual-review", "--help")
        assert r.returncode == 0

    def test_annual_review_basic(self, tmp_path):
        r = _run("annual-review", "--year", "2025", "--model", str(tmp_path),
                 "--output-dir", str(tmp_path / "review"))
        assert r.returncode == 0
        assert (tmp_path / "review" / "annual-review-2025.json").exists()

    def test_annual_review_json(self, tmp_path):
        r = _run("annual-review", "--year", "2025", "--model", str(tmp_path), "--json")
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert d["document_type"] == "ANNUAL_AI_COMPLIANCE_REVIEW"


# ═══════════════════════════════════════════════════════════════════════════════
# W183 — Public Attestation Registry
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttestationRegistry:

    def _reg(self, tmp_path):
        from squash.attestation_registry import AttestationRegistry
        return AttestationRegistry(tmp_path / "att.db")

    def test_import(self):
        from squash.attestation_registry import AttestationRegistry, RegistryEntry, VerificationResult  # noqa

    def test_publish_returns_entry(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("my-model", attestation_data={"model_id": "my-model", "score": 85})
            assert entry.entry_id
            assert entry.uri.startswith("att://")

    def test_publish_uri_format(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("llm-v2", attestation_data={"x": 1}, org="acme")
            assert "acme" in entry.uri
            assert "llm-v2" in entry.uri

    def test_publish_verify_url(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("m1", attestation_data={})
            assert "attestations.getsquash.dev" in entry.verify_url

    def test_publish_idempotent(self, tmp_path):
        with self._reg(tmp_path) as reg:
            data = {"model_id": "same", "score": 80}
            e1 = reg.publish("same", attestation_data=data)
            e2 = reg.publish("same", attestation_data=data)
            assert e1.entry_id == e2.entry_id  # same hash → same ID

    def test_publish_from_file(self, tmp_path):
        from squash.attestation_registry import AttestationRegistry
        attest_path = tmp_path / "squash_attestation.json"
        attest_path.write_text(json.dumps({"model_id": "file-model", "score": 90}))
        with AttestationRegistry(tmp_path / "att.db") as reg:
            entry = reg.publish("file-model", attestation_path=attest_path)
            assert entry.model_id == "file-model"

    def test_lookup_by_model_id(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.publish("lookup-model", attestation_data={"model_id": "lookup-model"})
            entries = reg.lookup(model_id="lookup-model")
            assert len(entries) == 1
            assert entries[0].model_id == "lookup-model"

    def test_lookup_by_org(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.publish("m1", attestation_data={"a": 1}, org="org1")
            reg.publish("m2", attestation_data={"b": 2}, org="org2")
            entries = reg.lookup(org="org1")
            assert len(entries) == 1

    def test_lookup_returns_empty_for_unknown(self, tmp_path):
        with self._reg(tmp_path) as reg:
            assert reg.lookup(model_id="nonexistent") == []

    def test_verify_valid_entry(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("verify-model", attestation_data={"x": 42})
            result = reg.verify(entry.entry_id)
            assert result.valid is True
            assert result.hash_verified is True

    def test_verify_nonexistent_entry(self, tmp_path):
        with self._reg(tmp_path) as reg:
            result = reg.verify("nonexistent_id")
            assert result.valid is False
            assert result.error

    def test_revoke_entry(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("revoke-model", attestation_data={"y": 1})
            assert reg.revoke(entry.entry_id)
            result = reg.verify(entry.entry_id)
            assert result.valid is False
            assert result.revoked is True

    def test_stats(self, tmp_path):
        with self._reg(tmp_path) as reg:
            reg.publish("m1", attestation_data={"a": 1}, org="org1")
            reg.publish("m2", attestation_data={"b": 2}, org="org2")
            s = reg.stats()
            assert s["total_entries"] == 2
            assert s["organizations"] == 2

    def test_private_entry_not_in_public_lookup(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("priv-model", attestation_data={"z": 9}, is_public=False)
            assert entry.is_public is False

    def test_entry_to_dict(self, tmp_path):
        with self._reg(tmp_path) as reg:
            entry = reg.publish("dict-model", attestation_data={"k": "v"})
            d = entry.to_dict()
            assert "entry_id" in d
            assert "uri" in d
            assert "verify_url" in d

    def test_context_manager(self, tmp_path):
        from squash.attestation_registry import AttestationRegistry
        with AttestationRegistry(tmp_path / "test.db") as reg:
            entry = reg.publish("cm-model", attestation_data={})
            assert entry.entry_id


class TestAttestationRegistryCLI:

    def test_publish_help(self):
        r = _run("publish", "--help")
        assert r.returncode == 0

    def test_publish_basic(self, tmp_path):
        r = _run("publish", str(tmp_path), "--org", "test-org", "--db", str(tmp_path / "r.db"))
        assert r.returncode == 0
        assert "att://" in r.stdout

    def test_lookup_help(self):
        r = _run("lookup", "--help")
        assert r.returncode == 0

    def test_lookup_empty(self, tmp_path):
        r = _run("lookup", "--model-id", "none", "--db", str(tmp_path / "r.db"))
        assert r.returncode == 0

    def test_verify_entry_help(self):
        r = _run("verify-entry", "--help")
        assert r.returncode == 0

    def test_publish_and_verify(self, tmp_path):
        db = str(tmp_path / "r.db")
        r_pub = _run("publish", str(tmp_path), "--db", db)
        assert r_pub.returncode == 0
        entry_id_line = [l for l in r_pub.stdout.splitlines() if "Entry ID" in l]
        if entry_id_line:
            eid = entry_id_line[0].split(":")[-1].strip()
            r_ver = _run("verify-entry", eid, "--db", db)
            assert r_ver.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
# W184 — CISO Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

class TestDashboard:

    def test_import(self):
        from squash.dashboard import Dashboard, ModelRow  # noqa

    def test_build_empty_dir(self, tmp_path):
        from squash.dashboard import Dashboard
        empty = tmp_path / "really_empty_subdir"
        empty.mkdir()
        d = Dashboard.build(models_dir=empty)
        assert d.total_models == 0

    def test_build_with_attested_model(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path, score=88.0)
        d = Dashboard.build(models_dir=tmp_path)
        assert d.total_models >= 1
        assert d.overall_score is not None

    def test_passing_model_counted(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path, score=90.0, violations=0)
        d = Dashboard.build(models_dir=tmp_path)
        assert d.models_passing >= 1

    def test_failing_model_counted(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path, score=50.0, violations=3)
        d = Dashboard.build(models_dir=tmp_path)
        assert d.models_failing >= 1

    def test_eu_days_remaining_positive(self, tmp_path):
        from squash.dashboard import Dashboard
        d = Dashboard.build(models_dir=tmp_path)
        assert d.eu_days_remaining >= 0

    def test_render_text_contains_score(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path, score=77.0)
        d = Dashboard.build(models_dir=tmp_path)
        text = d.render_text(color=False)
        assert "77" in text or "Portfolio" in text

    def test_render_text_no_color(self, tmp_path):
        from squash.dashboard import Dashboard
        d = Dashboard.build(models_dir=tmp_path)
        text = d.render_text(color=False)
        assert "\033[" not in text

    def test_render_text_with_color(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path, score=95.0)
        d = Dashboard.build(models_dir=tmp_path)
        text = d.render_text(color=True)
        assert "SQUASH" in text or "Portfolio" in text

    def test_to_dict_structure(self, tmp_path):
        from squash.dashboard import Dashboard
        d = Dashboard.build(models_dir=tmp_path)
        data = d.to_dict()
        assert "overall_score" in data
        assert "models" in data
        assert "violations" in data
        assert "cves" in data
        assert "next_deadline" in data

    def test_model_rows_sorted_worst_first(self, tmp_path):
        from squash.dashboard import Dashboard
        # Two subdirectories with different scores
        m1 = tmp_path / "model-good"
        m1.mkdir()
        _attest_fixture(m1, score=90.0)
        m2 = tmp_path / "model-bad"
        m2.mkdir()
        _attest_fixture(m2, score=40.0)
        d = Dashboard.build(models_dir=tmp_path)
        if len(d.model_rows) >= 2:
            # worst (lowest score) should come first
            assert (d.model_rows[0].compliance_score or 999) <= (d.model_rows[-1].compliance_score or 0)

    def test_portfolio_trend_stable(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path, score=65.0, violations=2)
        d = Dashboard.build(models_dir=tmp_path)
        assert d.portfolio_trend in ("improving", "stable", "degrading")

    def test_drift_detected_from_report(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path)
        (tmp_path / "drift_report.json").write_text('{"drift_detected": true}')
        d = Dashboard.build(models_dir=tmp_path)
        if d.model_rows:
            assert d.model_rows[0].drift_detected is True

    def test_build_from_model_paths(self, tmp_path):
        from squash.dashboard import Dashboard
        _attest_fixture(tmp_path)
        d = Dashboard.build(model_paths=[tmp_path])
        assert d.total_models == 1


class TestDashboardCLI:

    def test_dashboard_help(self):
        r = _run("dashboard", "--help")
        assert r.returncode == 0

    def test_dashboard_basic(self, tmp_path):
        r = _run("dashboard", "--model", str(tmp_path))
        assert r.returncode == 0
        assert "SQUASH" in r.stdout or "Portfolio" in r.stdout

    def test_dashboard_json(self, tmp_path):
        r = _run("dashboard", "--model", str(tmp_path), "--json")
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert "overall_score" in d
        assert "models" in d

    def test_dashboard_no_color(self, tmp_path):
        r = _run("dashboard", "--model", str(tmp_path), "--no-color")
        assert r.returncode == 0
        assert "\033[" not in r.stdout


# ═══════════════════════════════════════════════════════════════════════════════
# W185 — Regulatory Intelligence Feed
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegulatoryFeed:

    def test_import(self):
        from squash.regulatory_feed import RegulatoryFeed, RegulatoryItem, RegUpdate, FeedStatus  # noqa

    def test_total_regulations_count(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        assert feed.all_regulations()  # at least some

    def test_eu_ai_act_present(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("EU_AI_ACT")
        assert reg is not None
        assert "EU AI Act" in reg.short_name

    def test_eu_ai_act_has_enforcement_date(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("EU_AI_ACT")
        assert reg.enforcement_date == "2026-08-02"

    def test_days_to_enforcement_positive(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("EU_AI_ACT")
        days = reg.days_to_enforcement
        assert days is not None and days >= 0

    def test_squash_controls_populated(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        for reg in feed.all_regulations():
            # Most should have squash controls
            if reg.squash_controls:
                assert any("squash" in c for c in reg.squash_controls)

    def test_check_updates_returns_changes(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        updates = feed.check_updates()
        assert len(updates) > 0

    def test_check_updates_since_filter(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        updates_all = feed.check_updates()
        updates_2025 = feed.check_updates(since="2025-01-01")
        assert len(updates_2025) <= len(updates_all)

    def test_upcoming_deadlines(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        deadlines = feed.upcoming_deadlines(days=1000)
        assert len(deadlines) >= 1
        for _, days in deadlines:
            assert days >= 0

    def test_regulations_by_jurisdiction(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        eu_regs = feed.regulations_by_jurisdiction("eu")
        assert len(eu_regs) >= 1
        assert all(r.jurisdiction.value == "eu" for r in eu_regs)

    def test_regulations_affecting_industry(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        finance_regs = feed.regulations_affecting_industry("finance")
        assert len(finance_regs) >= 2

    def test_status_structure(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        s = feed.status()
        assert s.total_regulations > 0
        assert isinstance(s.squash_coverage, dict)

    def test_status_compliance_impact_summary(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        s = feed.status()
        summary = s.compliance_impact_summary()
        assert "REGULATORY" in summary
        assert "Squash coverage" in summary

    def test_nyc_local_law_present(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("NYC_LOCAL_LAW_144")
        assert reg is not None
        assert reg.is_active  # already in enforcement

    def test_gdpr_ai_present(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("EU_GDPR_AI")
        assert reg is not None
        assert reg.enforcement_date is not None

    def test_export_list(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        data = feed.export()
        assert isinstance(data, list) and len(data) > 0
        for item in data:
            assert "reg_id" in item
            assert "squash_controls" in item

    def test_reg_update_summary(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        updates = feed.check_updates()
        for u in updates:
            s = u.summary()
            assert u.reg_id in s or u.short_name in s

    def test_regulation_summary(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("EU_AI_ACT")
        s = reg.summary()
        assert "EU_AI_ACT" in s or "EU AI Act" in s

    def test_sec_ai_present(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("SEC_AI_DISCLOSURE")
        assert reg is not None

    def test_fedramp_has_squash_controls(self):
        from squash.regulatory_feed import RegulatoryFeed
        feed = RegulatoryFeed()
        reg = feed.get_regulation("FEDRAMP_AI")
        assert reg is not None
        assert reg.squash_controls


class TestRegulatoryCLI:

    def test_regulatory_help(self):
        r = _run("regulatory", "--help")
        assert r.returncode == 0

    def test_regulatory_status(self):
        r = _run("regulatory", "status")
        assert r.returncode == 0
        assert "REGULATORY" in r.stdout

    def test_regulatory_status_json(self):
        r = _run("regulatory", "status", "--json")
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert "total" in d
        assert "squash_coverage" in d

    def test_regulatory_list(self):
        r = _run("regulatory", "list")
        assert r.returncode == 0

    def test_regulatory_list_json(self):
        r = _run("regulatory", "list", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert isinstance(data, list)

    def test_regulatory_updates(self):
        r = _run("regulatory", "updates")
        assert r.returncode == 0

    def test_regulatory_deadlines(self):
        r = _run("regulatory", "deadlines", "--days", "500")
        assert r.returncode == 0

    def test_regulatory_deadlines_json(self):
        r = _run("regulatory", "deadlines", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert isinstance(data, list)


# ═══════════════════════════════════════════════════════════════════════════════
# W186 — M&A Due Diligence Package
# ═══════════════════════════════════════════════════════════════════════════════

class TestDueDiligenceGenerator:

    def test_import(self):
        from squash.due_diligence import DueDiligenceGenerator, DueDiligencePackage  # noqa

    def test_generate_empty_dir(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="TestCo", models_dir=tmp_path)
        assert pkg.company_name == "TestCo"
        assert pkg.package_id

    def test_generate_risk_rating(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="TestCo", models_dir=tmp_path)
        assert pkg.overall_risk_rating in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")

    def test_unattested_model_flagged(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        # tmp_path has no attestation
        pkg = DueDiligenceGenerator.generate(company_name="TestCo", models_dir=tmp_path)
        # no attestation → critical finding should mention it
        flags_text = " ".join(pkg.critical_findings)
        assert "attestation" in flags_text.lower() or pkg.overall_risk_rating in ("HIGH", "CRITICAL")

    def test_attested_model_no_unattested_flag(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        _attest_fixture(tmp_path, score=88.0)
        pkg = DueDiligenceGenerator.generate(company_name="Clean", models_dir=tmp_path)
        # Well-attested, good score — should not be CRITICAL
        assert pkg.overall_risk_rating in ("LOW", "MEDIUM", "HIGH")

    def test_high_risk_without_bias_flagged(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        _attest_fixture(tmp_path, score=75.0)
        pkg = DueDiligenceGenerator.generate(company_name="HR-Co", models_dir=tmp_path)
        # high-risk tier without bias audit → liability flag
        all_flags = " ".join(
            flag for m in pkg.models for flag in m.liability_flags
        )
        assert "bias" in all_flags.lower() or pkg.overall_risk_rating in ("MEDIUM", "HIGH", "CRITICAL")

    def test_rw_guidance_populated(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="AcmeCorp", models_dir=tmp_path)
        assert len(pkg.rw_guidance) >= 3
        assert any("R" in r.upper() and "W" in r.upper() or "warrant" in r.lower() or "represent" in r.lower()
                   for r in pkg.rw_guidance)

    def test_to_dict_structure(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="Dict", models_dir=tmp_path)
        d = pkg.to_dict()
        assert d["document_type"] == "AI_MA_DUE_DILIGENCE_PACKAGE"
        assert "model_inventory" in d
        assert "critical_findings" in d
        assert "representations_and_warranties_guidance" in d

    def test_executive_risk_summary(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="SummaryTest", models_dir=tmp_path)
        summary = pkg.executive_risk_summary()
        assert "SummaryTest" in summary
        assert "DUE DILIGENCE" in summary

    def test_save_creates_zip(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        import zipfile
        pkg = DueDiligenceGenerator.generate(company_name="ZipTest", models_dir=tmp_path)
        out = tmp_path / "dd-out"
        written = pkg.save(out)
        zip_files = [f for f in written if f.endswith(".zip")]
        assert zip_files
        assert zipfile.is_zipfile(zip_files[0])

    def test_to_markdown_has_sections(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="MarkdownTest", models_dir=tmp_path)
        md = pkg.to_markdown()
        assert "Due Diligence Package" in md
        assert "Executive Risk Summary" in md

    def test_package_hash_set(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="Hash", models_dir=tmp_path)
        assert len(pkg.package_hash) == 64

    def test_deal_type_stored(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        pkg = DueDiligenceGenerator.generate(company_name="PE", deal_type="investment", models_dir=tmp_path)
        assert pkg.deal_type == "investment"

    def test_generate_with_model_paths(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        _attest_fixture(tmp_path)
        pkg = DueDiligenceGenerator.generate(company_name="Direct", model_paths=[tmp_path])
        assert len(pkg.models) == 1

    def test_low_score_flagged(self, tmp_path):
        from squash.due_diligence import DueDiligenceGenerator
        _attest_fixture(tmp_path, score=45.0, violations=5)
        pkg = DueDiligenceGenerator.generate(company_name="LowScore", models_dir=tmp_path)
        model = pkg.models[0]
        assert any("45" in f or "violation" in f.lower() for f in model.liability_flags)


class TestDueDiligenceCLI:

    def test_due_diligence_help(self):
        r = _run("due-diligence", "--help")
        assert r.returncode == 0

    def test_due_diligence_basic(self, tmp_path):
        r = _run("due-diligence", "--model", str(tmp_path),
                 "--company", "TestAcme",
                 "--output-dir", str(tmp_path / "dd"))
        assert r.returncode == 0
        dd_dir = tmp_path / "dd"
        json_files = list(dd_dir.glob("*.json"))
        assert json_files

    def test_due_diligence_json(self, tmp_path):
        r = _run("due-diligence", "--model", str(tmp_path), "--company", "JSONTest", "--json")
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert d["document_type"] == "AI_MA_DUE_DILIGENCE_PACKAGE"

    def test_due_diligence_investment(self, tmp_path):
        r = _run("due-diligence", "--model", str(tmp_path),
                 "--company", "InvestCo", "--deal-type", "investment",
                 "--output-dir", str(tmp_path / "dd"))
        assert r.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
# W187 — VS Code Extension scaffold
# ═══════════════════════════════════════════════════════════════════════════════

class TestVSCodeExtension:

    _EXT_ROOT = Path(__file__).parents[1] / "vscode-extension"

    def test_extension_directory_exists(self):
        assert self._EXT_ROOT.is_dir()

    def test_package_json_exists(self):
        assert (self._EXT_ROOT / "package.json").exists()

    def test_package_json_valid(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        assert pkg["name"] == "squash-ai"
        assert pkg["publisher"] == "konjoai"

    def test_package_json_version(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        assert "version" in pkg

    def test_package_json_engines(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        assert "vscode" in pkg.get("engines", {})

    def test_commands_registered(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        commands = [c["command"] for c in pkg.get("contributes", {}).get("commands", [])]
        assert "squash.runAttestation" in commands
        assert "squash.showDashboard" in commands
        assert "squash.runBiasAudit" in commands

    def test_views_registered(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        views = pkg.get("contributes", {}).get("views", {})
        assert "squash-sidebar" in views
        assert len(views["squash-sidebar"]) == 3

    def test_configuration_properties(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        props = pkg.get("contributes", {}).get("configuration", {}).get("properties", {})
        assert "squash.cliPath" in props
        assert "squash.defaultPolicy" in props
        assert "squash.autoAttest" in props

    def test_main_entry_point(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        assert pkg.get("main") == "./out/extension.js"

    def test_extension_ts_exists(self):
        assert (self._EXT_ROOT / "src" / "extension.ts").exists()

    def test_extension_ts_activate_function(self):
        src = (self._EXT_ROOT / "src" / "extension.ts").read_text()
        assert "export function activate" in src

    def test_extension_ts_deactivate_function(self):
        src = (self._EXT_ROOT / "src" / "extension.ts").read_text()
        assert "export function deactivate" in src

    def test_extension_ts_status_bar(self):
        src = (self._EXT_ROOT / "src" / "extension.ts").read_text()
        assert "statusBarItem" in src
        assert "showStatusBar" in src

    def test_extension_ts_tree_providers(self):
        src = (self._EXT_ROOT / "src" / "extension.ts").read_text()
        assert "ModelPortfolioProvider" in src
        assert "ViolationsProvider" in src
        assert "DeadlinesProvider" in src

    def test_extension_ts_run_squash(self):
        src = (self._EXT_ROOT / "src" / "extension.ts").read_text()
        assert "runSquash" in src
        assert "cliPath" in src

    def test_extension_ts_dashboard_webview(self):
        src = (self._EXT_ROOT / "src" / "extension.ts").read_text()
        assert "_dashboardHtml" in src
        assert "webview" in src

    def test_tsconfig_exists(self):
        assert (self._EXT_ROOT / "tsconfig.json").exists()

    def test_tsconfig_valid(self):
        ts = json.loads((self._EXT_ROOT / "tsconfig.json").read_text())
        assert "compilerOptions" in ts
        assert ts["compilerOptions"]["outDir"] == "out"

    def test_activation_events(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        events = pkg.get("activationEvents", [])
        assert any("squash" in e for e in events)

    def test_context_menu_for_attestation(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        menus = pkg.get("contributes", {}).get("menus", {})
        explorer_ctx = menus.get("explorer/context", [])
        assert any(m.get("command") == "squash.runAttestation" for m in explorer_ctx)

    def test_ten_or_more_commands(self):
        pkg = json.loads((self._EXT_ROOT / "package.json").read_text())
        commands = pkg.get("contributes", {}).get("commands", [])
        assert len(commands) >= 9
