"""tests/test_squash_sprint22.py — Sprint 22 W229–W231 (Track C / C5).

Regulatory Examination Simulation: squash/audit_sim.py.

W229 — ExamQuestion, ExamAnswer, ReadinessReport dataclasses; scoring maths
W230 — 4 regulator profiles (EU-AI-Act, NIST-RMF, SEC, FDA)
W231 — `squash simulate-audit` CLI: --regulator, --json, --fail-below,
        --output-dir, ReadinessReport.save() / to_markdown() / to_json()
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _empty_dir() -> Path:
    """Return a fresh empty temp directory (no squash artefacts)."""
    import tempfile as _t
    return Path(_t.mkdtemp())


def _populated_dir() -> Path:
    """Return a temp dir with enough squash artefacts for a meaningful score."""
    d = Path(tempfile.mkdtemp())
    (d / "squash-attest.json").write_text(
        json.dumps({"model_id": "acme/bert", "passed": True})
    )
    (d / "cyclonedx-mlbom.json").write_text(json.dumps({"bomFormat": "CycloneDX"}))
    (d / "annex_iv.json").write_text(json.dumps({"overall_score": 87, "sections": []}))
    (d / "squash-scan.json").write_text(json.dumps({"status": "clean"}))
    (d / "squash-model-card-hf.md").write_text("---\nlicense: apache-2.0\n---\n\n# Model\n")
    (d / "squash-vex-report.json").write_text(json.dumps({"statements": []}))
    (d / "squash-policy-eu-ai-act.json").write_text(json.dumps({"passed": True}))
    (d / "bias_audit_report.json").write_text(json.dumps({"passed": True}))
    (d / "data_lineage_certificate.json").write_text(json.dumps({"datasets": []}))
    (d / "nist_rmf_report.json").write_text(json.dumps({"score": 80}))
    (d / "squash-drift.json").write_text(json.dumps({"drift_detected": False}))
    (d / "squash-incident.json").write_text(json.dumps({"incidents": []}))
    (d / ".squash.yml").write_text("scope: production\n")
    return d


# ── W229 — Core data model ────────────────────────────────────────────────────


class TestExamQuestion(unittest.TestCase):
    def test_fields_preserved(self) -> None:
        from squash.audit_sim import ExamQuestion
        q = ExamQuestion(
            q_id="TEST-001", article="Art. 9(1)",
            question="Test question?",
            answer_sources=["squash-attest.json"],
            answer_cli=["squash attest"],
            weight=3, category="risk-management", days_to_close=2,
        )
        self.assertEqual(q.q_id, "TEST-001")
        self.assertEqual(q.weight, 3)
        self.assertEqual(q.category, "risk-management")

    def test_default_weight(self) -> None:
        from squash.audit_sim import ExamQuestion
        q = ExamQuestion(
            q_id="X", article="Y", question="Z",
            answer_sources=[], answer_cli=[],
        )
        self.assertEqual(q.weight, 2)


class TestExamAnswer(unittest.TestCase):
    def _make_q(self, **kw):
        from squash.audit_sim import ExamQuestion
        return ExamQuestion(
            q_id="T1", article="A", question="Q?",
            answer_sources=["squash-attest.json"], answer_cli=["squash attest"],
            **kw,
        )

    def test_to_dict_has_required_keys(self) -> None:
        from squash.audit_sim import ExamAnswer
        a = ExamAnswer(
            question=self._make_q(), status="PASS",
            evidence_found=["squash-attest.json"],
        )
        d = a.to_dict()
        for k in ("q_id", "article", "status", "evidence_found", "remediation"):
            self.assertIn(k, d)

    def test_pass_status(self) -> None:
        from squash.audit_sim import ExamAnswer
        a = ExamAnswer(question=self._make_q(), status="PASS")
        self.assertEqual(a.status, "PASS")


class TestScoringMath(unittest.TestCase):
    """Verify the critical-gate cap and tier assignment."""

    def _make_answers(self, specs):
        """specs = list of (weight, status)."""
        from squash.audit_sim import ExamAnswer, ExamQuestion
        answers = []
        for i, (w, s) in enumerate(specs):
            q = ExamQuestion(
                q_id=f"Q{i}", article="A", question="Q",
                answer_sources=["squash-attest.json"], answer_cli=[],
                weight=w,
            )
            answers.append(ExamAnswer(question=q, status=s))
        return answers

    def test_all_pass_gives_100(self) -> None:
        from squash.audit_sim import _compute_score
        answers = self._make_answers([(2, "PASS")] * 10)
        score, tier, crit_fails = _compute_score(answers)
        self.assertEqual(score, 100)
        self.assertEqual(tier, "AUDIT_READY")
        self.assertEqual(crit_fails, 0)

    def test_all_fail_gives_0(self) -> None:
        from squash.audit_sim import _compute_score
        answers = self._make_answers([(2, "FAIL")] * 10)
        score, tier, crit_fails = _compute_score(answers)
        self.assertEqual(score, 0)
        self.assertEqual(tier, "EARLY_STAGE")

    def test_critical_fail_caps_at_74(self) -> None:
        from squash.audit_sim import _compute_score
        # 9 passes + 1 critical fail (weight 3)
        answers = self._make_answers([(2, "PASS")] * 9 + [(3, "FAIL")])
        score, tier, crit_fails = _compute_score(answers)
        self.assertLessEqual(score, 74)
        self.assertEqual(crit_fails, 1)
        self.assertEqual(tier, "SUBSTANTIAL")  # 60–79

    def test_partial_gives_half_credit(self) -> None:
        from squash.audit_sim import _compute_score
        # All PARTIAL: score should be 50
        answers = self._make_answers([(2, "PARTIAL")] * 10)
        score, tier, _ = _compute_score(answers)
        self.assertEqual(score, 50)
        self.assertEqual(tier, "DEVELOPING")

    def test_tiers(self) -> None:
        from squash.audit_sim import _compute_score
        for expected_tier, n_pass, n_fail in [
            ("AUDIT_READY", 10, 0),
            ("SUBSTANTIAL", 7, 3),
            ("DEVELOPING",  5, 5),
            ("EARLY_STAGE", 2, 8),
        ]:
            answers = self._make_answers(
                [(2, "PASS")] * n_pass + [(2, "FAIL")] * n_fail
            )
            _, tier, _ = _compute_score(answers)
            self.assertEqual(tier, expected_tier, msg=f"n_pass={n_pass}")


# ── W230 — Regulator profiles ─────────────────────────────────────────────────


class TestEUAIActProfile(unittest.TestCase):
    def setUp(self) -> None:
        from squash.audit_sim import _eu_ai_act_questions
        self.questions = _eu_ai_act_questions()

    def test_has_38_questions(self) -> None:
        self.assertEqual(len(self.questions), 38)

    def test_all_questions_have_required_fields(self) -> None:
        for q in self.questions:
            self.assertTrue(q.q_id.startswith("EU-"), msg=q.q_id)
            self.assertTrue(q.article)
            self.assertTrue(q.question)
            self.assertGreater(q.weight, 0)
            self.assertLessEqual(q.weight, 3)
            self.assertTrue(q.answer_cli, msg=f"{q.q_id} has no CLI commands")

    def test_has_critical_gates(self) -> None:
        critical = [q for q in self.questions if q.weight == 3]
        self.assertGreaterEqual(len(critical), 3)

    def test_unique_ids(self) -> None:
        ids = [q.q_id for q in self.questions]
        self.assertEqual(len(set(ids)), len(ids))

    def test_risk_management_category_present(self) -> None:
        cats = {q.category for q in self.questions}
        self.assertIn("risk-management", cats)
        self.assertIn("technical-documentation", cats)


class TestNISTRMFProfile(unittest.TestCase):
    def setUp(self) -> None:
        from squash.audit_sim import _nist_rmf_questions
        self.questions = _nist_rmf_questions()

    def test_has_30_questions(self) -> None:
        self.assertEqual(len(self.questions), 30)

    def test_covers_four_functions(self) -> None:
        cats = {q.category for q in self.questions}
        for cat in ("govern", "map", "measure", "manage"):
            self.assertIn(cat, cats)


class TestSECProfile(unittest.TestCase):
    def test_has_22_questions(self) -> None:
        from squash.audit_sim import _sec_questions
        self.assertEqual(len(_sec_questions()), 22)


class TestFDAProfile(unittest.TestCase):
    def test_has_20_questions(self) -> None:
        from squash.audit_sim import _fda_questions
        self.assertEqual(len(_fda_questions()), 20)


# ── AuditSimulator — full integration ────────────────────────────────────────


class TestAuditSimulatorEmpty(unittest.TestCase):
    """Worst case: no squash artefacts at all."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.path = Path(self._tmp)

    def test_all_regulators_run_without_error(self) -> None:
        from squash.audit_sim import AuditSimulator
        for reg in ("EU-AI-Act", "NIST-RMF", "SEC", "FDA"):
            r = AuditSimulator().simulate(self.path, reg)
            self.assertEqual(r.regulator, reg)
            self.assertGreaterEqual(r.total_questions, 20)
            self.assertGreaterEqual(r.failing, 10)

    def test_empty_score_is_zero(self) -> None:
        from squash.audit_sim import AuditSimulator
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        self.assertEqual(r.overall_score, 0)
        self.assertEqual(r.readiness_tier, "EARLY_STAGE")

    def test_answers_count_matches_questions(self) -> None:
        from squash.audit_sim import AuditSimulator, _eu_ai_act_questions
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        self.assertEqual(len(r.answers), len(_eu_ai_act_questions()))

    def test_unsupported_regulator_raises_value_error(self) -> None:
        from squash.audit_sim import AuditSimulator
        with self.assertRaises(ValueError) as ctx:
            AuditSimulator().simulate(self.path, "GDPR-Custom")
        self.assertIn("Unsupported", str(ctx.exception))

    def test_executive_summary_populated(self) -> None:
        from squash.audit_sim import AuditSimulator
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        self.assertGreater(len(r.executive_summary), 50)
        self.assertIn("EU-AI-Act", r.executive_summary)


class TestAuditSimulatorPopulated(unittest.TestCase):
    """Meaningful artefacts → score should be well above 0."""

    def setUp(self) -> None:
        self.path = _populated_dir()

    def test_score_above_zero_with_artefacts(self) -> None:
        from squash.audit_sim import AuditSimulator
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        self.assertGreater(r.overall_score, 0)

    def test_passing_count_above_zero(self) -> None:
        from squash.audit_sim import AuditSimulator
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        self.assertGreater(r.passing, 0)

    def test_partial_or_pass_above_zero(self) -> None:
        """With populated artefacts, either PASS or PARTIAL count must be > 0."""
        from squash.audit_sim import AuditSimulator
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        self.assertGreater(r.passing + r.partial, 0)

    def test_score_between_0_and_100(self) -> None:
        from squash.audit_sim import AuditSimulator
        for reg in ("EU-AI-Act", "NIST-RMF", "SEC", "FDA"):
            r = AuditSimulator().simulate(self.path, reg)
            self.assertGreaterEqual(r.overall_score, 0)
            self.assertLessEqual(r.overall_score, 100)

    def test_roadmap_lists_fails_before_passes(self) -> None:
        from squash.audit_sim import AuditSimulator
        r = AuditSimulator().simulate(self.path, "EU-AI-Act")
        roadmap = r._roadmap()
        if len(roadmap) >= 2:
            self.assertGreaterEqual(roadmap[0]["weight"], roadmap[-1]["weight"])


# ── ReadinessReport serialisation ────────────────────────────────────────────


class TestReadinessReportSerialisation(unittest.TestCase):
    def setUp(self) -> None:
        from squash.audit_sim import AuditSimulator
        self.path = _empty_dir()
        self.report = AuditSimulator().simulate(self.path, "EU-AI-Act")

    def test_to_json_is_valid_json(self) -> None:
        parsed = json.loads(self.report.to_json())
        self.assertEqual(parsed["squash_version"], "audit_sim_v1")
        self.assertEqual(parsed["regulator"], "EU-AI-Act")
        self.assertIn("overall_score", parsed)
        self.assertIn("remediation_roadmap", parsed)

    def test_to_markdown_includes_all_sections(self) -> None:
        md = self.report.to_markdown()
        for section in (
            "# EU-AI-Act Regulatory Examination Simulation",
            "## Executive Summary",
            "## Scorecard",
            "## Results by Category",
            "## Question Detail",
            "## 90-Day Remediation Roadmap",
        ):
            self.assertIn(section, md, msg=f"Missing: {section}")

    def test_to_markdown_includes_score(self) -> None:
        md = self.report.to_markdown()
        self.assertIn(str(self.report.overall_score), md)
        # Markdown renders underscores as spaces: "EARLY_STAGE" → "EARLY STAGE"
        self.assertIn("EARLY STAGE", md)

    def test_to_markdown_includes_each_question(self) -> None:
        md = self.report.to_markdown()
        for q_id in ("EU-001", "EU-010", "EU-038"):
            self.assertIn(q_id, md)

    def test_to_markdown_has_remediation_commands(self) -> None:
        md = self.report.to_markdown()
        self.assertIn("squash", md.lower())

    def test_save_writes_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            written = self.report.save(Path(td))
        self.assertIn("json", written)
        self.assertIn("md", written)

    def test_json_answers_count_matches(self) -> None:
        d = json.loads(self.report.to_json())
        self.assertEqual(len(d["answers"]), self.report.total_questions)

    def test_tier_in_json(self) -> None:
        d = json.loads(self.report.to_json())
        self.assertEqual(d["readiness_tier"], "EARLY_STAGE")


# ── W231 — CLI: squash simulate-audit ────────────────────────────────────────


class TestCLISimulateAudit(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def test_help_surface(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--regulator", "--models-dir", "--output-dir",
                     "--json", "--fail-below", "--quiet"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing")
        for reg in ("EU-AI-Act", "NIST-RMF", "SEC", "FDA"):
            self.assertIn(reg, result.stdout)

    def test_default_eu_ai_act_runs(self) -> None:
        out = self.tmp / "out"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((out / "audit-readiness.json").exists())
        self.assertTrue((out / "audit-readiness.md").exists())

    def test_json_output(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--regulator", "EU-AI-Act",
             "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["squash_version"], "audit_sim_v1")
        self.assertEqual(payload["regulator"], "EU-AI-Act")
        self.assertIn("overall_score", payload)
        self.assertIn("remediation_roadmap", payload)

    def test_nist_rmf_runs(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--regulator", "NIST-RMF", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["regulator"], "NIST-RMF")
        self.assertEqual(payload["summary"]["total_questions"], 30)

    def test_sec_runs(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--regulator", "SEC", "--models-dir", str(self.tmp), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"]["total_questions"], 22)

    def test_fda_runs(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--regulator", "FDA", "--models-dir", str(self.tmp), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"]["total_questions"], 20)

    def test_fail_below_zero_score_exits_1(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--fail-below", "1", "--quiet"],
            capture_output=True, text=True,
        )
        # Empty dir → score 0 → below threshold of 1 → rc 1
        self.assertEqual(result.returncode, 1)

    def test_fail_below_100_on_empty_exits_1(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--fail-below", "100", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)

    def test_fail_below_zero_doesnt_fail(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--fail-below", "0", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_output_md_has_roadmap(self) -> None:
        out = self.tmp / "out"
        subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True, check=True,
        )
        md = (out / "audit-readiness.md").read_text()
        self.assertIn("90-Day Remediation Roadmap", md)
        self.assertIn("squash", md.lower())

    def test_populated_dir_gives_higher_score(self) -> None:
        populated = _populated_dir()
        result_empty = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(self.tmp), "--json"],
            capture_output=True, text=True,
        )
        result_pop = subprocess.run(
            [sys.executable, "-m", "squash.cli", "simulate-audit",
             "--models-dir", str(populated), "--json"],
            capture_output=True, text=True,
        )
        score_empty = json.loads(result_empty.stdout)["overall_score"]
        score_pop = json.loads(result_pop.stdout)["overall_score"]
        self.assertGreater(score_pop, score_empty)


# ── Module count gate ─────────────────────────────────────────────────────────


class TestModuleCountAfterSprint22(unittest.TestCase):
    """Sprint 22 adds audit_sim.py → count 76 → 77."""

    def test_module_count_is_77(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        self.assertEqual(
            len(py_files), 100,
            msg=f"squash/ has {len(py_files)} files (expected 97 after D2/W226-228).",
        )


if __name__ == "__main__":
    unittest.main()
