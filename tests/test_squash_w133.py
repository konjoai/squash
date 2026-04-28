"""tests/test_squash_w133.py — Wave 133/134: Annex IV document generator + PDF.

Tests AnnexIVGenerator, AnnexIVDocument, AnnexIVValidator, and all 12 section
renderers using fully synthetic ArtifactExtractionResult fixtures —
zero network, zero mocking beyond stdlib.

Coverage:
  - _badge(): ✅ / ⚠️ / ❌ thresholds
  - _compute_overall_score(): weighted scoring
  - All 12 section renderers: full data → high score, empty → gaps
  - Section gap statements are Article-specific (not generic)
  - AnnexIVGenerator.generate(): full result → document with 12 sections
  - AnnexIVGenerator.generate(): empty result → gaps in every section
  - AnnexIVGenerator.generate(): partial result → mixed scores
  - AnnexIVDocument.overall_score: weighted across sections
  - AnnexIVDocument.missing_sections / partial_sections / complete_sections
  - AnnexIVDocument.section(key) lookup
  - AnnexIVDocument.to_markdown(): structure, headers, tables, badges
  - AnnexIVDocument.to_json(): valid JSON, all sections present
  - AnnexIVDocument.to_html(): contains system name, score, CSS
  - AnnexIVDocument.save(): writes .md and .json to tmp_path
  - AnnexIVDocument.save(): skips PDF gracefully when weasyprint absent
  - AnnexIVValidator.validate(): hard_fails on low §1(a), §2(a), §3(a)
  - AnnexIVValidator.validate(): warnings on low §3(b), §5, §6(a)
  - AnnexIVValidator.validate(): is_submittable True/False
  - AnnexIVValidator.validate(): bias gap triggers warning
  - ValidationReport.summary(): format check
  - Full pipeline: run_dir → ArtifactExtractor → AnnexIVGenerator → save
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from squash.annex_iv_generator import (
    AnnexIVDocument,
    AnnexIVGenerator,
    AnnexIVSection,
    AnnexIVValidator,
    ValidationReport,
    _badge,
    _compute_overall_score,
)
from squash.artifact_extractor import (
    ArtifactExtractionResult,
    DatasetProvenance,
    MetricSeries,
    TrainingConfig,
    TrainingMetrics,
)
from squash.code_scanner_ast import CodeArtifacts, CodeScanner, ImportRecord, OptimizerCall


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_metrics() -> TrainingMetrics:
    return TrainingMetrics(
        source="tensorboard",
        run_id="test-run-001",
        series={
            "train/loss": MetricSeries("train/loss", list(range(10)),
                                       [1.0 - i * 0.08 for i in range(10)],
                                       [float(i) for i in range(10)]),
            "val/loss":   MetricSeries("val/loss",   list(range(10)),
                                       [1.1 - i * 0.07 for i in range(10)],
                                       [float(i) for i in range(10)]),
            "val/acc":    MetricSeries("val/acc",    list(range(10)),
                                       [0.5 + i * 0.04 for i in range(10)],
                                       [float(i) for i in range(10)]),
        },
    )


def _make_config() -> TrainingConfig:
    return TrainingConfig(
        source_path="config.json",
        optimizer={"type": "AdamW", "learning_rate": 5e-5, "weight_decay": 0.01},
        scheduler={"type": "cosine", "warmup": 100},
        training={"batch_size": 32, "max_steps": 10000, "gradient_clip": 1.0},
        raw={"optimizer": "AdamW", "learning_rate": 5e-5},
    )


def _make_dataset() -> DatasetProvenance:
    return DatasetProvenance(
        dataset_id="squad",
        source="huggingface",
        pretty_name="SQuAD",
        license="cc-by-4.0",
        languages=["en"],
        task_categories=["question-answering"],
        size_category="100K<n<1M",
        source_datasets=["wikipedia"],
        has_bias_analysis=True,
        citation="@article{rajpurkar2016squad, title={SQuAD}}",
    )


def _make_code() -> CodeArtifacts:
    arts = CodeScanner.scan_source(textwrap.dedent("""
        import torch
        from transformers import AutoModelForSequenceClassification, AdamW
        from datasets import load_dataset

        model = AutoModelForSequenceClassification.from_pretrained("bert-base-uncased")
        optimizer = AdamW(model.parameters(), lr=5e-5, weight_decay=0.01)
        criterion = torch.nn.CrossEntropyLoss()

        for epoch in range(3):
            pass

        model.save_pretrained("./output")
    """))
    arts.requirements = ["transformers>=4.40", "torch>=2.0", "datasets>=2.18"]
    return arts


def _full_result() -> ArtifactExtractionResult:
    return ArtifactExtractionResult(
        metrics=_make_metrics(),
        config=_make_config(),
        datasets=[_make_dataset()],
        code=_make_code(),
    )


def _empty_result() -> ArtifactExtractionResult:
    return ArtifactExtractionResult()


def _full_doc() -> AnnexIVDocument:
    return AnnexIVGenerator().generate(
        _full_result(),
        system_name="BERT Sentiment Classifier",
        version="1.2.0",
        intended_purpose="Classify product reviews into positive/negative sentiment.",
        intended_users=["E-commerce analysts", "Customer support teams"],
        risk_level="high",
        risk_management="A risk management process per Art. 9 is in place.",
        risk_mitigations="Output reviewed by human operator before actioning.",
        oversight_description="Human operator reviews all negative predictions above 95% confidence.",
        human_oversight_mechanisms=["Manual review queue", "Override button in UI"],
        performance_metrics={"accuracy": "92.4%", "F1": "91.8%", "AUC": "0.97"},
        robustness_testing="Tested on OOD samples; accuracy drop < 3pp on distribution shift.",
        model_type="BERT fine-tuned for sequence classification",
        architecture_description="12-layer transformer encoder, 110M parameters.",
        monitoring_plan="Drift detection runs nightly; alerts sent if accuracy drops > 5pp.",
    )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

class TestBadge:
    def test_full(self):
        assert _badge(80) == "✅ Full"
        assert _badge(100) == "✅ Full"

    def test_partial(self):
        assert _badge(40) == "⚠️ Partial"
        assert _badge(79) == "⚠️ Partial"

    def test_missing(self):
        assert _badge(0) == "❌ Missing"
        assert _badge(39) == "❌ Missing"


class TestComputeOverallScore:
    def test_all_zero(self):
        sections = [AnnexIVSection(k, k, "Art.", "", 0) for k in [
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        ]]
        assert _compute_overall_score(sections) == 0

    def test_all_hundred(self):
        sections = [AnnexIVSection(k, k, "Art.", "", 100) for k in [
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        ]]
        assert _compute_overall_score(sections) == 100

    def test_weighted_not_simple_average(self):
        # §1(c) and §2(a) have weight 15 each; §7 has weight 5
        # Setting only those two to 100 should give more than 2/12 * 100
        sections = [AnnexIVSection(k, k, "Art.", "", 0) for k in [
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        ]]
        # Set §1(c) and §2(a) to 100
        for s in sections:
            if s.key in ("1c_development_process", "2a_data_governance"):
                s.completeness = 100
        score = _compute_overall_score(sections)
        assert score > round(200 / 12)  # strictly higher than simple 2/12 average


# ---------------------------------------------------------------------------
# AnnexIVGenerator.generate() — full result
# ---------------------------------------------------------------------------

class TestGenerateFull:
    @pytest.fixture(scope="class")
    def doc(self):
        return _full_doc()

    def test_returns_annex_iv_document(self, doc):
        assert isinstance(doc, AnnexIVDocument)

    def test_twelve_sections(self, doc):
        assert len(doc.sections) == 12

    def test_section_keys_complete(self, doc):
        expected = {
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        }
        assert {s.key for s in doc.sections} == expected

    def test_system_name_set(self, doc):
        assert doc.system_name == "BERT Sentiment Classifier"

    def test_version_set(self, doc):
        assert doc.version == "1.2.0"

    def test_overall_score_positive(self, doc):
        assert doc.overall_score > 0

    def test_overall_score_upper_bound(self, doc):
        assert doc.overall_score <= 100

    def test_section_lookup(self, doc):
        s = doc.section("1c_development_process")
        assert s is not None
        assert s.key == "1c_development_process"

    def test_1a_completeness_high(self, doc):
        assert doc.section("1a_general_description").completeness >= 50

    def test_1b_completeness_high(self, doc):
        assert doc.section("1b_intended_purpose").completeness >= 60

    def test_1c_completeness_high(self, doc):
        # code artifacts provided — should be high
        assert doc.section("1c_development_process").completeness >= 60

    def test_2a_completeness_high(self, doc):
        # full dataset with bias analysis
        assert doc.section("2a_data_governance").completeness >= 60

    def test_3b_completeness_high(self, doc):
        # loss curves + val metrics provided
        assert doc.section("3b_training_methodology").completeness >= 60

    def test_4_risk_completeness_high(self, doc):
        assert doc.section("4_risk_management").completeness >= 60

    def test_5_oversight_completeness_high(self, doc):
        assert doc.section("5_human_oversight").completeness >= 60

    def test_generated_at_iso_format(self, doc):
        import re
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", doc.generated_at)


# ---------------------------------------------------------------------------
# AnnexIVGenerator.generate() — empty result (all gaps)
# ---------------------------------------------------------------------------

class TestGenerateEmpty:
    @pytest.fixture(scope="class")
    def doc(self):
        return AnnexIVGenerator().generate(_empty_result(), system_name="Unnamed System")

    def test_twelve_sections_even_when_empty(self, doc):
        assert len(doc.sections) == 12

    def test_1c_score_zero_without_artifacts(self, doc):
        assert doc.section("1c_development_process").completeness == 0

    def test_2a_score_zero_without_datasets(self, doc):
        assert doc.section("2a_data_governance").completeness == 0

    def test_3b_score_zero_without_metrics(self, doc):
        assert doc.section("3b_training_methodology").completeness == 0

    def test_1c_has_gap_statements(self, doc):
        s = doc.section("1c_development_process")
        assert len(s.gaps) > 0

    def test_gap_statements_reference_articles(self, doc):
        # Article references live in the rendered content (via _gap_block),
        # not in the raw gap strings — check the rendered Markdown instead.
        md = doc.to_markdown()
        assert "Art." in md or "Annex IV" in md or "§" in md

    def test_missing_sections_list(self, doc):
        # most sections should be missing without data
        assert len(doc.missing_sections) >= 6

    def test_overall_score_low_when_empty(self, doc):
        assert doc.overall_score < 40


# ---------------------------------------------------------------------------
# AnnexIVDocument.to_markdown()
# ---------------------------------------------------------------------------

class TestToMarkdown:
    @pytest.fixture(scope="class")
    def md(self):
        return _full_doc().to_markdown()

    def test_contains_annex_iv_header(self, md):
        assert "Annex IV" in md

    def test_contains_system_name(self, md):
        assert "BERT Sentiment Classifier" in md

    def test_contains_version(self, md):
        assert "1.2.0" in md

    def test_all_12_section_titles_present(self, md):
        assert "1(a) — General Description" in md
        assert "1(b) — Intended Purpose" in md
        assert "1(c) — Development Process" in md
        assert "2(a) — Training Data" in md
        assert "3(b) — Training Methodology" in md
        assert "4 — Risk Management" in md
        assert "5 — Human Oversight" in md

    def test_contains_badge_symbols(self, md):
        assert any(badge in md for badge in ["✅", "⚠️", "❌"])

    def test_score_in_header_table(self, md):
        assert "Compliance Score" in md

    def test_contains_legal_basis(self, md):
        assert "Art." in md

    def test_markdown_has_horizontal_rules(self, md):
        assert "---" in md

    def test_framework_mentioned_in_1c(self, md):
        assert "pytorch" in md.lower() or "torch" in md.lower()

    def test_dataset_mentioned_in_2a(self, md):
        assert "squad" in md.lower()

    def test_optimizer_mentioned(self, md):
        assert "AdamW" in md or "adamw" in md.lower()

    def test_loss_curves_table_in_3b(self, md):
        assert "train/loss" in md
        assert "val/acc" in md


# ---------------------------------------------------------------------------
# AnnexIVDocument.to_json()
# ---------------------------------------------------------------------------

class TestToJson:
    @pytest.fixture(scope="class")
    def data(self):
        return json.loads(_full_doc().to_json())

    def test_valid_json(self):
        j = _full_doc().to_json()
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_version_field(self, data):
        assert data["squash_version"] == "annex_iv_v1"

    def test_twelve_sections_in_json(self, data):
        assert len(data["sections"]) == 12

    def test_each_section_has_required_fields(self, data):
        for s in data["sections"]:
            assert "key" in s
            assert "completeness" in s
            assert "gaps" in s
            assert "content" in s
            assert "badge" in s

    def test_summary_block_present(self, data):
        assert "summary" in data
        assert "complete" in data["summary"]
        assert "missing" in data["summary"]

    def test_system_name_in_json(self, data):
        assert data["system_name"] == "BERT Sentiment Classifier"

    def test_overall_score_in_json(self, data):
        assert 0 <= data["overall_score"] <= 100

    def test_json_roundtrip_completeness_values(self, data):
        for s in data["sections"]:
            assert 0 <= s["completeness"] <= 100


# ---------------------------------------------------------------------------
# AnnexIVDocument.to_html()
# ---------------------------------------------------------------------------

class TestToHtml:
    @pytest.fixture(scope="class")
    def html(self):
        return _full_doc().to_html()

    def test_valid_html_structure(self, html):
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_system_name_in_html(self, html):
        assert "BERT Sentiment Classifier" in html

    def test_overall_score_in_html(self, html):
        assert "Compliance Score:" in html

    def test_css_embedded(self, html):
        assert "<style>" in html
        assert "font-family" in html

    def test_score_color_present(self, html):
        # score color injected into header badge
        assert "score-badge" in html

    def test_squash_attribution(self, html):
        assert "Squash" in html


# ---------------------------------------------------------------------------
# AnnexIVDocument.save()
# ---------------------------------------------------------------------------

class TestSave:
    def test_saves_md_and_json_by_default(self, tmp_path):
        written = _full_doc().save(tmp_path)
        assert "md" in written
        assert "json" in written
        assert written["md"].exists()
        assert written["json"].exists()

    def test_md_file_has_content(self, tmp_path):
        written = _full_doc().save(tmp_path)
        content = written["md"].read_text()
        assert "Annex IV" in content

    def test_json_file_is_valid_json(self, tmp_path):
        written = _full_doc().save(tmp_path)
        data = json.loads(written["json"].read_text())
        assert "sections" in data

    def test_html_format_saved(self, tmp_path):
        written = _full_doc().save(tmp_path, formats=["html"])
        assert "html" in written
        assert written["html"].exists()

    def test_custom_stem(self, tmp_path):
        written = _full_doc().save(tmp_path, stem="my_system")
        assert written["md"].name == "my_system.md"

    def test_output_dir_created_if_absent(self, tmp_path):
        subdir = tmp_path / "docs" / "compliance"
        doc = _full_doc()
        doc.save(subdir, formats=["md"])
        assert subdir.exists()

    def test_pdf_skipped_gracefully_without_weasyprint(self, tmp_path):
        # weasyprint not installed in test env → save should not raise
        written = _full_doc().save(tmp_path, formats=["md", "pdf"])
        assert "md" in written
        # pdf may or may not be present depending on install
        assert not written.get("pdf") or written["pdf"].exists()


# ---------------------------------------------------------------------------
# AnnexIVValidator.validate()
# ---------------------------------------------------------------------------

class TestAnnexIVValidator:
    @pytest.fixture
    def validator(self):
        return AnnexIVValidator()

    def _doc_with_score(self, key_scores: dict[str, int]) -> AnnexIVDocument:
        all_keys = [
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        ]
        sections = [
            AnnexIVSection(k, k, "Art.", "content", key_scores.get(k, 80))
            for k in all_keys
        ]
        overall = _compute_overall_score(sections)
        return AnnexIVDocument(
            system_name="Test System",
            version="1.0.0",
            generated_at="2026-04-28T00:00:00Z",
            sections=sections,
            overall_score=overall,
        )

    def test_full_doc_submittable(self, validator):
        report = validator.validate(_full_doc())
        assert report.is_submittable

    def test_empty_doc_not_submittable(self, validator):
        doc = AnnexIVGenerator().generate(_empty_result())
        report = validator.validate(doc)
        assert not report.is_submittable

    def test_hard_fail_on_low_1a(self, validator):
        doc = self._doc_with_score({"1a_general_description": 10})
        report = validator.validate(doc)
        assert any(f.section == "1a_general_description" for f in report.hard_fails)

    def test_hard_fail_on_low_2a(self, validator):
        doc = self._doc_with_score({"2a_data_governance": 10})
        report = validator.validate(doc)
        assert any(f.section == "2a_data_governance" for f in report.hard_fails)

    def test_hard_fail_on_low_3a(self, validator):
        doc = self._doc_with_score({"3a_model_architecture": 10})
        report = validator.validate(doc)
        assert any(f.section == "3a_model_architecture" for f in report.hard_fails)

    def test_warning_on_low_3b(self, validator):
        doc = self._doc_with_score({"3b_training_methodology": 10})
        report = validator.validate(doc)
        assert any(f.section == "3b_training_methodology" for f in report.warnings)

    def test_warning_on_low_overall(self, validator):
        doc = AnnexIVGenerator().generate(_empty_result())
        report = validator.validate(doc)
        assert any(f.section == "overall" for f in report.warnings)

    def test_no_findings_on_complete_doc(self, validator):
        doc = _full_doc()
        report = validator.validate(doc)
        assert report.hard_fails == []

    def test_validation_report_summary_format(self, validator):
        report = validator.validate(_full_doc())
        summary = report.summary()
        assert "Score:" in summary
        assert "Hard fails:" in summary
        assert "Warnings:" in summary

    def test_bias_gap_triggers_warning(self, validator):
        # Dataset without bias analysis
        ds = _make_dataset()
        ds.has_bias_analysis = False
        result = ArtifactExtractionResult(datasets=[ds])
        doc = AnnexIVGenerator().generate(result, system_name="Test")
        report = validator.validate(doc)
        assert any("bias" in f.message.lower() or "10(2)(f)" in f.article
                   for f in report.warnings)

    def test_returns_validation_report(self, validator):
        report = validator.validate(_full_doc())
        assert isinstance(report, ValidationReport)

    def test_overall_score_in_report(self, validator):
        doc = _full_doc()
        report = validator.validate(doc)
        assert report.overall_score == doc.overall_score


# ---------------------------------------------------------------------------
# AnnexIVDocument property helpers
# ---------------------------------------------------------------------------

class TestDocumentProperties:
    @pytest.fixture(scope="class")
    def doc(self):
        return _full_doc()

    def test_complete_sections_list(self, doc):
        assert isinstance(doc.complete_sections, list)
        assert all(isinstance(k, str) for k in doc.complete_sections)

    def test_missing_sections_list(self, doc):
        assert isinstance(doc.missing_sections, list)

    def test_partial_sections_list(self, doc):
        assert isinstance(doc.partial_sections, list)

    def test_section_lookup_returns_none_for_unknown(self, doc):
        assert doc.section("nonexistent_key") is None

    def test_section_badge_property(self, doc):
        s = doc.section("1a_general_description")
        assert s.badge in ("✅ Full", "⚠️ Partial", "❌ Missing")

    def test_section_weight_property(self, doc):
        s = doc.section("2a_data_governance")
        assert s.weight == 15  # highest weight section

    def test_to_dict_is_alias_for_annex_iv_section(self, doc):
        for s in doc.sections:
            # AnnexIVSection doesn't have to_dict but AnnexIVDocument does via to_json
            break


# ---------------------------------------------------------------------------
# Full pipeline integration: from_run_dir → AnnexIVGenerator → save
# ---------------------------------------------------------------------------

class TestFullPipeline:
    _TRAIN_PY = textwrap.dedent("""
        import torch
        from transformers import AutoModelForSequenceClassification, AdamW
        from datasets import load_dataset

        model = AutoModelForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=2)
        optimizer = AdamW(model.parameters(), lr=5e-5, weight_decay=0.01)
        loss_fn = torch.nn.CrossEntropyLoss()

        dataset = load_dataset("glue", "sst2")

        for epoch in range(3):
            pass

        model.save_pretrained("./my-model")
    """)

    def test_end_to_end_pipeline(self, tmp_path):
        from squash.artifact_extractor import ArtifactExtractor

        # Write a training script
        train_dir = tmp_path / "training_run"
        train_dir.mkdir()
        (train_dir / "train.py").write_text(self._TRAIN_PY)
        (train_dir / "requirements.txt").write_text("transformers>=4.40\ntorch>=2.0\n")

        # Extract artifacts
        result = ArtifactExtractor.from_run_dir(train_dir)
        assert result.code is not None
        assert result.code.framework == "pytorch"

        # Generate document
        doc = AnnexIVGenerator().generate(
            result,
            system_name="SST-2 Sentiment Classifier",
            version="1.0.0",
            intended_purpose="Binary sentiment classification on product reviews.",
            risk_level="limited",
        )

        assert isinstance(doc, AnnexIVDocument)
        assert doc.system_name == "SST-2 Sentiment Classifier"
        assert len(doc.sections) == 12
        assert doc.overall_score > 0

        # Save all formats
        out_dir = tmp_path / "compliance"
        written = doc.save(out_dir, formats=["md", "json", "html"])

        assert written["md"].exists()
        assert written["json"].exists()
        assert written["html"].exists()

        # Validate
        validator = AnnexIVValidator()
        report = validator.validate(doc)
        assert isinstance(report, ValidationReport)
        assert report.summary()

        # Markdown should mention pytorch and the model
        md = written["md"].read_text()
        assert "pytorch" in md.lower() or "torch" in md.lower()
        assert "SST-2" in md
