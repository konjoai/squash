"""tests/test_squash_sprint10.py — Sprint 10 (W192–W194) tests.

Sprint 10: Model Card First-Class CLI (Tier 2 #15).

W192 — Annex IV / bias / lineage data fusion in model_card.py
W193 — squash/model_card_validator.py (HF schema validator)
W194 — CLI: --validate / --validate-only / --push-to-hub flows + extended HF sections
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Fixture helpers ──────────────────────────────────────────────────────────


def _write_squish_json(tmp: Path, model_id: str = "acme/test-int4") -> None:
    (tmp / "squish.json").write_text(
        json.dumps({"model_id": model_id, "quant_format": "INT4"}),
        encoding="utf-8",
    )


def _write_annex_iv(tmp: Path) -> None:
    """Write a minimal annex_iv.json with sections + metadata used by model_card."""
    doc = {
        "squash_version": "annex_iv_v1",
        "system_name": "Acme Sentiment Classifier",
        "version": "1.0.0",
        "generated_at": "2026-04-29T00:00:00Z",
        "overall_score": 87,
        "sections": [
            {
                "key": "§1(b)",
                "title": "Intended Purpose",
                "article": "Annex IV §1(b)",
                "completeness": 90,
                "badge": "✅",
                "gaps": [],
                "content": "Classify product reviews into positive / negative sentiment.",
            },
            {
                "key": "§2(a)",
                "title": "Training Data",
                "article": "Annex IV §2(a)",
                "completeness": 80,
                "badge": "✅",
                "gaps": [],
                "content": "Trained on the IMDb reviews dataset.",
            },
            {
                "key": "§6(a)",
                "title": "Evaluation",
                "article": "Annex IV §6(a)",
                "completeness": 85,
                "badge": "✅",
                "gaps": [],
                "content": "Test accuracy: 0.92 on the held-out IMDb test split.",
            },
        ],
        "metadata": {
            "intended_purpose": "Classify product reviews into positive / negative sentiment.",
            "intended_users": ["E-commerce review moderators"],
            "prohibited_uses": "Do not use for hiring or credit decisions.",
            "risk_management": "Quarterly retraining; drift monitoring via squash watch.",
            "adversarial_testing": "Tested on TextAttack PWWS perturbations; 78% robustness.",
            "oversight_description": "Human-in-the-loop review of all NEGATIVE classifications "
                                     "below 0.7 confidence.",
            "hardware_requirements": "Single A10G GPU; ~2 ms / inference at batch=1.",
        },
    }
    (tmp / "annex_iv.json").write_text(json.dumps(doc), encoding="utf-8")


def _write_bias_audit(tmp: Path, passed: bool = True) -> None:
    doc = {
        "passed": passed,
        "overall_status": "PASS" if passed else "FAIL",
        "protected_attributes": ["gender", "race"],
        "metrics": {"DPD": 0.04, "DIR": 0.92, "EOD": 0.03},
    }
    (tmp / "bias_audit_report.json").write_text(json.dumps(doc), encoding="utf-8")


def _write_lineage(tmp: Path) -> None:
    doc = {
        "datasets": [
            {
                "name": "imdb",
                "license": "other",
                "pii_risk": "low",
                "source": "https://huggingface.co/datasets/imdb",
            },
            {
                "name": "amazon_reviews_multi",
                "license": "Apache-2.0",
                "pii_risk": "medium",
                "source": "https://huggingface.co/datasets/amazon_reviews_multi",
            },
        ],
    }
    (tmp / "data_lineage_certificate.json").write_text(json.dumps(doc), encoding="utf-8")


# ── W192 — Annex IV / bias / lineage data fusion ─────────────────────────────


class TestW192AnnexIVFusion(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        _write_squish_json(self.tmp)

    def test_intended_use_falls_back_without_annex_iv(self) -> None:
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._intended_use_text()
        self.assertIn("text generation tasks", text.lower() + " ")

    def test_intended_use_uses_annex_iv_purpose(self) -> None:
        _write_annex_iv(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._intended_use_text()
        self.assertIn("product reviews", text)
        self.assertIn("Prohibited uses", text)
        self.assertIn("hiring or credit", text)

    def test_limitations_pulls_risk_and_adversarial(self) -> None:
        _write_annex_iv(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._limitations_text()
        self.assertIn("Quarterly retraining", text)
        self.assertIn("PWWS", text)

    def test_bias_summary_empty_when_no_artifact(self) -> None:
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        self.assertEqual(gen._bias_summary(), "")

    def test_bias_summary_lists_protected_attributes(self) -> None:
        _write_bias_audit(self.tmp, passed=True)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._bias_summary()
        self.assertIn("gender", text)
        self.assertIn("race", text)
        self.assertIn("PASS", text)

    def test_bias_summary_reports_failure(self) -> None:
        _write_bias_audit(self.tmp, passed=False)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        self.assertIn("FAIL", gen._bias_summary())

    def test_training_data_falls_back_without_lineage(self) -> None:
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._training_data_text()
        self.assertTrue(len(text) > 0)

    def test_training_data_uses_lineage_certificate(self) -> None:
        _write_lineage(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._training_data_text()
        self.assertIn("imdb", text)
        self.assertIn("amazon_reviews_multi", text)
        self.assertIn("Apache-2.0", text)

    def test_training_data_uses_annex_iv_when_no_lineage(self) -> None:
        _write_annex_iv(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._training_data_text()
        self.assertIn("IMDb", text)

    def test_evaluation_pulls_annex_iv_section(self) -> None:
        _write_annex_iv(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._evaluation_text()
        self.assertIn("0.92", text)

    def test_environmental_impact_uses_hardware(self) -> None:
        _write_annex_iv(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._environmental_impact_text()
        self.assertIn("A10G", text)

    def test_ethical_considerations_uses_oversight(self) -> None:
        _write_annex_iv(self.tmp)
        _write_bias_audit(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        text = gen._ethical_considerations_text()
        self.assertIn("Human-in-the-loop", text)
        self.assertIn("gender", text)

    def test_full_hf_card_renders_extended_sections(self) -> None:
        _write_annex_iv(self.tmp)
        _write_bias_audit(self.tmp)
        _write_lineage(self.tmp)
        from squash.model_card import ModelCardGenerator
        gen = ModelCardGenerator(self.tmp)
        paths = gen.generate("hf")
        body = paths[0].read_text(encoding="utf-8")
        for section in (
            "## Intended Use",
            "## Limitations",
            "## Training Data",
            "## Evaluation",
            "## Environmental Impact",
            "## Ethical Considerations",
            "## How to Use",
        ):
            self.assertIn(section, body, msg=f"missing section: {section}")
        # Annex IV content should be reflected
        self.assertIn("product reviews", body)
        # Lineage content should be reflected
        self.assertIn("imdb", body)
        # Bias content should be reflected
        self.assertIn("gender", body)


# ── W193 — model_card_validator ──────────────────────────────────────────────


class TestW193ValidatorParser(unittest.TestCase):
    def test_parse_simple_scalar_frontmatter(self) -> None:
        from squash.model_card_validator import _parse_frontmatter
        text = "---\nlicense: apache-2.0\nmodel_id: foo/bar\n---\n\n# Hello\n"
        fm = _parse_frontmatter(text)
        self.assertEqual(fm["license"], "apache-2.0")
        self.assertEqual(fm["model_id"], "foo/bar")

    def test_parse_list_frontmatter(self) -> None:
        from squash.model_card_validator import _parse_frontmatter
        text = "---\ntags:\n  - quantized\n  - int4\nlanguage:\n  - en\n  - fr\n---\n"
        fm = _parse_frontmatter(text)
        self.assertEqual(fm["tags"], ["quantized", "int4"])
        self.assertEqual(fm["language"], ["en", "fr"])

    def test_parse_quoted_string(self) -> None:
        from squash.model_card_validator import _parse_frontmatter
        text = '---\ntitle: "with: colon"\n---\n'
        fm = _parse_frontmatter(text)
        self.assertEqual(fm["title"], "with: colon")

    def test_parse_bool(self) -> None:
        from squash.model_card_validator import _parse_frontmatter
        text = "---\nsquash_attested: true\nflag: false\n---\n"
        fm = _parse_frontmatter(text)
        self.assertIs(fm["squash_attested"], True)
        self.assertIs(fm["flag"], False)

    def test_extract_section_titles(self) -> None:
        from squash.model_card_validator import _extract_section_titles
        text = "# H1\n\n## Intended Use\n\nbody\n\n## Limitations\n\nmore\n"
        titles = _extract_section_titles(text)
        self.assertEqual(titles, ["Intended Use", "Limitations"])


class TestW193ValidatorChecks(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def _write(self, text: str) -> Path:
        p = self.tmp / "card.md"
        p.write_text(text, encoding="utf-8")
        return p

    def test_missing_file_is_error(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        report = ModelCardValidator().validate(self.tmp / "no-such.md")
        self.assertFalse(report.is_valid)
        self.assertEqual(report.errors[0].field, "card_path")

    def test_empty_file_is_error(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        p = self._write("")
        report = ModelCardValidator().validate(p)
        self.assertFalse(report.is_valid)

    def test_no_frontmatter_is_error(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        p = self._write("# Hello\n\n## Intended Use\n\nbody\n## Limitations\n\nbody\n")
        report = ModelCardValidator().validate(p)
        self.assertFalse(report.is_valid)
        fields = [e.field for e in report.errors]
        self.assertIn("frontmatter", fields)

    def test_missing_required_frontmatter_field_errors(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        # missing license + tags
        p = self._write(
            "---\nlanguage:\n  - en\n---\n\n## Intended Use\n\nx\n## Limitations\n\nx\n"
        )
        report = ModelCardValidator().validate(p)
        self.assertFalse(report.is_valid)
        err_fields = {e.field for e in report.errors}
        self.assertIn("frontmatter.license", err_fields)
        self.assertIn("frontmatter.tags", err_fields)

    def test_missing_required_section_errors(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        # Missing Limitations
        p = self._write(
            "---\nlicense: apache-2.0\nlanguage:\n  - en\ntags:\n  - x\n---\n\n"
            "## Intended Use\n\nbody\n"
        )
        report = ModelCardValidator().validate(p)
        self.assertFalse(report.is_valid)
        err_fields = {e.field for e in report.errors}
        self.assertIn("section.Limitations", err_fields)

    def test_unknown_license_warns(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        p = self._write(
            "---\nlicense: my-weird-license\nlanguage:\n  - en\ntags:\n  - x\n"
            "pipeline_tag: text-generation\n---\n\n"
            "## Intended Use\n\n" + ("filler " * 50) + "\n"
            "## Limitations\n\n" + ("filler " * 50) + "\n"
        )
        report = ModelCardValidator().validate(p)
        self.assertTrue(report.is_valid)
        warn_fields = {w.field for w in report.warnings}
        self.assertIn("frontmatter.license", warn_fields)

    def test_recommended_section_missing_is_info(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        p = self._write(
            "---\nlicense: apache-2.0\nlanguage:\n  - en\ntags:\n  - x\n"
            "pipeline_tag: text-generation\nmodel_id: foo/bar\n---\n\n"
            "## Intended Use\n\n" + ("filler " * 60) + "\n"
            "## Limitations\n\n" + ("filler " * 60) + "\n"
        )
        report = ModelCardValidator().validate(p)
        self.assertTrue(report.is_valid)
        info_fields = {i.field for i in report.infos}
        # Training Data, Evaluation, etc. should be flagged as info-missing
        self.assertIn("section.Training Data", info_fields)

    def test_short_body_warns(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        p = self._write(
            "---\nlicense: apache-2.0\nlanguage:\n  - en\ntags:\n  - x\n---\n\n"
            "## Intended Use\n\nshort\n"
            "## Limitations\n\nshort\n"
        )
        report = ModelCardValidator().validate(p)
        warn_fields = {w.field for w in report.warnings}
        self.assertIn("body", warn_fields)

    def test_to_dict_round_trip(self) -> None:
        from squash.model_card_validator import ModelCardValidator
        p = self._write(
            "---\nlicense: apache-2.0\nlanguage:\n  - en\ntags:\n  - x\n---\n\n"
            "## Intended Use\n\n" + ("filler " * 60) + "\n"
            "## Limitations\n\n" + ("filler " * 60) + "\n"
        )
        report = ModelCardValidator().validate(p)
        d = report.to_dict()
        self.assertIn("is_valid", d)
        self.assertIn("frontmatter", d)
        self.assertIn("errors", d)


# ── W194 — CLI integration: validate / push / extended sections ──────────────


class TestW194CLIValidate(unittest.TestCase):
    """Integration tests of `squash model-card --validate` / --validate-only."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        _write_squish_json(self.tmp)
        _write_annex_iv(self.tmp)
        _write_bias_audit(self.tmp)
        _write_lineage(self.tmp)

    def test_generate_then_validate_passes(self) -> None:
        result = subprocess.run(
            [
                sys.executable, "-m", "squash.cli", "model-card",
                str(self.tmp), "--format", "hf", "--validate", "--quiet",
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        # generated card should exist
        self.assertTrue((self.tmp / "squash-model-card-hf.md").exists())

    def test_validate_only_on_existing_card(self) -> None:
        # First generate
        subprocess.run(
            [sys.executable, "-m", "squash.cli", "model-card",
             str(self.tmp), "--format", "hf", "--quiet"],
            check=True, capture_output=True,
        )
        # Now validate-only
        result = subprocess.run(
            [
                sys.executable, "-m", "squash.cli", "model-card",
                str(self.tmp), "--validate-only", "--quiet",
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_validate_only_json_emits_structured_report(self) -> None:
        subprocess.run(
            [sys.executable, "-m", "squash.cli", "model-card",
             str(self.tmp), "--format", "hf", "--quiet"],
            check=True, capture_output=True,
        )
        result = subprocess.run(
            [
                sys.executable, "-m", "squash.cli", "model-card",
                str(self.tmp), "--validate-only", "--json",
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("is_valid", payload)
        self.assertTrue(payload["is_valid"])

    def test_validate_only_missing_card_fails(self) -> None:
        empty = Path(tempfile.mkdtemp())
        result = subprocess.run(
            [
                sys.executable, "-m", "squash.cli", "model-card",
                str(empty), "--validate-only",
            ],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)


class TestW194CLIPush(unittest.TestCase):
    """Test the --push-to-hub flow with huggingface_hub mocked."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        _write_squish_json(self.tmp)
        # Pre-generate the card so push has something to upload
        from squash.model_card import ModelCardConfig, ModelCardGenerator
        gen = ModelCardGenerator(self.tmp, ModelCardConfig(model_dir=self.tmp))
        gen.generate("hf")

    def test_push_without_huggingface_hub_returns_2(self) -> None:
        # Force ImportError by monkey-patching sys.modules then calling
        # the CLI helper directly.
        from squash import cli as _cli
        with mock.patch.dict(sys.modules, {"huggingface_hub": None}):
            rc = _cli._model_card_push(
                card_path=self.tmp / "squash-model-card-hf.md",
                repo_id="user/model",
                token="dummy",
                quiet=True,
            )
        self.assertEqual(rc, 2)

    def test_push_without_token_returns_1(self) -> None:
        from squash import cli as _cli
        fake_hf = mock.MagicMock()
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}), \
             mock.patch.dict("os.environ", {}, clear=False):
            # Strip env tokens for the duration
            import os as _os
            for k in ("HUGGING_FACE_HUB_TOKEN", "HF_TOKEN"):
                _os.environ.pop(k, None)
            rc = _cli._model_card_push(
                card_path=self.tmp / "squash-model-card-hf.md",
                repo_id="user/model",
                token=None,
                quiet=True,
            )
        self.assertEqual(rc, 1)

    def test_push_calls_hf_upload_file(self) -> None:
        from squash import cli as _cli
        fake_api = mock.MagicMock()
        fake_module = mock.MagicMock()
        fake_module.HfApi = mock.MagicMock(return_value=fake_api)
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_module}):
            rc = _cli._model_card_push(
                card_path=self.tmp / "squash-model-card-hf.md",
                repo_id="user/model",
                token="dummy",
                quiet=True,
            )
        self.assertEqual(rc, 0)
        fake_api.upload_file.assert_called_once()
        kwargs = fake_api.upload_file.call_args.kwargs
        self.assertEqual(kwargs.get("repo_id"), "user/model")
        self.assertEqual(kwargs.get("path_in_repo"), "README.md")

    def test_push_missing_card_returns_1(self) -> None:
        from squash import cli as _cli
        fake_module = mock.MagicMock()
        fake_module.HfApi = mock.MagicMock()
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_module}):
            rc = _cli._model_card_push(
                card_path=self.tmp / "no-such.md",
                repo_id="user/model",
                token="dummy",
                quiet=True,
            )
        self.assertEqual(rc, 1)


class TestW194CLIPushSurface(unittest.TestCase):
    """End-to-end: --push-to-hub flag is wired and reports missing dep cleanly."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        _write_squish_json(self.tmp)

    def test_push_flag_is_wired_in_argparse(self) -> None:
        # Check the help surface exposes the new flags
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "model-card", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--validate", "--validate-only", "--push-to-hub", "--hub-token"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing from --help output")


if __name__ == "__main__":
    unittest.main()
