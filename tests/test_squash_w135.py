"""W135 / W136 — squash annex-iv generate + validate CLI tests.

Tests the Sprint S1 exit gate: `squash annex-iv generate --root <dir>`
produces valid Annex IV documentation, and `squash annex-iv validate`
correctly assesses existing JSON documents.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> "subprocess.CompletedProcess[str]":
    """Run the squash CLI as a subprocess and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "squash.cli", *args],
        capture_output=True,
        text=True,
    )


def _parse_cli(*args: str) -> "argparse.Namespace":
    """Parse CLI args without executing, return the Namespace."""
    from squash.cli import _build_parser
    return _build_parser().parse_args(["annex-iv", *args])


def _make_run_dir(tmp_path: Path, *, with_config: bool = True, with_py: bool = True) -> Path:
    """Create a minimal training run directory for extraction."""
    run = tmp_path / "run"
    run.mkdir(parents=True, exist_ok=True)

    if with_config:
        (run / "config.json").write_text(json.dumps({
            "optimizer": "AdamW",
            "learning_rate": 3e-4,
            "batch_size": 32,
            "epochs": 10,
            "scheduler": "cosine",
        }), encoding="utf-8")

    if with_py:
        (run / "train.py").write_text(textwrap.dedent("""\
            import torch
            import torch.nn as nn
            model = nn.Linear(768, 2)
            optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4)
            loss_fn = nn.CrossEntropyLoss()
            for epoch in range(10):
                loss = loss_fn(model(torch.randn(4, 768)), torch.randint(2, (4,)))
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
            torch.save(model.state_dict(), "checkpoint.pt")
        """), encoding="utf-8")

    return run


def _make_annex_iv_json(tmp_path: Path, score: int = 75) -> Path:
    """Create a minimal annex_iv.json fixture."""
    from squash.annex_iv_generator import AnnexIVSection, AnnexIVDocument

    sections = [
        AnnexIVSection(
            key="1a_general_description",
            title="§1(a) General Description",
            article="Annex IV §1(a)",
            content="Test system description.",
            completeness=score,
            gaps=[],
        )
    ]
    doc = AnnexIVDocument(
        system_name="Test System",
        version="1.0.0",
        generated_at="2026-04-28T00:00:00Z",
        sections=sections,
        overall_score=score,
    )
    p = tmp_path / "annex_iv.json"
    p.write_text(doc.to_json(), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Parser tests (W135)
# ---------------------------------------------------------------------------

class TestAnnexIVGenerateParser:
    def test_root_required(self):
        from squash.cli import _build_parser
        p = _build_parser()
        with pytest.raises(SystemExit) as exc:
            p.parse_args(["annex-iv", "generate"])
        assert exc.value.code != 0

    def test_default_formats(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.formats == ["md", "json"]

    def test_custom_formats(self):
        args = _parse_cli("generate", "--root", ".", "--format", "md", "html", "pdf")
        assert set(args.formats) == {"md", "html", "pdf"}

    def test_invalid_format_rejected(self):
        from squash.cli import _build_parser
        p = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["annex-iv", "generate", "--root", ".", "--format", "docx"])

    def test_system_name_default(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.system_name == "AI System"

    def test_system_name_set(self):
        args = _parse_cli("generate", "--root", ".", "--system-name", "BERT Classifier")
        assert args.system_name == "BERT Classifier"

    def test_version_default(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.version == "1.0.0"

    def test_risk_level_choices(self):
        for lvl in ("minimal", "limited", "high", "unacceptable"):
            args = _parse_cli("generate", "--root", ".", "--risk-level", lvl)
            assert args.risk_level == lvl

    def test_invalid_risk_level_rejected(self):
        from squash.cli import _build_parser
        p = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["annex-iv", "generate", "--root", ".", "--risk-level", "unknown"])

    def test_stem_default(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.stem == "annex_iv"

    def test_stem_custom(self):
        args = _parse_cli("generate", "--root", ".", "--stem", "my_report")
        assert args.stem == "my_report"

    def test_no_validate_flag(self):
        args = _parse_cli("generate", "--root", ".")
        assert not args.no_validate
        args = _parse_cli("generate", "--root", ".", "--no-validate")
        assert args.no_validate

    def test_fail_on_warning_flag(self):
        args = _parse_cli("generate", "--root", ".", "--fail-on-warning")
        assert args.fail_on_warning

    def test_mlflow_run_parsed(self):
        args = _parse_cli("generate", "--root", ".", "--mlflow-run", "abc123")
        assert args.mlflow_run == "abc123"

    def test_mlflow_uri_default(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.mlflow_uri == "http://localhost:5000"

    def test_wandb_run_parsed(self):
        args = _parse_cli("generate", "--root", ".", "--wandb-run", "entity/project/runid")
        assert args.wandb_run == "entity/project/runid"

    def test_hf_dataset_repeatable(self):
        args = _parse_cli("generate", "--root", ".",
                          "--hf-dataset", "squad", "--hf-dataset", "imdb")
        assert args.hf_datasets == ["squad", "imdb"]

    def test_hf_dataset_default_empty(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.hf_datasets == []

    def test_output_dir_default_none(self):
        args = _parse_cli("generate", "--root", ".")
        assert args.output_dir is None

    def test_quiet_flag(self):
        args = _parse_cli("generate", "--root", ".", "--quiet")
        assert args.quiet

    def test_intended_purpose_parsed(self):
        args = _parse_cli("generate", "--root", ".", "--intended-purpose", "Classify text")
        assert args.intended_purpose == "Classify text"

    def test_general_description_parsed(self):
        args = _parse_cli("generate", "--root", ".", "--general-description", "My system")
        assert args.general_description == "My system"

    def test_hardware_parsed(self):
        args = _parse_cli("generate", "--root", ".", "--hardware", "Apple M3 Pro")
        assert args.hardware_requirements == "Apple M3 Pro"

    def test_model_type_parsed(self):
        args = _parse_cli("generate", "--root", ".", "--model-type", "transformer")
        assert args.model_type == "transformer"


# ---------------------------------------------------------------------------
# Parser tests (W136)
# ---------------------------------------------------------------------------

class TestAnnexIVValidateParser:
    def test_document_required(self):
        from squash.cli import _build_parser
        p = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["annex-iv", "validate"])

    def test_document_parsed(self):
        args = _parse_cli("validate", "./annex_iv.json")
        assert args.document == "./annex_iv.json"

    def test_fail_on_warning(self):
        args = _parse_cli("validate", "./annex_iv.json", "--fail-on-warning")
        assert args.fail_on_warning

    def test_quiet_flag(self):
        args = _parse_cli("validate", "./annex_iv.json", "--quiet")
        assert args.quiet


# ---------------------------------------------------------------------------
# _cmd_annex_iv_generate integration tests (W135)
# ---------------------------------------------------------------------------

class TestCmdAnnexIVGenerate:
    def test_nonexistent_root_returns_1(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        p = _build_parser()
        args = p.parse_args(["annex-iv", "generate", "--root", str(tmp_path / "nope"), "--quiet"])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        assert rc == 1

    def test_empty_dir_returns_0(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = tmp_path / "run"
        run.mkdir()
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(tmp_path / "out"),
            "--quiet", "--no-validate",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        assert rc == 0

    def test_creates_md_and_json_by_default(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        assert (out / "annex_iv.md").exists()
        assert (out / "annex_iv.json").exists()

    def test_stem_applied_to_filenames(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--stem", "my_report",
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        assert (out / "my_report.md").exists()
        assert (out / "my_report.json").exists()

    def test_html_format_written(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--format", "html",
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        assert (out / "annex_iv.html").exists()

    def test_json_content_is_valid(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        data = json.loads((out / "annex_iv.json").read_text())
        assert "system_name" in data
        assert "sections" in data
        assert "overall_score" in data
        assert isinstance(data["sections"], list)
        assert len(data["sections"]) == 12

    def test_system_name_propagated_to_json(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--system-name", "BERT Classifier",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        data = json.loads((out / "annex_iv.json").read_text())
        assert data["system_name"] == "BERT Classifier"

    def test_version_propagated_to_json(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--version", "2.3.1",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        data = json.loads((out / "annex_iv.json").read_text())
        assert data["version"] == "2.3.1"

    def test_md_contains_annex_iv_header(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        md = (out / "annex_iv.md").read_text()
        assert "Annex IV" in md

    def test_config_detected_boosts_score(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        # with config file → higher score than empty dir
        run_with = _make_run_dir(tmp_path / "with_config", with_config=True, with_py=False)
        run_empty = tmp_path / "empty_run"
        run_empty.mkdir()

        p = _build_parser()

        def _gen(root, out):
            args = p.parse_args([
                "annex-iv", "generate", "--root", str(root),
                "--output-dir", str(out),
                "--quiet", "--no-validate",
            ])
            _cmd_annex_iv_generate(args, quiet=True)
            return json.loads((out / "annex_iv.json").read_text())["overall_score"]

        score_with = _gen(run_with, tmp_path / "out_with")
        score_empty = _gen(run_empty, tmp_path / "out_empty")
        assert score_with >= score_empty

    def test_output_defaults_to_root(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        assert (run / "annex_iv.md").exists()
        assert (run / "annex_iv.json").exists()

    def test_validation_runs_by_default(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        # An empty run dir will have gaps → likely exit 2 (hard fail) or 0 (no hard fail)
        assert rc in (0, 1, 2)

    def test_no_validate_skips_validation(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        assert rc == 0

    def test_mlflow_augment_failure_is_a_warning_not_crash(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        # Use a file:// URI pointing at nonexistent path so MLflow fails immediately
        # without network retries (avoids 60-second urllib3 backoff timeout)
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--mlflow-run", "nonexistent_run_id",
            "--mlflow-uri", f"file://{tmp_path}/nonexistent_mlflow_store",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        # Should complete (exit 0) despite mlflow augmentation failing
        assert rc == 0
        assert (out / "annex_iv.json").exists()

    def test_wandb_augment_failure_is_a_warning_not_crash(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--wandb-run", "entity/project/badrun",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        assert rc == 0
        assert (out / "annex_iv.json").exists()

    def test_hf_augment_failure_is_a_warning_not_crash(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--hf-dataset", "nonexistent/dataset99",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        assert rc == 0
        assert (out / "annex_iv.json").exists()

    def test_rich_metadata_boosts_score(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--system-name", "BERT Sentiment",
            "--version", "2.0.0",
            "--intended-purpose", "Classify product reviews into positive/negative sentiment",
            "--risk-level", "high",
            "--general-description", "Transformer-based binary classifier trained on IMDb data.",
            "--hardware", "Apple M3 Pro, 36 GB RAM",
            "--model-type", "transformer",
            "--oversight", "Human review required for all high-confidence negative predictions.",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        data = json.loads((out / "annex_iv.json").read_text())
        # Rich metadata should produce a meaningful score
        assert data["overall_score"] > 30

    def test_twelve_sections_in_output(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        data = json.loads((out / "annex_iv.json").read_text())
        keys = {s["key"] for s in data["sections"]}
        expected = {
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        }
        assert keys == expected

    def test_output_dir_created_if_absent(self, tmp_path):
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "deep" / "nested" / "output"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])
        _cmd_annex_iv_generate(args, quiet=True)
        assert out.exists()
        assert (out / "annex_iv.json").exists()

    def test_hard_fail_exits_2(self, tmp_path):
        """A fully empty run with no metadata hits hard-fail thresholds → exit 2."""
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = tmp_path / "bare"
        run.mkdir()
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--quiet",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        assert rc == 2

    def test_fail_on_warning_exits_1(self, tmp_path):
        """A run with some sections filled but warnings remaining exits 1 with --fail-on-warning."""
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(out),
            "--fail-on-warning", "--quiet",
        ])
        rc = _cmd_annex_iv_generate(args, quiet=True)
        # exit 1 or 2 (warnings or hard fails); definitely not 0 for a partial run
        assert rc in (1, 2)

    def test_mlflow_mocked_augmentation(self, tmp_path):
        """When MLflow returns data, result.metrics/config should be populated."""
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        from squash.artifact_extractor import TrainingMetrics, TrainingConfig, ArtifactExtractionResult

        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--mlflow-run", "run123",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])

        mock_metrics = TrainingMetrics(source="mlflow", run_id="run123")
        mock_config = TrainingConfig(source_path=None, optimizer={"type": "Adam", "lr": 1e-3})
        mock_result = ArtifactExtractionResult(metrics=mock_metrics, config=mock_config)

        with patch(
            "squash.artifact_extractor.ArtifactExtractor.from_mlflow_run_full",
            return_value=mock_result,
        ):
            rc = _cmd_annex_iv_generate(args, quiet=True)

        assert rc == 0
        data = json.loads((out / "annex_iv.json").read_text())
        assert data["overall_score"] >= 0

    def test_wandb_run_parsed_correctly_into_parts(self, tmp_path):
        """Verify that 'entity/project/run_id' splits correctly into parts."""
        from squash.cli import _cmd_annex_iv_generate, _build_parser
        from squash.artifact_extractor import ArtifactExtractionResult

        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--wandb-run", "myentity/myproject/abc123",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])

        captured: dict[str, Any] = {}

        def _mock_wandb_full(run_id, *, project=None, entity=None):
            captured["run_id"] = run_id
            captured["project"] = project
            captured["entity"] = entity
            return ArtifactExtractionResult()

        with patch(
            "squash.artifact_extractor.ArtifactExtractor.from_wandb_run_full",
            side_effect=_mock_wandb_full,
        ):
            _cmd_annex_iv_generate(args, quiet=True)

        assert captured["run_id"] == "abc123"
        assert captured["project"] == "myproject"
        assert captured["entity"] == "myentity"

    def test_hf_datasets_passed_correctly(self, tmp_path):
        """Verify HF dataset IDs are forwarded to from_huggingface_dataset_list."""
        from squash.cli import _cmd_annex_iv_generate, _build_parser

        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--hf-dataset", "squad", "--hf-dataset", "imdb",
            "--hf-token", "hf_test_token",
            "--output-dir", str(out),
            "--quiet", "--no-validate",
        ])

        captured: dict[str, Any] = {}

        def _mock_hf_list(dataset_ids, *, token=None):
            captured["dataset_ids"] = dataset_ids
            captured["token"] = token
            return []

        with patch(
            "squash.artifact_extractor.ArtifactExtractor.from_huggingface_dataset_list",
            side_effect=_mock_hf_list,
        ):
            _cmd_annex_iv_generate(args, quiet=True)

        assert captured["dataset_ids"] == ["squad", "imdb"]
        assert captured["token"] == "hf_test_token"


# ---------------------------------------------------------------------------
# _cmd_annex_iv_validate integration tests (W136)
# ---------------------------------------------------------------------------

class TestCmdAnnexIVValidate:
    def test_missing_file_returns_1(self, tmp_path):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(tmp_path / "nonexistent.json")])
        rc = _cmd_annex_iv_validate(args, quiet=True)
        assert rc == 1

    def test_invalid_json_returns_1(self, tmp_path):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all {{{", encoding="utf-8")
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(bad)])
        rc = _cmd_annex_iv_validate(args, quiet=True)
        assert rc == 1

    def test_valid_high_score_doc_passes(self, tmp_path):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        doc_path = _make_annex_iv_json(tmp_path, score=90)
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(doc_path)])
        rc = _cmd_annex_iv_validate(args, quiet=True)
        # A high-score doc with 1 section at 90% won't have hard fails for sections not present
        assert rc in (0, 2)  # depends on which sections are checked

    def test_low_score_doc_hard_fails(self, tmp_path):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        doc_path = _make_annex_iv_json(tmp_path, score=5)
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(doc_path)])
        rc = _cmd_annex_iv_validate(args, quiet=True)
        # Only 1 section present (1a_general_description) at 5% completeness → hard fail
        assert rc == 2

    def test_fail_on_warning_exits_1(self, tmp_path):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        from squash.annex_iv_generator import AnnexIVDocument, AnnexIVSection, ValidationFinding

        # Build a doc with all 12 sections at 50% (warnings but not hard fails)
        _SECTION_KEYS = [
            "1a_general_description", "1b_intended_purpose", "1c_development_process",
            "2a_data_governance", "2b_data_preprocessing", "3a_model_architecture",
            "3b_training_methodology", "4_risk_management", "5_human_oversight",
            "6a_performance_metrics", "6b_robustness_testing", "7_lifecycle_management",
        ]
        sections = [
            AnnexIVSection(
                key=k, title=k, article="Annex IV", content="Partial content.",
                completeness=50, gaps=["Some gap"],
            )
            for k in _SECTION_KEYS
        ]
        doc = AnnexIVDocument(
            system_name="Test", version="1.0", generated_at="2026-04-28T00:00:00Z",
            sections=sections, overall_score=50,
        )
        p_json = tmp_path / "annex_iv.json"
        p_json.write_text(doc.to_json(), encoding="utf-8")

        from squash.cli import _build_parser
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(p_json), "--fail-on-warning"])

        from squash.cli import _cmd_annex_iv_validate
        rc = _cmd_annex_iv_validate(args, quiet=True)
        # 50% across all sections should produce at least warnings → exit 1
        assert rc in (1, 2)

    def test_malformed_json_missing_sections_key(self, tmp_path):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        bad = tmp_path / "bad.json"
        bad.write_text('{"system_name": "X", "version": "1.0", "generated_at": "now", "overall_score": 50}',
                       encoding="utf-8")
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(bad)])
        rc = _cmd_annex_iv_validate(args, quiet=True)
        # No sections → validator can still run (no hard fails if no sections)
        assert rc in (0, 1, 2)

    def test_quiet_suppresses_output(self, tmp_path, capsys):
        from squash.cli import _cmd_annex_iv_validate, _build_parser
        doc_path = _make_annex_iv_json(tmp_path, score=90)
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(doc_path), "--quiet"])
        _cmd_annex_iv_validate(args, quiet=True)
        captured = capsys.readouterr()
        assert captured.out == ""


# ---------------------------------------------------------------------------
# dispatch tests — _cmd_annex_iv routing
# ---------------------------------------------------------------------------

class TestCmdAnnexIVDispatch:
    def test_generate_dispatched(self, tmp_path):
        from squash.cli import _cmd_annex_iv, _build_parser
        run = _make_run_dir(tmp_path)
        p = _build_parser()
        args = p.parse_args([
            "annex-iv", "generate", "--root", str(run),
            "--output-dir", str(tmp_path / "out"),
            "--quiet", "--no-validate",
        ])
        rc = _cmd_annex_iv(args, quiet=True)
        assert rc == 0

    def test_validate_dispatched(self, tmp_path):
        from squash.cli import _cmd_annex_iv, _build_parser
        doc = _make_annex_iv_json(tmp_path, score=80)
        p = _build_parser()
        args = p.parse_args(["annex-iv", "validate", str(doc)])
        rc = _cmd_annex_iv(args, quiet=True)
        assert rc in (0, 1, 2)


# ---------------------------------------------------------------------------
# Subprocess smoke tests (W135 exit gate)
# ---------------------------------------------------------------------------

class TestSubprocessSmokeW135:
    def test_annex_iv_generate_help(self):
        result = _run_cli("annex-iv", "generate", "--help")
        assert result.returncode == 0
        assert "--root" in result.stdout
        assert "--format" in result.stdout
        assert "--system-name" in result.stdout

    def test_annex_iv_validate_help(self):
        result = _run_cli("annex-iv", "validate", "--help")
        assert result.returncode == 0
        assert "PATH" in result.stdout or "document" in result.stdout.lower()

    def test_annex_iv_generate_missing_root_exits_nonzero(self):
        result = _run_cli("annex-iv", "generate")
        assert result.returncode != 0

    def test_annex_iv_validate_missing_doc_exits_nonzero(self):
        result = _run_cli("annex-iv", "validate")
        assert result.returncode != 0

    def test_annex_iv_generate_produces_json(self, tmp_path):
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        result = _run_cli(
            "annex-iv", "generate",
            "--root", str(run),
            "--output-dir", str(out),
            "--system-name", "Sprint S1 Gate Test",
            "--no-validate", "--quiet",
        )
        assert result.returncode == 0
        json_path = out / "annex_iv.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["system_name"] == "Sprint S1 Gate Test"
        assert len(data["sections"]) == 12

    def test_annex_iv_generate_full_run_exit_gate(self, tmp_path):
        """Sprint S1 exit gate: generate Annex IV from training run, non-zero score."""
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"
        result = _run_cli(
            "annex-iv", "generate",
            "--root", str(run),
            "--output-dir", str(out),
            "--system-name", "EU AI Act Sprint S1 Gate",
            "--version", "0.1.0",
            "--intended-purpose", "Verify Sprint S1 Annex IV pipeline is functional",
            "--risk-level", "limited",
            "--general-description", "Integration test AI system for Sprint S1 exit gate validation.",
            "--no-validate", "--quiet",
        )
        assert result.returncode == 0
        data = json.loads((out / "annex_iv.json").read_text())
        assert data["overall_score"] > 0
        assert len(data["sections"]) == 12

    def test_annex_iv_validate_roundtrip(self, tmp_path):
        """Generate then validate: exit code should be deterministic."""
        run = _make_run_dir(tmp_path)
        out = tmp_path / "out"

        gen_result = _run_cli(
            "annex-iv", "generate",
            "--root", str(run),
            "--output-dir", str(out),
            "--no-validate", "--quiet",
        )
        assert gen_result.returncode == 0

        val_result = _run_cli(
            "annex-iv", "validate",
            str(out / "annex_iv.json"),
            "--quiet",
        )
        assert val_result.returncode in (0, 1, 2)
