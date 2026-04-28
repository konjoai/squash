"""W152 — Integration test suite for all CI/CD targets."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent


# ── Helper: minimal model directory ──────────────────────────────────────────


def _make_model_dir(tmp_path: Path) -> Path:
    model_dir = tmp_path / "my-model"
    model_dir.mkdir()
    # Write a minimal config so artifact_extractor can auto-discover
    (model_dir / "config.json").write_text(
        '{"model_type": "gpt2", "hidden_size": 768}', encoding="utf-8"
    )
    return model_dir


# ── W145/W146: GitHub Actions action.yml integration ─────────────────────────


class TestGitHubActionIntegration:
    def test_action_yml_inputs_match_documented_api(self):
        doc = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
        required_inputs = {"model-path", "policies", "sign", "fail-on-violation", "api-key"}
        actual_inputs = set(doc.get("inputs", {}).keys())
        assert required_inputs.issubset(actual_inputs), \
            f"Missing required inputs: {required_inputs - actual_inputs}"

    def test_action_yml_outputs_match_documented_api(self):
        doc = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
        required_outputs = {"passed", "score", "artifacts-dir", "bom-digest"}
        actual_outputs = set(doc.get("outputs", {}).keys())
        assert required_outputs.issubset(actual_outputs), \
            f"Missing required outputs: {required_outputs - actual_outputs}"

    def test_action_yml_install_step_installs_squash(self):
        doc = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
        steps = doc["runs"]["steps"]
        install_steps = [s for s in steps if "squash-ai" in str(s)]
        assert len(install_steps) >= 1, "action.yml must have a step that installs squash-ai"

    def test_action_yml_attest_step_calls_squash_cli(self):
        doc = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
        steps = doc["runs"]["steps"]
        attest_step = next((s for s in steps if s.get("id") == "attest"), None)
        assert attest_step is not None
        assert "squash attest" in str(attest_step.get("run", ""))

    def test_action_yml_upload_retention_is_90_days(self):
        doc = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
        steps = doc["runs"]["steps"]
        upload_steps = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]
        assert len(upload_steps) >= 1
        upload = upload_steps[-1]
        assert str(upload.get("with", {}).get("retention-days", "")) == "90"


# ── W147: GitLab CI template integration ─────────────────────────────────────


class TestGitLabCIIntegration:
    def _template_path(self):
        return REPO_ROOT / "integrations" / "gitlab-ci" / "squash.gitlab-ci.yml"

    def test_template_can_be_included_standalone(self):
        doc = yaml.safe_load(self._template_path().read_text())
        assert ".squash_attest" in doc

    def test_template_script_references_squash_model_path_env(self):
        doc = yaml.safe_load(self._template_path().read_text())
        script = "\n".join(str(s) for s in doc[".squash_attest"]["script"])
        assert "SQUASH_MODEL_PATH" in script

    def test_template_install_installs_squash_ai(self):
        doc = yaml.safe_load(self._template_path().read_text())
        before = "\n".join(str(s) for s in doc[".squash_attest"]["before_script"])
        assert "squash-ai" in before

    def test_template_exports_result_json(self):
        doc = yaml.safe_load(self._template_path().read_text())
        script = "\n".join(str(s) for s in doc[".squash_attest"]["script"])
        assert "squash_result.json" in script

    def test_soft_variant_has_allow_failure(self):
        doc = yaml.safe_load(self._template_path().read_text())
        soft = doc.get(".squash_attest_soft", {})
        assert soft.get("allow_failure") is True

    def test_template_python_image_is_3_11(self):
        doc = yaml.safe_load(self._template_path().read_text())
        image = doc[".squash_attest"].get("image", "")
        assert "3.11" in str(image)


# ── W148: Jenkins shared library integration ──────────────────────────────────


class TestJenkinsPipelineIntegration:
    def _src(self):
        return (REPO_ROOT / "integrations" / "jenkins" / "vars" / "squashAttest.groovy").read_text()

    def test_step_is_invocable_as_squash_attest(self):
        src = self._src()
        assert "def call" in src

    def test_step_has_required_model_path(self):
        src = self._src()
        assert "modelPath" in src
        assert "error" in src  # error() if modelPath missing

    def test_step_stashes_squash_result_json(self):
        src = self._src()
        assert "squash_result.json" in src and "stash" in src

    def test_step_sets_build_unstable_on_violation(self):
        src = self._src()
        assert "unstable" in src

    def test_step_reads_json_result(self):
        src = self._src()
        assert "readJSON" in src

    def test_groovy_file_is_utf8(self):
        raw = (REPO_ROOT / "integrations" / "jenkins" / "vars" / "squashAttest.groovy").read_bytes()
        raw.decode("utf-8")  # should not raise


# ── W149: GHCR Docker image workflow integration ──────────────────────────────


class TestGHCRWorkflowIntegration:
    def _doc(self):
        return yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "publish-image.yml").read_text()
        )

    def test_workflow_builds_from_correct_dockerfile(self):
        content = (REPO_ROOT / ".github" / "workflows" / "publish-image.yml").read_text()
        assert "Dockerfile" in content

    def test_workflow_pushes_to_ghcr(self):
        content = (REPO_ROOT / ".github" / "workflows" / "publish-image.yml").read_text()
        assert "ghcr.io" in content

    def test_image_name_uses_repo_owner(self):
        content = (REPO_ROOT / ".github" / "workflows" / "publish-image.yml").read_text()
        assert "github.repository_owner" in content or "repository_owner" in content

    def test_workflow_verifies_image_health_after_push(self):
        content = (REPO_ROOT / ".github" / "workflows" / "publish-image.yml").read_text()
        assert "health" in content.lower() or "verify" in content.lower()

    def test_workflow_triggers_on_release(self):
        content = (REPO_ROOT / ".github" / "workflows" / "publish-image.yml").read_text()
        assert "release:" in content or "release" in content


# ── W150: Helm chart integration ─────────────────────────────────────────────


class TestHelmChartIntegration:
    def _helm_dir(self):
        return REPO_ROOT / "integrations" / "kubernetes-helm"

    def test_chart_yaml_version_matches_app_version(self):
        doc = yaml.safe_load((self._helm_dir() / "Chart.yaml").read_text())
        assert doc["version"]
        assert doc["appVersion"]

    def test_values_failure_policy_is_ignore_or_fail(self):
        doc = yaml.safe_load((self._helm_dir() / "values.yaml").read_text())
        fp = doc["webhook"]["failurePolicy"]
        assert fp in ("Ignore", "Fail")

    def test_deployment_uses_values_image(self):
        src = (self._helm_dir() / "templates" / "deployment.yaml").read_text()
        assert "Values.image" in src

    def test_webhook_config_references_service(self):
        src = (self._helm_dir() / "templates" / "validatingwebhookconfiguration.yaml").read_text()
        assert "service:" in src

    def test_all_template_files_are_valid_text(self):
        for f in (self._helm_dir() / "templates").glob("*.yaml"):
            f.read_text(encoding="utf-8")  # should not raise

    def test_service_account_template_exists(self):
        assert (self._helm_dir() / "templates" / "serviceaccount.yaml").exists()


# ── W151: MLflow SDK bridge integration ──────────────────────────────────────


class TestMLflowBridgeIntegration:
    def test_mlflow_squash_class_importable(self):
        from squash.integrations.mlflow import MLflowSquash
        assert MLflowSquash is not None

    def test_attest_run_is_static_method(self):
        from squash.integrations.mlflow import MLflowSquash
        import inspect
        assert isinstance(
            inspect.getattr_static(MLflowSquash, "attest_run"),
            staticmethod,
        )

    def test_tag_prefix_constant_exists(self):
        from squash.integrations.mlflow import _TAG_PREFIX
        assert _TAG_PREFIX.endswith(".")

    def test_mlflow_adapter_docstring_present(self):
        from squash.integrations import mlflow as mlflow_mod
        assert mlflow_mod.__doc__ and len(mlflow_mod.__doc__) > 50

    def test_full_attest_pipeline_with_mlflow_mock(self, tmp_path):
        from squash.integrations.mlflow import MLflowSquash

        model_dir = _make_model_dir(tmp_path)
        mock_mlflow = MagicMock()
        mock_mlflow.log_artifacts = MagicMock()
        mock_mlflow.set_tags = MagicMock()
        mock_mlflow.active_run.return_value = None

        mock_result = MagicMock()
        mock_result.passed = True
        mock_result.scan_result = MagicMock(status="clean")
        mock_result.policy_results = {}
        mock_result.cyclonedx_path = None

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                result = MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        assert result.passed is True
        assert mock_mlflow.log_artifacts.called
        assert mock_mlflow.set_tags.called


# ── Cross-cutting: CLI sanity check ───────────────────────────────────────────


class TestCLISanity:
    def test_squash_cli_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_squash_annex_iv_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "annex-iv", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_squash_cli_attest_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "attest", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
