"""W151 — Real MLflow SDK bridge tests."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from squash.integrations.mlflow import MLflowSquash, _TAG_PREFIX


class TestMLflowSquashImportError:
    def test_raises_import_error_when_mlflow_missing(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        with patch.dict("sys.modules", {"mlflow": None}):
            with pytest.raises(ImportError, match="mlflow"):
                MLflowSquash.attest_run(
                    run=MagicMock(),
                    model_path=model_dir,
                )


class TestMLflowSquashTagPrefix:
    def test_tag_prefix_is_squash_dot(self):
        assert _TAG_PREFIX == "squash."


class TestMLflowSquashAttest:
    def _make_mock_mlflow(self):
        mock_mlflow = MagicMock()
        mock_mlflow.log_artifacts = MagicMock()
        mock_mlflow.set_tags = MagicMock()
        mock_mlflow.active_run.return_value = MagicMock()
        mock_mlflow.active_run.return_value.info.run_id = "test-run-001"
        return mock_mlflow

    def _make_mock_result(self, passed=True):
        result = MagicMock()
        result.passed = passed
        result.scan_result = MagicMock()
        result.scan_result.status = "clean"
        result.policy_results = {
            "eu-ai-act": MagicMock(passed=passed, error_count=0 if passed else 2),
        }
        result.cyclonedx_path = Path("/tmp/cyclonedx.json")
        return result

    def test_calls_log_artifacts(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        mock_mlflow.log_artifacts.assert_called_once()

    def test_calls_set_tags(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        mock_mlflow.set_tags.assert_called_once()

    def test_passed_tag_is_true_when_passing(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        tags = mock_mlflow.set_tags.call_args[0][0]
        assert tags[f"{_TAG_PREFIX}passed"] == "true"

    def test_passed_tag_is_false_when_failing(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=False)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        tags = mock_mlflow.set_tags.call_args[0][0]
        assert tags[f"{_TAG_PREFIX}passed"] == "false"

    def test_scan_status_tag_set(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        tags = mock_mlflow.set_tags.call_args[0][0]
        assert f"{_TAG_PREFIX}scan_status" in tags
        assert tags[f"{_TAG_PREFIX}scan_status"] == "clean"

    def test_policy_tags_set_for_each_policy(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        tags = mock_mlflow.set_tags.call_args[0][0]
        policy_tags = [k for k in tags if "policy" in k]
        assert len(policy_tags) >= 1

    def test_artifact_prefix_defaults_to_squash(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        call_kwargs = mock_mlflow.log_artifacts.call_args
        artifact_path = call_kwargs[1].get("artifact_path") or call_kwargs[0][-1]
        assert artifact_path == "squash"

    def test_custom_artifact_prefix(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(
                    run=MagicMock(),
                    model_path=model_dir,
                    artifact_prefix="compliance",
                )

        call_kwargs = mock_mlflow.log_artifacts.call_args
        artifact_path = call_kwargs[1].get("artifact_path") or call_kwargs[0][-1]
        assert artifact_path == "compliance"

    def test_returns_attest_result(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result) as mock_run:
                result = MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        assert result is mock_result

    def test_output_dir_defaults_under_model_path(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result) as mock_run:
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        config = mock_run.call_args[0][0]
        assert "squash" in str(config.output_dir)

    def test_custom_output_dir_respected(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        custom_out = tmp_path / "artifacts"
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result) as mock_run:
                MLflowSquash.attest_run(
                    run=MagicMock(),
                    model_path=model_dir,
                    output_dir=custom_out,
                )

        config = mock_run.call_args[0][0]
        assert config.output_dir == custom_out

    def test_default_policies_list(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result) as mock_run:
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        config = mock_run.call_args[0][0]
        assert isinstance(config.policies, list)
        assert len(config.policies) >= 1

    def test_no_scan_result_uses_skipped(self, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        mock_mlflow = self._make_mock_mlflow()
        mock_result = self._make_mock_result(passed=True)
        mock_result.scan_result = None

        with patch.dict("sys.modules", {"mlflow": mock_mlflow}):
            with patch("squash.integrations.mlflow.AttestPipeline.run", return_value=mock_result):
                MLflowSquash.attest_run(run=MagicMock(), model_path=model_dir)

        tags = mock_mlflow.set_tags.call_args[0][0]
        assert tags[f"{_TAG_PREFIX}scan_status"] == "skipped"
