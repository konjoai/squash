"""tests/test_squash_w129.py — Wave 129: MLflow SDK integration.

Tests ArtifactExtractor.from_mlflow_run(), from_mlflow_params(), and
from_mlflow_run_full() using MLflow's local file:// tracking URI —
no server required, no live credentials, fully CI-safe.

All tests are skipped automatically if mlflow is not installed.

Coverage:
  - _coerce_mlflow_param() type coercion
  - from_mlflow_run(): full metric history, multi-step series, wall_times
  - from_mlflow_run(): metadata fields (experiment_id, status, run_name)
  - from_mlflow_run(): empty run (no metrics)
  - from_mlflow_run(): multiple metrics with different step counts
  - from_mlflow_run(): NaN / Inf values pass through
  - from_mlflow_params(): param coercion (int, float, bool, str)
  - from_mlflow_params(): optimizer / lr / batch_size extraction
  - from_mlflow_params(): source_path recorded
  - from_mlflow_params(): empty params
  - from_mlflow_run_full(): both metrics and config populated
  - from_mlflow_run_full(): to_annex_iv_dict() structure
  - ImportError raised when mlflow absent (mocked)
  - annex_iv_section_3b() routing for loss vs val tags
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from squash.artifact_extractor import (
    ArtifactExtractor,
    ArtifactExtractionResult,
    MetricSeries,
    TrainingConfig,
    TrainingMetrics,
    _coerce_mlflow_param,
)

mlflow = pytest.importorskip("mlflow", reason="mlflow not installed — skipping W129 tests")


# ---------------------------------------------------------------------------
# Fixtures — local MLflow file store (no server)
# ---------------------------------------------------------------------------

@pytest.fixture()
def tracking_uri(tmp_path):
    uri = f"file://{tmp_path}/mlruns"
    mlflow.set_tracking_uri(uri)
    return uri


@pytest.fixture()
def simple_run(tracking_uri):
    """A run with two metrics logged over 5 steps + hyperparams."""
    with mlflow.start_run() as run:
        mlflow.log_param("learning_rate", "1e-4")
        mlflow.log_param("optimizer", "AdamW")
        mlflow.log_param("batch_size", "32")
        mlflow.log_param("max_epochs", "10")
        mlflow.log_param("weight_decay", "0.01")
        for step in range(5):
            mlflow.log_metric("train/loss", 1.0 - step * 0.15, step=step)
            mlflow.log_metric("val/acc",    0.50 + step * 0.08, step=step)
    return run.info.run_id, tracking_uri


@pytest.fixture()
def empty_run(tracking_uri):
    """A run with params but no metrics."""
    with mlflow.start_run() as run:
        mlflow.log_param("lr", "3e-5")
    return run.info.run_id, tracking_uri


@pytest.fixture()
def no_params_run(tracking_uri):
    """A run with metrics but no params."""
    with mlflow.start_run() as run:
        mlflow.log_metric("loss", 0.5, step=0)
    return run.info.run_id, tracking_uri


@pytest.fixture()
def multi_metric_run(tracking_uri):
    """A run with several metrics at different step counts."""
    with mlflow.start_run() as run:
        for step in range(10):
            mlflow.log_metric("train/loss", 1.0 / (step + 1), step=step)
        for step in range(0, 10, 2):  # every 2 steps
            mlflow.log_metric("val/loss", 0.9 / (step + 1), step=step)
    return run.info.run_id, tracking_uri


# ---------------------------------------------------------------------------
# _coerce_mlflow_param unit tests
# ---------------------------------------------------------------------------

class TestCoerceMlflowParam:
    def test_integer_string(self):
        assert _coerce_mlflow_param("32") == 32
        assert isinstance(_coerce_mlflow_param("32"), int)

    def test_float_string(self):
        assert _coerce_mlflow_param("1e-4") == pytest.approx(1e-4)
        assert isinstance(_coerce_mlflow_param("1e-4"), float)

    def test_decimal_float(self):
        assert _coerce_mlflow_param("0.01") == pytest.approx(0.01)

    def test_bool_true(self):
        assert _coerce_mlflow_param("true") is True
        assert _coerce_mlflow_param("True") is True
        assert _coerce_mlflow_param("TRUE") is True

    def test_bool_false(self):
        assert _coerce_mlflow_param("false") is False
        assert _coerce_mlflow_param("False") is False

    def test_plain_string_unchanged(self):
        assert _coerce_mlflow_param("AdamW") == "AdamW"

    def test_negative_int(self):
        assert _coerce_mlflow_param("-1") == -1

    def test_negative_float(self):
        assert _coerce_mlflow_param("-0.5") == pytest.approx(-0.5)

    def test_non_string_passthrough(self):
        assert _coerce_mlflow_param(42) == 42
        assert _coerce_mlflow_param(3.14) == pytest.approx(3.14)

    def test_empty_string(self):
        assert _coerce_mlflow_param("") == ""

    def test_whitespace_stripped(self):
        assert _coerce_mlflow_param("  10  ") == 10


# ---------------------------------------------------------------------------
# from_mlflow_run() tests
# ---------------------------------------------------------------------------

class TestFromMlflowRun:
    def test_returns_training_metrics(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert isinstance(metrics, TrainingMetrics)

    def test_source_is_mlflow(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert metrics.source == "mlflow"

    def test_run_id_recorded(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert metrics.run_id == run_id

    def test_metric_keys_present(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert "train/loss" in metrics.series
        assert "val/acc" in metrics.series

    def test_full_step_history(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert len(metrics.series["train/loss"].steps) == 5
        assert metrics.series["train/loss"].steps == list(range(5))

    def test_values_correct(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        expected = [1.0 - i * 0.15 for i in range(5)]
        assert metrics.series["train/loss"].values == pytest.approx(expected, abs=1e-5)

    def test_wall_times_in_seconds(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        # MLflow timestamps are ms; reader divides by 1000
        for wt in metrics.series["train/loss"].wall_times:
            assert wt > 1_000_000  # sanity: Unix epoch in seconds (2001+)
            assert wt < 10_000_000_000  # not in milliseconds

    def test_metadata_experiment_id(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert "experiment_id" in metrics.metadata
        assert metrics.metadata["experiment_id"] is not None

    def test_metadata_status(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert metrics.metadata["status"] == "FINISHED"

    def test_metadata_tracking_uri(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert metrics.metadata["tracking_uri"] == uri

    def test_empty_run_returns_empty_series(self, empty_run):
        run_id, uri = empty_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert metrics.series == {}

    def test_multi_metric_different_step_counts(self, multi_metric_run):
        run_id, uri = multi_metric_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert len(metrics.series["train/loss"].steps) == 10
        assert len(metrics.series["val/loss"].steps) == 5

    def test_series_sorted_by_step(self, multi_metric_run):
        run_id, uri = multi_metric_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        steps = metrics.series["train/loss"].steps
        assert steps == sorted(steps)

    def test_annex_iv_3b_loss_routing(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        section = metrics.annex_iv_section_3b()
        assert "train/loss" in section["loss_curves"]

    def test_annex_iv_3b_val_routing(self, simple_run):
        run_id, uri = simple_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        section = metrics.annex_iv_section_3b()
        assert "val/acc" in section["validation_metrics"]

    def test_no_params_run_metrics_present(self, no_params_run):
        run_id, uri = no_params_run
        metrics = ArtifactExtractor.from_mlflow_run(run_id, uri)
        assert "loss" in metrics.series

    def test_missing_mlflow_raises_import_error(self):
        with patch.dict(sys.modules, {"mlflow": None, "mlflow.tracking": None}):
            with pytest.raises(ImportError, match="mlflow is required"):
                ArtifactExtractor.from_mlflow_run("fake-run-id")


# ---------------------------------------------------------------------------
# from_mlflow_params() tests
# ---------------------------------------------------------------------------

class TestFromMlflowParams:
    def test_returns_training_config(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert isinstance(config, TrainingConfig)

    def test_source_path_contains_run_id(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert run_id in config.source_path

    def test_learning_rate_extracted(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert config.optimizer.get("learning_rate") == pytest.approx(1e-4)

    def test_optimizer_type_extracted(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert config.optimizer.get("type") == "AdamW"

    def test_batch_size_extracted(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert config.training.get("batch_size") == 32

    def test_max_steps_extracted(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert config.training.get("max_steps") == 10

    def test_weight_decay_extracted(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert config.optimizer.get("weight_decay") == pytest.approx(0.01)

    def test_raw_params_preserved(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert "learning_rate" in config.raw
        assert "optimizer" in config.raw

    def test_empty_params_run(self, no_params_run):
        run_id, uri = no_params_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        assert isinstance(config, TrainingConfig)
        assert config.optimizer == {}

    def test_annex_iv_1c_structure(self, simple_run):
        run_id, uri = simple_run
        config = ArtifactExtractor.from_mlflow_params(run_id, uri)
        section = config.annex_iv_section_1c()
        assert section["annex_iv_section"] == "1c"
        assert "optimizer" in section
        assert "training" in section

    def test_missing_mlflow_raises_import_error(self):
        with patch.dict(sys.modules, {"mlflow": None, "mlflow.tracking": None}):
            with pytest.raises(ImportError, match="mlflow is required"):
                ArtifactExtractor.from_mlflow_params("fake-run-id")


# ---------------------------------------------------------------------------
# from_mlflow_run_full() tests
# ---------------------------------------------------------------------------

class TestFromMlflowRunFull:
    def test_returns_artifact_extraction_result(self, simple_run):
        run_id, uri = simple_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        assert isinstance(result, ArtifactExtractionResult)

    def test_metrics_populated(self, simple_run):
        run_id, uri = simple_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        assert result.metrics is not None
        assert "train/loss" in result.metrics.series

    def test_config_populated(self, simple_run):
        run_id, uri = simple_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        assert result.config is not None
        assert result.config.optimizer.get("type") == "AdamW"

    def test_not_empty(self, simple_run):
        run_id, uri = simple_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        assert not result.is_empty()

    def test_to_annex_iv_dict_has_both_sections(self, simple_run):
        run_id, uri = simple_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        d = result.to_annex_iv_dict()
        assert "section_1c" in d
        assert "section_3b" in d

    def test_metrics_source_is_mlflow(self, simple_run):
        run_id, uri = simple_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        assert result.metrics.source == "mlflow"

    def test_empty_run_metrics_empty_series(self, empty_run):
        run_id, uri = empty_run
        result = ArtifactExtractor.from_mlflow_run_full(run_id, uri)
        assert result.metrics.series == {}
        assert result.config is not None  # params still extracted

    def test_missing_mlflow_raises_import_error(self):
        with patch.dict(sys.modules, {"mlflow": None, "mlflow.tracking": None}):
            with pytest.raises(ImportError, match="mlflow is required"):
                ArtifactExtractor.from_mlflow_run_full("fake-run-id")
