"""tests/test_squash_w130.py — Wave 130: W&B API integration.

Tests ArtifactExtractor.from_wandb_run(), from_wandb_config(), and
from_wandb_run_full() via mocked wandb.Api — no live credentials, no
network, fully CI-safe.

The mock faithfully reproduces the W&B SDK object shapes:
  - run.id, run.name, run.entity, run.project, run.state, run.url, run.tags
  - run.config — dict-like with potential _wandb internal keys
  - run.scan_history() — generator of {_step, _timestamp, key: value | None}

Coverage:
  - _build_wandb_path(): all path construction variants
  - _extract_wandb_metrics(): single-pass streaming, None-skip, step order
  - _extract_wandb_config(): _wandb key filtering
  - from_wandb_run(): metric series, wall_times, metadata, source
  - from_wandb_run(): None values skipped per metric
  - from_wandb_run(): system/ metrics excluded by default, opt-in works
  - from_wandb_run(): non-numeric values skipped
  - from_wandb_run(): empty run (no history rows)
  - from_wandb_run(): run_id in full "entity/project/id" path format
  - from_wandb_config(): LR, optimizer, batch_size, _wandb keys stripped
  - from_wandb_config(): source_path contains wandb:// scheme
  - from_wandb_run_full(): single api.run() call (no duplicate round-trips)
  - from_wandb_run_full(): both sections in to_annex_iv_dict()
  - ImportError raised when wandb absent
  - Annex IV §3(b) loss/val routing
  - Annex IV §1(c) structure
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, call, patch

import pytest

from squash.artifact_extractor import (
    ArtifactExtractor,
    ArtifactExtractionResult,
    MetricSeries,
    TrainingConfig,
    TrainingMetrics,
    _build_wandb_path,
    _extract_wandb_config,
    _extract_wandb_metrics,
)


# ---------------------------------------------------------------------------
# Fixtures — mock W&B run objects
# ---------------------------------------------------------------------------

def _make_mock_run(
    run_id: str = "abc123",
    entity: str = "konjoai",
    project: str = "llm-training",
    name: str = "sleek-run-7",
    state: str = "finished",
    config: dict | None = None,
    history_rows: list[dict] | None = None,
    tags: list[str] | None = None,
) -> MagicMock:
    """Build a MagicMock that mirrors a wandb.sdk.wandb_run.Run public API."""
    run = MagicMock()
    run.id = run_id
    run.name = name
    run.entity = entity
    run.project = project
    run.state = state
    run.url = f"https://wandb.ai/{entity}/{project}/runs/{run_id}"
    run.tags = tags or []
    run.config = config if config is not None else {
        "learning_rate": 1e-4,
        "optimizer": "AdamW",
        "batch_size": 32,
        "max_epochs": 20,
        "weight_decay": 0.01,
        "_wandb": {"version": "0.16.0", "run_id": run_id},  # internal — must be stripped
    }
    rows = history_rows if history_rows is not None else [
        {"_step": 0, "_timestamp": 1_700_000_000.0, "train/loss": 1.20, "val/loss": 1.30, "val/acc": None},
        {"_step": 1, "_timestamp": 1_700_000_010.0, "train/loss": 0.95, "val/loss": 1.05, "val/acc": 0.62},
        {"_step": 2, "_timestamp": 1_700_000_020.0, "train/loss": 0.75, "val/loss": 0.85, "val/acc": 0.71},
        {"_step": 3, "_timestamp": 1_700_000_030.0, "train/loss": 0.60, "val/loss": 0.70, "val/acc": 0.78},
        {"_step": 4, "_timestamp": 1_700_000_040.0, "train/loss": 0.50, "val/loss": 0.62, "val/acc": 0.83},
    ]
    run.scan_history.return_value = iter(rows)
    return run


@pytest.fixture()
def mock_api_cls():
    """Patch wandb.Api to return a controllable factory."""
    with patch("wandb.Api") as api_cls:
        yield api_cls


@pytest.fixture()
def standard_run(mock_api_cls):
    """A complete mock run with 5-step history and full config."""
    run = _make_mock_run()
    mock_api_cls.return_value.run.return_value = run
    return run, mock_api_cls


# ---------------------------------------------------------------------------
# _build_wandb_path() unit tests
# ---------------------------------------------------------------------------

class TestBuildWandbPath:
    def test_full_path_passthrough(self):
        assert _build_wandb_path("entity/project/runid", "", "") == "entity/project/runid"

    def test_entity_project_run_id_combined(self):
        assert _build_wandb_path("runid", "myentity", "myproject") == "myentity/myproject/runid"

    def test_project_only(self):
        assert _build_wandb_path("runid", "", "myproject") == "myproject/runid"

    def test_bare_run_id(self):
        assert _build_wandb_path("runid", "", "") == "runid"

    def test_slashes_in_run_id_treated_as_full_path(self):
        assert _build_wandb_path("a/b/c", "ignored", "ignored") == "a/b/c"

    def test_entity_without_project_uses_bare(self):
        # entity alone doesn't help without project
        assert _build_wandb_path("runid", "myentity", "") == "runid"


# ---------------------------------------------------------------------------
# _extract_wandb_metrics() unit tests (no wandb import required)
# ---------------------------------------------------------------------------

class TestExtractWandbMetrics:
    def _run_with_history(self, rows):
        run = MagicMock()
        run.scan_history.return_value = iter(rows)
        run.id = "test"
        run.entity = "e"
        run.project = "p"
        run.name = "n"
        run.state = "finished"
        run.url = "http://example.com"
        run.tags = []
        return run

    def test_builds_series_for_each_metric(self):
        run = self._run_with_history([
            {"_step": 0, "_timestamp": 1.0, "loss": 1.0, "acc": 0.5},
        ])
        m = _extract_wandb_metrics(run)
        assert "loss" in m.series
        assert "acc" in m.series

    def test_none_values_skipped(self):
        run = self._run_with_history([
            {"_step": 0, "_timestamp": 1.0, "loss": 1.0, "val/acc": None},
            {"_step": 1, "_timestamp": 2.0, "loss": 0.8, "val/acc": 0.7},
        ])
        m = _extract_wandb_metrics(run)
        # val/acc has None at step 0 — only step 1 should appear
        assert m.series["val/acc"].steps == [1]
        assert m.series["val/acc"].values == pytest.approx([0.7])

    def test_underscore_keys_excluded(self):
        run = self._run_with_history([
            {"_step": 0, "_timestamp": 1.0, "_runtime": 5.0, "loss": 0.5},
        ])
        m = _extract_wandb_metrics(run)
        assert "_runtime" not in m.series
        assert "_step" not in m.series

    def test_system_metrics_excluded_by_default(self):
        run = self._run_with_history([
            {"_step": 0, "_timestamp": 1.0, "system/gpu.0.utilization": 82.0, "loss": 0.5},
        ])
        m = _extract_wandb_metrics(run)
        assert "system/gpu.0.utilization" not in m.series
        assert "loss" in m.series

    def test_system_metrics_included_when_opted_in(self):
        run = self._run_with_history([
            {"_step": 0, "_timestamp": 1.0, "system/gpu.0.utilization": 82.0, "loss": 0.5},
        ])
        m = _extract_wandb_metrics(run, include_system_metrics=True)
        assert "system/gpu.0.utilization" in m.series

    def test_non_numeric_values_skipped(self):
        run = self._run_with_history([
            {"_step": 0, "_timestamp": 1.0, "tag_label": "epoch_end", "loss": 0.5},
        ])
        m = _extract_wandb_metrics(run)
        assert "tag_label" not in m.series
        assert "loss" in m.series

    def test_wall_times_in_seconds(self):
        ts = 1_700_000_000.0
        run = self._run_with_history([{"_step": 0, "_timestamp": ts, "loss": 1.0}])
        m = _extract_wandb_metrics(run)
        assert m.series["loss"].wall_times[0] == pytest.approx(ts)

    def test_source_is_wandb(self):
        run = self._run_with_history([{"_step": 0, "_timestamp": 1.0, "loss": 1.0}])
        m = _extract_wandb_metrics(run)
        assert m.source == "wandb"

    def test_empty_history_returns_empty_series(self):
        run = self._run_with_history([])
        m = _extract_wandb_metrics(run)
        assert m.series == {}

    def test_metadata_fields_populated(self):
        run = self._run_with_history([])
        run.entity = "myorg"
        run.project = "myproject"
        run.name = "cool-run"
        run.state = "finished"
        run.url = "https://wandb.ai/myorg/myproject/runs/abc"
        run.tags = ["prod", "v2"]
        m = _extract_wandb_metrics(run)
        assert m.metadata["entity"] == "myorg"
        assert m.metadata["project"] == "myproject"
        assert m.metadata["run_name"] == "cool-run"
        assert m.metadata["state"] == "finished"
        assert "prod" in m.metadata["tags"]

    def test_single_pass_scan_history_called_once(self):
        run = self._run_with_history([{"_step": 0, "_timestamp": 1.0, "loss": 1.0}])
        _extract_wandb_metrics(run)
        run.scan_history.assert_called_once()


# ---------------------------------------------------------------------------
# _extract_wandb_config() unit tests
# ---------------------------------------------------------------------------

class TestExtractWandbConfig:
    def _run_with_config(self, cfg):
        run = MagicMock()
        run.config = cfg
        return run

    def test_wandb_internal_keys_stripped(self):
        run = self._run_with_config({
            "learning_rate": 1e-4,
            "_wandb": {"version": "1.0"},
            "_wandb.something": "internal",
        })
        tc = _extract_wandb_config(run, "entity/project/run1")
        assert "_wandb" not in tc.raw
        assert "_wandb.something" not in tc.raw

    def test_learning_rate_extracted(self):
        run = self._run_with_config({"learning_rate": 3e-5, "optimizer": "AdamW"})
        tc = _extract_wandb_config(run, "entity/project/run1")
        assert tc.optimizer.get("learning_rate") == pytest.approx(3e-5)

    def test_optimizer_type_extracted(self):
        run = self._run_with_config({"optimizer": "SGD", "lr": 0.01})
        tc = _extract_wandb_config(run, "entity/project/run1")
        assert tc.optimizer.get("type") == "SGD"

    def test_source_path_wandb_scheme(self):
        run = self._run_with_config({})
        tc = _extract_wandb_config(run, "e/p/r")
        assert tc.source_path == "wandb://e/p/r"

    def test_empty_config(self):
        run = self._run_with_config({})
        tc = _extract_wandb_config(run, "e/p/r")
        assert isinstance(tc, TrainingConfig)
        assert tc.optimizer == {}


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_wandb_run() integration tests
# ---------------------------------------------------------------------------

class TestFromWandbRun:
    def test_returns_training_metrics(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        assert isinstance(m, TrainingMetrics)

    def test_source_is_wandb(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        assert m.source == "wandb"

    def test_run_id_recorded(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        assert m.run_id == "abc123"

    def test_metric_series_present(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        assert "train/loss" in m.series
        assert "val/loss" in m.series

    def test_full_five_step_history(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        assert len(m.series["train/loss"].steps) == 5
        assert m.series["train/loss"].steps == [0, 1, 2, 3, 4]

    def test_none_val_acc_at_step0_skipped(self, standard_run):
        # val/acc is None at step 0 in default fixture — should only have 4 points
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        assert m.series["val/acc"].steps == [1, 2, 3, 4]

    def test_values_decreasing_loss(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        vals = m.series["train/loss"].values
        assert vals == sorted(vals, reverse=True)  # monotonically decreasing

    def test_wall_times_in_seconds(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        wt = m.series["train/loss"].wall_times[0]
        assert wt == pytest.approx(1_700_000_000.0)

    def test_full_path_run_id(self, mock_api_cls):
        run = _make_mock_run()
        mock_api_cls.return_value.run.return_value = run
        with patch("wandb.Api", mock_api_cls):
            ArtifactExtractor.from_wandb_run("konjoai/llm-training/abc123")
        mock_api_cls.return_value.run.assert_called_once_with("konjoai/llm-training/abc123")

    def test_path_built_from_entity_project(self, mock_api_cls):
        run = _make_mock_run()
        mock_api_cls.return_value.run.return_value = run
        with patch("wandb.Api", mock_api_cls):
            ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        mock_api_cls.return_value.run.assert_called_once_with("konjoai/llm-training/abc123")

    def test_empty_run_empty_series(self, mock_api_cls):
        run = _make_mock_run(history_rows=[])
        mock_api_cls.return_value.run.return_value = run
        with patch("wandb.Api", mock_api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="e", project="p")
        assert m.series == {}

    def test_system_metrics_excluded_by_default(self, mock_api_cls):
        run = _make_mock_run(history_rows=[
            {"_step": 0, "_timestamp": 1.0, "loss": 0.5, "system/gpu.0.utilization": 90.0},
        ])
        mock_api_cls.return_value.run.return_value = run
        with patch("wandb.Api", mock_api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="e", project="p")
        assert "system/gpu.0.utilization" not in m.series

    def test_system_metrics_opt_in(self, mock_api_cls):
        run = _make_mock_run(history_rows=[
            {"_step": 0, "_timestamp": 1.0, "loss": 0.5, "system/gpu.0.utilization": 90.0},
        ])
        mock_api_cls.return_value.run.return_value = run
        with patch("wandb.Api", mock_api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="e", project="p", include_system_metrics=True)
        assert "system/gpu.0.utilization" in m.series

    def test_annex_iv_3b_loss_routing(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        section = m.annex_iv_section_3b()
        assert "train/loss" in section["loss_curves"]
        assert "val/loss" in section["loss_curves"]

    def test_annex_iv_3b_val_routing(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            m = ArtifactExtractor.from_wandb_run("abc123", entity="konjoai", project="llm-training")
        section = m.annex_iv_section_3b()
        assert "val/loss" in section["validation_metrics"]
        assert "val/acc" in section["validation_metrics"]

    def test_missing_wandb_raises_import_error(self):
        with patch.dict(sys.modules, {"wandb": None}):
            with pytest.raises(ImportError, match="wandb is required"):
                ArtifactExtractor.from_wandb_run("abc123")


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_wandb_config() tests
# ---------------------------------------------------------------------------

class TestFromWandbConfig:
    def test_returns_training_config(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        assert isinstance(tc, TrainingConfig)

    def test_learning_rate_extracted(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        assert tc.optimizer.get("learning_rate") == pytest.approx(1e-4)

    def test_optimizer_type_extracted(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        assert tc.optimizer.get("type") == "AdamW"

    def test_batch_size_extracted(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        assert tc.training.get("batch_size") == 32

    def test_wandb_internal_keys_not_in_raw(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        assert "_wandb" not in tc.raw

    def test_source_path_wandb_scheme(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        assert tc.source_path.startswith("wandb://")
        assert "abc123" in tc.source_path

    def test_annex_iv_1c_structure(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            tc = ArtifactExtractor.from_wandb_config("abc123", entity="konjoai", project="llm-training")
        section = tc.annex_iv_section_1c()
        assert section["annex_iv_section"] == "1c"
        assert "optimizer" in section

    def test_missing_wandb_raises_import_error(self):
        with patch.dict(sys.modules, {"wandb": None}):
            with pytest.raises(ImportError, match="wandb is required"):
                ArtifactExtractor.from_wandb_config("abc123")


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_wandb_run_full() tests
# ---------------------------------------------------------------------------

class TestFromWandbRunFull:
    def test_returns_artifact_extraction_result(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            result = ArtifactExtractor.from_wandb_run_full("abc123", entity="konjoai", project="llm-training")
        assert isinstance(result, ArtifactExtractionResult)

    def test_metrics_populated(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            result = ArtifactExtractor.from_wandb_run_full("abc123", entity="konjoai", project="llm-training")
        assert result.metrics is not None
        assert "train/loss" in result.metrics.series

    def test_config_populated(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            result = ArtifactExtractor.from_wandb_run_full("abc123", entity="konjoai", project="llm-training")
        assert result.config is not None
        assert result.config.optimizer.get("type") == "AdamW"

    def test_single_api_run_call(self, mock_api_cls):
        """Full extraction must make exactly one api.run() call — no duplicate round-trips."""
        run = _make_mock_run()
        mock_api_cls.return_value.run.return_value = run
        with patch("wandb.Api", mock_api_cls):
            ArtifactExtractor.from_wandb_run_full("abc123", entity="e", project="p")
        assert mock_api_cls.return_value.run.call_count == 1

    def test_not_empty(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            result = ArtifactExtractor.from_wandb_run_full("abc123", entity="konjoai", project="llm-training")
        assert not result.is_empty()

    def test_to_annex_iv_dict_has_both_sections(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            result = ArtifactExtractor.from_wandb_run_full("abc123", entity="konjoai", project="llm-training")
        d = result.to_annex_iv_dict()
        assert "section_1c" in d
        assert "section_3b" in d

    def test_source_is_wandb(self, standard_run):
        run, api_cls = standard_run
        with patch("wandb.Api", api_cls):
            result = ArtifactExtractor.from_wandb_run_full("abc123", entity="konjoai", project="llm-training")
        assert result.metrics.source == "wandb"

    def test_missing_wandb_raises_import_error(self):
        with patch.dict(sys.modules, {"wandb": None}):
            with pytest.raises(ImportError, match="wandb is required"):
                ArtifactExtractor.from_wandb_run_full("abc123")
