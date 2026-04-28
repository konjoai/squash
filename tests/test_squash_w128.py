"""tests/test_squash_w128.py — Wave 128: TensorBoard event file parser.

Tests the zero-dependency native TFRecord reader and training config parser
in squash/artifact_extractor.py.

Coverage:
  - MetricSeries dataclass (summary stats)
  - TrainingMetrics.annex_iv_section_3b() structure
  - TrainingConfig.annex_iv_section_1c() structure
  - ArtifactExtractionResult.to_annex_iv_dict()
  - Native TFRecord binary writer + reader round-trip
  - TensorBoard log directory scanning
  - Training config parsing: JSON, flat dict, nested dict
  - from_run_dir() auto-discovery
  - Missing / empty / corrupt file handling
  - Stub methods raise NotImplementedError (W129/W130/W131)
"""

from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

import pytest

from squash.artifact_extractor import (
    ArtifactExtractor,
    ArtifactExtractionResult,
    MetricSeries,
    TrainingConfig,
    TrainingMetrics,
    _decode_proto_fields,
    _iter_tfrecord_bytes,
    _parse_tb_scalars,
    _read_varint,
    _parse_config_dict,
)


# ---------------------------------------------------------------------------
# Helpers — minimal TFRecord + Event proto writer (for test fixtures)
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _encode_double(field_num: int, value: float) -> bytes:
    """Encode a double field (wire type 1)."""
    tag = (field_num << 3) | 1
    return _encode_varint(tag) + struct.pack("<d", value)


def _encode_varint_field(field_num: int, value: int) -> bytes:
    """Encode a varint field (wire type 0)."""
    tag = (field_num << 3) | 0
    return _encode_varint(tag) + _encode_varint(value)


def _encode_bytes_field(field_num: int, data: bytes) -> bytes:
    """Encode a length-delimited field (wire type 2)."""
    tag = (field_num << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def _encode_float_field(field_num: int, value: float) -> bytes:
    """Encode a 32-bit float field (wire type 5)."""
    tag = (field_num << 3) | 5
    return _encode_varint(tag) + struct.pack("<f", value)


def _build_summary_value(tag: str, simple_value: float) -> bytes:
    """Build a Summary.Value proto bytes."""
    return (
        _encode_bytes_field(1, tag.encode())  # field 1: tag
        + _encode_float_field(2, simple_value)  # field 2: simple_value
    )


def _build_summary(scalars: list[tuple[str, float]]) -> bytes:
    """Build a Summary proto bytes containing scalar values."""
    out = b""
    for tag, value in scalars:
        value_bytes = _build_summary_value(tag, value)
        out += _encode_bytes_field(1, value_bytes)  # field 1: repeated Value
    return out


def _build_event(wall_time: float, step: int, scalars: list[tuple[str, float]]) -> bytes:
    """Build a TensorBoard Event proto bytes."""
    summary_bytes = _build_summary(scalars)
    return (
        _encode_double(1, wall_time)           # field 1: wall_time
        + _encode_varint_field(2, step)        # field 2: step
        + _encode_bytes_field(5, summary_bytes)  # field 5: summary
    )


def _write_tfrecord(fh, data: bytes) -> None:
    """Write one TFRecord entry (no CRC validation in reader, so we write zeros)."""
    length = len(data)
    fh.write(struct.pack("<Q", length))  # uint64 length
    fh.write(b"\x00" * 4)               # masked crc (skipped by reader)
    fh.write(data)
    fh.write(b"\x00" * 4)               # masked crc (skipped by reader)


def _make_tfevents_file(path: Path, events: list[tuple[float, int, list[tuple[str, float]]]]) -> None:
    """Write a synthetic .tfevents file with the given scalar events."""
    with open(path, "wb") as fh:
        for wall_time, step, scalars in events:
            event_bytes = _build_event(wall_time, step, scalars)
            _write_tfrecord(fh, event_bytes)


# ---------------------------------------------------------------------------
# MetricSeries tests
# ---------------------------------------------------------------------------

class TestMetricSeries:
    def test_empty_series(self):
        ms = MetricSeries(tag="loss")
        assert ms.last() is None
        assert ms.min() is None
        assert ms.max() is None

    def test_summary_stats(self):
        ms = MetricSeries(tag="train/loss", steps=[0, 1, 2], values=[1.0, 0.5, 0.2], wall_times=[0.0, 1.0, 2.0])
        assert ms.last() == pytest.approx(0.2)
        assert ms.min() == pytest.approx(0.2)
        assert ms.max() == pytest.approx(1.0)

    def test_to_dict_structure(self):
        ms = MetricSeries(tag="val/acc", steps=[0, 10], values=[0.6, 0.9], wall_times=[0.0, 10.0])
        d = ms.to_dict()
        assert d["tag"] == "val/acc"
        assert d["summary"]["count"] == 2
        assert d["summary"]["last"] == pytest.approx(0.9)
        assert "steps" in d
        assert "values" in d
        assert "wall_times" in d


# ---------------------------------------------------------------------------
# TrainingMetrics tests
# ---------------------------------------------------------------------------

class TestTrainingMetrics:
    def _make_metrics(self) -> TrainingMetrics:
        return TrainingMetrics(
            source="tensorboard",
            run_id="test-run",
            series={
                "train/loss": MetricSeries("train/loss", [0, 1, 2], [1.0, 0.5, 0.2], [0.0, 1.0, 2.0]),
                "val/loss":   MetricSeries("val/loss",   [0, 1, 2], [1.1, 0.6, 0.3], [0.0, 1.0, 2.0]),
                "val/acc":    MetricSeries("val/acc",    [0, 1, 2], [0.5, 0.7, 0.9], [0.0, 1.0, 2.0]),
            },
        )

    def test_annex_iv_section_3b_keys(self):
        m = self._make_metrics()
        section = m.annex_iv_section_3b()
        assert section["annex_iv_section"] == "3b"
        assert "loss_curves" in section
        assert "validation_metrics" in section
        assert "all_metrics" in section
        assert section["source"] == "tensorboard"

    def test_annex_iv_section_3b_loss_routing(self):
        m = self._make_metrics()
        section = m.annex_iv_section_3b()
        assert "train/loss" in section["loss_curves"]
        assert "val/loss" in section["loss_curves"]

    def test_annex_iv_section_3b_val_routing(self):
        m = self._make_metrics()
        section = m.annex_iv_section_3b()
        assert "val/loss" in section["validation_metrics"]
        assert "val/acc" in section["validation_metrics"]

    def test_empty_metrics(self):
        m = TrainingMetrics(source="tensorboard", run_id=None)
        section = m.annex_iv_section_3b()
        assert section["loss_curves"] == {}
        assert section["validation_metrics"] == {}


# ---------------------------------------------------------------------------
# Native binary parser unit tests
# ---------------------------------------------------------------------------

class TestNativeBinaryParser:
    def test_read_varint_single_byte(self):
        buf = memoryview(b"\x05")
        val, pos = _read_varint(buf, 0)
        assert val == 5
        assert pos == 1

    def test_read_varint_multibyte(self):
        # 300 = 0xAC 0x02 in varint
        buf = memoryview(b"\xac\x02")
        val, pos = _read_varint(buf, 0)
        assert val == 300
        assert pos == 2

    def test_decode_proto_double(self):
        # field 1, wire type 1 (double) = tag byte 0x09
        data = b"\x09" + struct.pack("<d", 3.14)
        fields = _decode_proto_fields(data)
        assert 1 in fields
        assert fields[1][0] == pytest.approx(3.14)

    def test_decode_proto_varint(self):
        # field 2, wire type 0 (varint) = tag byte 0x10
        data = b"\x10" + _encode_varint(42)
        fields = _decode_proto_fields(data)
        assert fields[2][0] == 42

    def test_decode_proto_float(self):
        # field 2, wire type 5 (float) = tag byte 0x15
        data = b"\x15" + struct.pack("<f", 0.5)
        fields = _decode_proto_fields(data)
        assert fields[2][0] == pytest.approx(0.5, abs=1e-5)

    def test_decode_proto_bytes(self):
        # field 1, wire type 2 (bytes) = tag byte 0x0a
        payload = b"hello"
        data = b"\x0a" + _encode_varint(len(payload)) + payload
        fields = _decode_proto_fields(data)
        assert fields[1][0] == b"hello"

    def test_parse_tb_scalars_round_trip(self):
        scalars_in = [("train/loss", 0.42), ("val/acc", 0.88)]
        event_bytes = _build_event(wall_time=1234567890.0, step=100, scalars=scalars_in)
        wall_time, step, scalars_out = _parse_tb_scalars(event_bytes)
        assert wall_time == pytest.approx(1234567890.0)
        assert step == 100
        tags_out = {t: v for t, v in scalars_out}
        assert tags_out["train/loss"] == pytest.approx(0.42, abs=1e-4)
        assert tags_out["val/acc"] == pytest.approx(0.88, abs=1e-4)

    def test_parse_empty_event(self):
        wall_time, step, scalars = _parse_tb_scalars(b"")
        assert scalars == []

    def test_iter_tfrecord_bytes_round_trip(self):
        payload = b"test payload"
        with tempfile.NamedTemporaryFile(suffix=".tfevents") as f:
            _write_tfrecord(f, payload)
            f.flush()
            records = list(_iter_tfrecord_bytes(Path(f.name)))
        assert records == [payload]

    def test_iter_tfrecord_multiple_records(self):
        payloads = [b"alpha", b"beta", b"gamma"]
        with tempfile.NamedTemporaryFile(suffix=".tfevents") as f:
            for p in payloads:
                _write_tfrecord(f, p)
            f.flush()
            records = list(_iter_tfrecord_bytes(Path(f.name)))
        assert records == payloads


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_tensorboard_logs() integration tests
# ---------------------------------------------------------------------------

class TestFromTensorboardLogs:
    def _make_log_dir(self, tmp_path: Path, events: list) -> Path:
        log_dir = tmp_path / "tb_logs"
        log_dir.mkdir()
        _make_tfevents_file(log_dir / "events.out.tfevents.000.localhost", events)
        return log_dir

    def test_single_tag(self, tmp_path):
        events = [(1000.0, 0, [("loss", 1.0)]), (1001.0, 1, [("loss", 0.8)])]
        log_dir = self._make_log_dir(tmp_path, events)
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        assert "loss" in metrics.series
        assert metrics.series["loss"].values == pytest.approx([1.0, 0.8], abs=1e-4)
        assert metrics.series["loss"].steps == [0, 1]

    def test_multiple_tags(self, tmp_path):
        events = [
            (1000.0, 0, [("train/loss", 1.2), ("val/acc", 0.5)]),
            (1001.0, 1, [("train/loss", 0.9), ("val/acc", 0.65)]),
        ]
        log_dir = self._make_log_dir(tmp_path, events)
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        assert "train/loss" in metrics.series
        assert "val/acc" in metrics.series
        assert len(metrics.series["train/loss"].values) == 2

    def test_missing_log_dir(self, tmp_path):
        metrics = ArtifactExtractor.from_tensorboard_logs(tmp_path / "nonexistent")
        assert metrics.source == "tensorboard"
        assert metrics.series == {}
        assert "error" in metrics.metadata

    def test_empty_log_dir(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        metrics = ArtifactExtractor.from_tensorboard_logs(empty)
        assert metrics.series == {}

    def test_nested_subdirectory_discovery(self, tmp_path):
        sub = tmp_path / "train" / "run_001"
        sub.mkdir(parents=True)
        _make_tfevents_file(sub / "events.out.tfevents.000.localhost", [(1.0, 0, [("acc", 0.5)])])
        metrics = ArtifactExtractor.from_tensorboard_logs(tmp_path)
        assert "acc" in metrics.series

    def test_metrics_source_is_tensorboard(self, tmp_path):
        log_dir = self._make_log_dir(tmp_path, [(1.0, 0, [("x", 1.0)])])
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        assert metrics.source == "tensorboard"

    def test_wall_times_recorded(self, tmp_path):
        events = [(9999.0, 0, [("loss", 0.5)]), (10000.0, 1, [("loss", 0.4)])]
        log_dir = self._make_log_dir(tmp_path, events)
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        assert metrics.series["loss"].wall_times[0] == pytest.approx(9999.0)

    def test_annex_iv_3b_output(self, tmp_path):
        events = [(1.0, 0, [("train/loss", 1.0), ("val/loss", 1.1)])]
        log_dir = self._make_log_dir(tmp_path, events)
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        section = metrics.annex_iv_section_3b()
        assert section["annex_iv_section"] == "3b"
        assert "train/loss" in section["loss_curves"]
        assert "val/loss" in section["validation_metrics"]

    def test_multiple_event_files(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _make_tfevents_file(log_dir / "events.out.tfevents.001.host", [(1.0, 0, [("loss", 1.0)])])
        _make_tfevents_file(log_dir / "events.out.tfevents.002.host", [(2.0, 1, [("loss", 0.8)])])
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        assert len(metrics.series["loss"].values) == 2

    def test_corrupt_tfevents_does_not_raise(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        (log_dir / "events.out.tfevents.bad").write_bytes(b"\x00\x01\x02corrupt data")
        # should not raise — warnings logged internally
        metrics = ArtifactExtractor.from_tensorboard_logs(log_dir)
        assert isinstance(metrics, TrainingMetrics)


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_training_config() tests
# ---------------------------------------------------------------------------

class TestFromTrainingConfig:
    def test_json_flat_config(self, tmp_path):
        cfg = {"learning_rate": 1e-4, "optimizer": "AdamW", "batch_size": 32, "max_epochs": 10}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        tc = ArtifactExtractor.from_training_config(p)
        assert tc.optimizer.get("learning_rate") == pytest.approx(1e-4)
        assert tc.optimizer.get("type") == "AdamW"
        assert tc.training.get("batch_size") == 32

    def test_json_nested_config(self, tmp_path):
        cfg = {
            "model": {"optimizer": "SGD", "learning_rate": 0.01},
            "trainer": {"max_epochs": 20, "gradient_clip_val": 1.0},
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        tc = ArtifactExtractor.from_training_config(p)
        assert tc.optimizer.get("type") == "SGD"
        assert tc.training.get("gradient_clip") == pytest.approx(1.0)

    def test_source_path_recorded(self, tmp_path):
        p = tmp_path / "hparams.json"
        p.write_text(json.dumps({"lr": 0.001}))
        tc = ArtifactExtractor.from_training_config(p)
        assert tc.source_path == str(p)

    def test_annex_iv_1c_structure(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"optimizer": "Adam", "learning_rate": 3e-4}))
        tc = ArtifactExtractor.from_training_config(p)
        section = tc.annex_iv_section_1c()
        assert section["annex_iv_section"] == "1c"
        assert "optimizer" in section
        assert "training" in section

    def test_empty_config_file(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text("{}")
        tc = ArtifactExtractor.from_training_config(p)
        assert isinstance(tc, TrainingConfig)
        assert tc.optimizer == {}

    def test_unsupported_extension_returns_empty(self, tmp_path):
        p = tmp_path / "config.xml"
        p.write_text("<config/>")
        tc = ArtifactExtractor.from_training_config(p)
        assert isinstance(tc, TrainingConfig)
        assert tc.optimizer == {}

    def test_from_config_dict_direct(self):
        raw = {"learning_rate": 5e-5, "optimizer": "AdamW", "num_train_epochs": 3}
        tc = ArtifactExtractor.from_config_dict(raw)
        assert tc.optimizer.get("learning_rate") == pytest.approx(5e-5)
        assert tc.training.get("max_steps") == 3

    def test_weight_decay_extracted(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"weight_decay": 0.01, "optimizer": "AdamW"}))
        tc = ArtifactExtractor.from_training_config(p)
        assert tc.optimizer.get("weight_decay") == pytest.approx(0.01)

    def test_gradient_accumulation_extracted(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"gradient_accumulation_steps": 4}))
        tc = ArtifactExtractor.from_training_config(p)
        assert tc.training.get("gradient_accumulation_steps") == 4

    def test_precision_extracted(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"fp16": True, "learning_rate": 1e-5}))
        tc = ArtifactExtractor.from_training_config(p)
        assert tc.training.get("precision") is True


# ---------------------------------------------------------------------------
# from_run_dir() auto-discovery tests
# ---------------------------------------------------------------------------

class TestFromRunDir:
    def test_discovers_tfevents(self, tmp_path):
        _make_tfevents_file(
            tmp_path / "events.out.tfevents.000.host",
            [(1.0, 0, [("loss", 0.5)])],
        )
        result = ArtifactExtractor.from_run_dir(tmp_path)
        assert result.metrics is not None
        assert "loss" in result.metrics.series

    def test_discovers_json_config(self, tmp_path):
        (tmp_path / "config.json").write_text(json.dumps({"learning_rate": 1e-4}))
        result = ArtifactExtractor.from_run_dir(tmp_path)
        assert result.config is not None
        assert result.config.optimizer.get("learning_rate") == pytest.approx(1e-4)

    def test_discovers_both(self, tmp_path):
        _make_tfevents_file(tmp_path / "events.out.tfevents.000.host", [(1.0, 0, [("loss", 1.0)])])
        (tmp_path / "config.json").write_text(json.dumps({"optimizer": "Adam"}))
        result = ArtifactExtractor.from_run_dir(tmp_path)
        assert result.metrics is not None
        assert result.config is not None

    def test_missing_run_dir_returns_warning(self, tmp_path):
        result = ArtifactExtractor.from_run_dir(tmp_path / "nonexistent")
        assert result.is_empty()
        assert len(result.warnings) > 0

    def test_empty_dir_adds_warning(self, tmp_path):
        result = ArtifactExtractor.from_run_dir(tmp_path)
        assert result.is_empty()
        assert any("no recognized artifacts" in w for w in result.warnings)

    def test_to_annex_iv_dict_both_sections(self, tmp_path):
        _make_tfevents_file(tmp_path / "events.out.tfevents.000.host", [(1.0, 0, [("val/loss", 0.3)])])
        (tmp_path / "config.json").write_text(json.dumps({"optimizer": "AdamW", "learning_rate": 2e-5}))
        result = ArtifactExtractor.from_run_dir(tmp_path)
        d = result.to_annex_iv_dict()
        assert "section_1c" in d
        assert "section_3b" in d


# ---------------------------------------------------------------------------
# ArtifactExtractionResult tests
# ---------------------------------------------------------------------------

class TestArtifactExtractionResult:
    def test_is_empty_true(self):
        r = ArtifactExtractionResult()
        assert r.is_empty()

    def test_is_empty_false_with_metrics(self):
        r = ArtifactExtractionResult(metrics=TrainingMetrics(source="tb", run_id=None))
        assert not r.is_empty()

    def test_to_annex_iv_dict_empty(self):
        r = ArtifactExtractionResult()
        assert r.to_annex_iv_dict() == {}

    def test_to_annex_iv_dict_warnings(self):
        r = ArtifactExtractionResult(warnings=["something failed"])
        d = r.to_annex_iv_dict()
        assert "warnings" in d


# ---------------------------------------------------------------------------
# Stub methods raise NotImplementedError
# ---------------------------------------------------------------------------

class TestStubMethods:
    pass  # all stubs implemented — see W129, W130, W131 test files
