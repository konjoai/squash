"""squash/artifact_extractor.py — Annex IV artifact extraction engine.

Extracts training-time metadata required by EU AI Act Annex IV from experiment
trackers, training configs, and source code — converting raw ML engineering
artifacts into structured compliance evidence.

Annex IV coverage:
  §1(c) — Development information: hyperparameters, optimizer, scheduler
  §2(a) — Data governance: dataset provenance, preprocessing, bias checks
  §3(b) — Training methodology: loss curves, validation metrics, checkpointing

Wave 128: TensorBoard event file parser + training config parser (YAML/JSON).
  Zero-dependency native TFRecord reader — no tensorflow or tensorboard required.
  Fast path via tensorboard SDK if installed (guarded import).

Wave 129: MLflow SDK integration — real MlflowClient, full metric history,
  param coercion, run metadata, experiment tags. Local file:// URI supported
  (no server needed for CI).

Wave 130: W&B API integration.
Wave 131: HuggingFace Datasets provenance tracker.
Wave 132: Python AST code scanner.
"""

from __future__ import annotations

import json
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class MetricSeries:
    """A time series of scalar metric values from a training run."""
    tag: str
    steps: list[int] = field(default_factory=list)
    values: list[float] = field(default_factory=list)
    wall_times: list[float] = field(default_factory=list)

    def last(self) -> float | None:
        return self.values[-1] if self.values else None

    def min(self) -> float | None:
        return min(self.values) if self.values else None

    def max(self) -> float | None:
        return max(self.values) if self.values else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "steps": self.steps,
            "values": self.values,
            "wall_times": self.wall_times,
            "summary": {
                "last": self.last(),
                "min": self.min(),
                "max": self.max(),
                "count": len(self.values),
            },
        }


@dataclass
class TrainingMetrics:
    """Scalar metrics extracted from a training run — Annex IV §3(b) evidence."""
    source: str  # "tensorboard" | "mlflow" | "wandb"
    run_id: str | None
    series: dict[str, MetricSeries] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def annex_iv_section_3b(self) -> dict[str, Any]:
        """Render Annex IV §3(b) training methodology evidence block."""
        loss_tags = [t for t in self.series if "loss" in t.lower()]
        val_tags = [t for t in self.series if any(k in t.lower() for k in ("val", "valid", "eval", "test"))]
        return {
            "annex_iv_section": "3b",
            "title": "Training and Validation Metrics",
            "source": self.source,
            "run_id": self.run_id,
            "loss_curves": {t: self.series[t].to_dict() for t in loss_tags},
            "validation_metrics": {t: self.series[t].to_dict() for t in val_tags},
            "all_metrics": {t: self.series[t].to_dict() for t in self.series},
            "metadata": self.metadata,
        }


@dataclass
class TrainingConfig:
    """Hyperparameters and training settings — Annex IV §1(c) evidence."""
    source_path: str | None
    optimizer: dict[str, Any] = field(default_factory=dict)
    scheduler: dict[str, Any] = field(default_factory=dict)
    training: dict[str, Any] = field(default_factory=dict)
    model: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def annex_iv_section_1c(self) -> dict[str, Any]:
        """Render Annex IV §1(c) development information evidence block."""
        return {
            "annex_iv_section": "1c",
            "title": "Training Hyperparameters and Development Configuration",
            "source": self.source_path,
            "optimizer": self.optimizer,
            "scheduler": self.scheduler,
            "training": self.training,
            "model_config": self.model,
        }


@dataclass
class DatasetProvenance:
    """Dataset provenance record for EU AI Act Annex IV §2(a).

    Captures the data governance evidence required by Article 11 —
    provenance, scope, characteristics, preprocessing, and bias analysis.
    """
    dataset_id: str
    source: str                          # "huggingface" | "local" | "custom"
    pretty_name: str | None = None
    description: str | None = None
    license: str | None = None
    languages: list[str] = field(default_factory=list)
    task_categories: list[str] = field(default_factory=list)
    size_category: str | None = None     # e.g. "10K<n<100K", "1M<n<10M"
    split_info: dict[str, Any] = field(default_factory=dict)
    source_datasets: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    citation: str | None = None
    created_at: str | None = None
    last_modified: str | None = None
    downloads: int | None = None
    has_bias_analysis: bool = False      # README contains bias/fairness content
    card_data_raw: dict[str, Any] = field(default_factory=dict)

    def completeness_score(self) -> int:
        """Percentage of Annex IV §2(a) required fields populated (0–100).

        Uses a weighted scoring model aligned with Article 10(2) obligations.
        A score below 60 indicates gaps that an auditor will flag.
        """
        score = 0
        weights = {
            "description":       20,
            "license":           20,
            "languages":         15,
            "source_datasets":   15,
            "task_categories":   10,
            "size_category":     10,
            "has_bias_analysis":  5,
            "citation":           5,
        }
        for attr, weight in weights.items():
            val = getattr(self, attr)
            if val is True or (val and val != [] and val != {}):
                score += weight
        return min(score, 100)

    def completeness_gaps(self) -> list[str]:
        """Return list of Annex IV §2(a) fields that are missing or empty."""
        field_labels = {
            "description":       "General description (§2(a))",
            "license":           "License / data provenance (§2(a))",
            "languages":         "Language distribution (§2(a))",
            "source_datasets":   "Source dataset origin (§2(a))",
            "task_categories":   "Task categories / intended use",
            "size_category":     "Dataset size / scope",
            "has_bias_analysis": "Bias and fairness analysis (Art. 10(2)(f))",
            "citation":          "Citation / academic reference",
        }
        gaps = []
        for attr, label in field_labels.items():
            val = getattr(self, attr)
            if not val and val is not True:
                gaps.append(label)
        return gaps

    def annex_iv_section_2a(self) -> dict[str, Any]:
        """Render EU AI Act Annex IV §2(a) data governance evidence block."""
        return {
            "annex_iv_section": "2a",
            "title": "Training Data Governance and Provenance",
            "dataset_id": self.dataset_id,
            "source": self.source,
            "pretty_name": self.pretty_name,
            "description": self.description,
            "license": self.license,
            "languages": self.languages,
            "task_categories": self.task_categories,
            "size_category": self.size_category,
            "split_info": self.split_info,
            "source_datasets": self.source_datasets,
            "tags": self.tags,
            "citation": self.citation,
            "provenance": {
                "created_at": self.created_at,
                "last_modified": self.last_modified,
                "downloads": self.downloads,
            },
            "bias_analysis": {
                "has_bias_content_in_card": self.has_bias_analysis,
                "note": (
                    "Bias analysis content detected in dataset card."
                    if self.has_bias_analysis
                    else "No bias analysis detected — required by Art. 10(2)(f)."
                ),
            },
            "completeness": {
                "score": self.completeness_score(),
                "gaps": self.completeness_gaps(),
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return self.annex_iv_section_2a()


@dataclass
class ArtifactExtractionResult:
    """Aggregated Annex IV artifacts from one or more sources.

    Covers all four extractable Annex IV sections:
      section_1c — TrainingConfig (hyperparams) or CodeArtifacts (software)
      section_2a — DatasetProvenance list (data governance)
      section_3b — TrainingMetrics (training methodology)
    """
    metrics: TrainingMetrics | None = None
    config: TrainingConfig | None = None
    datasets: list["DatasetProvenance"] = field(default_factory=list)
    code: "CodeArtifacts | None" = None
    warnings: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return (
            self.metrics is None
            and self.config is None
            and not self.datasets
            and self.code is None
        )

    def to_annex_iv_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        # §1(c): prefer code artifacts when available (richer software evidence),
        # fall back to config (hyperparameters from training config file)
        if self.code:
            result["section_1c"] = self.code.annex_iv_section_1c()
        elif self.config:
            result["section_1c"] = self.config.annex_iv_section_1c()
        if self.datasets:
            result["section_2a"] = [d.annex_iv_section_2a() for d in self.datasets]
        if self.metrics:
            result["section_3b"] = self.metrics.annex_iv_section_3b()
        if self.warnings:
            result["warnings"] = self.warnings
        return result


# ---------------------------------------------------------------------------
# W128: Native TFRecord / TensorBoard binary reader
# ---------------------------------------------------------------------------

def _read_varint(buf: memoryview, pos: int) -> tuple[int, int]:
    """Decode a protobuf varint from buf at pos. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return result, pos


def _decode_proto_fields(buf: bytes) -> dict[int, list[Any]]:
    """Decode a protobuf message into {field_number: [values]}.

    Handles wire types: 0 (varint), 1 (64-bit double), 2 (bytes), 5 (32-bit float).
    Sufficient for parsing TensorBoard Event + Summary + Value protos.
    """
    mv = memoryview(buf)
    pos = 0
    fields: dict[int, list[Any]] = {}
    while pos < len(mv):
        try:
            tag_raw, pos = _read_varint(mv, pos)
        except Exception:
            break
        field_num = tag_raw >> 3
        wire_type = tag_raw & 0x7
        try:
            if wire_type == 0:  # varint
                val, pos = _read_varint(mv, pos)
                fields.setdefault(field_num, []).append(val)
            elif wire_type == 1:  # 64-bit (double)
                if pos + 8 > len(mv):
                    break
                val = struct.unpack_from("<d", mv, pos)[0]
                pos += 8
                fields.setdefault(field_num, []).append(val)
            elif wire_type == 2:  # length-delimited (string, bytes, nested)
                length, pos = _read_varint(mv, pos)
                if pos + length > len(mv):
                    break
                val = bytes(mv[pos : pos + length])
                pos += length
                fields.setdefault(field_num, []).append(val)
            elif wire_type == 5:  # 32-bit (float)
                if pos + 4 > len(mv):
                    break
                val = struct.unpack_from("<f", mv, pos)[0]
                pos += 4
                fields.setdefault(field_num, []).append(val)
            else:
                break  # unknown wire type — stop parsing this message
        except Exception:
            break
    return fields


def _iter_tfrecord_bytes(path: Path) -> Iterator[bytes]:
    """Yield raw proto bytes from a TFRecord file.

    TFRecord format per record:
      uint64  length           (little-endian)
      uint32  masked_crc32     (skipped — not validated)
      bytes   data[length]
      uint32  masked_crc32     (skipped — not validated)
    """
    with open(path, "rb") as fh:
        while True:
            header = fh.read(12)  # 8 (length) + 4 (crc)
            if len(header) < 12:
                return
            length = struct.unpack_from("<Q", header, 0)[0]
            data = fh.read(length)
            fh.read(4)  # skip data CRC
            if len(data) < length:
                return
            yield data


def _parse_tb_scalars(event_bytes: bytes) -> tuple[float, int, list[tuple[str, float]]]:
    """Parse one TensorBoard Event proto into (wall_time, step, scalars).

    Event proto field map:
      1  wall_time    double (wire 1)
      2  step         int64  (wire 0)
      5  summary      bytes  (wire 2) → Summary proto

    Summary.Value field map:
      1  tag          string (wire 2)
      2  simple_value float  (wire 5)
    """
    event = _decode_proto_fields(event_bytes)
    wall_time: float = event.get(1, [0.0])[0]
    step: int = int(event.get(2, [0])[0])
    scalars: list[tuple[str, float]] = []

    for summary_bytes in event.get(5, []):
        summary = _decode_proto_fields(summary_bytes)
        for value_bytes in summary.get(1, []):  # repeated Summary.Value
            value = _decode_proto_fields(value_bytes)
            tag_raw = value.get(1, [b""])[0]
            tag = tag_raw.decode("utf-8", errors="replace") if isinstance(tag_raw, bytes) else str(tag_raw)
            simple_value = value.get(2, [None])[0]  # wire type 5 → float
            if simple_value is not None and isinstance(simple_value, float):
                scalars.append((tag, simple_value))

    return wall_time, step, scalars


def _parse_tensorboard_native(log_dir: Path) -> TrainingMetrics:
    """Parse all .tfevents files under log_dir using the native binary reader."""
    series: dict[str, MetricSeries] = {}
    event_files = sorted(log_dir.rglob("events.out.tfevents.*"))

    if not event_files:
        log.debug("artifact_extractor: no tfevents files found in %s", log_dir)

    for ef in event_files:
        try:
            for raw in _iter_tfrecord_bytes(ef):
                wall_time, step, scalars = _parse_tb_scalars(raw)
                for tag, value in scalars:
                    if tag not in series:
                        series[tag] = MetricSeries(tag=tag)
                    series[tag].steps.append(step)
                    series[tag].values.append(value)
                    series[tag].wall_times.append(wall_time)
        except Exception as exc:
            log.warning("artifact_extractor: failed to parse %s: %s", ef, exc)

    return TrainingMetrics(
        source="tensorboard",
        run_id=str(log_dir),
        series=series,
        metadata={"log_dir": str(log_dir), "event_files": [str(e) for e in event_files]},
    )


def _parse_tensorboard_sdk(log_dir: Path) -> TrainingMetrics:
    """Fast path: parse via tensorboard EventAccumulator SDK if installed."""
    from tensorboard.backend.event_processing.event_accumulator import EventAccumulator  # type: ignore

    ea = EventAccumulator(str(log_dir))
    ea.Reload()
    series: dict[str, MetricSeries] = {}
    for tag in ea.Tags().get("scalars", []):
        events = ea.Scalars(tag)
        series[tag] = MetricSeries(
            tag=tag,
            steps=[e.step for e in events],
            values=[e.value for e in events],
            wall_times=[e.wall_time for e in events],
        )
    return TrainingMetrics(
        source="tensorboard",
        run_id=str(log_dir),
        series=series,
        metadata={"log_dir": str(log_dir), "sdk": "tensorboard"},
    )


# ---------------------------------------------------------------------------
# W128: Training config parser (YAML / JSON)
# ---------------------------------------------------------------------------

_OPTIMIZER_KEYS = {"optimizer", "optim", "opt"}
_LR_KEYS = {"learning_rate", "lr", "initial_lr", "base_lr"}
_WD_KEYS = {"weight_decay", "wd", "l2"}
_MOMENTUM_KEYS = {"momentum", "beta1", "betas"}
_SCHEDULER_KEYS = {"scheduler", "lr_scheduler", "schedule"}
_WARMUP_KEYS = {"warmup_steps", "warmup_ratio", "warmup_epochs"}
_BATCH_KEYS = {"batch_size", "per_device_train_batch_size", "train_batch_size"}
_EPOCH_KEYS = {"max_epochs", "num_train_epochs", "epochs", "max_steps"}
_GRAD_CLIP_KEYS = {"gradient_clip_val", "max_grad_norm", "clip_grad_norm"}
_GRAD_ACCUM_KEYS = {"gradient_accumulation_steps", "grad_accum", "accumulate_grad_batches"}
_DROPOUT_KEYS = {"dropout", "attention_dropout", "hidden_dropout_prob"}
_PRECISION_KEYS = {"precision", "fp16", "bf16", "mixed_precision", "dtype"}


def _find_key(d: dict, keys: set[str]) -> Any | None:
    """Case-insensitive search for any of `keys` in dict `d`."""
    for k, v in d.items():
        if k.lower() in keys:
            return v
    return None


def _flatten_nested(d: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict for key search across training config formats."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_nested(v, full_key))
        else:
            out[full_key] = v
    return out


def _extract_optimizer(raw: dict) -> dict[str, Any]:
    """Extract optimizer config from a training config dict."""
    opt: dict[str, Any] = {}
    flat = _flatten_nested(raw)

    # optimizer type — check top-level first, then flat-nested (e.g. {"model": {"optimizer": "SGD"}})
    opt_val = _find_key(raw, _OPTIMIZER_KEYS)
    if opt_val is None:
        for full_key, v in flat.items():
            short = full_key.split(".")[-1].lower()
            if short in _OPTIMIZER_KEYS:
                opt_val = v
                break
    if isinstance(opt_val, str):
        opt["type"] = opt_val
    elif isinstance(opt_val, dict):
        opt["type"] = opt_val.get("type") or opt_val.get("name") or opt_val.get("_target_", "")
        for k in ("lr", "learning_rate"):
            if k in opt_val:
                opt["learning_rate"] = float(opt_val[k])
        for k in ("weight_decay", "wd"):
            if k in opt_val:
                opt["weight_decay"] = float(opt_val[k])
        betas = opt_val.get("betas") or opt_val.get("beta1")
        if betas:
            opt["betas"] = betas

    # learning rate (flat search)
    for full_key, v in flat.items():
        short = full_key.split(".")[-1].lower()
        if short in _LR_KEYS and "lr" not in opt:
            try:
                opt["learning_rate"] = float(v)
            except (TypeError, ValueError):
                pass
        if short in _WD_KEYS and "weight_decay" not in opt:
            try:
                opt["weight_decay"] = float(v)
            except (TypeError, ValueError):
                pass
        if short in _MOMENTUM_KEYS and "momentum" not in opt:
            opt["momentum"] = v

    return opt


def _extract_scheduler(raw: dict) -> dict[str, Any]:
    """Extract LR scheduler config from a training config dict."""
    sched: dict[str, Any] = {}
    sched_val = _find_key(raw, _SCHEDULER_KEYS)
    if isinstance(sched_val, str):
        sched["type"] = sched_val
    elif isinstance(sched_val, dict):
        sched["type"] = sched_val.get("type") or sched_val.get("name") or sched_val.get("_target_", "")

    flat = _flatten_nested(raw)
    for full_key, v in flat.items():
        short = full_key.split(".")[-1].lower()
        if short in _WARMUP_KEYS and "warmup" not in sched:
            sched["warmup"] = v

    return sched


def _extract_training(raw: dict) -> dict[str, Any]:
    """Extract training loop settings from a training config dict."""
    tr: dict[str, Any] = {}
    flat = _flatten_nested(raw)

    for full_key, v in flat.items():
        short = full_key.split(".")[-1].lower()
        if short in _BATCH_KEYS and "batch_size" not in tr:
            try:
                tr["batch_size"] = int(v)
            except (TypeError, ValueError):
                pass
        if short in _EPOCH_KEYS and "max_steps" not in tr:
            tr["max_steps"] = v
        if short in _GRAD_CLIP_KEYS and "gradient_clip" not in tr:
            try:
                tr["gradient_clip"] = float(v)
            except (TypeError, ValueError):
                pass
        if short in _GRAD_ACCUM_KEYS and "gradient_accumulation_steps" not in tr:
            try:
                tr["gradient_accumulation_steps"] = int(v)
            except (TypeError, ValueError):
                pass
        if short in _DROPOUT_KEYS and "dropout" not in tr:
            try:
                tr["dropout"] = float(v)
            except (TypeError, ValueError):
                pass
        if short in _PRECISION_KEYS and "precision" not in tr:
            tr["precision"] = v

    return tr


def _coerce_mlflow_param(value: str) -> Any:
    """Coerce an MLflow param string to a native Python type.

    MLflow logs all params as str. We try int first, then float, then bool,
    leaving strings that don't convert as-is.
    """
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if stripped.lower() in ("true", "false"):
        return stripped.lower() == "true"
    try:
        int_val = int(stripped)
        return int_val
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        return value


def _build_wandb_path(run_id: str, entity: str, project: str) -> str:
    """Build a canonical W&B run path from its components.

    W&B ``Api.run()`` expects ``"entity/project/run_id"``.  If *run_id*
    already contains slashes it is used verbatim; otherwise the entity and
    project kwargs are prepended when provided.
    """
    if "/" in run_id:
        return run_id
    if entity and project:
        return f"{entity}/{project}/{run_id}"
    if project:
        return f"{project}/{run_id}"
    return run_id  # let W&B resolve via default entity


def _extract_wandb_metrics(run: Any, *, include_system_metrics: bool = False) -> TrainingMetrics:
    """Single-pass streaming extraction of all scalar series from a W&B run.

    Iterates ``run.scan_history()`` once, accumulating steps/values/wall_times
    for every metric key encountered. None values (step where metric was not
    logged) are skipped. Non-numeric values are skipped.

    W&B ``_timestamp`` is already Unix seconds — written directly to
    wall_times without conversion (contrast: MLflow uses milliseconds).
    """
    # Pre-declare as lists to avoid repeated dict-get in the hot loop
    steps_map: dict[str, list[int]] = {}
    values_map: dict[str, list[float]] = {}
    times_map: dict[str, list[float]] = {}

    for row in run.scan_history():
        step = int(row.get("_step", 0))
        wall_time = float(row.get("_timestamp", 0.0))

        for key, value in row.items():
            if key.startswith("_"):
                continue
            if not include_system_metrics and key.startswith("system/"):
                continue
            if value is None:
                continue
            if not isinstance(value, (int, float)):
                continue

            if key not in steps_map:
                steps_map[key] = []
                values_map[key] = []
                times_map[key] = []

            steps_map[key].append(step)
            values_map[key].append(float(value))
            times_map[key].append(wall_time)

    series = {
        key: MetricSeries(
            tag=key,
            steps=steps_map[key],
            values=values_map[key],
            wall_times=times_map[key],
        )
        for key in steps_map
    }

    return TrainingMetrics(
        source="wandb",
        run_id=getattr(run, "id", None),
        series=series,
        metadata={
            "entity": getattr(run, "entity", None),
            "project": getattr(run, "project", None),
            "run_name": getattr(run, "name", None),
            "state": getattr(run, "state", None),
            "url": getattr(run, "url", None),
            "tags": list(getattr(run, "tags", []) or []),
        },
    )


def _extract_wandb_config(run: Any, path: str) -> TrainingConfig:
    """Extract and sanitise W&B run config → TrainingConfig.

    W&B injects internal keys prefixed ``_wandb`` into the run config
    (e.g. ``_wandb.version``, ``_wandb.run_id``). These are stripped before
    passing to the standard config extractor so they do not pollute the
    Annex IV §1(c) hyperparameter record.
    """
    raw_config = dict(getattr(run, "config", {}) or {})
    filtered = {k: v for k, v in raw_config.items() if not k.startswith("_wandb")}
    return _parse_config_dict(filtered, source_path=f"wandb://{path}")


def _parse_config_dict(raw: dict, source_path: str | None = None) -> TrainingConfig:
    return TrainingConfig(
        source_path=source_path,
        optimizer=_extract_optimizer(raw),
        scheduler=_extract_scheduler(raw),
        training=_extract_training(raw),
        model={k: v for k, v in raw.items() if k.lower() in {"model", "architecture", "arch"}},
        raw=raw,
    )


# ---------------------------------------------------------------------------
# W131: HuggingFace dataset provenance helpers
# ---------------------------------------------------------------------------

# Keywords that indicate bias/fairness analysis in a dataset README.
_BIAS_KEYWORDS: frozenset[str] = frozenset({
    "bias", "fairness", "limitation", "demographic", "underrepresented",
    "protected attribute", "discrimination", "stereotyp", "unrepresent",
    "sensitive attribute", "equity", "disparity", "imbalance",
})


def _has_bias_content(text: str) -> bool:
    """Return True if *text* contains EU AI Act Art. 10(2)(f) bias indicators."""
    lower = text.lower()
    return any(kw in lower for kw in _BIAS_KEYWORDS)


def _extract_citation(text: str) -> str | None:
    """Pull the first BibTeX entry from a README, if present."""
    import re
    match = re.search(r"@\w+\s*\{[^}]+\}", text, re.DOTALL)
    return match.group(0).strip() if match else None


def _parse_hf_tags(tags: list[str]) -> dict[str, list[str]]:
    """Split raw HuggingFace tags into namespaced buckets.

    HF tags follow the convention ``"namespace:value"`` (e.g.
    ``"language:en"``, ``"license:apache-2.0"``). Tags without a colon
    are stored under the ``"other"`` key.
    """
    buckets: dict[str, list[str]] = {}
    for tag in tags or []:
        if ":" in tag:
            ns, _, val = tag.partition(":")
            buckets.setdefault(ns, []).append(val)
        else:
            buckets.setdefault("other", []).append(tag)
    return buckets


def _build_dataset_provenance(
    info: Any,
    dataset_id: str,
    card_content: str | None,
) -> DatasetProvenance:
    """Assemble a DatasetProvenance from a HfApi DatasetInfo + optional card text."""
    card_data = getattr(info, "card_data", None) or {}
    tag_buckets = _parse_hf_tags(list(getattr(info, "tags", []) or []))

    # Languages — prefer card_data, fall back to tags
    languages: list[str] = list(getattr(card_data, "language", None) or tag_buckets.get("language", []))

    # License — prefer card_data, fall back to tags, then None
    license_val: str | None = getattr(card_data, "license", None)
    if not license_val:
        license_list = tag_buckets.get("license", [])
        license_val = license_list[0] if license_list else None

    # Task categories
    task_categories: list[str] = list(getattr(card_data, "task_categories", None) or [])

    # Size bucket — first entry from card_data
    size_cats = list(getattr(card_data, "size_categories", None) or [])
    size_category: str | None = size_cats[0] if size_cats else None

    # Source datasets
    source_datasets: list[str] = list(getattr(card_data, "source_datasets", None) or [])

    # Pretty name
    pretty_name: str | None = getattr(card_data, "pretty_name", None) or getattr(info, "pretty_name", None)

    # Timestamps → ISO strings
    created_raw = getattr(info, "created_at", None)
    modified_raw = getattr(info, "last_modified", None)
    created_at = created_raw.isoformat() if hasattr(created_raw, "isoformat") else str(created_raw) if created_raw else None
    last_modified = modified_raw.isoformat() if hasattr(modified_raw, "isoformat") else str(modified_raw) if modified_raw else None

    # Downloads
    downloads = getattr(info, "downloads", None)

    # Bias analysis & citation from card README
    has_bias = _has_bias_content(card_content) if card_content else False
    citation = _extract_citation(card_content) if card_content else None

    # Raw card metadata for full transparency
    card_data_raw: dict[str, Any] = {}
    if card_data:
        for key in ("language", "license", "task_categories", "size_categories",
                    "source_datasets", "pretty_name", "multilinguality",
                    "task_ids", "annotations_creators", "paperswithcode_id"):
            val = getattr(card_data, key, None)
            if val is not None:
                card_data_raw[key] = val

    return DatasetProvenance(
        dataset_id=dataset_id,
        source="huggingface",
        pretty_name=pretty_name,
        description=None,  # HF API v0.36 doesn't expose description directly; comes from card
        license=license_val,
        languages=languages,
        task_categories=task_categories,
        size_category=size_category,
        split_info={},  # populated by datasets library if available
        source_datasets=source_datasets,
        tags=list(getattr(info, "tags", []) or []),
        citation=citation,
        created_at=created_at,
        last_modified=last_modified,
        downloads=downloads,
        has_bias_analysis=has_bias,
        card_data_raw=card_data_raw,
    )


# ---------------------------------------------------------------------------
# Public API — ArtifactExtractor
# ---------------------------------------------------------------------------

class ArtifactExtractor:
    """Extract EU AI Act Annex IV artifacts from ML training runs.

    Supports: TensorBoard (W128), MLflow (W129), W&B (W130),
    HuggingFace Datasets (W131), Python AST (W132).
    """

    # ------------------------------------------------------------------
    # W128: TensorBoard event file parser
    # ------------------------------------------------------------------

    @staticmethod
    def from_tensorboard_logs(log_dir: str | Path) -> TrainingMetrics:
        """Parse TensorBoard event files → loss curves and validation metrics.

        Uses the tensorboard SDK fast path if available, otherwise falls back
        to the zero-dependency native TFRecord binary reader.

        Args:
            log_dir: Directory containing .tfevents.* files (searched recursively).

        Returns:
            TrainingMetrics with all scalar series keyed by tag name.
            Addresses Annex IV §3(b): training and validation methodology.
        """
        log_dir = Path(log_dir)
        if not log_dir.exists():
            return TrainingMetrics(
                source="tensorboard",
                run_id=str(log_dir),
                series={},
                metadata={"error": f"log_dir not found: {log_dir}"},
            )

        try:
            import tensorboard  # noqa: F401
            return _parse_tensorboard_sdk(log_dir)
        except ImportError:
            log.debug("artifact_extractor: tensorboard SDK not installed, using native reader")
            return _parse_tensorboard_native(log_dir)

    # ------------------------------------------------------------------
    # W128: Training config parser (YAML / JSON / TOML)
    # ------------------------------------------------------------------

    @staticmethod
    def from_training_config(config_path: str | Path) -> TrainingConfig:
        """Parse a training config file → structured hyperparameter metadata.

        Supports JSON, YAML (requires PyYAML), and TOML (Python 3.11+).
        Extracts optimizer type, learning rate, scheduler, batch size, and
        all other training settings for Annex IV §1(c) documentation.

        Args:
            config_path: Path to a JSON, YAML, or TOML training config.

        Returns:
            TrainingConfig with structured optimizer, scheduler, training fields.
            Addresses Annex IV §1(c): development process and hyperparameters.
        """
        config_path = Path(config_path)
        suffix = config_path.suffix.lower()

        raw: dict[str, Any] = {}

        if suffix == ".json":
            with open(config_path) as fh:
                raw = json.load(fh)

        elif suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                with open(config_path) as fh:
                    raw = yaml.safe_load(fh) or {}
            except ImportError:
                # PyYAML not installed — attempt naive JSON parse as last resort
                with open(config_path) as fh:
                    content = fh.read()
                try:
                    raw = json.loads(content)
                except json.JSONDecodeError:
                    raw = {}
                    log.warning("artifact_extractor: PyYAML not installed, could not parse %s", config_path)

        elif suffix == ".toml":
            try:
                import tomllib  # Python 3.11+
                with open(config_path, "rb") as fh:
                    raw = tomllib.load(fh)
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore
                    with open(config_path, "rb") as fh:
                        raw = tomllib.load(fh)
                except ImportError:
                    log.warning("artifact_extractor: tomllib/tomli not available for %s", config_path)
        else:
            log.warning("artifact_extractor: unsupported config format %s", suffix)

        return _parse_config_dict(raw, source_path=str(config_path))

    @staticmethod
    def from_config_dict(raw: dict[str, Any]) -> TrainingConfig:
        """Parse an already-loaded config dict → TrainingConfig.

        Useful when config is embedded in a larger experiment object (MLflow
        params, W&B config, Ray Tune search space, etc.).
        """
        return _parse_config_dict(raw, source_path=None)

    # ------------------------------------------------------------------
    # W129: MLflow SDK integration
    # ------------------------------------------------------------------

    @staticmethod
    def from_mlflow_run(run_id: str, tracking_uri: str = "http://localhost:5000") -> TrainingMetrics:
        """Pull full metric history from an MLflow run → TrainingMetrics.

        Uses MlflowClient.get_metric_history() for each metric key so that
        complete loss curves are captured, not just the final value. All
        MLflow metric timestamps (milliseconds) are converted to seconds to
        match the wall_times contract in MetricSeries.

        Supports local file:// tracking URIs (no server required in CI):
            tracking_uri="file:///path/to/mlruns"

        Args:
            run_id:       MLflow run UUID (shown in the MLflow UI or
                          ``run.info.run_id``).
            tracking_uri: MLflow tracking server URI or local file:// path.
                          Defaults to the standard local server port.

        Returns:
            TrainingMetrics with one MetricSeries per logged metric.
            Addresses Annex IV §3(b): training and validation methodology.

        Raises:
            ImportError: if mlflow is not installed.
            mlflow.exceptions.MlflowException: if the run_id is not found.
        """
        try:
            from mlflow.tracking import MlflowClient  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "mlflow is required for from_mlflow_run(). "
                "Install with: pip install mlflow"
            ) from exc

        client = MlflowClient(tracking_uri=tracking_uri)
        run = client.get_run(run_id)
        metric_keys = list(run.data.metrics.keys())

        series: dict[str, MetricSeries] = {}
        for key in metric_keys:
            history = client.get_metric_history(run_id, key)
            history_sorted = sorted(history, key=lambda m: (m.step, m.timestamp))
            series[key] = MetricSeries(
                tag=key,
                steps=[m.step for m in history_sorted],
                values=[m.value for m in history_sorted],
                wall_times=[m.timestamp / 1000.0 for m in history_sorted],  # ms → s
            )

        run_info = run.info
        return TrainingMetrics(
            source="mlflow",
            run_id=run_id,
            series=series,
            metadata={
                "tracking_uri": tracking_uri,
                "experiment_id": run_info.experiment_id,
                "run_name": getattr(run_info, "run_name", None),
                "status": run_info.status,
                "start_time_ms": run_info.start_time,
                "end_time_ms": run_info.end_time,
                "artifact_uri": run_info.artifact_uri,
                "tags": dict(run.data.tags),
            },
        )

    @staticmethod
    def from_mlflow_params(run_id: str, tracking_uri: str = "http://localhost:5000") -> TrainingConfig:
        """Pull run params from an MLflow run → TrainingConfig.

        MLflow stores all params as strings. Numeric strings are coerced to
        int or float so the downstream config extractors can apply proper
        type comparisons and threshold logic.

        Args:
            run_id:       MLflow run UUID.
            tracking_uri: MLflow tracking server URI or local file:// path.

        Returns:
            TrainingConfig with optimizer, scheduler, and training fields
            populated from the run's logged params.
            Addresses Annex IV §1(c): development hyperparameters.

        Raises:
            ImportError: if mlflow is not installed.
        """
        try:
            from mlflow.tracking import MlflowClient  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "mlflow is required for from_mlflow_params(). "
                "Install with: pip install mlflow"
            ) from exc

        client = MlflowClient(tracking_uri=tracking_uri)
        run = client.get_run(run_id)
        raw_params = dict(run.data.params)

        # Coerce numeric strings — MLflow stores everything as str
        coerced: dict[str, Any] = {}
        for k, v in raw_params.items():
            coerced[k] = _coerce_mlflow_param(v)

        return _parse_config_dict(coerced, source_path=f"mlflow+run://{run_id}")

    @staticmethod
    def from_mlflow_run_full(
        run_id: str, tracking_uri: str = "http://localhost:5000"
    ) -> "ArtifactExtractionResult":
        """Extract both metrics and params from one MLflow run.

        Equivalent to calling from_mlflow_run() and from_mlflow_params()
        together, with a single MlflowClient round-trip for metadata.

        Returns:
            ArtifactExtractionResult with .metrics (TrainingMetrics) and
            .config (TrainingConfig) both populated.
        """
        try:
            from mlflow.tracking import MlflowClient  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "mlflow is required for from_mlflow_run_full(). "
                "Install with: pip install mlflow"
            ) from exc

        client = MlflowClient(tracking_uri=tracking_uri)
        run = client.get_run(run_id)
        metric_keys = list(run.data.metrics.keys())

        series: dict[str, MetricSeries] = {}
        for key in metric_keys:
            history = client.get_metric_history(run_id, key)
            history_sorted = sorted(history, key=lambda m: (m.step, m.timestamp))
            series[key] = MetricSeries(
                tag=key,
                steps=[m.step for m in history_sorted],
                values=[m.value for m in history_sorted],
                wall_times=[m.timestamp / 1000.0 for m in history_sorted],
            )

        run_info = run.info
        metrics = TrainingMetrics(
            source="mlflow",
            run_id=run_id,
            series=series,
            metadata={
                "tracking_uri": tracking_uri,
                "experiment_id": run_info.experiment_id,
                "run_name": getattr(run_info, "run_name", None),
                "status": run_info.status,
                "artifact_uri": run_info.artifact_uri,
                "tags": dict(run.data.tags),
            },
        )

        coerced: dict[str, Any] = {k: _coerce_mlflow_param(v) for k, v in run.data.params.items()}
        config = _parse_config_dict(coerced, source_path=f"mlflow+run://{run_id}")

        return ArtifactExtractionResult(metrics=metrics, config=config)

    # ------------------------------------------------------------------
    # W130: W&B API integration
    # ------------------------------------------------------------------

    @staticmethod
    def from_wandb_run(
        run_id: str,
        *,
        entity: str = "",
        project: str = "",
        include_system_metrics: bool = False,
    ) -> TrainingMetrics:
        """Pull full metric history from a W&B run → TrainingMetrics.

        Uses a single streaming pass through ``run.scan_history()`` to build
        all MetricSeries simultaneously — O(1) memory overhead regardless of
        run size, never one API call per metric key.

        W&B timestamps are already in seconds (unlike MLflow's milliseconds),
        so they are written directly to ``MetricSeries.wall_times``.

        ``None`` values — logged when a metric was not recorded at a given
        step — are silently skipped to keep series contiguous.

        Args:
            run_id:     W&B run ID, or full ``"entity/project/run_id"`` path.
            entity:     W&B entity (user or team). Combined with *project* and
                        *run_id* when *run_id* is not a full path.
            project:    W&B project name.
            include_system_metrics:
                        If True, include ``system/`` hardware metrics (GPU
                        utilisation, memory, etc.) in the returned series.
                        Defaults to False — system metrics are not required
                        for Annex IV but useful for hardware context.

        Returns:
            TrainingMetrics with one MetricSeries per logged scalar metric.
            Addresses Annex IV §3(b): training and validation methodology.

        Raises:
            ImportError: if wandb is not installed.
            wandb.errors.CommError: if the run is not found or API unreachable.
        """
        try:
            import wandb  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "wandb is required for from_wandb_run(). "
                "Install with: pip install wandb"
            ) from exc

        path = _build_wandb_path(run_id, entity, project)
        api = wandb.Api()
        run = api.run(path)

        metrics = _extract_wandb_metrics(run, include_system_metrics=include_system_metrics)
        metrics.run_id = run.id
        return metrics

    @staticmethod
    def from_wandb_config(
        run_id: str,
        *,
        entity: str = "",
        project: str = "",
    ) -> TrainingConfig:
        """Pull run config from a W&B run → TrainingConfig.

        Filters out W&B-internal config keys (prefixed ``_wandb``) before
        passing through the standard config extractor so optimizer, LR,
        scheduler, and training loop settings are cleanly resolved.

        Args:
            run_id:   W&B run ID or full ``"entity/project/run_id"`` path.
            entity:   W&B entity (user or team).
            project:  W&B project name.

        Returns:
            TrainingConfig with Annex IV §1(c) evidence.

        Raises:
            ImportError: if wandb is not installed.
        """
        try:
            import wandb  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "wandb is required for from_wandb_config(). "
                "Install with: pip install wandb"
            ) from exc

        path = _build_wandb_path(run_id, entity, project)
        api = wandb.Api()
        run = api.run(path)
        return _extract_wandb_config(run, path)

    @staticmethod
    def from_wandb_run_full(
        run_id: str,
        *,
        entity: str = "",
        project: str = "",
        include_system_metrics: bool = False,
    ) -> "ArtifactExtractionResult":
        """Extract both metrics and config from one W&B run.

        Makes a single ``api.run()`` call and derives both
        ``TrainingMetrics`` (§3(b)) and ``TrainingConfig`` (§1(c)) from the
        same run object — no redundant API round-trips.

        Returns:
            ArtifactExtractionResult with ``.metrics`` and ``.config`` both
            populated. Suitable for direct ``to_annex_iv_dict()`` output.
        """
        try:
            import wandb  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "wandb is required for from_wandb_run_full(). "
                "Install with: pip install wandb"
            ) from exc

        path = _build_wandb_path(run_id, entity, project)
        api = wandb.Api()
        run = api.run(path)

        metrics = _extract_wandb_metrics(run, include_system_metrics=include_system_metrics)
        metrics.run_id = run.id
        config = _extract_wandb_config(run, path)
        return ArtifactExtractionResult(metrics=metrics, config=config)

    # ------------------------------------------------------------------
    # W131: HuggingFace Datasets provenance tracker
    # ------------------------------------------------------------------

    @staticmethod
    def from_huggingface_dataset(
        dataset_id: str,
        *,
        token: str | None = None,
        revision: str | None = None,
    ) -> DatasetProvenance:
        """Extract Annex IV §2(a) provenance from a HuggingFace Hub dataset.

        Calls ``HfApi.dataset_info()`` for structured metadata and attempts
        ``DatasetCard.load()`` for the full README (bias analysis, description,
        citation). Card load failures are handled gracefully — metadata alone
        is sufficient for a valid (lower-score) provenance record.

        Args:
            dataset_id: HuggingFace dataset identifier, e.g. ``"squad"`` or
                        ``"allenai/c4"``.
            token:      HuggingFace API token for private/gated datasets.
            revision:   Dataset revision (branch/tag/commit). Defaults to
                        ``"main"``.

        Returns:
            DatasetProvenance with completeness score and §2(a) evidence.

        Raises:
            ImportError: if huggingface_hub is not installed.
            huggingface_hub.errors.RepositoryNotFoundError: if dataset_id
                does not exist on the Hub.
        """
        try:
            from huggingface_hub import HfApi  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "huggingface_hub is required for from_huggingface_dataset(). "
                "Install with: pip install huggingface-hub"
            ) from exc

        api = HfApi()
        info = api.dataset_info(dataset_id, revision=revision, token=token)

        # Attempt full card load for README content (bias, description, citation)
        card_content: str | None = None
        try:
            from huggingface_hub import DatasetCard  # type: ignore
            card = DatasetCard.load(dataset_id, token=token, repo_type="dataset")
            card_content = card.content
        except Exception:
            log.debug("artifact_extractor: DatasetCard.load failed for %s — using API metadata only", dataset_id)

        return _build_dataset_provenance(info, dataset_id, card_content)

    @staticmethod
    def from_huggingface_dataset_list(
        dataset_ids: list[str],
        *,
        token: str | None = None,
    ) -> list[DatasetProvenance]:
        """Extract §2(a) provenance for multiple datasets in one call.

        Handles partial failures — if one dataset cannot be fetched, a minimal
        provenance record with a warning is inserted so the overall extraction
        still succeeds. Training runs often mix several datasets; this method
        extracts all of them for complete Annex IV coverage.

        Args:
            dataset_ids: List of HuggingFace dataset identifiers.
            token:       HuggingFace API token for private/gated datasets.

        Returns:
            List of DatasetProvenance, one per dataset_id, in input order.
        """
        results: list[DatasetProvenance] = []
        for did in dataset_ids:
            try:
                results.append(ArtifactExtractor.from_huggingface_dataset(did, token=token))
            except Exception as exc:
                log.warning("artifact_extractor: failed to fetch provenance for %s: %s", did, exc)
                results.append(DatasetProvenance(
                    dataset_id=did,
                    source="huggingface",
                    card_data_raw={"extraction_error": str(exc)},
                ))
        return results

    # ------------------------------------------------------------------
    # W132: Python AST code scanner wrappers
    # ------------------------------------------------------------------

    @staticmethod
    def from_training_script(script_path: str | Path) -> "CodeArtifacts":
        """Scan a single Python training script → CodeArtifacts.

        Extracts ML framework, optimizer calls with hyperparameter kwargs,
        loss functions, model classes, data loaders, checkpoint operations,
        and training loop patterns using the stdlib ``ast`` module.

        No external dependencies — runs on any Python ≥ 3.10 without
        additional packages.

        Args:
            script_path: Path to a ``.py`` training script.

        Returns:
            CodeArtifacts with Annex IV §1(c) software evidence.
        """
        from squash.code_scanner_ast import CodeScanner  # noqa: PLC0415
        return CodeScanner.scan_file(Path(script_path))

    @staticmethod
    def from_training_directory(
        root: str | Path,
        pattern: str = "*.py",
    ) -> "CodeArtifacts":
        """Scan all Python files in a training directory → merged CodeArtifacts.

        Recursively discovers ``.py`` files matching *pattern*, scans each
        one, merges the results into a single artifact deduplicating imports
        by module, and auto-discovers requirements files
        (``requirements.txt``, ``pyproject.toml``) for the full training-time
        dependency BOM.

        Args:
            root:    Root directory to search.
            pattern: Glob pattern for Python files. Defaults to ``"*.py"``.

        Returns:
            Merged CodeArtifacts covering the full training codebase.
        """
        from squash.code_scanner_ast import CodeScanner  # noqa: PLC0415
        return CodeScanner.scan_training_run(Path(root))

    # ------------------------------------------------------------------
    # Convenience: extract everything from a training run directory
    # ------------------------------------------------------------------

    @staticmethod
    def from_run_dir(run_dir: str | Path) -> ArtifactExtractionResult:
        """Auto-discover and extract all Annex IV artifacts from a training run directory.

        Searches for:
        - TensorBoard event files (*.tfevents.*)
        - Training configs (config.{yaml,yml,json,toml}, train_config.*, hparams.*)
        """
        run_dir = Path(run_dir)
        result = ArtifactExtractionResult()

        if not run_dir.exists():
            result.warnings.append(f"run_dir not found: {run_dir}")
            return result

        # TensorBoard logs
        has_tfevents = any(run_dir.rglob("events.out.tfevents.*"))
        if has_tfevents:
            result.metrics = ArtifactExtractor.from_tensorboard_logs(run_dir)

        # Training config — common filename patterns
        config_patterns = [
            "config.yaml", "config.yml", "config.json", "config.toml",
            "train_config.yaml", "train_config.yml", "train_config.json",
            "hparams.yaml", "hparams.yml", "hparams.json",
            "training_args.json", "args.json",
        ]
        for pattern in config_patterns:
            config_path = run_dir / pattern
            if config_path.exists():
                try:
                    result.config = ArtifactExtractor.from_training_config(config_path)
                    break
                except Exception as exc:
                    result.warnings.append(f"config parse failed ({pattern}): {exc}")

        # Python training scripts — AST scan (W132)
        py_files = list(run_dir.rglob("*.py"))
        if py_files:
            try:
                result.code = ArtifactExtractor.from_training_directory(run_dir)
            except Exception as exc:
                result.warnings.append(f"AST scan failed: {exc}")

        if result.is_empty():
            result.warnings.append(f"no recognized artifacts found in {run_dir}")

        return result
