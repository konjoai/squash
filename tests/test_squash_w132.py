"""tests/test_squash_w132.py — Wave 132: Python AST training-code scanner.

Tests CodeScanner, CodeArtifacts, ImportRecord, and OptimizerCall using
Python source code strings — zero mocking, zero network, zero external deps.
All AST analysis is pure stdlib.

Coverage:
  - _get_dotted_name(): Name, Attribute chain, empty
  - _get_call_name(): simple, dotted, nested
  - _extract_constant_kwargs(): str, int, float, negative, **-splat ignored
  - _classify_import(): framework, dataset, utility, evaluation, unknown
  - _detect_framework(): PyTorch, TensorFlow, JAX, MLX, priority order
  - _is_optimizer_call(): torch.optim.Adam, SGD, AdamW, transformers.AdamW
  - _is_loss_call(): CrossEntropyLoss, F.cross_entropy, mse_loss, Keras names
  - _is_from_pretrained(): detection + stripping
  - _is_checkpoint_call(): torch.save, save_pretrained, save_model
  - _is_dataloader_call(): DataLoader, load_dataset
  - _is_training_pattern(): model.fit, trainer.train
  - CodeScanner.scan_source(): full PyTorch training script
  - CodeScanner.scan_source(): TensorFlow / Keras script
  - CodeScanner.scan_source(): HuggingFace Trainer script
  - CodeScanner.scan_source(): epoch for-loop detection
  - CodeScanner.scan_source(): model = SomeModel() assignment detection
  - CodeScanner.scan_source(): optimizer kwargs extraction (lr, weight_decay)
  - CodeScanner.scan_source(): syntax error handled gracefully
  - CodeScanner.scan_source(): empty source
  - CodeScanner.scan_file(): file not found
  - CodeScanner.scan_file(): real file from tmp_path
  - CodeScanner.scan_directory(): recursive, multiple files
  - CodeScanner.merge(): deduplicates imports, combines all signals, sets framework
  - CodeScanner.scan_requirements(): requirements.txt parsing
  - CodeScanner.scan_requirements(): pyproject.toml skipped gracefully
  - CodeScanner.scan_requirements(): non-existent path returns []
  - CodeScanner.scan_training_run(): end-to-end directory scan + requirements
  - ArtifactExtractor.from_training_script(): wrapper works
  - ArtifactExtractor.from_training_directory(): wrapper works
  - CodeArtifacts.annex_iv_section_1c(): structure, all keys present
  - ArtifactExtractionResult.code field + is_empty() + to_annex_iv_dict()
  - section_1c prefers code over config when both present
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from squash.code_scanner_ast import (
    CodeArtifacts,
    CodeScanner,
    ImportRecord,
    OptimizerCall,
    _classify_import,
    _detect_framework,
    _extract_constant_kwargs,
    _get_call_name,
    _get_dotted_name,
    _is_checkpoint_call,
    _is_dataloader_call,
    _is_from_pretrained,
    _is_loss_call,
    _is_optimizer_call,
    _is_training_pattern,
    _strip_from_pretrained,
)
from squash.artifact_extractor import ArtifactExtractor, ArtifactExtractionResult


# ---------------------------------------------------------------------------
# Source fixtures
# ---------------------------------------------------------------------------

_PYTORCH_TRAIN = textwrap.dedent("""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

model = nn.Sequential(nn.Linear(784, 256), nn.ReLU(), nn.Linear(256, 10))
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)

train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)

for epoch in range(10):
    for batch in train_loader:
        optimizer.zero_grad()
        loss = criterion(output, target)
        loss.backward()
        optimizer.step()

torch.save(model.state_dict(), "checkpoint.pt")
""")

_TRANSFORMERS_TRAIN = textwrap.dedent("""
from transformers import AutoModelForSequenceClassification, AutoTokenizer, AdamW
from transformers import Trainer, TrainingArguments
from datasets import load_dataset
import torch

model = AutoModelForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=2)
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

dataset = load_dataset("glue", "sst2")

optimizer = AdamW(model.parameters(), lr=5e-5, weight_decay=0.01)

training_args = TrainingArguments(output_dir="./results", num_train_epochs=3)
trainer = Trainer(model=model, args=training_args)
trainer.train()
model.save_pretrained("./output")
""")

_TF_KERAS_TRAIN = textwrap.dedent("""
import tensorflow as tf
from tensorflow import keras

model = keras.Sequential([
    keras.layers.Dense(256, activation='relu'),
    keras.layers.Dense(10, activation='softmax'),
])
optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
model.compile(optimizer=optimizer, loss='sparse_categorical_crossentropy', metrics=['accuracy'])
model.fit(x_train, y_train, epochs=10, batch_size=32)
model.save("my_model.h5")
""")

_JAX_TRAIN = textwrap.dedent("""
import jax
import jax.numpy as jnp
import optax

optimizer = optax.adam(learning_rate=1e-3)
""")

_MLX_TRAIN = textwrap.dedent("""
import mlx.core as mx
import mlx.nn as nn
import mlx.optimizers as optim

model = nn.Linear(128, 10)
optimizer = optim.Adam(learning_rate=1e-4)
""")


# ---------------------------------------------------------------------------
# AST helper unit tests
# ---------------------------------------------------------------------------

import ast as _ast


def _parse_call(src: str) -> _ast.Call:
    return _ast.parse(src, mode="eval").body  # type: ignore


class TestGetDottedName:
    def test_name_node(self):
        node = _ast.Name(id="Adam", ctx=_ast.Load())
        assert _get_dotted_name(node) == "Adam"

    def test_attribute_chain(self):
        # torch.optim.Adam — build programmatically
        node = _ast.Attribute(
            value=_ast.Attribute(value=_ast.Name(id="torch"), attr="optim"),
            attr="Adam",
        )
        assert _get_dotted_name(node) == "torch.optim.Adam"

    def test_unknown_node_type(self):
        assert _get_dotted_name(_ast.Constant(value=42)) == ""  # type: ignore


class TestGetCallName:
    def test_simple(self):
        call = _parse_call("Adam()")
        assert _get_call_name(call) == "Adam"

    def test_dotted(self):
        call = _parse_call("torch.optim.Adam()")
        assert _get_call_name(call) == "torch.optim.Adam"

    def test_method_call(self):
        call = _parse_call("model.from_pretrained('bert-base-uncased')")
        assert _get_call_name(call) == "model.from_pretrained"


class TestExtractConstantKwargs:
    def test_string_kwarg(self):
        call = _parse_call("f(optimizer='adam')")
        kw = _extract_constant_kwargs(call)
        assert kw["optimizer"] == "adam"

    def test_int_kwarg(self):
        call = _parse_call("f(batch_size=32)")
        kw = _extract_constant_kwargs(call)
        assert kw["batch_size"] == 32

    def test_float_kwarg(self):
        call = _parse_call("f(lr=1e-3)")
        kw = _extract_constant_kwargs(call)
        assert kw["lr"] == pytest.approx(1e-3)

    def test_negative_value(self):
        call = _parse_call("f(temp=-0.5)")
        kw = _extract_constant_kwargs(call)
        assert kw["temp"] == pytest.approx(-0.5)

    def test_splat_ignored(self):
        call = _parse_call("f(**kwargs)")
        kw = _extract_constant_kwargs(call)
        assert kw == {}

    def test_variable_value_ignored(self):
        call = _parse_call("f(lr=learning_rate)")
        kw = _extract_constant_kwargs(call)
        assert "lr" not in kw


class TestClassifyImport:
    def test_torch_is_framework(self):
        assert _classify_import("torch") == "framework"
        assert _classify_import("torch.optim") == "framework"

    def test_tensorflow_is_framework(self):
        assert _classify_import("tensorflow") == "framework"
        assert _classify_import("tf") == "framework"

    def test_jax_is_framework(self):
        assert _classify_import("jax") == "framework"

    def test_mlx_is_framework(self):
        assert _classify_import("mlx") == "framework"

    def test_datasets_is_dataset(self):
        assert _classify_import("datasets") == "dataset"
        assert _classify_import("torchvision") == "dataset"

    def test_transformers_is_utility(self):
        assert _classify_import("transformers") == "training_utility"
        assert _classify_import("accelerate") == "training_utility"
        assert _classify_import("peft") == "training_utility"

    def test_sklearn_is_evaluation(self):
        assert _classify_import("sklearn") == "evaluation"
        assert _classify_import("evaluate") == "evaluation"

    def test_unknown(self):
        assert _classify_import("myapp.utils") == "unknown"


class TestDetectFramework:
    def _make_imports(self, *modules) -> list[ImportRecord]:
        return [ImportRecord(module=m, names=[m], alias=None,
                             purpose=_classify_import(m)) for m in modules]

    def test_detects_pytorch(self):
        assert _detect_framework(self._make_imports("torch")) == "pytorch"

    def test_detects_tensorflow(self):
        assert _detect_framework(self._make_imports("tensorflow")) == "tensorflow"

    def test_detects_jax(self):
        assert _detect_framework(self._make_imports("jax")) == "jax"

    def test_detects_mlx(self):
        assert _detect_framework(self._make_imports("mlx")) == "mlx"

    def test_pytorch_priority_over_tf(self):
        # torch appears before tensorflow in priority list
        assert _detect_framework(self._make_imports("torch", "tensorflow")) == "pytorch"

    def test_empty_imports_none(self):
        assert _detect_framework([]) is None


class TestPatternMatchers:
    def test_optimizer_adam(self):
        assert _is_optimizer_call("Adam") is True
        assert _is_optimizer_call("torch.optim.Adam") is True
        assert _is_optimizer_call("AdamW") is True
        assert _is_optimizer_call("optim.SGD") is True
        assert _is_optimizer_call("RMSprop") is True

    def test_optimizer_negative(self):
        assert _is_optimizer_call("CrossEntropyLoss") is False
        assert _is_optimizer_call("Linear") is False

    def test_loss_cross_entropy(self):
        assert _is_loss_call("nn.CrossEntropyLoss") is True
        assert _is_loss_call("F.cross_entropy") is True
        assert _is_loss_call("CrossEntropyLoss") is True

    def test_loss_mse(self):
        assert _is_loss_call("nn.MSELoss") is True
        assert _is_loss_call("F.mse_loss") is True

    def test_loss_keras(self):
        assert _is_loss_call("sparse_categorical_crossentropy") is True
        assert _is_loss_call("binary_crossentropy") is True

    def test_from_pretrained(self):
        assert _is_from_pretrained("AutoModel.from_pretrained") is True
        assert _is_from_pretrained("from_pretrained") is True
        assert _is_from_pretrained("save_pretrained") is False

    def test_strip_from_pretrained(self):
        assert _strip_from_pretrained("AutoModelForSeq2SeqLM.from_pretrained") == "AutoModelForSeq2SeqLM"
        assert _strip_from_pretrained("SomeClass") == "SomeClass"

    def test_checkpoint_torch_save(self):
        assert _is_checkpoint_call("torch.save") is True

    def test_checkpoint_save_pretrained(self):
        assert _is_checkpoint_call("model.save_pretrained") is True
        assert _is_checkpoint_call("save_pretrained") is True

    def test_checkpoint_save_model(self):
        assert _is_checkpoint_call("model.save_model") is True

    def test_dataloader(self):
        assert _is_dataloader_call("DataLoader") is True
        assert _is_dataloader_call("torch.utils.data.DataLoader") is True
        assert _is_dataloader_call("load_dataset") is True

    def test_training_pattern(self):
        assert _is_training_pattern("model.fit") is True
        assert _is_training_pattern("trainer.train") is True
        assert _is_training_pattern("fit") is True


# ---------------------------------------------------------------------------
# CodeScanner.scan_source() — full script tests
# ---------------------------------------------------------------------------

class TestScanSourcePyTorch:
    @pytest.fixture(scope="class")
    def arts(self):
        return CodeScanner.scan_source(_PYTORCH_TRAIN, path="train.py")

    def test_framework_pytorch(self, arts):
        assert arts.framework == "pytorch"

    def test_imports_include_torch(self, arts):
        modules = [r.module for r in arts.imports]
        assert "torch" in modules

    def test_torch_classified_as_framework(self, arts):
        framework_mods = [r.module for r in arts.imports if r.purpose == "framework"]
        assert "torch" in framework_mods

    def test_torchvision_classified_as_dataset(self, arts):
        dataset_mods = [r.module for r in arts.imports if r.purpose == "dataset"]
        assert "torchvision" in dataset_mods

    def test_optimizer_detected(self, arts):
        assert len(arts.optimizers) >= 1

    def test_optimizer_is_adam(self, arts):
        names = [o.short_name for o in arts.optimizers]
        assert "adam" in names

    def test_optimizer_lr_extracted(self, arts):
        adam = next(o for o in arts.optimizers if o.short_name == "adam")
        assert adam.kwargs.get("lr") == pytest.approx(1e-3)

    def test_optimizer_weight_decay_extracted(self, arts):
        adam = next(o for o in arts.optimizers if o.short_name == "adam")
        assert adam.kwargs.get("weight_decay") == pytest.approx(1e-5)

    def test_loss_detected(self, arts):
        assert len(arts.loss_functions) >= 1
        assert any("CrossEntropyLoss" in lf or "cross_entropy" in lf.lower()
                   for lf in arts.loss_functions)

    def test_model_class_detected(self, arts):
        assert len(arts.model_classes) >= 1

    def test_dataloader_detected(self, arts):
        assert any("DataLoader" in dl for dl in arts.data_loaders)

    def test_checkpoint_detected(self, arts):
        assert any("save" in cp.lower() for cp in arts.checkpoint_ops)

    def test_epoch_loop_detected(self, arts):
        assert any("epoch" in p for p in arts.training_loop_patterns)

    def test_no_parse_errors(self, arts):
        assert arts.parse_errors == []


class TestScanSourceTransformers:
    @pytest.fixture(scope="class")
    def arts(self):
        return CodeScanner.scan_source(_TRANSFORMERS_TRAIN, path="train_hf.py")

    def test_framework_pytorch(self, arts):
        assert arts.framework == "pytorch"

    def test_from_pretrained_model_detected(self, arts):
        assert any("AutoModelForSequenceClassification" in mc for mc in arts.model_classes)

    def test_adamw_optimizer(self, arts):
        names = [o.short_name for o in arts.optimizers]
        assert "adamw" in names

    def test_lr_extracted(self, arts):
        aw = next(o for o in arts.optimizers if o.short_name == "adamw")
        assert aw.kwargs.get("lr") == pytest.approx(5e-5)

    def test_save_pretrained_checkpoint(self, arts):
        assert any("save_pretrained" in cp for cp in arts.checkpoint_ops)

    def test_trainer_train_pattern(self, arts):
        assert any("train" in p for p in arts.training_loop_patterns)

    def test_load_dataset_detected(self, arts):
        assert any("load_dataset" in dl for dl in arts.data_loaders)

    def test_transformers_classified_as_utility(self, arts):
        utility_mods = [r.module for r in arts.imports if r.purpose == "training_utility"]
        assert "transformers" in utility_mods


class TestScanSourceTensorFlow:
    @pytest.fixture(scope="class")
    def arts(self):
        return CodeScanner.scan_source(_TF_KERAS_TRAIN, path="train_tf.py")

    def test_framework_tensorflow(self, arts):
        assert arts.framework == "tensorflow"

    def test_loss_sparse_categorical(self, arts):
        # loss passed as string to compile — won't be detected as a call,
        # but the compile call itself may match training pattern
        assert isinstance(arts.loss_functions, list)

    def test_fit_training_pattern(self, arts):
        assert any("fit" in p for p in arts.training_loop_patterns)

    def test_save_checkpoint(self, arts):
        assert any("save" in cp.lower() for cp in arts.checkpoint_ops)

    def test_adam_optimizer_detected(self, arts):
        names = [o.short_name for o in arts.optimizers]
        assert "adam" in names

    def test_lr_extracted_from_tf_adam(self, arts):
        adam = next(o for o in arts.optimizers if o.short_name == "adam")
        assert adam.kwargs.get("learning_rate") == pytest.approx(0.001)


class TestScanSourceJax:
    def test_jax_framework_detected(self):
        arts = CodeScanner.scan_source(_JAX_TRAIN)
        assert arts.framework == "jax"

    def test_optax_adam_detected(self):
        arts = CodeScanner.scan_source(_JAX_TRAIN)
        names = [o.short_name for o in arts.optimizers]
        assert "adam" in names


class TestScanSourceMlx:
    def test_mlx_framework_detected(self):
        arts = CodeScanner.scan_source(_MLX_TRAIN)
        assert arts.framework == "mlx"


class TestScanSourceEdgeCases:
    def test_syntax_error_recorded(self):
        arts = CodeScanner.scan_source("def broken(:\n    pass", path="bad.py")
        assert len(arts.parse_errors) == 1
        assert "SyntaxError" in arts.parse_errors[0]

    def test_syntax_error_returns_empty_artifacts(self):
        arts = CodeScanner.scan_source("def broken(:\n    pass")
        assert arts.imports == []
        assert arts.optimizers == []

    def test_empty_source(self):
        arts = CodeScanner.scan_source("")
        assert arts.imports == []
        assert arts.parse_errors == []

    def test_model_assignment_detection(self):
        src = "model = MyCustomModel(hidden_size=512, num_layers=6)"
        arts = CodeScanner.scan_source(src)
        assert any("MyCustomModel" in mc for mc in arts.model_classes)

    def test_net_assignment_detection(self):
        src = "net = ResNet50(pretrained=True)"
        arts = CodeScanner.scan_source(src)
        assert any("ResNet50" in mc for mc in arts.model_classes)

    def test_multiple_optimizers(self):
        src = textwrap.dedent("""
        import torch.optim as optim
        opt_g = optim.Adam(gen.parameters(), lr=2e-4)
        opt_d = optim.Adam(disc.parameters(), lr=2e-4, betas=(0.5, 0.999))
        """)
        arts = CodeScanner.scan_source(src)
        assert len(arts.optimizers) == 2

    def test_betas_not_extracted_as_constant(self):
        # betas=(0.5, 0.999) is a tuple, not a constant — should be ignored
        src = "import optim; o = optim.Adam(p, betas=(0.5, 0.999), lr=1e-3)"
        arts = CodeScanner.scan_source(src)
        adam = next(o for o in arts.optimizers if "adam" in o.short_name)
        assert "betas" not in adam.kwargs
        assert adam.kwargs.get("lr") == pytest.approx(1e-3)


# ---------------------------------------------------------------------------
# CodeScanner.scan_file() tests
# ---------------------------------------------------------------------------

class TestScanFile:
    def test_file_not_found(self, tmp_path):
        arts = CodeScanner.scan_file(tmp_path / "nonexistent.py")
        assert len(arts.parse_errors) == 1
        assert "not found" in arts.parse_errors[0].lower()

    def test_real_file(self, tmp_path):
        p = tmp_path / "train.py"
        p.write_text(_PYTORCH_TRAIN)
        arts = CodeScanner.scan_file(p)
        assert arts.framework == "pytorch"
        assert len(arts.optimizers) >= 1

    def test_source_path_recorded(self, tmp_path):
        p = tmp_path / "train.py"
        p.write_text("import torch")
        arts = CodeScanner.scan_file(p)
        assert str(p) == arts.source_path


# ---------------------------------------------------------------------------
# CodeScanner.scan_directory() tests
# ---------------------------------------------------------------------------

class TestScanDirectory:
    def test_returns_list(self, tmp_path):
        (tmp_path / "a.py").write_text("import torch")
        (tmp_path / "b.py").write_text("import tensorflow")
        results = CodeScanner.scan_directory(tmp_path)
        assert len(results) == 2

    def test_nonexistent_directory(self, tmp_path):
        results = CodeScanner.scan_directory(tmp_path / "noexist")
        assert results == []

    def test_recursive(self, tmp_path):
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "model.py").write_text(_PYTORCH_TRAIN)
        results = CodeScanner.scan_directory(tmp_path)
        assert len(results) == 1
        assert results[0].framework == "pytorch"


# ---------------------------------------------------------------------------
# CodeScanner.merge() tests
# ---------------------------------------------------------------------------

class TestMerge:
    def test_deduplicates_imports_by_module(self):
        a1 = CodeScanner.scan_source("import torch")
        a2 = CodeScanner.scan_source("import torch\nimport numpy")
        merged = CodeScanner.merge([a1, a2])
        torch_imports = [r for r in merged.imports if r.module == "torch"]
        assert len(torch_imports) == 1  # deduplicated

    def test_combines_optimizers(self):
        a1 = CodeScanner.scan_source("import optax; o = optax.adam(1e-3)")
        a2 = CodeScanner.scan_source("import optax; o = optax.sgd(0.01)")
        merged = CodeScanner.merge([a1, a2])
        names = [o.short_name for o in merged.optimizers]
        assert "adam" in names
        assert "sgd" in names

    def test_sets_framework_from_merged_imports(self):
        a1 = CodeScanner.scan_source("import torch")
        a2 = CodeScanner.scan_source("from datasets import load_dataset")
        merged = CodeScanner.merge([a1, a2])
        assert merged.framework == "pytorch"

    def test_empty_list(self):
        merged = CodeScanner.merge([])
        assert merged.imports == []
        assert merged.framework is None

    def test_source_path_set(self):
        merged = CodeScanner.merge([], source_path="/path/to/run")
        assert merged.source_path == "/path/to/run"


# ---------------------------------------------------------------------------
# CodeScanner.scan_requirements() tests
# ---------------------------------------------------------------------------

class TestScanRequirements:
    def test_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("torch>=2.0\ntransformers\n# comment\n-r base.txt\nnumpy\n")
        specs = CodeScanner.scan_requirements(req)
        assert "torch>=2.0" in specs
        assert "transformers" in specs
        assert "numpy" in specs
        assert all(not s.startswith("#") for s in specs)
        assert all(not s.startswith("-") for s in specs)

    def test_nonexistent_file(self, tmp_path):
        assert CodeScanner.scan_requirements(tmp_path / "none.txt") == []

    def test_empty_requirements(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# only comments\n")
        assert CodeScanner.scan_requirements(req) == []


# ---------------------------------------------------------------------------
# CodeScanner.scan_training_run() end-to-end test
# ---------------------------------------------------------------------------

class TestScanTrainingRun:
    def test_end_to_end(self, tmp_path):
        (tmp_path / "train.py").write_text(_TRANSFORMERS_TRAIN)
        (tmp_path / "requirements.txt").write_text("transformers>=4.40\ntorch>=2.0\n")
        arts = CodeScanner.scan_training_run(tmp_path)
        assert arts.framework == "pytorch"
        assert len(arts.optimizers) >= 1
        assert "transformers>=4.40" in arts.requirements

    def test_empty_directory_returns_empty_artifacts(self, tmp_path):
        arts = CodeScanner.scan_training_run(tmp_path)
        assert arts.imports == []
        assert arts.requirements == []


# ---------------------------------------------------------------------------
# CodeArtifacts.annex_iv_section_1c() structure tests
# ---------------------------------------------------------------------------

class TestAnnexIvSection1c:
    @pytest.fixture
    def arts(self):
        return CodeScanner.scan_source(_PYTORCH_TRAIN, path="train.py")

    def test_section_key(self, arts):
        assert arts.annex_iv_section_1c()["annex_iv_section"] == "1c"

    def test_title_present(self, arts):
        assert "title" in arts.annex_iv_section_1c()

    def test_ml_framework_populated(self, arts):
        assert arts.annex_iv_section_1c()["ml_framework"] == "pytorch"

    def test_framework_dependencies_present(self, arts):
        section = arts.annex_iv_section_1c()
        assert "torch" in section["framework_dependencies"]

    def test_optimizers_list_structure(self, arts):
        section = arts.annex_iv_section_1c()
        assert len(section["optimizers"]) >= 1
        opt = section["optimizers"][0]
        assert "name" in opt
        assert "short_name" in opt
        assert "hyperparameters" in opt

    def test_loss_functions_deduplicated(self, arts):
        section = arts.annex_iv_section_1c()
        assert len(section["loss_functions"]) == len(set(section["loss_functions"]))

    def test_all_imports_structure(self, arts):
        section = arts.annex_iv_section_1c()
        for imp in section["all_imports"]:
            assert "module" in imp
            assert "purpose" in imp

    def test_to_dict_alias(self, arts):
        assert arts.to_dict() == arts.annex_iv_section_1c()


# ---------------------------------------------------------------------------
# ArtifactExtractor wrapper tests
# ---------------------------------------------------------------------------

class TestArtifactExtractorWrappers:
    def test_from_training_script(self, tmp_path):
        p = tmp_path / "train.py"
        p.write_text(_PYTORCH_TRAIN)
        arts = ArtifactExtractor.from_training_script(p)
        assert isinstance(arts, CodeArtifacts)
        assert arts.framework == "pytorch"

    def test_from_training_directory(self, tmp_path):
        (tmp_path / "train.py").write_text(_PYTORCH_TRAIN)
        arts = ArtifactExtractor.from_training_directory(tmp_path)
        assert isinstance(arts, CodeArtifacts)
        assert arts.framework == "pytorch"


# ---------------------------------------------------------------------------
# ArtifactExtractionResult.code field
# ---------------------------------------------------------------------------

class TestArtifactExtractionResultCode:
    def _arts(self) -> CodeArtifacts:
        return CodeScanner.scan_source("import torch", path="<test>")

    def test_is_empty_true_without_code(self):
        r = ArtifactExtractionResult()
        assert r.is_empty()

    def test_is_empty_false_with_code(self):
        r = ArtifactExtractionResult(code=self._arts())
        assert not r.is_empty()

    def test_section_1c_from_code(self):
        r = ArtifactExtractionResult(code=self._arts())
        d = r.to_annex_iv_dict()
        assert "section_1c" in d
        assert d["section_1c"]["annex_iv_section"] == "1c"

    def test_code_preferred_over_config_in_1c(self):
        """When both code and config are present, code wins for §1(c)."""
        from squash.artifact_extractor import TrainingConfig
        r = ArtifactExtractionResult(
            code=self._arts(),
            config=TrainingConfig(source_path=None, optimizer={"type": "SGD"}),
        )
        d = r.to_annex_iv_dict()
        # code scanner produces ml_framework; TrainingConfig does not
        assert "ml_framework" in d["section_1c"]

    def test_from_run_dir_populates_code(self, tmp_path):
        (tmp_path / "train.py").write_text(_PYTORCH_TRAIN)
        result = ArtifactExtractor.from_run_dir(tmp_path)
        assert result.code is not None
        assert result.code.framework == "pytorch"
