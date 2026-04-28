"""squash/code_scanner_ast.py — Python AST training-code scanner.

Extracts EU AI Act Annex IV §1(c) evidence from Python training scripts:
  - ML framework and training-time dependency graph
  - Optimizer instantiation with extracted hyperparameter kwargs
  - Loss function calls
  - Model class / from_pretrained() usage
  - Data loader construction
  - Checkpoint save operations
  - Training loop patterns (epoch loops, model.fit, trainer.train)
  - requirements.txt / pyproject.toml dependency lists

Zero dependencies — uses only the stdlib ``ast`` module. Handles both
single-file scans and recursive directory scans with artifact merging.

Wave 132 of the Squash Annex IV artifact extraction pipeline.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

_FRAMEWORK_ROOTS: frozenset[str] = frozenset({
    "torch", "tensorflow", "tf", "jax", "flax", "mlx",
    "paddle", "mxnet", "mindspore", "oneflow",
})

_DATASET_ROOTS: frozenset[str] = frozenset({
    "datasets", "torchvision", "torchtext", "torchaudio",
    "tensorflow_datasets", "tfds", "tfdata",
    "albumentations", "torchdata",
})

_TRAINING_UTILITY_ROOTS: frozenset[str] = frozenset({
    "transformers", "accelerate", "peft", "trl", "deepspeed",
    "lightning", "pytorch_lightning", "lightning_fabric",
    "ray", "wandb", "mlflow", "comet_ml", "neptune",
    "bitsandbytes", "triton", "flash_attn", "xformers",
    "unsloth", "axolotl",
})

_EVAL_ROOTS: frozenset[str] = frozenset({
    "evaluate", "sklearn", "scipy", "seqeval",
    "sacrebleu", "rouge_score", "bert_score",
})

# Case-insensitive last-component match against call names.
# All entries are pre-normalized (underscores stripped, lower) so the
# runtime lookup can strip on both sides without re-allocating the set.
_OPTIMIZER_NAMES: frozenset[str] = frozenset({
    "adam", "adamw", "sgd", "rmsprop", "adagrad", "adadelta",
    "adamax", "nadam", "ftrl", "lion", "sophia", "adafactor",
    "lamb", "lars", "novograd", "ranger", "radam", "adan",
    "pagedadamw32bit", "pagedadamw8bit", "paged_adamw_32bit",
    "paged_adamw_8bit", "anyprecisionadamw",
})

_LOSS_NAMES: frozenset[str] = frozenset({
    # PyTorch nn  (already underscore-free)
    "crossentropyloss", "mseloss", "bcewithlogitsloss", "bceloss",
    "nllloss", "huberloss", "smoothl1loss", "kldivloss", "ctcloss",
    "cosineembeddingloss", "tripletmarginloss", "hingeembeddingloss",
    "multilabelmarginloss", "multilabelsoftmarginloss",
    "multimarginloss", "poissonnnllloss", "gaussiannllloss",
    # PyTorch functional (F.xxx) — stored underscore-free for uniform lookup
    "crossentropy", "binarycrossentropy", "binarycrossentropywithlogits",
    "mseloss", "l1loss", "smoothl1loss", "huberloss",
    "kldiv", "nllloss", "ctcloss",
    # TensorFlow / Keras — stored underscore-free
    "sparsecategoricalcrossentropy", "categoricalcrossentropy",
    "binarycrossentropy", "meansquarederror", "meanabsoluteerror",
    # Generic
    "focalloss", "diceloss", "tverskyloss", "lovaszloss",
    "contrastiveloss", "tripletloss", "infonce",
})

_CHECKPOINT_KEYWORDS: frozenset[str] = frozenset({
    "save_pretrained", "save_weights", "save_model",
    "save_checkpoint", "export_model",
})

_EXPLICIT_CHECKPOINT_CALLS: frozenset[str] = frozenset({
    "torch.save", "tf.saved_model.save",
    "joblib.dump", "pickle.dump",
})

_DATALOADER_NAMES: frozenset[str] = frozenset({
    "dataloader", "datapipe", "datamodule",
    "load_dataset", "get_dataset",
    "imagefolder", "cifar10", "cifar100", "mnist",
    "fashionmnist", "imagenet", "coco",
    "collate_fn",
})

_TRAINING_PATTERN_NAMES: frozenset[str] = frozenset({
    "fit", "train", "training_step",
    "training_epoch_end",
})

_MODEL_VAR_NAMES: frozenset[str] = frozenset({
    "model", "net", "network", "classifier", "encoder",
    "decoder", "backbone", "head", "module",
})

_FRAMEWORK_PRIORITY: list[tuple[str, str]] = [
    ("torch",       "pytorch"),
    ("tensorflow",  "tensorflow"),
    ("tf",          "tensorflow"),
    ("jax",         "jax"),
    ("flax",        "jax"),
    ("mlx",         "mlx"),
    ("paddle",      "paddle"),
]


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class ImportRecord:
    """A single import statement extracted from a training script."""
    module: str
    names: list[str]
    alias: str | None
    purpose: str   # "framework" | "dataset" | "training_utility" | "evaluation" | "unknown"
    line: int = 0


@dataclass
class OptimizerCall:
    """An optimizer instantiation found in a training script."""
    name: str                       # e.g. "torch.optim.Adam", "AdamW"
    short_name: str                 # e.g. "adam", "adamw"
    framework: str                  # "pytorch" | "tensorflow" | "unknown"
    kwargs: dict[str, Any] = field(default_factory=dict)   # constant kwargs only
    line: int = 0


@dataclass
class CodeArtifacts:
    """Training-code artifacts for EU AI Act Annex IV §1(c) evidence."""
    source_path: str
    imports: list[ImportRecord] = field(default_factory=list)
    framework: str | None = None           # detected primary ML framework
    model_classes: list[str] = field(default_factory=list)
    loss_functions: list[str] = field(default_factory=list)
    optimizers: list[OptimizerCall] = field(default_factory=list)
    data_loaders: list[str] = field(default_factory=list)
    checkpoint_ops: list[str] = field(default_factory=list)
    training_loop_patterns: list[str] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)   # from requirements files
    parse_errors: list[str] = field(default_factory=list)

    def annex_iv_section_1c(self) -> dict[str, Any]:
        """Render Annex IV §1(c) software and development process evidence."""
        by_purpose: dict[str, list[str]] = {}
        for r in self.imports:
            by_purpose.setdefault(r.purpose, []).append(r.module)

        return {
            "annex_iv_section": "1c",
            "title": "Training Software and Development Process",
            "source": self.source_path,
            "ml_framework": self.framework,
            "framework_dependencies": sorted(set(by_purpose.get("framework", []))),
            "training_utilities": sorted(set(by_purpose.get("training_utility", []))),
            "dataset_libraries": sorted(set(by_purpose.get("dataset", []))),
            "evaluation_libraries": sorted(set(by_purpose.get("evaluation", []))),
            "model_classes": self.model_classes,
            "loss_functions": list(dict.fromkeys(self.loss_functions)),  # deduplicated, ordered
            "optimizers": [
                {
                    "name": o.name,
                    "short_name": o.short_name,
                    "framework": o.framework,
                    "hyperparameters": o.kwargs,
                    "line": o.line,
                }
                for o in self.optimizers
            ],
            "data_loaders": list(dict.fromkeys(self.data_loaders)),
            "checkpoint_operations": list(dict.fromkeys(self.checkpoint_ops)),
            "training_patterns": list(dict.fromkeys(self.training_loop_patterns)),
            "all_imports": [
                {
                    "module": r.module,
                    "names": r.names,
                    "purpose": r.purpose,
                    "line": r.line,
                }
                for r in self.imports
            ],
            "requirements": self.requirements,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.annex_iv_section_1c()


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _get_dotted_name(node: ast.expr) -> str:
    """Extract a dotted name from an AST Name or chained Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _get_call_name(node: ast.Call) -> str:
    return _get_dotted_name(node.func)


def _extract_constant_kwargs(node: ast.Call) -> dict[str, Any]:
    """Extract keyword arguments with literal constant values from a Call node."""
    kwargs: dict[str, Any] = {}
    for kw in node.keywords:
        if kw.arg is None:
            continue
        v = kw.value
        if isinstance(v, ast.Constant):
            kwargs[kw.arg] = v.value
        elif isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.USub):
            if isinstance(v.operand, ast.Constant):
                kwargs[kw.arg] = -v.operand.value
    return kwargs


def _classify_import(module: str) -> str:
    root = module.split(".")[0].lower()
    if root in _FRAMEWORK_ROOTS:
        return "framework"
    if root in _DATASET_ROOTS:
        return "dataset"
    if root in _TRAINING_UTILITY_ROOTS:
        return "training_utility"
    if root in _EVAL_ROOTS:
        return "evaluation"
    return "unknown"


def _detect_framework(imports: list[ImportRecord]) -> str | None:
    roots = {r.module.split(".")[0].lower() for r in imports}
    for root, framework in _FRAMEWORK_PRIORITY:
        if root in roots:
            return framework
    return None


def _infer_framework_from_call(call_name: str) -> str:
    lower = call_name.lower()
    if "torch" in lower or "optim" in lower:
        return "pytorch"
    if "tf" in lower or "keras" in lower or "tensorflow" in lower:
        return "tensorflow"
    if "jax" in lower or "optax" in lower:
        return "jax"
    return "unknown"


def _is_optimizer_call(call_name: str) -> bool:
    last = call_name.split(".")[-1].lower().replace("_", "")
    return last in _OPTIMIZER_NAMES


def _is_loss_call(call_name: str) -> bool:
    last = call_name.split(".")[-1].lower().replace("_", "")
    return last in _LOSS_NAMES


def _is_checkpoint_call(call_name: str) -> bool:
    lower = call_name.lower()
    last = lower.split(".")[-1]
    if lower in _EXPLICIT_CHECKPOINT_CALLS:
        return True
    for kw in _CHECKPOINT_KEYWORDS:
        if lower.endswith(kw):
            return True
    # Generic: any method named exactly "save" on a non-builtin object
    if "." in call_name and last == "save":
        return True
    return False


def _is_dataloader_call(call_name: str) -> bool:
    last = call_name.split(".")[-1].lower().replace("_", "")
    return any(dl.replace("_", "") in last for dl in _DATALOADER_NAMES)


def _is_training_pattern(call_name: str) -> bool:
    last = call_name.split(".")[-1].lower()
    return last in _TRAINING_PATTERN_NAMES


def _is_from_pretrained(call_name: str) -> bool:
    return call_name.split(".")[-1] == "from_pretrained"


def _strip_from_pretrained(call_name: str) -> str:
    """'AutoModelForSeq2SeqLM.from_pretrained' → 'AutoModelForSeq2SeqLM'"""
    parts = call_name.split(".")
    if parts[-1] == "from_pretrained":
        return ".".join(parts[:-1])
    return call_name


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _TrainingScriptVisitor(ast.NodeVisitor):
    """Single-pass visitor accumulating all Annex IV §1(c) signals."""

    def __init__(self) -> None:
        self.imports: list[ImportRecord] = []
        self.optimizers: list[OptimizerCall] = []
        self.loss_functions: list[str] = []
        self.model_classes: list[str] = []
        self.data_loaders: list[str] = []
        self.checkpoint_ops: list[str] = []
        self.training_patterns: list[str] = []

    # -- imports --

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(ImportRecord(
                module=alias.name,
                names=[alias.name],
                alias=alias.asname,
                purpose=_classify_import(alias.name),
                line=node.lineno,
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        names = [alias.name for alias in node.names]
        self.imports.append(ImportRecord(
            module=module,
            names=names,
            alias=None,
            purpose=_classify_import(module),
            line=node.lineno,
        ))
        self.generic_visit(node)

    # -- calls --

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _get_call_name(node)

        if _is_optimizer_call(call_name):
            short = call_name.split(".")[-1].lower().replace("_", "")
            self.optimizers.append(OptimizerCall(
                name=call_name,
                short_name=short,
                framework=_infer_framework_from_call(call_name),
                kwargs=_extract_constant_kwargs(node),
                line=node.lineno,
            ))

        elif _is_loss_call(call_name):
            self.loss_functions.append(call_name)

        elif _is_from_pretrained(call_name):
            self.model_classes.append(_strip_from_pretrained(call_name))

        elif _is_checkpoint_call(call_name):
            self.checkpoint_ops.append(call_name)

        elif _is_dataloader_call(call_name):
            self.data_loaders.append(call_name)

        elif _is_training_pattern(call_name):
            self.training_patterns.append(call_name)

        self.generic_visit(node)

    # -- assignments: detect `model = SomeClass(...)` --

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            call_name = _get_call_name(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.lower() in _MODEL_VAR_NAMES:
                    if call_name and not _is_optimizer_call(call_name):
                        self.model_classes.append(call_name)
                    break
        self.generic_visit(node)

    # -- for loops: detect `for epoch in range(...)` training patterns --

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.iter, ast.Call):
            iter_name = _get_call_name(node.iter)
            if iter_name == "range":
                target = node.target
                if isinstance(target, ast.Name) and any(
                    kw in target.id.lower()
                    for kw in ("epoch", "step", "iter", "batch")
                ):
                    self.training_patterns.append(f"for_{target.id}_in_range")
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Requirements file parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: Path) -> list[str]:
    """Extract package specs from requirements.txt, ignoring comments and -r includes."""
    specs: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip inline comments
            line = line.split("#")[0].strip()
            if line:
                specs.append(line)
    return specs


def _parse_pyproject_toml(path: Path) -> list[str]:
    """Extract dependencies from pyproject.toml [project] or [tool.poetry] tables."""
    specs: list[str] = []
    try:
        import tomllib  # Python 3.11+
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except ImportError:
            log.debug("code_scanner_ast: tomllib/tomli not available for %s", path)
            return specs

    # PEP 621 [project.dependencies]
    deps = data.get("project", {}).get("dependencies", [])
    specs.extend(deps)
    # Poetry [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for k, v in poetry_deps.items():
        if k.lower() == "python":
            continue
        specs.append(f"{k}{('==' + v) if isinstance(v, str) and not any(c in v for c in '><!=^~') else ''}")

    return specs


# ---------------------------------------------------------------------------
# Public API — CodeScanner
# ---------------------------------------------------------------------------

class CodeScanner:
    """Scan Python training scripts for EU AI Act Annex IV §1(c) evidence.

    Zero external dependencies — uses only the stdlib ``ast`` module.
    Handles single files, directory trees, and requirements manifests.
    """

    @staticmethod
    def scan_source(source: str, path: str = "<string>") -> CodeArtifacts:
        """Scan Python source code given as a string.

        Useful for testing and for scanning code obtained from version
        control APIs without writing to disk.

        Args:
            source: Python source text.
            path:   Label for the ``source_path`` field. Defaults to
                    ``"<string>"``.

        Returns:
            CodeArtifacts with all extracted §1(c) signals.
        """
        artifacts = CodeArtifacts(source_path=path)
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            artifacts.parse_errors.append(f"SyntaxError in {path}: {exc}")
            return artifacts

        visitor = _TrainingScriptVisitor()
        visitor.visit(tree)

        artifacts.imports = visitor.imports
        artifacts.optimizers = visitor.optimizers
        artifacts.loss_functions = visitor.loss_functions
        artifacts.model_classes = visitor.model_classes
        artifacts.data_loaders = visitor.data_loaders
        artifacts.checkpoint_ops = visitor.checkpoint_ops
        artifacts.training_loop_patterns = visitor.training_patterns
        artifacts.framework = _detect_framework(visitor.imports)
        return artifacts

    @staticmethod
    def scan_file(path: Path) -> CodeArtifacts:
        """Scan a single Python file.

        Args:
            path: Path to a ``.py`` file. Non-existent paths return an
                  artifact with a parse error recorded.

        Returns:
            CodeArtifacts.
        """
        if not path.exists():
            a = CodeArtifacts(source_path=str(path))
            a.parse_errors.append(f"File not found: {path}")
            return a
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            a = CodeArtifacts(source_path=str(path))
            a.parse_errors.append(str(exc))
            return a
        return CodeScanner.scan_source(source, path=str(path))

    @staticmethod
    def scan_directory(root: Path, pattern: str = "*.py") -> list[CodeArtifacts]:
        """Scan all Python files matching *pattern* under *root*.

        Args:
            root:    Directory to search recursively.
            pattern: Glob pattern relative to *root*. Defaults to ``"*.py"``.

        Returns:
            List of CodeArtifacts, one per matched file.
        """
        if not root.is_dir():
            return []
        return [CodeScanner.scan_file(p) for p in sorted(root.rglob(pattern))]

    @staticmethod
    def merge(artifacts: list[CodeArtifacts], source_path: str = "") -> CodeArtifacts:
        """Merge multiple CodeArtifacts into a single aggregate record.

        Combines all imports, optimizers, losses, etc. Deduplicates imports
        by module name. Sets framework from the merged import list.

        Args:
            artifacts:   List of per-file artifacts to merge.
            source_path: Label for the merged record's ``source_path``.

        Returns:
            Single CodeArtifacts covering all input files.
        """
        merged = CodeArtifacts(source_path=source_path)
        seen_modules: set[str] = set()

        for a in artifacts:
            for imp in a.imports:
                if imp.module not in seen_modules:
                    seen_modules.add(imp.module)
                    merged.imports.append(imp)
            merged.optimizers.extend(a.optimizers)
            merged.loss_functions.extend(a.loss_functions)
            merged.model_classes.extend(a.model_classes)
            merged.data_loaders.extend(a.data_loaders)
            merged.checkpoint_ops.extend(a.checkpoint_ops)
            merged.training_loop_patterns.extend(a.training_loop_patterns)
            merged.requirements.extend(a.requirements)
            merged.parse_errors.extend(a.parse_errors)

        merged.framework = _detect_framework(merged.imports)
        return merged

    @staticmethod
    def scan_requirements(path: Path) -> list[str]:
        """Parse a requirements file into a list of package spec strings.

        Supports:
          - ``requirements.txt`` (and variants)
          - ``pyproject.toml`` (PEP 621 and Poetry formats)

        Args:
            path: Path to the requirements file.

        Returns:
            List of package spec strings, e.g. ``["torch>=2.0", "transformers"]``.
        """
        if not path.exists():
            return []
        name = path.name.lower()
        if name.endswith(".txt"):
            return _parse_requirements_txt(path)
        if name == "pyproject.toml":
            return _parse_pyproject_toml(path)
        return []

    @staticmethod
    def scan_training_run(root: Path) -> CodeArtifacts:
        """Full scan of a training run directory.

        Scans all ``*.py`` files, then discovers and parses any requirements
        manifest (``requirements.txt``, ``pyproject.toml``). Returns a single
        merged CodeArtifacts covering the entire training codebase.

        Args:
            root: Root directory of the training run.

        Returns:
            Merged CodeArtifacts with requirements populated.
        """
        py_artifacts = CodeScanner.scan_directory(root)
        merged = CodeScanner.merge(py_artifacts, source_path=str(root))

        # Discover requirements files
        req_patterns = [
            "requirements.txt", "requirements-train.txt",
            "requirements-dev.txt", "pyproject.toml",
        ]
        for pattern in req_patterns:
            req_path = root / pattern
            if req_path.exists():
                merged.requirements.extend(CodeScanner.scan_requirements(req_path))

        return merged
