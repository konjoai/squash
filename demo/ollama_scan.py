"""demo/ollama_scan.py — Real side-by-side Ollama model scanner.

Picks two random locally-installed Ollama models, runs the real squash
attestation pipeline against synthetic artefacts seeded by each model's
identity, and returns a structured comparison record. Used by:

* ``demo/demo.py`` — section 11 (TUI side-by-side panel)
* ``demo/server.py`` — ``POST /api/ollama-scan``

We deliberately do NOT pull weights from Ollama (multi-GB downloads are
not what a demo is for). Instead, we synthesise an attestation surface
from each model's *manifest* (name, size, digest, families, parameter
count) — which is what squash actually attests to in practice.

Make it Konjo.
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
sys.path.insert(0, str(_REPO_ROOT))


@dataclass
class OllamaModel:
    """One installed Ollama model."""
    name: str
    size_bytes: int
    digest: str
    family: str = ""


@dataclass
class ModelScanResult:
    """Attestation outcome for one Ollama model."""
    model: OllamaModel
    attestation_id: str = ""
    canonical_sha256: str = ""
    input_manifest_sha256: str = ""
    cyclonedx_components: int = 0
    spdx_emitted: bool = False
    file_count: int = 0
    total_bytes: int = 0
    issued_at: str = ""
    score: int = 0
    passed: bool | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    remediations: list[dict[str, Any]] = field(default_factory=list)
    elapsed_ms: float = 0.0
    family: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": asdict(self.model),
            **{k: v for k, v in asdict(self).items() if k != "model"},
        }


def is_available() -> bool:
    return shutil.which("ollama") is not None


def _parse_size(token: str) -> int:
    if not token:
        return 0
    parts = token.strip().split()
    if not parts:
        return 0
    try:
        n = float(parts[0])
    except ValueError:
        return 0
    unit = parts[1].upper() if len(parts) > 1 else "B"
    mult = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit, 1)
    return int(n * mult)


def _detect_family(name: str) -> str:
    n = name.lower()
    for fam in ("llama", "qwen", "mistral", "mixtral", "gemma", "phi",
                "smollm", "tinyllama", "deepseek", "yi", "command", "falcon"):
        if fam in n:
            return fam
    return "unknown"


def list_models(include_synthetic: bool = True) -> list[OllamaModel]:
    """Run ``ollama list`` and parse its output."""
    if not is_available():
        return _synthetic_fallback() if include_synthetic else []
    try:
        out = subprocess.run(
            ["ollama", "list"], capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return _synthetic_fallback() if include_synthetic else []
    if out.returncode != 0:
        return _synthetic_fallback() if include_synthetic else []

    models: list[OllamaModel] = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("NAME"):
            continue
        toks = [t for t in line.split() if t]
        if len(toks) < 4:
            continue
        name = toks[0]
        digest = toks[1]
        size_tok = ""
        for i in range(2, len(toks) - 1):
            if toks[i + 1].upper() in {"B", "KB", "MB", "GB", "TB"}:
                size_tok = f"{toks[i]} {toks[i + 1]}"
                break
        models.append(OllamaModel(
            name=name, size_bytes=_parse_size(size_tok),
            digest=digest, family=_detect_family(name),
        ))
    if not models and include_synthetic:
        return _synthetic_fallback()
    return models


def _synthetic_fallback() -> list[OllamaModel]:
    return [
        OllamaModel("llama3.2:3b", 2_023_000_000, "a80c4f17acd5", "llama"),
        OllamaModel("qwen2.5:0.5b", 397_000_000, "a8b0c5157701", "qwen"),
        OllamaModel("mistral:7b", 4_111_000_000, "f974a74358d6", "mistral"),
        OllamaModel("gemma3:4b", 3_300_000_000, "a2af6cc3eb7f", "gemma"),
        OllamaModel("phi3:3.8b", 2_396_000_000, "4f2222927938", "phi"),
    ]


def scan_one(model: OllamaModel, *, work_root: Path | None = None) -> ModelScanResult:
    """Run AttestPipeline.run against a synthetic dir keyed on *model*."""
    import time

    from squash.attest import AttestConfig, AttestPipeline
    from squash.canon import canonical_bytes
    from squash.clock import FrozenClock, with_clock

    work = work_root or Path(tempfile.mkdtemp(prefix="squash-ollama-"))
    work.mkdir(parents=True, exist_ok=True)
    md = work / model.name.replace(":", "_").replace("/", "_")
    md.mkdir(exist_ok=True)

    seed = (model.digest * 64).encode()[:32_768]
    (md / "model.gguf").write_bytes(seed)
    (md / "config.json").write_text(
        json.dumps({"model_type": model.family, "name_or_path": model.name,
                    "ollama_digest": model.digest, "size_bytes": model.size_bytes},
                   indent=2, sort_keys=True)
    )
    (md / "modelfile").write_text(
        f'FROM {model.name}\nPARAMETER temperature 0.7\nSYSTEM "Demo synthetic"\n'
    )

    clock = FrozenClock(datetime(2026, 5, 4, 0, 0, 0, tzinfo=timezone.utc))
    t0 = time.perf_counter()
    with with_clock(clock):
        AttestPipeline.run(AttestConfig(
            model_path=md, output_dir=md, policies=[],
            fail_on_violation=False, emit_input_manifest=True,
        ))
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    res = ModelScanResult(model=model, family=model.family, elapsed_ms=elapsed_ms)
    master_path = md / "squash-attest.json"
    bom_path = md / "cyclonedx-mlbom.json"
    spdx_path = md / "spdx-mlbom.json"
    manifest_path = md / "input_manifest.json"

    if master_path.exists():
        master = json.loads(master_path.read_text())
        res.attestation_id = master.get("model_id", "")
        res.canonical_sha256 = __import__("hashlib").sha256(
            canonical_bytes(master)).hexdigest()
        res.input_manifest_sha256 = master.get("input_manifest_sha256", "")
        res.issued_at = master.get("attested_at", "")
        res.passed = bool(master.get("passed"))
    if bom_path.exists():
        bom = json.loads(bom_path.read_text())
        res.cyclonedx_components = len(bom.get("components", []) or [])
    if spdx_path.exists():
        res.spdx_emitted = True
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        res.file_count = manifest.get("file_count", 0)
        res.total_bytes = manifest.get("total_bytes", 0)

    from demo.remediation import build_findings_for_model
    findings, remediations, score = build_findings_for_model(model, res)
    res.findings = findings
    res.remediations = remediations
    res.score = score
    return res


def pick_two(seed: int | None = None) -> tuple[OllamaModel, OllamaModel]:
    """Pick two distinct random models, biased toward different families."""
    rng = random.Random(seed)
    models = list_models()
    if len(models) < 2:
        if not models:
            models = _synthetic_fallback()
        else:
            models = models + [m for m in _synthetic_fallback() if m.name != models[0].name]
    rng.shuffle(models)
    a, b = models[0], models[1]
    for cand in models[2:]:
        if cand.family != a.family:
            b = cand
            break
    return a, b


def scan_pair(seed: int | None = None) -> dict[str, Any]:
    """Pick two models and return a side-by-side scan record."""
    a, b = pick_two(seed=seed)
    work = Path(tempfile.mkdtemp(prefix="squash-pair-"))
    try:
        ra = scan_one(a, work_root=work)
        rb = scan_one(b, work_root=work)
        return {
            "ok": True,
            "available": is_available(),
            "model_a": ra.to_dict(),
            "model_b": rb.to_dict(),
            "verdict_winner": _pick_winner(ra, rb),
            "shared_findings": _intersect_findings(ra, rb),
        }
    finally:
        try:
            shutil.rmtree(work)
        except Exception:
            pass


def _pick_winner(a: ModelScanResult, b: ModelScanResult) -> str:
    if a.score > b.score:
        return a.model.name
    if b.score > a.score:
        return b.model.name
    return a.model.name if a.model.size_bytes <= b.model.size_bytes else b.model.name


def _intersect_findings(a: ModelScanResult, b: ModelScanResult) -> list[dict[str, Any]]:
    a_codes = {f["code"] for f in a.findings}
    b_codes = {f["code"] for f in b.findings}
    shared = a_codes & b_codes
    return [f for f in a.findings if f["code"] in shared]


if __name__ == "__main__":
    pair = scan_pair(seed=None)
    json.dump(pair, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
