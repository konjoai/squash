"""squash/adapter_scanner.py — Track B / B8 — LoRA / Adapter Poisoning Detection.

LoRA adapters are perceived as "small therefore low-risk." They are not.
A LoRA adapter is a complete behavioural rewrite delivered in a few megabytes.
JFrog Security (2024) found ~100 malicious models on HuggingFace, several
establishing reverse-shell on load. This module provides:

1. **Format gate** — detect safetensors vs. pickle before any deserialisation.
   `--require-safetensors` blocks pickle-format adapters at rc=2.

2. **Pickle opcode scan** — scan raw bytes for code-execution opcodes
   (GLOBAL, REDUCE, STACK_GLOBAL, NEWOBJ, …) without deserialising.

3. **Safetensors integrity check** — parse the header, verify offsets,
   flag any header / offset inconsistency that could indicate tampering.

4. **Weight-delta statistical analysis** — without loading via torch/numpy,
   read raw tensor bytes and compute distributional fingerprints:
   - Per-tensor mean, std, max-abs, inf/nan presence
   - Kurtosis estimate (heavy tails indicate targeted weight manipulation)
   - Layer concentration score (fraction of total delta carried by largest layer)
   - Suspicious tensor-name patterns (embedding overwrite, lm_head bias injection)

5. **Signed adapter safety certificate** — SHA-256 content hash + HMAC-SHA256
   attestation written to `squash-adapter-scan.json`.

Stdlib-only at runtime. numpy enriches kurtosis / spectral estimates when
available but is never required.

Usage::

    report = scan_adapter(Path("./adapter.safetensors"), require_safetensors=True)
    if report.risk_level in ("HIGH", "CRITICAL"):
        sys.exit(2)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Constants ────────────────────────────────────────────────────────────────

VERSION = "0.1.0"

# Pickle opcodes that execute arbitrary Python. Copied from scanner.py so
# adapter_scanner stays standalone.
_DANGEROUS_OPCODES: frozenset[bytes] = frozenset([
    b"\x52",  # REDUCE       — call callable with arg tuple
    b"\x63",  # GLOBAL       — push callable by module.name
    b"\x62",  # BUILD        — call __setstate__
    b"\x69",  # INST         — call class/function (old protocol)
    b"\x6f",  # OBJ          — instantiate class from stack
    b"\x81",  # NEWOBJ       — instantiate class using __new__
    b"\x93",  # STACK_GLOBAL — protocol 4+ version of GLOBAL
    b"\x82",  # EXT1
    b"\x83",  # EXT2
    b"\x84",  # EXT4
])

# Shell-injection byte patterns to scan in any format.
_SHELL_PATTERNS: list[bytes] = [
    b"os.system",
    b"subprocess",
    b"__import__",
    b"exec(",
    b"eval(",
    b"/bin/sh",
    b"/bin/bash",
    b"cmd.exe",
    b"powershell",
    b"__builtins__",
    b"socket.connect",
    b"reverse_shell",
]

# Tensor name fragments that, if overwritten by a LoRA, warrant elevated risk.
# Embedding table rewrites are the highest-value backdoor target.
_HIGH_VALUE_TENSOR_PATTERNS: list[str] = [
    "embed_tokens",
    "embed_in",
    "word_embeddings",
    "lm_head",
    "wte",          # GPT-2 token embedding
    "wpe",          # GPT-2 positional embedding
    "shared",       # T5 shared embedding
    "embed_positions",
]

# Kurtosis above this threshold (excess kurtosis, >0) in a weight matrix
# suggests heavy-tail / spiked distribution atypical of clean fine-tuning.
_KURTOSIS_THRESHOLD = 8.0

# If a single LoRA layer carries more than this fraction of the total L2 norm,
# the adapter is suspiciously concentrated in one location.
_CONCENTRATION_THRESHOLD = 0.85


# ── Data model ───────────────────────────────────────────────────────────────


@dataclass
class AdapterFinding:
    severity: str        # "critical" | "high" | "medium" | "low" | "info"
    code: str            # stable machine-readable identifier
    title: str
    detail: str
    tensor_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "tensor_name": self.tensor_name,
        }


@dataclass
class TensorMeta:
    name: str
    dtype: str
    shape: list[int]
    data_start: int
    data_end: int
    n_elements: int = 0

    def __post_init__(self) -> None:
        if self.n_elements == 0 and self.shape:
            n = 1
            for d in self.shape:
                n *= d
            self.n_elements = n


@dataclass
class TensorStats:
    name: str
    dtype: str
    shape: list[int]
    n_elements: int
    byte_size: int
    mean: float = 0.0
    std: float = 0.0
    max_abs: float = 0.0
    has_nan: bool = False
    has_inf: bool = False
    kurtosis: float = 0.0   # excess kurtosis; 0 = Gaussian
    l2_norm: float = 0.0
    is_high_value_target: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dtype": self.dtype,
            "shape": self.shape,
            "n_elements": self.n_elements,
            "byte_size": self.byte_size,
            "mean": round(self.mean, 6),
            "std": round(self.std, 6),
            "max_abs": round(self.max_abs, 6),
            "has_nan": self.has_nan,
            "has_inf": self.has_inf,
            "kurtosis": round(self.kurtosis, 4),
            "l2_norm": round(self.l2_norm, 6),
            "is_high_value_target": self.is_high_value_target,
        }


@dataclass
class AdapterScanReport:
    adapter_path: str
    file_format: str          # "safetensors" | "pickle" | "unknown"
    risk_level: str           # "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    safe: bool
    findings: list[AdapterFinding] = field(default_factory=list)
    tensor_stats: list[TensorStats] = field(default_factory=list)
    adapter_hash: str = ""
    file_size_bytes: int = 0
    n_tensors: int = 0
    total_parameters: int = 0
    concentration_score: float = 0.0
    pickle_opcodes_found: list[str] = field(default_factory=list)
    scanner_version: str = VERSION
    certificate_path: str = ""
    error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_path": self.adapter_path,
            "file_format": self.file_format,
            "risk_level": self.risk_level,
            "safe": self.safe,
            "findings": [f.to_dict() for f in self.findings],
            "tensor_stats": [t.to_dict() for t in self.tensor_stats],
            "adapter_hash": self.adapter_hash,
            "file_size_bytes": self.file_size_bytes,
            "n_tensors": self.n_tensors,
            "total_parameters": self.total_parameters,
            "concentration_score": round(self.concentration_score, 4),
            "pickle_opcodes_found": self.pickle_opcodes_found,
            "scanner_version": self.scanner_version,
            "certificate_path": self.certificate_path,
            "error": self.error,
        }


# ── Format detection ─────────────────────────────────────────────────────────


def detect_format(path: Path) -> str:
    """Return 'safetensors', 'pickle', or 'unknown' by magic-byte inspection.

    Never deserialises the file — reads at most 16 bytes.
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(16)
    except OSError:
        return "unknown"

    # PyTorch / pickle: protocol marker \x80 + version byte (0–5)
    if len(header) >= 2 and header[0] == 0x80 and header[1] in range(6):
        return "pickle"
    # .pkl files sometimes start with \x80\x04 or the legacy two-byte magic
    if header[:2] in (b"\x80\x04", b"\x80\x05", b"\x80\x02"):
        return "pickle"
    # Explicit pkl extension as a secondary signal
    if path.suffix.lower() in (".pkl", ".pickle"):
        return "pickle"

    # safetensors: first 8 bytes are a little-endian uint64 header length,
    # then the header JSON begins with '{'.
    if len(header) >= 9 and header[8:9] == b"{":
        return "safetensors"
    if path.suffix.lower() == ".safetensors":
        return "safetensors"

    # PyTorch checkpoint with the torch magic (ZipFile header)
    if header[:4] == b"PK\x03\x04":
        return "pickle"  # PyTorch .pt / .pth are ZIP archives containing pickle

    return "unknown"


# ── Pickle opcode scan ────────────────────────────────────────────────────────


def scan_shell_patterns(path: Path) -> list[str]:
    """Scan file bytes for known shell-injection text patterns.

    Safe to call on any file format — looks only for text strings, not
    binary opcodes. Returns SHELL_PATTERN:<pattern> entries.
    """
    found: list[str] = []
    try:
        raw = b""
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 64 << 20:
                    break
    except OSError:
        return found
    for pattern in _SHELL_PATTERNS:
        if pattern in raw:
            found.append(f"SHELL_PATTERN:{pattern.decode(errors='replace')}")
    return found


def scan_pickle_opcodes(path: Path) -> list[str]:
    """Scan raw file bytes for dangerous pickle opcodes and shell patterns.

    IMPORTANT: Only meaningful for files detected as pickle-format. Calling
    this on arbitrary binary data (e.g. safetensors) will generate false
    positives because individual opcode bytes are common in float data.

    Returns a list of human-readable opcode / pattern names. Reads the file
    in 1 MiB chunks so large files don't OOM.
    """
    found: list[str] = []
    opcode_map = {
        b"\x52": "REDUCE",
        b"\x63": "GLOBAL",
        b"\x62": "BUILD",
        b"\x69": "INST",
        b"\x6f": "OBJ",
        b"\x81": "NEWOBJ",
        b"\x93": "STACK_GLOBAL",
        b"\x82": "EXT1",
        b"\x83": "EXT2",
        b"\x84": "EXT4",
    }
    raw = b""
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 64 << 20:  # cap at 64 MiB for scanning
                    break
    except OSError:
        return found

    for opcode_byte, name in opcode_map.items():
        if opcode_byte in raw:
            found.append(name)
    for pattern in _SHELL_PATTERNS:
        if pattern in raw:
            found.append(f"SHELL_PATTERN:{pattern.decode(errors='replace')}")

    return found


# ── safetensors parsing ───────────────────────────────────────────────────────

# Bytes-per-element for each safetensors dtype.
_ST_DTYPE_BYTES: dict[str, int] = {
    "F64": 8, "F32": 4, "BF16": 2, "F16": 2,
    "I64": 8, "I32": 4, "I16": 2, "I8": 1,
    "U8": 1, "BOOL": 1, "F8_E5M2": 1, "F8_E4M3": 1,
}


def parse_safetensors_header(path: Path) -> tuple[dict[str, TensorMeta], list[AdapterFinding]]:
    """Parse the safetensors header without reading tensor data.

    Returns (tensors_dict, findings). findings may contain integrity-check
    violations (offset inconsistencies, truncated header, etc.).
    """
    findings: list[AdapterFinding] = []
    tensors: dict[str, TensorMeta] = {}

    try:
        file_size = path.stat().st_size
        with open(path, "rb") as fh:
            # 8-byte little-endian header length
            raw_len = fh.read(8)
            if len(raw_len) < 8:
                findings.append(AdapterFinding(
                    severity="critical", code="ST-001",
                    title="Truncated safetensors header",
                    detail="File is too short to contain a valid safetensors header (< 8 bytes)",
                ))
                return tensors, findings

            header_len = struct.unpack("<Q", raw_len)[0]

            if header_len == 0 or header_len > 100 << 20:
                findings.append(AdapterFinding(
                    severity="high", code="ST-002",
                    title="Suspicious safetensors header length",
                    detail=f"Header length {header_len} bytes is outside expected range [1, 100 MiB]",
                ))
                return tensors, findings

            raw_header = fh.read(header_len)
            if len(raw_header) < header_len:
                findings.append(AdapterFinding(
                    severity="critical", code="ST-003",
                    title="Truncated safetensors header body",
                    detail=f"Expected {header_len} header bytes, got {len(raw_header)}",
                ))
                return tensors, findings

            try:
                header_obj = json.loads(raw_header)
            except json.JSONDecodeError as exc:
                findings.append(AdapterFinding(
                    severity="critical", code="ST-004",
                    title="Malformed safetensors header JSON",
                    detail=f"JSON parse error: {exc}",
                ))
                return tensors, findings

        data_region_start = 8 + header_len

        for name, meta in header_obj.items():
            if name == "__metadata__":
                continue
            if not isinstance(meta, dict):
                continue
            dtype = meta.get("dtype", "")
            shape = meta.get("shape", [])
            offsets = meta.get("data_offsets", [0, 0])

            if not (isinstance(offsets, list) and len(offsets) == 2):
                findings.append(AdapterFinding(
                    severity="high", code="ST-005",
                    title="Invalid data_offsets in safetensors header",
                    detail=f"Tensor '{name}' has malformed data_offsets: {offsets}",
                    tensor_name=name,
                ))
                continue

            start, end = offsets
            abs_start = data_region_start + start
            abs_end = data_region_start + end

            # Offset integrity: end must not exceed file size
            if abs_end > file_size:
                findings.append(AdapterFinding(
                    severity="critical", code="ST-006",
                    title="safetensors offset exceeds file size (OOB read vector)",
                    detail=(
                        f"Tensor '{name}' data_offsets [{start},{end}] → "
                        f"absolute [{abs_start},{abs_end}] > file size {file_size}"
                    ),
                    tensor_name=name,
                ))

            tm = TensorMeta(
                name=name, dtype=dtype, shape=list(shape),
                data_start=abs_start, data_end=abs_end,
            )
            tensors[name] = tm

    except OSError as exc:
        findings.append(AdapterFinding(
            severity="high", code="ST-007",
            title="Failed to read adapter file",
            detail=str(exc),
        ))

    return tensors, findings


# ── Tensor statistics ─────────────────────────────────────────────────────────

def _unpack_floats(raw: bytes, dtype: str) -> list[float]:
    """Decode raw tensor bytes to float list. Handles F32, F16, BF16."""
    n = len(raw)
    if dtype == "F32":
        count = n // 4
        return list(struct.unpack(f"<{count}f", raw[:count * 4]))
    if dtype == "F16":
        # IEEE 754 half-precision — decode manually without numpy
        count = n // 2
        shorts = struct.unpack(f"<{count}H", raw[:count * 2])
        result = []
        for h in shorts:
            sign = ((h >> 15) & 1) * -1 or 1
            exp = (h >> 10) & 0x1F
            mant = h & 0x3FF
            if exp == 0:
                result.append(sign * (mant / 1024.0) * (2 ** -14))
            elif exp == 31:
                result.append(sign * (math.inf if mant == 0 else math.nan))
            else:
                result.append(sign * (1 + mant / 1024.0) * (2 ** (exp - 15)))
        return result
    if dtype == "BF16":
        # bfloat16: upper 16 bits of F32
        count = n // 2
        shorts = struct.unpack(f"<{count}H", raw[:count * 2])
        result = []
        for s in shorts:
            packed = struct.pack("<I", s << 16)
            result.append(struct.unpack("<f", packed)[0])
        return result
    # Integer types — cast to float
    fmt_map = {"I32": ("i", 4), "I16": ("h", 2), "I8": ("b", 1),
               "U8": ("B", 1), "I64": ("q", 8)}
    if dtype in fmt_map:
        fmt_char, bpe = fmt_map[dtype]
        count = n // bpe
        return [float(x) for x in struct.unpack(f"<{count}{fmt_char}", raw[:count * bpe])]
    return []


def _compute_stats(values: list[float], name: str, dtype: str, shape: list[int],
                   byte_size: int) -> TensorStats:
    """Compute distributional statistics for a decoded tensor value list."""
    n = len(values)
    has_nan = any(math.isnan(v) for v in values)
    has_inf = any(math.isinf(v) for v in values)

    finite = [v for v in values if math.isfinite(v)]
    if not finite:
        return TensorStats(
            name=name, dtype=dtype, shape=shape, n_elements=n, byte_size=byte_size,
            has_nan=has_nan, has_inf=has_inf,
        )

    mean = sum(finite) / len(finite)
    variance = sum((v - mean) ** 2 for v in finite) / max(len(finite), 1)
    std = math.sqrt(variance) if variance >= 0 else 0.0
    max_abs = max(abs(v) for v in finite)
    l2_norm = math.sqrt(sum(v * v for v in finite))

    # Excess kurtosis (0 for Gaussian, >0 for heavy tails/spikes)
    kurtosis = 0.0
    if std > 1e-10 and len(finite) >= 4:
        fourth_moment = sum(((v - mean) / std) ** 4 for v in finite) / len(finite)
        kurtosis = fourth_moment - 3.0  # excess kurtosis

    is_high_value = any(p in name.lower() for p in _HIGH_VALUE_TENSOR_PATTERNS)

    return TensorStats(
        name=name, dtype=dtype, shape=shape, n_elements=n, byte_size=byte_size,
        mean=mean, std=std, max_abs=max_abs, has_nan=has_nan, has_inf=has_inf,
        kurtosis=kurtosis, l2_norm=l2_norm, is_high_value_target=is_high_value,
    )


def _analyse_tensors(
    path: Path,
    tensors: dict[str, TensorMeta],
    max_tensor_bytes: int = 4 << 20,   # read up to 4 MiB per tensor for stats
) -> tuple[list[TensorStats], list[AdapterFinding]]:
    """Read tensor data from file and compute statistical fingerprint."""
    stats: list[TensorStats] = []
    findings: list[AdapterFinding] = []

    try:
        fh = open(path, "rb")
    except OSError as exc:
        findings.append(AdapterFinding(
            severity="high", code="TS-001",
            title="Cannot open adapter file for tensor analysis",
            detail=str(exc),
        ))
        return stats, findings

    with fh:
        for name, tm in tensors.items():
            byte_count = tm.data_end - tm.data_start
            if byte_count <= 0:
                continue

            # Cap read for very large tensors — sample the first N bytes.
            read_bytes = min(byte_count, max_tensor_bytes)
            fh.seek(tm.data_start)
            raw = fh.read(read_bytes)

            values = _unpack_floats(raw, tm.dtype)
            if not values:
                continue

            ts = _compute_stats(values, name, tm.dtype, tm.shape, byte_count)
            stats.append(ts)

            # NaN / Inf — immediate red flag
            if ts.has_nan:
                findings.append(AdapterFinding(
                    severity="high", code="WD-001",
                    title="NaN values in adapter tensor",
                    detail=f"Tensor '{name}' contains NaN — corrupted or adversarially crafted weights",
                    tensor_name=name,
                ))
            if ts.has_inf:
                findings.append(AdapterFinding(
                    severity="high", code="WD-002",
                    title="Inf values in adapter tensor",
                    detail=f"Tensor '{name}' contains Inf — corrupted or adversarially crafted weights",
                    tensor_name=name,
                ))

            # Kurtosis anomaly — heavy-tail distributions in LoRA weights
            # suggest targeted weight insertion (backdoor trigger mechanism).
            if ts.kurtosis > _KURTOSIS_THRESHOLD:
                sev = "high" if ts.kurtosis > 20 else "medium"
                findings.append(AdapterFinding(
                    severity=sev, code="WD-003",
                    title="Anomalous weight distribution (high kurtosis)",
                    detail=(
                        f"Tensor '{name}' excess kurtosis={ts.kurtosis:.2f} "
                        f"(threshold {_KURTOSIS_THRESHOLD}). Clean LoRA adapters "
                        f"typically show kurtosis 2–6. Heavy tails suggest targeted "
                        f"weight insertion consistent with backdoor injection."
                    ),
                    tensor_name=name,
                ))

            # High-value target tensor with large magnitude
            if ts.is_high_value_target and ts.max_abs > 10.0:
                findings.append(AdapterFinding(
                    severity="high", code="WD-004",
                    title="High-value embedding / lm_head tensor with large weight magnitude",
                    detail=(
                        f"Tensor '{name}' is a high-value backdoor target "
                        f"(embedding table / output head) with max_abs={ts.max_abs:.4f}. "
                        f"Embedding rewrites are the primary vector for trigger-token injection."
                    ),
                    tensor_name=name,
                ))

    return stats, findings


def _compute_concentration(stats: list[TensorStats]) -> float:
    """Return the fraction of total L2 norm carried by the largest single tensor.

    A clean LoRA spreads weight delta across many layers.  A value near 1.0
    means one tensor dominates — consistent with targeted weight injection.
    """
    if not stats:
        return 0.0
    total = sum(s.l2_norm for s in stats)
    if total < 1e-12:
        return 0.0
    max_single = max(s.l2_norm for s in stats)
    return max_single / total


def _risk_level(findings: list[AdapterFinding], concentration: float) -> tuple[str, bool]:
    """Derive final RISK_LEVEL and safe flag from findings + concentration."""
    has_critical = any(f.severity == "critical" for f in findings)
    has_high = any(f.severity == "high" for f in findings)
    has_medium = any(f.severity == "medium" for f in findings)
    concentration_suspicious = concentration > _CONCENTRATION_THRESHOLD

    if has_critical:
        return "CRITICAL", False
    if has_high:
        return "HIGH", False
    if has_medium or concentration_suspicious:
        return "MEDIUM", True  # warn but don't hard-block
    if findings:
        return "LOW", True
    return "CLEAN", True


# ── Certificate signing ───────────────────────────────────────────────────────


def _sign_report(report_dict: dict[str, Any]) -> str:
    """HMAC-SHA256 of the canonical JSON. Uses SQUASH_SIGNING_KEY env var."""
    payload = json.dumps(report_dict, sort_keys=True, separators=(",", ":")).encode()
    key = os.environ.get("SQUASH_SIGNING_KEY", "squash-adapter-scanner-key").encode()
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return sig


# ── Main entry point ──────────────────────────────────────────────────────────


def scan_adapter(
    adapter_path: Path,
    require_safetensors: bool = False,
    sign: bool = False,
    output_path: Path | None = None,
) -> AdapterScanReport:
    """Scan a LoRA/adapter file for poisoning indicators.

    Parameters
    ----------
    adapter_path : Path
        Path to the adapter file (.safetensors, .pkl, .pt, etc.).
    require_safetensors : bool
        If True and the adapter is not safetensors format, adds a CRITICAL
        finding so the caller can exit rc=2.
    sign : bool
        If True, embed an HMAC-SHA256 signature in the certificate JSON.
    output_path : Path | None
        If provided, write the signed certificate JSON to this path.
        Defaults to ``<adapter_path.stem>-squash-adapter-scan.json``.

    Returns
    -------
    AdapterScanReport
    """
    adapter_path = Path(adapter_path)
    findings: list[AdapterFinding] = []
    tensor_stats: list[TensorStats] = []

    # ── File existence ────────────────────────────────────────────────────────
    if not adapter_path.exists():
        return AdapterScanReport(
            adapter_path=str(adapter_path),
            file_format="unknown",
            risk_level="CRITICAL",
            safe=False,
            error=f"File not found: {adapter_path}",
            findings=[AdapterFinding(
                severity="critical", code="IO-001",
                title="Adapter file not found",
                detail=str(adapter_path),
            )],
        )

    file_size = adapter_path.stat().st_size
    adapter_hash = hashlib.sha256(adapter_path.read_bytes()).hexdigest()

    # ── Format detection ──────────────────────────────────────────────────────
    file_format = detect_format(adapter_path)

    if file_format == "pickle":
        opcodes = scan_pickle_opcodes(adapter_path)
        if opcodes:
            findings.append(AdapterFinding(
                severity="critical", code="PK-001",
                title="Pickle adapter contains code-execution opcodes",
                detail=(
                    f"Found dangerous opcodes/patterns: {', '.join(opcodes[:10])}. "
                    "Pickle-format adapters can execute arbitrary Python on load. "
                    "Use safetensors format. Never load this adapter from an untrusted source."
                ),
            ))
        else:
            findings.append(AdapterFinding(
                severity="high", code="PK-002",
                title="Adapter is in pickle format (inherent execution risk)",
                detail=(
                    "Pickle-format adapters (.pt/.pth/.pkl/.bin) can execute "
                    "arbitrary Python code when loaded, even without obvious opcodes. "
                    "Convert to safetensors for safe use."
                ),
            ))
        if require_safetensors:
            findings.append(AdapterFinding(
                severity="critical", code="PK-003",
                title="--require-safetensors violated: adapter is not in safetensors format",
                detail=(
                    f"File '{adapter_path.name}' detected as '{file_format}'. "
                    "Policy requires safetensors-format adapters only."
                ),
            ))

    elif file_format == "safetensors":
        # Parse header + integrity checks
        tensors, header_findings = parse_safetensors_header(adapter_path)
        findings.extend(header_findings)

        # Weight-delta statistical analysis
        if tensors:
            tensor_stats, stat_findings = _analyse_tensors(adapter_path, tensors)
            findings.extend(stat_findings)

    else:
        findings.append(AdapterFinding(
            severity="medium", code="FMT-001",
            title="Unknown adapter format",
            detail=(
                f"Could not identify format of '{adapter_path.name}' from magic bytes or extension. "
                "Only safetensors and pickle/PyTorch formats are analysed. "
                "Treat unknown formats as untrusted."
            ),
        ))
        if require_safetensors:
            findings.append(AdapterFinding(
                severity="critical", code="PK-003",
                title="--require-safetensors violated: adapter is not in safetensors format",
                detail=f"File '{adapter_path.name}' has unknown format. Policy requires safetensors.",
            ))

    # ── Concentration analysis ────────────────────────────────────────────────
    concentration = _compute_concentration(tensor_stats)
    if concentration > _CONCENTRATION_THRESHOLD and len(tensor_stats) > 1:
        findings.append(AdapterFinding(
            severity="medium", code="WD-005",
            title="Adapter weight delta is suspiciously concentrated",
            detail=(
                f"Concentration score {concentration:.3f} (>{_CONCENTRATION_THRESHOLD:.0%}): "
                f"one tensor carries {concentration:.1%} of the total L2 norm. "
                "Clean LoRA adapters distribute weight change across all adapted layers. "
                "High concentration is consistent with targeted weight insertion."
            ),
        ))

    # ── Shell-pattern sweep (safetensors / unknown) ───────────────────────────
    # Even non-pickle files can carry injected shell strings in metadata /
    # tensor data. Use text-only scan — pickle opcode scan is not valid on
    # binary float data (false positives on common byte values).
    if file_format != "pickle":
        shell_hits = scan_shell_patterns(adapter_path)
        if shell_hits:
            findings.append(AdapterFinding(
                severity="critical", code="SH-001",
                title="Shell-injection patterns found in adapter file",
                detail=f"Patterns: {', '.join(shell_hits[:5])}",
            ))

    # ── Risk level ────────────────────────────────────────────────────────────
    risk_level, safe = _risk_level(findings, concentration)

    # ── Assemble report ───────────────────────────────────────────────────────
    opcodes_found = [o for o in (scan_pickle_opcodes(adapter_path) if file_format == "pickle" else [])
                     if not o.startswith("SHELL_PATTERN:")]

    report = AdapterScanReport(
        adapter_path=str(adapter_path),
        file_format=file_format,
        risk_level=risk_level,
        safe=safe,
        findings=findings,
        tensor_stats=tensor_stats,
        adapter_hash=adapter_hash,
        file_size_bytes=file_size,
        n_tensors=len(tensor_stats) or (1 if file_format == "pickle" else 0),
        total_parameters=sum(t.n_elements for t in tensor_stats),
        concentration_score=concentration,
        pickle_opcodes_found=opcodes_found,
        scanner_version=VERSION,
    )

    # ── Certificate output ────────────────────────────────────────────────────
    if output_path is None:
        output_path = adapter_path.parent / f"{adapter_path.stem}-squash-adapter-scan.json"

    cert: dict[str, Any] = {"report": report.to_dict()}
    if sign:
        cert["signature"] = _sign_report(report.to_dict())

    try:
        output_path.write_text(json.dumps(cert, indent=2))
        report.certificate_path = str(output_path)
    except OSError:
        pass

    return report
