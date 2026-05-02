"""Phase G.4 — Edge-case tests: empty input, N=1, unicode, paths-with-spaces, 0-byte files."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from squash.canon import canonical_bytes, canonical_hash
from squash.clock import FrozenClock, with_clock
from squash.ids import cert_id, deterministic_uuid
from squash.input_manifest import build_input_manifest, manifest_hash, verify_manifest


# ---------------------------------------------------------------------------
# canon edge inputs
# ---------------------------------------------------------------------------


class TestCanonEdge:
    def test_deeply_nested_dict(self):
        d = {"k": "v"}
        for i in range(50):
            d = {"k": d}
        # Deep nesting must not crash.
        b = canonical_bytes(d)
        assert b.startswith(b'{"k":')

    def test_large_array(self):
        arr = list(range(10_000))
        b = canonical_bytes(arr)
        assert b.startswith(b"[0,1,2,") and b.endswith(b"9999]")

    def test_unicode_keys_and_values(self):
        v = {"ቆንጆ": "konjo", "根性": "konjō", "건조": "geonjo"}
        # Non-ASCII flows through unmodified (RFC 8785 — UTF-8).
        b = canonical_bytes(v)
        # Keys are sorted by UTF-16 code-unit value; assert byte stability.
        assert canonical_bytes(v) == b

    def test_empty_dict_and_list(self):
        assert canonical_bytes({}) == b"{}"
        assert canonical_bytes([]) == b"[]"
        assert canonical_bytes({"k": []}) == b'{"k":[]}'
        assert canonical_bytes({"k": {}}) == b'{"k":{}}'

    def test_empty_string_value(self):
        assert canonical_bytes({"k": ""}) == b'{"k":""}'

    def test_zero_int_and_zero_float(self):
        assert canonical_bytes(0) == b"0"
        assert canonical_bytes(0.0) == b"0"


# ---------------------------------------------------------------------------
# input_manifest edge inputs
# ---------------------------------------------------------------------------


class TestInputManifestEdge:
    def test_empty_directory_yields_zero_files(self, tmp_path):
        m = build_input_manifest(tmp_path)
        assert m.file_count == 0
        assert m.total_bytes == 0
        ok, errs = verify_manifest(m, tmp_path)
        assert ok, errs

    def test_zero_byte_file(self, tmp_path):
        (tmp_path / "empty.bin").write_bytes(b"")
        m = build_input_manifest(tmp_path)
        assert m.file_count == 1
        assert m.files[0].size == 0
        # SHA-256 of empty input is well-known.
        assert m.files[0].sha256 == hashlib.sha256(b"").hexdigest()

    def test_path_with_spaces(self, tmp_path):
        d = tmp_path / "dir with spaces"
        d.mkdir()
        (d / "file with spaces.bin").write_bytes(b"hello")
        m = build_input_manifest(d)
        assert m.file_count == 1
        assert "file with spaces.bin" in m.files[0].path

    def test_unicode_filenames(self, tmp_path):
        if sys.platform == "win32":
            pytest.skip("Windows filename encoding varies")
        (tmp_path / "ቆንጆ.bin").write_bytes(b"konjo")
        m = build_input_manifest(tmp_path)
        assert m.file_count == 1
        # Manifest stores the POSIX-encoded path; round-trip via canonical
        # bytes must succeed (UTF-8 throughout).
        assert canonical_bytes(m.to_dict())

    def test_single_file_input(self, tmp_path):
        # build_input_manifest accepts a single-file root.
        f = tmp_path / "model.safetensors"
        f.write_bytes(b"\x00" * 16)
        m = build_input_manifest(f)
        assert m.file_count == 1
        assert m.files[0].size == 16

    def test_nested_directories(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b").mkdir()
        (tmp_path / "a" / "b" / "c.bin").write_bytes(b"deep")
        m = build_input_manifest(tmp_path)
        assert m.file_count == 1
        # POSIX-style path with forward slashes.
        assert m.files[0].path == "a/b/c.bin"

    def test_artefacts_excluded_by_default(self, tmp_path):
        # Ignore set excludes squash-* and BOM artefacts so a re-run does
        # not pull in last-run output.
        (tmp_path / "weights.bin").write_bytes(b"data")
        (tmp_path / "input_manifest.json").write_text("{}")
        (tmp_path / "cyclonedx-mlbom.json").write_text("{}")
        m = build_input_manifest(tmp_path)
        names = {fd.path for fd in m.files}
        assert "weights.bin" in names
        assert "input_manifest.json" not in names
        assert "cyclonedx-mlbom.json" not in names


# ---------------------------------------------------------------------------
# cert_id edge inputs
# ---------------------------------------------------------------------------


class TestCertIdEdge:
    def test_small_payload(self):
        cid = cert_id("hac", {"a": 1})
        assert cid.startswith("hac-")
        assert len(cid) == len("hac-") + 16

    def test_large_payload(self):
        # 10K nested entries — must still produce a 16-hex suffix.
        big = {"k": list(range(10_000))}
        cid = cert_id("hac", big)
        assert len(cid.split("-", 1)[1]) == 16

    def test_unicode_payload(self):
        cid = cert_id("hac", {"name": "ቆንጆ"})
        assert cid.startswith("hac-")

    def test_payload_with_set_is_order_invariant(self):
        cid_a = cert_id("hac", {"tags": {"a", "b", "c"}})
        cid_b = cert_id("hac", {"tags": {"c", "b", "a"}})
        assert cid_a == cid_b


# ---------------------------------------------------------------------------
# Pipeline edge: frozen-clock attest with N=1 input file
# ---------------------------------------------------------------------------


class TestPipelineEdge:
    def test_attest_pipeline_handles_single_file_model(self, tmp_path):
        from squash.attest import AttestConfig, AttestPipeline

        d = tmp_path / "model"
        d.mkdir()
        (d / "weights.bin").write_bytes(b"\x00" * 64)
        clk = FrozenClock(datetime(2026, 5, 1, tzinfo=timezone.utc))
        with with_clock(clk):
            r = AttestPipeline.run(
                AttestConfig(
                    model_path=d,
                    output_dir=d,
                    policies=[],
                    fail_on_violation=False,
                )
            )
        # Master record exists (when input is non-empty).
        # input_manifest.json should be the first artefact written.
        assert (d / "input_manifest.json").exists()

    def test_attest_pipeline_emits_input_manifest_with_single_file(self, tmp_path):
        from squash.attest import AttestConfig, AttestPipeline

        d = tmp_path / "model"
        d.mkdir()
        (d / "model.safetensors").write_bytes(b"\x00" * 32)
        AttestPipeline.run(
            AttestConfig(
                model_path=d,
                output_dir=d,
                policies=[],
                fail_on_violation=False,
            )
        )
        manifest = json.loads((d / "input_manifest.json").read_text())
        assert manifest["file_count"] >= 1
