"""Phase G.4 — Negative-path tests for new modules.

Every error path is exercised: malformed input, missing files,
truncated bytes, wrong types. Each test asserts the *specific*
exception is raised so future refactors cannot silently swallow errors.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from squash.canon import CanonError, canonical_bytes, prepare
from squash.clock import FrozenClock
from squash.ids import cert_id, short_id
from squash.input_manifest import (
    build_input_manifest,
    from_dict,
    manifest_hash,
    verify_manifest,
)
from squash.self_verify import (
    check_canonical_body,
    check_input_manifest,
    check_slsa_provenance,
    check_tsa_timestamp,
    verify,
)
from squash.tsa import (
    TSAError,
    build_request,
    timestamp_or_fail,
    verify_timestamp_token,
)


# ---------------------------------------------------------------------------
# canon — every unsupported type raises CanonError, never silently coerces
# ---------------------------------------------------------------------------


class TestCanonNegative:
    def test_naive_datetime_rejected(self):
        with pytest.raises(CanonError, match="naive datetime"):
            canonical_bytes(datetime(2026, 1, 1))

    def test_nan_rejected(self):
        with pytest.raises(CanonError, match="non-finite"):
            canonical_bytes(float("nan"))

    def test_inf_rejected(self):
        with pytest.raises(CanonError, match="non-finite"):
            canonical_bytes(float("inf"))

    def test_neg_inf_rejected(self):
        with pytest.raises(CanonError, match="non-finite"):
            canonical_bytes(float("-inf"))

    def test_int_dict_key_rejected(self):
        with pytest.raises(CanonError, match="dict keys must be str"):
            canonical_bytes({1: "v"})

    def test_object_rejected(self):
        with pytest.raises(CanonError, match="unsupported type"):
            canonical_bytes(object())

    def test_complex_number_rejected(self):
        with pytest.raises(CanonError, match="unsupported type"):
            canonical_bytes(complex(1, 2))

    def test_none_dict_key_rejected(self):
        with pytest.raises(CanonError):
            canonical_bytes({None: "v"})


# ---------------------------------------------------------------------------
# ids — prefix validation is strict
# ---------------------------------------------------------------------------


class TestIdsNegative:
    def test_empty_prefix_rejected(self):
        with pytest.raises(ValueError):
            cert_id("", {"a": 1})

    def test_dash_in_prefix_rejected(self):
        with pytest.raises(ValueError, match="must not contain"):
            cert_id("foo-bar", {"a": 1})

    def test_short_id_zero_length(self):
        with pytest.raises(ValueError):
            short_id({"a": 1}, length=0)

    def test_short_id_overflow_length(self):
        with pytest.raises(ValueError):
            short_id({"a": 1}, length=33)

    def test_non_string_prefix_rejected(self):
        with pytest.raises(ValueError):
            cert_id(123, {"a": 1})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# input_manifest
# ---------------------------------------------------------------------------


class TestInputManifestNegative:
    def test_missing_root_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            build_input_manifest(tmp_path / "does-not-exist")

    def test_verify_detects_tampered_file(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(b"hello")
        m = build_input_manifest(tmp_path)
        # Tamper with the file on disk.
        (tmp_path / "a.bin").write_bytes(b"goodbye")
        ok, errors = verify_manifest(m, tmp_path)
        assert not ok
        assert any("sha256 mismatch" in e for e in errors)

    def test_verify_detects_missing_file(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(b"hello")
        m = build_input_manifest(tmp_path)
        (tmp_path / "a.bin").unlink()
        ok, errors = verify_manifest(m, tmp_path)
        assert not ok
        assert any("missing file" in e for e in errors)

    def test_verify_detects_tampered_manifest_self_hash(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(b"hello")
        m = build_input_manifest(tmp_path)
        m.manifest_sha256 = "0" * 64  # tamper
        ok, errors = verify_manifest(m, tmp_path)
        assert not ok
        assert any("manifest_sha256 mismatch" in e for e in errors)

    def test_round_trip_through_dict_preserves_self_hash(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(b"hello")
        m = build_input_manifest(tmp_path)
        m2 = from_dict(json.loads(canonical_bytes(m.to_dict()).decode("utf-8")))
        assert m2.manifest_sha256 == m.manifest_sha256


# ---------------------------------------------------------------------------
# tsa — DER encoder exercised in isolation; live network tests skipped
# ---------------------------------------------------------------------------


class TestTSANegative:
    def test_build_request_emits_valid_der_sequence(self):
        der, nonce = build_request(b"hello", nonce=42)
        # First byte is SEQUENCE tag (0x30).
        assert der[0] == 0x30
        # Nonce is captured as supplied.
        assert nonce == 42

    def test_build_request_nonce_default_is_random(self):
        _, n1 = build_request(b"hello")
        _, n2 = build_request(b"hello")
        # 64-bit random nonce — collision is negligible.
        assert n1 != n2

    def test_offline_mode_blocks_tsa_call(self, monkeypatch):
        monkeypatch.setenv("SQUASH_OFFLINE", "1")
        with pytest.raises(TSAError, match="OFFLINE"):
            timestamp_or_fail(b"x")

    def test_verify_rejects_unrelated_response(self):
        # Random bytes that do NOT contain the expected message digest.
        import base64

        bogus = base64.b64encode(b"\x30\x03\x02\x01\x00").decode("ascii")
        ok, detail = verify_timestamp_token(bogus, b"hello")
        assert not ok


# ---------------------------------------------------------------------------
# self_verify — reports failure cleanly on missing inputs
# ---------------------------------------------------------------------------


class TestSelfVerifyNegative:
    def test_missing_dir_reports_failure(self, tmp_path):
        rep = verify(tmp_path / "nonexistent")
        assert not rep.passed
        assert any(c.name == "attestation_dir" and not c.passed for c in rep.checks)

    def test_missing_manifest_reports_failure(self, tmp_path):
        # Empty dir — input_manifest.json absent.
        result = check_input_manifest(tmp_path)
        assert not result.passed
        assert "not found" in result.detail

    def test_corrupt_manifest_reports_parse_failure(self, tmp_path):
        (tmp_path / "input_manifest.json").write_text("{not json")
        result = check_input_manifest(tmp_path)
        assert not result.passed
        assert "parse failed" in result.detail

    def test_corrupt_master_record_reports_parse_failure(self, tmp_path):
        (tmp_path / "squash-attest.json").write_text("{nope")
        result = check_canonical_body(tmp_path)
        assert not result.passed

    def test_slsa_subject_mismatch_reports_failure(self, tmp_path):
        # SLSA Statement claims a subject that does NOT match the BOM bytes.
        (tmp_path / "cyclonedx-mlbom.json").write_bytes(b'{"bom":1}')
        (tmp_path / "squash-slsa-provenance.json").write_text(
            json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
                    "predicateType": "https://slsa.dev/provenance/v1",
                }
            )
        )
        result = check_slsa_provenance(tmp_path)
        assert not result.passed
        assert "no subject digest" in result.detail
