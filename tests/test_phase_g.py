"""Phase G Sprint — Reproducibility helper modules and Tier 0 signing paths.

Tests for:
- squash._canonical  (canonical_bytes, canonical_hex, raises on unknown type)
- squash._clock      (utc_now, freeze_clock context manager)
- squash._ids        (cert_id, is_valid_cert_id, determinism)
- Tier 0 reproducibility: attest, slsa, anchor, chain_attest canonical paths

≥ 40 tests verifying byte-identity guarantees introduced in Phase G.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# squash._canonical
# ---------------------------------------------------------------------------


class TestCanonicalBytes:
    """squash._canonical.canonical_bytes — byte stability and error handling."""

    def _sha256(self, b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()

    def test_bytes_stability_same_input_same_sha256(self):
        from squash._canonical import canonical_bytes

        obj = {"model": "llama-3", "sha256": "abc123", "score": 0.95}
        a = canonical_bytes(obj)
        b = canonical_bytes(obj)
        assert a == b
        assert self._sha256(a) == self._sha256(b)

    def test_bytes_are_bytes_type(self):
        from squash._canonical import canonical_bytes

        result = canonical_bytes({"key": "value"})
        assert isinstance(result, bytes)

    def test_nested_dict_stability(self):
        from squash._canonical import canonical_bytes

        obj = {
            "outer": {"inner": {"deep": "value"}},
            "list": [1, 2, {"nested": True}],
        }
        assert canonical_bytes(obj) == canonical_bytes(obj)

    def test_dict_key_order_independent(self):
        from squash._canonical import canonical_bytes

        obj_a = {"b": 2, "a": 1, "c": 3}
        obj_b = {"a": 1, "c": 3, "b": 2}
        # Same logical content regardless of insertion order
        assert canonical_bytes(obj_a) == canonical_bytes(obj_b)

    def test_handles_string(self):
        from squash._canonical import canonical_bytes

        result = canonical_bytes("hello world")
        assert isinstance(result, bytes)
        assert canonical_bytes("hello world") == canonical_bytes("hello world")

    def test_handles_int(self):
        from squash._canonical import canonical_bytes

        result = canonical_bytes(42)
        assert result == canonical_bytes(42)

    def test_handles_bool_true(self):
        from squash._canonical import canonical_bytes

        assert canonical_bytes(True) == canonical_bytes(True)

    def test_handles_bool_false(self):
        from squash._canonical import canonical_bytes

        assert canonical_bytes(False) == canonical_bytes(False)

    def test_handles_none(self):
        from squash._canonical import canonical_bytes

        assert canonical_bytes(None) == canonical_bytes(None)

    def test_handles_list(self):
        from squash._canonical import canonical_bytes

        obj = [1, "two", 3.0, None, True]
        assert canonical_bytes(obj) == canonical_bytes(obj)

    def test_handles_nested_list(self):
        from squash._canonical import canonical_bytes

        obj = [[1, 2], [3, [4, 5]]]
        assert canonical_bytes(obj) == canonical_bytes(obj)

    def test_raises_on_unserializable_type(self):
        from squash._canonical import CanonError, canonical_bytes

        class _Custom:
            pass

        with pytest.raises((CanonError, TypeError)):
            canonical_bytes(_Custom())

    def test_raises_on_set_directly(self):
        """Sets must be converted by caller; raw sets should raise or sort."""
        from squash._canonical import canonical_bytes
        from squash.canon import CanonError

        # sets go through prepare() which converts them to sorted lists — so
        # canonical_bytes({1, 2, 3}) should either succeed deterministically
        # or raise CanonError. Either is acceptable; what's NOT acceptable is
        # silent non-determinism.
        try:
            a = canonical_bytes({3, 1, 2})
            b = canonical_bytes({1, 2, 3})
            # If it succeeds, it must be deterministic (sets sorted)
            assert a == b
        except (CanonError, TypeError):
            pass  # also acceptable

    def test_output_no_insignificant_whitespace(self):
        from squash._canonical import canonical_bytes

        result = canonical_bytes({"a": 1, "b": 2})
        assert b" " not in result
        assert b"\n" not in result

    def test_different_inputs_produce_different_bytes(self):
        from squash._canonical import canonical_bytes

        a = canonical_bytes({"model": "llama-3"})
        b = canonical_bytes({"model": "gpt-4"})
        assert a != b


class TestCanonicalHex:
    """squash._canonical.canonical_hex — SHA-256 of canonical bytes."""

    def test_returns_64_char_hex(self):
        from squash._canonical import canonical_hex

        result = canonical_hex({"key": "value"})
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_stable_across_calls(self):
        from squash._canonical import canonical_hex

        obj = {"model": "test", "version": 1}
        assert canonical_hex(obj) == canonical_hex(obj)

    def test_matches_sha256_of_canonical_bytes(self):
        from squash._canonical import canonical_bytes, canonical_hex

        obj = {"a": 1, "b": [2, 3]}
        expected = hashlib.sha256(canonical_bytes(obj)).hexdigest()
        assert canonical_hex(obj) == expected

    def test_different_inputs_different_hex(self):
        from squash._canonical import canonical_hex

        assert canonical_hex({"x": 1}) != canonical_hex({"x": 2})


# ---------------------------------------------------------------------------
# squash._clock
# ---------------------------------------------------------------------------


class TestClockUtcNow:
    """squash._clock.utc_now — returns UTC-aware datetime."""

    def test_utc_now_returns_datetime(self):
        from squash._clock import utc_now

        result = utc_now()
        assert isinstance(result, datetime)

    def test_utc_now_is_timezone_aware(self):
        from squash._clock import utc_now

        result = utc_now()
        assert result.tzinfo is not None

    def test_utc_now_is_utc(self):
        from squash._clock import utc_now

        result = utc_now()
        # astimezone(timezone.utc) should be equivalent
        assert result.astimezone(timezone.utc).tzinfo == timezone.utc

    def test_utc_now_returns_different_values_over_time(self):
        """Two calls to utc_now() should not return the exact same instant
        (they might in very fast systems, so just check the type contract)."""
        from squash._clock import utc_now

        t1 = utc_now()
        t2 = utc_now()
        assert isinstance(t1, datetime)
        assert isinstance(t2, datetime)
        # t2 >= t1 always (monotonic contract)
        assert t2 >= t1


class TestFreezeClock:
    """squash._clock.freeze_clock — context manager freezes utc_now."""

    def test_freeze_clock_returns_frozen_value(self):
        from squash._clock import freeze_clock, utc_now

        fixed = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
        with freeze_clock(fixed):
            result = utc_now()
        assert result == fixed

    def test_freeze_clock_restores_on_exit(self):
        from squash._clock import freeze_clock, utc_now

        fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with freeze_clock(fixed):
            pass
        # After exit, utc_now() should no longer be frozen
        live = utc_now()
        # live should be very close to now, not 2026-01-01
        from datetime import datetime as _dt

        now = _dt.now(timezone.utc)
        # The thawed clock should be within 60 seconds of now
        diff = abs((now - live).total_seconds())
        assert diff < 60

    def test_freeze_clock_context_manager_yields_frozen_clock(self):
        from squash._clock import freeze_clock

        fixed = datetime(2026, 3, 15, 9, 30, 0, tzinfo=timezone.utc)
        with freeze_clock(fixed) as clk:
            assert clk() == fixed

    def test_freeze_clock_nested(self):
        """Nested freeze_clock should restore correctly."""
        from squash._clock import freeze_clock, utc_now

        outer = datetime(2026, 1, 1, tzinfo=timezone.utc)
        inner = datetime(2026, 6, 15, tzinfo=timezone.utc)

        with freeze_clock(outer):
            assert utc_now() == outer
            with freeze_clock(inner):
                assert utc_now() == inner
            assert utc_now() == outer

    def test_default_clock_type(self):
        from squash._clock import DEFAULT_CLOCK

        result = DEFAULT_CLOCK()
        assert isinstance(result, datetime)
        assert result.tzinfo is not None

    def test_clock_type_alias_is_callable(self):

        # ClockType is just Callable[[], datetime]; verify we can call DEFAULT_CLOCK
        from squash._clock import DEFAULT_CLOCK

        assert isinstance(DEFAULT_CLOCK(), datetime)


# ---------------------------------------------------------------------------
# squash._ids
# ---------------------------------------------------------------------------


class TestCertId:
    """squash._ids.cert_id — deterministic, content-addressed IDs."""

    def _payload(self, data: Any) -> bytes:
        from squash._canonical import canonical_bytes

        return canonical_bytes(data)

    def test_cert_id_is_deterministic(self):
        from squash._ids import cert_id

        payload = self._payload({"model": "llama-3", "sha256": "abc"})
        a = cert_id("slsa", canonical_payload=payload)
        b = cert_id("slsa", canonical_payload=payload)
        assert a == b

    def test_cert_id_different_payloads_different_ids(self):
        from squash._ids import cert_id

        p1 = self._payload({"model": "llama-3"})
        p2 = self._payload({"model": "gpt-4"})
        assert cert_id("slsa", canonical_payload=p1) != cert_id("slsa", canonical_payload=p2)

    def test_cert_id_different_prefix_different_ids(self):
        from squash._ids import cert_id

        payload = self._payload({"x": 1})
        assert cert_id("slsa", canonical_payload=payload) != cert_id(
            "anc", canonical_payload=payload
        )

    def test_cert_id_format_prefix_dash_16hex(self):
        from squash._ids import cert_id

        payload = self._payload({"key": "value"})
        result = cert_id("slsa", canonical_payload=payload)
        parts = result.split("-")
        assert len(parts) == 2
        assert parts[0] == "slsa"
        assert len(parts[1]) == 16
        assert all(c in "0123456789abcdef" for c in parts[1])

    def test_cert_id_empty_bytes_payload(self):
        from squash._ids import cert_id

        result = cert_id("anc", canonical_payload=b"")
        assert result.startswith("anc-")
        assert len(result.split("-")[1]) == 16

    def test_cert_id_raises_on_empty_prefix(self):
        from squash._ids import cert_id

        with pytest.raises(ValueError):
            cert_id("", canonical_payload=b"payload")

    def test_cert_id_raises_on_hyphen_in_prefix(self):
        from squash._ids import cert_id

        with pytest.raises(ValueError):
            cert_id("my-prefix", canonical_payload=b"payload")

    def test_cert_id_with_anc_prefix(self):
        from squash._ids import cert_id

        payload = self._payload({"root": "a" * 64, "backend": "local"})
        result = cert_id("anc", canonical_payload=payload)
        assert result.startswith("anc-")


class TestIsValidCertId:
    """squash._ids.is_valid_cert_id — format validator."""

    def test_valid_slsa_id(self):
        from squash._ids import is_valid_cert_id

        assert is_valid_cert_id("slsa-1d2e3f4a5b6c7d8e")

    def test_valid_anc_id(self):
        from squash._ids import is_valid_cert_id

        assert is_valid_cert_id("anc-abcdef1234567890")

    def test_valid_single_char_prefix(self):
        from squash._ids import is_valid_cert_id

        assert is_valid_cert_id("a-0123456789abcdef")

    def test_invalid_too_short_suffix(self):
        from squash._ids import is_valid_cert_id

        assert not is_valid_cert_id("slsa-abc123")

    def test_invalid_no_prefix(self):
        from squash._ids import is_valid_cert_id

        assert not is_valid_cert_id("-1d2e3f4a5b6c7d8e")

    def test_invalid_uppercase_in_suffix(self):
        from squash._ids import is_valid_cert_id

        assert not is_valid_cert_id("slsa-1D2E3F4A5B6C7D8E")

    def test_invalid_no_separator(self):
        from squash._ids import is_valid_cert_id

        assert not is_valid_cert_id("slsa1d2e3f4a5b6c7d8e")

    def test_generated_id_passes_validator(self):
        from squash._canonical import canonical_bytes
        from squash._ids import cert_id, is_valid_cert_id

        payload = canonical_bytes({"test": True})
        cid = cert_id("hac", canonical_payload=payload)
        assert is_valid_cert_id(cid)


class TestSquashNs:
    """SQUASH_NS constant stability."""

    def test_squash_ns_is_uuid(self):
        import uuid as _uuid

        from squash._ids import SQUASH_NS

        assert isinstance(SQUASH_NS, _uuid.UUID)

    def test_squash_ns_matches_ids_module(self):
        from squash._ids import SQUASH_NS as ns_ids
        from squash.ids import SQUASH_NS as ns_core

        assert ns_ids == ns_core


# ---------------------------------------------------------------------------
# Tier 0 reproducibility tests
# ---------------------------------------------------------------------------


class TestAttestateBuildMasterRecordReproducibility:
    """_build_master_record produces byte-identical canonical output on re-run."""

    def _make_fake_result(self, tmp_path: Path):
        from squash.attest import AttestResult
        from squash.scanner import ScanResult

        scan = ScanResult(
            scanned_path=str(tmp_path / "model.gguf"),
            status="PASS",
            scanner_version="0.0.1",
        )
        return AttestResult(
            model_id="test-model",
            output_dir=tmp_path,
            passed=True,
            scan_result=scan,
        )

    def test_master_record_byte_identical_frozen_clock(self, tmp_path):
        from squash._canonical import canonical_bytes
        from squash._clock import freeze_clock
        from squash.attest import AttestConfig, _build_master_record

        fixed = datetime(2026, 5, 19, 10, 0, 0, tzinfo=timezone.utc)
        config = AttestConfig(model_path=tmp_path / "model.gguf")
        result = self._make_fake_result(tmp_path)

        with freeze_clock(fixed):
            a = _build_master_record(config, result)
            b = _build_master_record(config, result)

        ha = hashlib.sha256(canonical_bytes(a)).hexdigest()
        hb = hashlib.sha256(canonical_bytes(b)).hexdigest()
        assert ha == hb


class TestSlsaReproducibility:
    """SlsaProvenanceBuilder produces byte-identical statements under frozen clock."""

    def test_slsa_byte_identical_on_rerun(self, tmp_path):
        from squash._canonical import canonical_bytes
        from squash.clock import FrozenClock
        from squash.slsa import SlsaLevel, SlsaProvenanceBuilder

        clk = FrozenClock(datetime(2026, 5, 19, 0, 0, 0, tzinfo=timezone.utc))
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}

        # Two parallel runs with identical inputs
        d_a = tmp_path / "run_a" / "model"
        d_b = tmp_path / "run_b" / "model"
        d_a.mkdir(parents=True)
        d_b.mkdir(parents=True)
        bom_bytes = canonical_bytes(bom)
        (d_a / "cyclonedx-mlbom.json").write_bytes(bom_bytes)
        (d_b / "cyclonedx-mlbom.json").write_bytes(bom_bytes)

        at_a = SlsaProvenanceBuilder.build(d_a, level=SlsaLevel.L1, clock=clk)
        at_b = SlsaProvenanceBuilder.build(d_b, level=SlsaLevel.L1, clock=clk)

        ha = hashlib.sha256(at_a.output_path.read_bytes()).hexdigest()
        hb = hashlib.sha256(at_b.output_path.read_bytes()).hexdigest()
        assert ha == hb
        assert at_a.invocation_id == at_b.invocation_id


class TestAnchorCanonicalReproducibility:
    """anchor.canonical_json and hash_attestation are byte-identical."""

    def test_canonical_json_stable(self):
        from squash.anchor import canonical_json, hash_attestation

        record = {
            "model_id": "llama-3",
            "policies": ["eu-ai-act"],
            "score": 0.98,
            "issued_at": datetime(2026, 5, 19, tzinfo=timezone.utc),
        }
        a = canonical_json(record)
        b = canonical_json(record)
        assert a == b
        assert hash_attestation(record) == hash_attestation(record)

    def test_anchor_id_from_ids_module_is_deterministic(self):
        from squash.ids import cert_id

        seed = {"root": "deadbeef" * 8, "backend": "local"}
        assert cert_id("anc", seed) == cert_id("anc", seed)

    def test_anchor_id_changes_with_different_root(self):
        from squash.ids import cert_id

        seed1 = {"root": "a" * 64}
        seed2 = {"root": "b" * 64}
        assert cert_id("anc", seed1) != cert_id("anc", seed2)


class TestChainAttestReproducibility:
    """ChainAttestation.canonical_bytes is byte-identical on re-run."""

    def test_canonical_bytes_stable(self):
        from squash.chain_attest import (
            ChainAttestation,
            ChainComponent,
            ChainKind,
            ChainSpec,
            ComponentAttestation,
            ComponentRole,
        )

        comp = ChainComponent(name="retriever", role=ComponentRole.LLM, model_path=None)
        spec = ChainSpec(chain_id="ch-test", kind=ChainKind.RAG, components=[comp])
        ca = ComponentAttestation(component=comp, skipped=True, skipped_reason="demo")
        attest = ChainAttestation(
            chain_id="ch-test",
            kind=ChainKind.RAG,
            generated_at="2026-05-19T00:00:00Z",
            spec=spec,
            components=[ca],
            composite_score=100,
            composite_passed=True,
            external_components=[],
        )
        ha = hashlib.sha256(attest.canonical_bytes()).hexdigest()
        hb = hashlib.sha256(attest.canonical_bytes()).hexdigest()
        assert ha == hb


class TestIdsModuleCertId:
    """squash.ids.cert_id (the core module) is deterministic."""

    def test_cert_id_deterministic(self):
        from squash.ids import cert_id

        payload = {"subject": "test", "builder": "local"}
        assert cert_id("slsa", payload) == cert_id("slsa", payload)

    def test_cert_id_hex_prefix_format(self):
        from squash.ids import cert_id

        result = cert_id("hac", {"key": "val"})
        prefix, suffix = result.split("-", 1)
        assert prefix == "hac"
        assert len(suffix) == 16
        assert all(c in "0123456789abcdef" for c in suffix)
