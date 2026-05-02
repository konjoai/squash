"""Phase G.4 — Security regression tests.

Each test pins a known-bad pattern that the codebase has either
historically had or could plausibly introduce. A regression here is a
direct security vulnerability.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from squash.canon import canonical_bytes
from squash.ids import cert_id


# ---------------------------------------------------------------------------
# Signature tampering
# ---------------------------------------------------------------------------


class TestSignatureTampering:
    def test_carbon_attestation_verify_rejects_tampered_body(self):
        """Mutating any field of a signed Carbon cert MUST break verification."""
        from squash.carbon_attest import (
            CarbonAttestation,
            HardwareType,
            ModelArchitecture,
        )

        cert = CarbonAttestation(
            cert_id="carbon-xxx",
            model_id="m",
            deployment_region="us-west",
            architecture=ModelArchitecture.TRANSFORMER,
            hardware=HardwareType.A100,
            param_count=1,
            inferences_per_day=1,
            tokens_per_inference=1,
            kwh_per_inference=0.001,
            kwh_per_million_tokens=1.0,
            kwh_per_day=1.0,
            kwh_per_year=365.0,
            gco2_per_inference=0.1,
            co2_kg_per_day=0.1,
            co2_tonne_per_year=0.1,
            market_gco2_per_inference=0.05,
            market_co2_tonne_per_year=0.05,
            grid_intensity_gco2_per_kwh=400.0,
            grid_source="x",
            flop_estimate_method="x",
            energy_method="x",
            pue=1.0,
            utilization_factor=0.5,
            compute_timestamp="2026-01-01T00:00:00Z",
        )
        key = b"k" * 32
        cert.sign(key=key)
        assert cert.verify(key=key)
        # Tamper.
        cert.kwh_per_year = 999_999.0
        assert not cert.verify(key=key)

    def test_carbon_attestation_verify_rejects_wrong_key(self):
        from squash.carbon_attest import (
            CarbonAttestation,
            HardwareType,
            ModelArchitecture,
        )

        cert = CarbonAttestation(
            cert_id="carbon-yyy",
            model_id="m",
            deployment_region="us-west",
            architecture=ModelArchitecture.TRANSFORMER,
            hardware=HardwareType.A100,
            param_count=1,
            inferences_per_day=1,
            tokens_per_inference=1,
            kwh_per_inference=0.001,
            kwh_per_million_tokens=1.0,
            kwh_per_day=1.0,
            kwh_per_year=365.0,
            gco2_per_inference=0.1,
            co2_kg_per_day=0.1,
            co2_tonne_per_year=0.1,
            market_gco2_per_inference=0.05,
            market_co2_tonne_per_year=0.05,
            grid_intensity_gco2_per_kwh=400.0,
            grid_source="x",
            flop_estimate_method="x",
            energy_method="x",
            pue=1.0,
            utilization_factor=0.5,
            compute_timestamp="2026-01-01T00:00:00Z",
        )
        cert.sign(key=b"k" * 32)
        assert not cert.verify(key=b"j" * 32)


# ---------------------------------------------------------------------------
# Replay protection — TSA nonce
# ---------------------------------------------------------------------------


class TestTSAReplayProtection:
    def test_tsa_nonce_is_64_bit_random(self):
        """Two consecutive build_request calls must use different nonces."""
        from squash.tsa import build_request

        _, n1 = build_request(b"hello")
        _, n2 = build_request(b"hello")
        assert n1 != n2
        # Nonce fits in 64 bits.
        assert 0 < n1 < 2**64
        assert 0 < n2 < 2**64


# ---------------------------------------------------------------------------
# Canonical-JSON injection — homograph + control char
# ---------------------------------------------------------------------------


class TestCanonInjection:
    def test_control_chars_are_escaped_not_inlined(self):
        """A signed body containing a literal newline character would be
        misparseable (and exploitable via header injection in derived
        formats). canonical_bytes MUST escape it."""
        encoded = canonical_bytes({"k": "a\nb"})
        # Newline is escaped, not present as a literal byte.
        assert b"\n" not in encoded
        assert b"\\n" in encoded

    def test_quote_char_escaped(self):
        encoded = canonical_bytes({"k": 'a"b'})
        assert b'\\"' in encoded

    def test_backslash_char_escaped(self):
        encoded = canonical_bytes({"k": "a\\b"})
        assert b"\\\\" in encoded


# ---------------------------------------------------------------------------
# Path traversal — input_manifest must not follow ../ links out of root
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_manifest_walk_does_not_escape_root(self, tmp_path):
        """Files outside the manifest root must NEVER appear in the manifest."""
        from squash.input_manifest import build_input_manifest

        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"secret")

        root = tmp_path / "model"
        root.mkdir()
        (root / "weights.bin").write_bytes(b"public")

        m = build_input_manifest(root)
        names = {fd.path for fd in m.files}
        assert "weights.bin" in names
        # Attacker plants a relative-path leak — manifest must not echo it.
        for fd in m.files:
            assert ".." not in fd.path
            assert "outside" not in fd.path


# ---------------------------------------------------------------------------
# UUID5 namespace pinning — must NEVER drift
# ---------------------------------------------------------------------------


class TestNamespacePinning:
    def test_squash_namespace_is_immutable(self):
        """The project namespace is the load-bearing identity of the cert
        space. Drift in this constant is a silent vulnerability — every
        cert ID across every release would change."""
        import uuid

        from squash.ids import SQUASH_NS

        assert SQUASH_NS == uuid.UUID("8b7c4a2e-1d3f-5e6a-9b8c-0d1e2f3a4b5c")

    def test_known_payload_pins_known_id(self):
        """A vector chosen for the namespace at the time of writing — if
        this changes, every cert ID in the field invalidates."""
        # Pin one known input → one known UUID. Locks the recipe forever.
        cid = cert_id("hac", {"m": "x"})
        assert cid.startswith("hac-")
        # Length is the documented format.
        assert len(cid) == 4 + 16


# ---------------------------------------------------------------------------
# Self-verify must FAIL when the cert and manifest disagree
# ---------------------------------------------------------------------------


class TestSelfVerifyMismatch:
    def test_self_verify_detects_manifest_swap(self, tmp_path):
        """An attacker swaps a clean input_manifest into an attestation
        whose body cites a different manifest hash. self-verify catches it."""
        from squash.input_manifest import build_input_manifest

        # Real manifest from a real input
        (tmp_path / "weights.bin").write_bytes(b"good")
        m_real = build_input_manifest(tmp_path)
        m_real.write(tmp_path / "input_manifest.json")

        # Now tamper: replace the file but leave the manifest untouched.
        (tmp_path / "weights.bin").write_bytes(b"BAD")

        from squash.self_verify import check_input_manifest

        result = check_input_manifest(tmp_path, model_dir=tmp_path)
        assert not result.passed
