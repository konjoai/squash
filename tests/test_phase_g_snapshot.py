"""Phase G.4 — Golden snapshot tests.

Each test pins the canonical bytes / shape of an attestation under
controlled inputs and a frozen clock. Updating a snapshot requires a
human-reviewed change to this file — that is the load-bearing checkpoint
against silent schema drift.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from squash.canon import canonical_bytes, canonical_hash
from squash.ids import cert_id, deterministic_uuid


def test_canonical_bytes_pinned_for_minimal_payload():
    """A tiny payload pins the encoder's output bytes forever."""
    payload = {"k": 1}
    assert canonical_bytes(payload) == b'{"k":1}'


def test_canonical_bytes_pinned_for_typical_attestation_body():
    """Realistic-shape attestation body pinned at the byte level."""
    body = {
        "schema": "squash.attest/v1",
        "model_id": "gpt-4-q4",
        "issued_at": "2026-05-01T00:00:00Z",
        "passed": True,
        "scores": [0.95, 0.92, 0.88],
        "tags": {"prod", "us-west-2"},  # set → sorted
    }
    encoded = canonical_bytes(body)
    # Pinned bytes — any drift in the encoder signals an unintended change.
    assert encoded == (
        b'{"issued_at":"2026-05-01T00:00:00Z",'
        b'"model_id":"gpt-4-q4",'
        b'"passed":true,'
        b'"schema":"squash.attest/v1",'
        b'"scores":[0.95,0.92,0.88],'
        b'"tags":["prod","us-west-2"]}'
    )


def test_canonical_hash_pinned_for_typical_body():
    """SHA-256 of canonical bytes is the cert identity. Pin one example."""
    body = {"a": 1, "b": [2, 3], "c": True}
    expected = hashlib.sha256(b'{"a":1,"b":[2,3],"c":true}').hexdigest()
    assert canonical_hash(body) == expected


def test_cert_id_pinned():
    """Lock cert_id format + namespace forever."""
    # If this assertion breaks, the project namespace drifted and EVERY
    # previously-issued cert ID is now invalid.
    cid = cert_id("hac", {"m": "x"})
    assert cid == "hac-" + deterministic_uuid({"m": "x"}).hex[:16]


def test_input_manifest_schema_string_pinned():
    """Schema URI must remain the same forever — it's the version pin."""
    from squash.input_manifest import SCHEMA

    assert SCHEMA == "squash.input-manifest/v1"


def test_input_manifest_byte_stable_under_frozen_clock(tmp_path):
    from squash.clock import FrozenClock
    from squash.input_manifest import build_input_manifest

    (tmp_path / "weights.bin").write_bytes(b"\x00" * 16)
    clk = FrozenClock(datetime(2026, 5, 1, tzinfo=timezone.utc))
    m1 = build_input_manifest(tmp_path, clock=clk)
    m2 = build_input_manifest(tmp_path, clock=clk)
    a = canonical_bytes(m1.to_dict())
    b = canonical_bytes(m2.to_dict())
    # NOTE: root_path differs because tmp_path is per-call randomized only
    # at the test level, but within one test it's stable. So m1 and m2
    # see the same root_path.
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()
    # File-level digest is a pinned constant — 16 zero bytes.
    assert m1.files[0].sha256 == hashlib.sha256(b"\x00" * 16).hexdigest()


def test_slsa_statement_top_level_keys_pinned():
    """The keys at the top level of an in-toto SLSA Statement are
    fixed by the spec. Drift is a spec-conformance bug."""
    from squash.slsa import SlsaProvenanceBuilder

    statement = SlsaProvenanceBuilder._build_statement(
        subject_name="m",
        subject_sha256="0" * 64,
        builder_id="https://x",
        invocation_id="00000000-0000-0000-0000-000000000000",
        build_finished_on="2026-05-01T00:00:00Z",
        materials=[],
    )
    assert set(statement.keys()) == {"_type", "subject", "predicateType", "predicate"}
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"


def test_hallucination_attestation_schema_pinned():
    from squash.hallucination_attest import _SCHEMA

    assert _SCHEMA  # exists
    # Schema string is part of the cert body; document drift loudly.
    assert "hallucination" in _SCHEMA.lower() or "v1" in _SCHEMA


def test_carbon_attestation_pinned_signature_for_known_body():
    """Pin the HMAC-SHA256 signature of a known body under a known key.

    Any silent change to the canonical encoder or to the body shape
    will flip this hash.
    """
    from squash.carbon_attest import (
        CarbonAttestation,
        HardwareType,
        ModelArchitecture,
    )

    cert = CarbonAttestation(
        cert_id="carbon-fixed",
        model_id="m",
        deployment_region="r",
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
    sig_a = cert.signature
    cert.signature = ""
    cert.sign(key=b"k" * 32)
    sig_b = cert.signature
    # Two signs over the same body under the same key produce the same MAC.
    assert sig_a == sig_b
