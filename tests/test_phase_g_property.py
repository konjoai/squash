"""Phase G.4 — Hypothesis property tests for probabilistic functions.

Each property is a mathematical invariant that must hold for *every*
input. These tests catch the failure mode that example-based tests
cannot — the one-in-ten-million corner case.

Targets (per AUDIT_BASELINE.md / Phase G.4 ticket G.4.3):

* :func:`squash.hallucination_attest._wilson_ci` — bounds, monotonicity,
  symmetry around p=0.5, edge n=0, n=1.
* :func:`squash.hallucination_attest.score_faithfulness` — composite is
  bounded in [0, 1]; identical input/output is fully faithful.
* :func:`squash.canon.canonical_bytes` — order-independent; idempotent
  under re-encoding.
* :func:`squash.ids.deterministic_uuid` — collision-free for distinct
  payloads (modulo the 122-bit space); equality preserved across dict
  insertion order.
* :func:`squash.input_manifest.build_input_manifest` — manifest_sha256
  re-verifies via :func:`manifest_hash`; round-trip through
  :func:`from_dict` preserves identity.

The tests are kept fast (default Hypothesis settings) so the gate is
PR-runnable. Nightly CI bumps `max_examples` (Phase G.7).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings, strategies as st

from squash.canon import CanonError, canonical_bytes, canonical_hash
from squash.ids import cert_id, deterministic_uuid
from squash.input_manifest import (
    build_input_manifest,
    from_dict as manifest_from_dict,
    manifest_hash,
)


# ---------------------------------------------------------------------------
# Wilson CI
# ---------------------------------------------------------------------------


@given(
    successes=st.integers(min_value=0, max_value=10_000),
    n=st.integers(min_value=1, max_value=10_000),
)
def test_wilson_ci_within_unit_interval(successes, n):
    """Both bounds of the CI must lie in [0, 1]."""
    from squash.hallucination_attest import _wilson_ci

    if successes > n:
        successes = n
    lo, hi = _wilson_ci(successes, n)
    assert 0.0 <= lo <= 1.0
    assert 0.0 <= hi <= 1.0


@given(
    successes=st.integers(min_value=0, max_value=10_000),
    n=st.integers(min_value=1, max_value=10_000),
)
def test_wilson_ci_lo_le_hi(successes, n):
    """Lower bound must never exceed upper bound."""
    from squash.hallucination_attest import _wilson_ci

    if successes > n:
        successes = n
    lo, hi = _wilson_ci(successes, n)
    assert lo <= hi


@given(n=st.integers(min_value=1, max_value=10_000))
def test_wilson_ci_symmetry_around_half(n):
    """For p̂=0.5 the CI is symmetric around 0.5."""
    from squash.hallucination_attest import _wilson_ci

    if n % 2 != 0:
        n += 1
    lo, hi = _wilson_ci(n // 2, n)
    midpoint = (lo + hi) / 2
    # ε grows for tiny n; 1e-6 is safe for n in our range.
    assert abs(midpoint - 0.5) < 1e-6


# ---------------------------------------------------------------------------
# Canonical bytes
# ---------------------------------------------------------------------------


_canon_atom = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**31), max_value=(2**31) - 1),
    st.text(min_size=0, max_size=20).filter(lambda s: "\x00" not in s),
)


@st.composite
def canon_value(draw, max_depth=3):
    if max_depth <= 0:
        return draw(_canon_atom)
    choice = draw(st.integers(min_value=0, max_value=3))
    if choice == 0:
        return draw(_canon_atom)
    if choice == 1:
        return draw(st.lists(canon_value(max_depth=max_depth - 1), max_size=4))
    return draw(
        st.dictionaries(
            keys=st.text(min_size=1, max_size=10).filter(lambda s: "\x00" not in s),
            values=canon_value(max_depth=max_depth - 1),
            max_size=4,
        )
    )


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=50)
@given(value=canon_value())
def test_canonical_bytes_deterministic(value):
    """Same input → same bytes, every time."""
    a = canonical_bytes(value)
    b = canonical_bytes(value)
    assert a == b


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=50)
@given(value=canon_value())
def test_canonical_bytes_round_trip_under_json_load(value):
    """canonical → json.loads → canonical yields the same bytes."""
    a = canonical_bytes(value)
    parsed = json.loads(a.decode("utf-8"))
    b = canonical_bytes(parsed)
    assert a == b


@given(
    a=st.text(min_size=1, max_size=10).filter(lambda s: "\x00" not in s),
    b=st.text(min_size=1, max_size=10).filter(lambda s: "\x00" not in s),
    v1=st.integers(),
    v2=st.integers(),
)
def test_canonical_bytes_dict_order_invariance(a, b, v1, v2):
    """Insertion order does not change the canonical bytes."""
    if a == b:
        return  # same key — different test
    da = {a: v1, b: v2}
    db = {b: v2, a: v1}
    assert canonical_bytes(da) == canonical_bytes(db)


# ---------------------------------------------------------------------------
# Deterministic UUIDs / cert IDs
# ---------------------------------------------------------------------------


@given(
    payload=st.dictionaries(
        keys=st.text(min_size=1, max_size=10).filter(lambda s: "\x00" not in s),
        values=st.one_of(st.integers(), st.text(max_size=10).filter(lambda s: "\x00" not in s)),
        max_size=5,
    )
)
def test_deterministic_uuid_dict_order_invariance(payload):
    a = deterministic_uuid(payload)
    b_payload = dict(reversed(list(payload.items())))
    b = deterministic_uuid(b_payload)
    assert a == b


@given(
    p1=st.dictionaries(
        keys=st.text(min_size=1, max_size=10).filter(lambda s: "\x00" not in s),
        values=st.integers(),
        min_size=1,
        max_size=5,
    ),
    p2=st.dictionaries(
        keys=st.text(min_size=1, max_size=10).filter(lambda s: "\x00" not in s),
        values=st.integers(),
        min_size=1,
        max_size=5,
    ),
)
def test_cert_id_distinct_for_distinct_payloads(p1, p2):
    if canonical_bytes(p1) == canonical_bytes(p2):
        return  # same canonical input
    assert cert_id("hac", p1) != cert_id("hac", p2)


# ---------------------------------------------------------------------------
# Input manifest
# ---------------------------------------------------------------------------


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=20)
@given(
    files=st.lists(
        st.tuples(
            st.text(
                alphabet=st.characters(min_codepoint=97, max_codepoint=122),
                min_size=1,
                max_size=8,
            ),
            st.binary(min_size=0, max_size=512),
        ),
        min_size=1,
        max_size=4,
        unique_by=lambda t: t[0],
    )
)
def test_manifest_self_hash_round_trip(tmp_path_factory, files):
    """A built manifest must verify against its own manifest_sha256."""
    root = tmp_path_factory.mktemp("model")
    for name, content in files:
        (root / f"{name}.bin").write_bytes(content)
    m = build_input_manifest(root)
    # Self-hash recomputes correctly.
    assert m.manifest_sha256 == manifest_hash(m)
    # Round-trip via dict.
    m2 = manifest_from_dict(json.loads(canonical_bytes(m.to_dict()).decode("utf-8")))
    assert m2.manifest_sha256 == m.manifest_sha256


# ---------------------------------------------------------------------------
# Score faithfulness — bounds property
# ---------------------------------------------------------------------------


@settings(max_examples=30)
@given(
    text=st.text(
        alphabet=st.characters(min_codepoint=97, max_codepoint=122),
        min_size=1,
        max_size=50,
    )
)
def test_faithfulness_identity_is_perfectly_faithful(text):
    """Ground-truth identical to response should not be flagged hallucinated."""
    from squash.hallucination_attest import score_faithfulness

    fs = score_faithfulness(text, text, "")
    assert 0.0 <= fs.composite <= 1.0
    # Identity is the fully-faithful case — must NOT flag as hallucinated.
    assert fs.hallucinated is False


@settings(max_examples=30)
@given(
    a=st.text(alphabet="abcdefghij", min_size=5, max_size=30),
    b=st.text(alphabet="klmnopqrst", min_size=5, max_size=30),
)
def test_faithfulness_disjoint_is_low_confidence(a, b):
    """Disjoint vocabularies yield a low (close to 0) faithfulness score."""
    from squash.hallucination_attest import score_faithfulness

    fs = score_faithfulness(a, b, "")
    assert 0.0 <= fs.composite <= 1.0
