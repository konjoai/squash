"""Phase G.2 — uuid5-keyed cert ID contract tests."""

from __future__ import annotations

import uuid

import pytest

from squash.ids import (
    SQUASH_NS,
    cert_id,
    deterministic_uuid,
    short_id,
)


def test_namespace_is_pinned():
    # The project namespace must NEVER drift — it pins the ID space across
    # every squash version and every cert ever issued. Hardcoded check is
    # the load-bearing guarantee of cross-version stability.
    assert SQUASH_NS == uuid.UUID("8b7c4a2e-1d3f-5e6a-9b8c-0d1e2f3a4b5c")


def test_deterministic_uuid_stable_across_calls():
    a = deterministic_uuid({"k": "v", "n": 1})
    b = deterministic_uuid({"n": 1, "k": "v"})  # different insertion order
    assert a == b


def test_deterministic_uuid_is_uuid5_in_namespace():
    u = deterministic_uuid({"a": 1})
    # version 5 (SHA-1)  per RFC 4122 §4.3
    assert u.version == 5


def test_cert_id_format():
    cid = cert_id("hac", {"a": 1})
    assert cid.startswith("hac-")
    suffix = cid.split("-", 1)[1]
    assert len(suffix) == 16
    int(suffix, 16)  # valid hex


def test_cert_id_independent_of_dict_order():
    a = cert_id("hac", {"a": 1, "b": 2})
    b = cert_id("hac", {"b": 2, "a": 1})
    assert a == b


def test_cert_id_changes_with_payload():
    a = cert_id("hac", {"a": 1})
    b = cert_id("hac", {"a": 2})
    assert a != b


def test_cert_id_prefix_validation():
    with pytest.raises(ValueError):
        cert_id("", {"a": 1})
    with pytest.raises(ValueError):
        cert_id("with-dash", {"a": 1})


def test_short_id_length():
    s = short_id({"a": 1})
    assert len(s) == 12
    assert short_id({"a": 1}, length=8).__len__() == 8


def test_short_id_length_bounds():
    with pytest.raises(ValueError):
        short_id({"a": 1}, length=0)
    with pytest.raises(ValueError):
        short_id({"a": 1}, length=33)
