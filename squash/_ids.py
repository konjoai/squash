# SQUASH-CANONICAL
"""Content-addressed IDs for reproducible attestation artifacts.

This module is the **public interface** for all signing and attestation paths
that need deterministic, content-addressed certificate IDs. It wraps
:mod:`squash.ids` which carries the full UUIDv5-based implementation.

Usage::

    from squash._ids import cert_id, is_valid_cert_id, SQUASH_NS

    payload = b'{"model":"llama-3","sha256":"abc123"}'
    cid = cert_id("slsa", canonical_payload=payload)  # e.g. "slsa-1d2e3f4a5b6c7d8e"
    assert is_valid_cert_id(cid)

Rules enforced
--------------
* IDs are keyed on :func:`squash.canon.canonical_bytes` output — invariant
  under cosmetic JSON differences (whitespace, key order).
* Prefix must be a non-empty string containing no hyphens.
* The trailing hex suffix is always exactly 16 lowercase hex characters
  (64-bit truncation of the UUIDv5 hex form).
* Two calls with the same prefix and payload always return the same ID,
  on every host, in every Python version.

See :mod:`squash.ids` for the full specification.
"""

from __future__ import annotations

import re
import uuid

from squash.ids import SQUASH_NS as SQUASH_NS  # noqa: F401 — re-export
from squash.ids import deterministic_uuid as deterministic_uuid  # noqa: F401 — re-export

__all__ = [
    "SQUASH_NS",
    "cert_id",
    "is_valid_cert_id",
    "deterministic_uuid",
]

# Pattern: "<prefix>-<16 lowercase hex chars>"
_CERT_ID_RE = re.compile(r"^[a-z][a-z0-9]*-[0-9a-f]{16}$")


def cert_id(prefix: str, *, canonical_payload: bytes) -> str:
    """Return a deterministic display ID: ``{prefix}-{16-hex-chars}``.

    The ID is keyed on *canonical_payload* (raw bytes already produced by
    :func:`squash._canonical.canonical_bytes`) so two calls with the same
    prefix and payload always return the same string.

    Parameters
    ----------
    prefix:
        Short lowercase identifier for the cert type, e.g. ``"slsa"``,
        ``"anc"``, ``"hac"``.  Must not contain hyphens.
    canonical_payload:
        The RFC 8785 canonical JSON bytes of the signed body.  Callers
        should produce these via :func:`squash._canonical.canonical_bytes`.

    Returns
    -------
    str
        ``f"{prefix}-{uuid5(SQUASH_NS, payload.hex()).hex[:16]}"``

    Raises
    ------
    ValueError
        If *prefix* is empty or contains a hyphen.
    """
    # Delegate to ids.cert_id using the hex string of the raw bytes
    # as the payload so callers can pass pre-computed canonical bytes
    # directly without a double-encode round-trip.
    if not isinstance(prefix, str) or not prefix:
        raise ValueError("cert_id requires a non-empty string prefix")
    if "-" in prefix:
        raise ValueError(
            "cert_id prefix must not contain '-' (the separator). "
            "Use a contiguous lowercase identifier like 'slsa', 'hac', 'anc'."
        )
    uid = uuid.uuid5(SQUASH_NS, canonical_payload.hex())
    return f"{prefix}-{uid.hex[:16]}"


def is_valid_cert_id(s: str) -> bool:
    """Return ``True`` if *s* matches the ``{prefix}-{16-hex}`` format.

    Parameters
    ----------
    s:
        String to test.

    Returns
    -------
    bool
        ``True`` iff *s* is a valid cert ID produced by :func:`cert_id`.
    """
    return bool(_CERT_ID_RE.match(s))
