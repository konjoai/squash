# SQUASH-CANONICAL
"""Canonical JSON serialization — RFC 8785 / JCS for squash signing paths.

This module is the **public interface** for all signing and attestation paths
that need byte-identical output across runs. It wraps :mod:`squash.canon`
which carries the full RFC 8785 implementation.

Usage::

    from squash._canonical import canonical_bytes, canonical_hex

    payload = {"model": "llama-3", "sha256": "abc123"}
    raw = canonical_bytes(payload)    # RFC 8785 bytes
    digest = canonical_hex(payload)   # SHA-256 hex of those bytes

Rules enforced
--------------
* ``rfc8785`` is used when available (installed via ``pip install rfc8785``);
  the in-process fallback in :mod:`squash.canon` otherwise.
* Dict keys are sorted by UTF-16 code-unit value (RFC 8785 §3.2.3).
* No insignificant whitespace.
* Strings are NFC-normalised before encoding.
* Non-finite floats (``NaN``, ``Inf``) raise :class:`squash.canon.CanonError`.
* Unknown types raise :class:`squash.canon.CanonError` — **no** ``default=str``
  silencing. The caller converts at the boundary.

See :mod:`squash.canon` for the full specification and the ``prepare()``
type-conversion helper.
"""

from __future__ import annotations

import hashlib
from typing import Any

from squash.canon import CanonError as CanonError  # noqa: F401 — re-export for callers
from squash.canon import canonical_bytes as _canonical_bytes

__all__ = [
    "canonical_bytes",
    "canonical_hex",
    "CanonError",
]


def canonical_bytes(obj: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes for *obj*.

    Delegates to :func:`squash.canon.canonical_bytes`. Raises
    :class:`squash.canon.CanonError` on unserializable types — never falls
    back to ``str()``.

    Parameters
    ----------
    obj:
        Any JSON-representable value. Rich types (dataclasses, ``Path``,
        ``datetime``, ``UUID``, ``set``, ``Enum``) are prepared via
        :func:`squash.canon.prepare` using documented, deterministic rules.

    Returns
    -------
    bytes
        UTF-8 RFC 8785 canonical JSON, no trailing newline.
    """
    return _canonical_bytes(obj)


def canonical_hex(obj: Any) -> str:
    """Return the SHA-256 hex digest of :func:`canonical_bytes(obj)`.

    Convenience helper for signing paths that only need the content hash,
    not the raw bytes.

    Parameters
    ----------
    obj:
        Any value accepted by :func:`canonical_bytes`.

    Returns
    -------
    str
        64-character lowercase hex string.
    """
    return hashlib.sha256(_canonical_bytes(obj)).hexdigest()
