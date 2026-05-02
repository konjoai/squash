"""squash/ids.py — Deterministic certificate IDs (UUIDv5 keyed on canonical bytes).

Phase G.2 — Determinism. Every cert ID, anchor ID, freeze ID, incident
ID, etc. that is **embedded in a signed body** must be a function of the
input — never a fresh ``uuid.uuid4()``. This module is the load-bearing
primitive; every Tier 0/1 emitter routes its IDs through here.

Rule
----

    cert_id(prefix, payload)  =  f"{prefix}-{uuid5(SQUASH_NS, canonical(payload)).hex[:16]}"

* ``SQUASH_NS`` is a fixed, project-scoped UUID — the namespace per
  RFC 4122 §4.3. It pins the ID space to squash forever.
* ``canonical(payload)`` is :func:`squash.canon.canonical_bytes`, so the
  ID is invariant under cosmetic JSON differences (whitespace, key
  order). This is the same canonicalisation used by signing, so the ID
  is the **content identity** of the cert.
* ``hex[:16]`` truncates to 64 bits — collision-resistant for any
  realistic squash deployment (>4 billion certs before a 50% birthday
  collision). Use the full ``uuid5`` form for comparison; the truncated
  form is only for human display / filenames.

Operational IDs (request IDs, payload IDs, job IDs in ``api.py``) keep
``uuid4`` — they are not in any signed body, and freshness there is the
right behaviour. The audit gate is "no uuid4 in a Tier 0/1 signed
field"; this module enforces the discipline by providing a clean
uuid5-based API for those fields.

Konjo notes
~~~~~~~~~~~

* 건조 — one helper, one rule. The namespace is hardcoded; do not let
  callers override it. Stability of IDs across squash versions is the
  feature.
"""

from __future__ import annotations

import uuid
from typing import Any

from .canon import canonical_bytes

__all__ = [
    "SQUASH_NS",
    "deterministic_uuid",
    "cert_id",
    "short_id",
]


# Project namespace — UUIDv5 per RFC 4122 §4.3. The string below is the
# DNS-style URI ``urn:konjo:squash:v1`` hashed under the standard URL
# namespace, captured as a constant so the ID space is permanent.
SQUASH_NS: uuid.UUID = uuid.UUID("8b7c4a2e-1d3f-5e6a-9b8c-0d1e2f3a4b5c")


def deterministic_uuid(payload: Any) -> uuid.UUID:
    """Return ``uuid5(SQUASH_NS, canonical_bytes(payload))``.

    The full UUID — use this for cross-version equality checks and for
    the canonical ``urn:uuid:…`` form. For human-display IDs, prefer
    :func:`cert_id`.
    """
    return uuid.uuid5(SQUASH_NS, canonical_bytes(payload).decode("utf-8"))


def cert_id(prefix: str, payload: Any) -> str:
    """Stable display ID: ``{prefix}-{16-hex-chars}``.

    *payload* is the canonicalised input that determines the cert. For
    a hallucination cert that is the prompt + model + response triple;
    for a freeze it is the model digest + scope. The same payload always
    yields the same ID, on every host, in every Python version.

    >>> cert_id("hac", {"model": "gpt-4", "prompt_sha": "abc"})  # doctest: +SKIP
    'hac-1d2e3f4a5b6c7d8e'
    """
    if not isinstance(prefix, str) or not prefix:
        raise ValueError("cert_id requires a non-empty string prefix")
    if "-" in prefix:
        raise ValueError(
            "cert_id prefix must not contain '-' (the separator). "
            "Use a contiguous lowercase identifier like 'hac', 'carbon', 'anc'."
        )
    return f"{prefix}-{deterministic_uuid(payload).hex[:16]}"


def short_id(payload: Any, *, length: int = 12) -> str:
    """Bare hex prefix of ``deterministic_uuid(payload)`` — no prefix string.

    Useful for filenames and short references where a prefix-tagged ID
    is overkill. *length* must be ≤ 32 (the full hex form).
    """
    if not 1 <= length <= 32:
        raise ValueError("short_id length must be in [1, 32]")
    return deterministic_uuid(payload).hex[:length]
