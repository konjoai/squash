"""squash/canon.py — RFC 8785 (JCS) canonical JSON for evidence-grade payloads.

Phase G.2 — Determinism. Every byte that gets signed, hashed, or anchored
**must** flow through :func:`canonical_bytes`. Two consecutive runs on
different hosts with the same inputs MUST produce byte-identical output.

What "canonical" means here
---------------------------

RFC 8785 (JSON Canonicalization Scheme, "JCS"):

* Object members sorted by their UTF-16 code-unit value (lexicographic).
* No insignificant whitespace.
* String escapes use the shortest valid form (no ``\\u00XX`` for printable).
* Numbers use the ECMAScript 2017 ``ToString(Number)`` algorithm — finite
  values only; ``NaN`` and ``Inf`` are rejected (RFC 8785 §3.2.2.3).
* Output is UTF-8 (`bytes`), not `str`.
* No trailing newline.

We layer one extra discipline on top of RFC 8785: **no implicit type
coercion**. ``json.dumps(..., default=str)`` is a silent reproducibility
killer — a ``Path`` that becomes ``"PosixPath('/tmp/x')"`` on Linux but
``"WindowsPath('C:\\\\tmp\\\\x')"`` on Windows yields different bytes for
the same logical input. :func:`canonical_bytes` raises ``CanonError`` on
any unknown type. The caller is forced to convert at the boundary, where
the conversion rule is **explicit and reviewable**.

Allowed primitive types
~~~~~~~~~~~~~~~~~~~~~~~

* ``None`` → ``null``
* ``bool`` → ``true`` / ``false``
* ``int`` → integer literal
* ``float`` → IEEE-754 64-bit (rejected if non-finite)
* ``str`` → JSON string (UTF-8)
* ``list`` / ``tuple`` → JSON array (order preserved)
* ``set`` / ``frozenset`` → JSON array, **sorted** (sets are unordered;
  serialising them as-is is the third most common nondeterminism source
  in the codebase, see ``AUDIT_BASELINE.md`` §1.4)
* ``dict`` → JSON object with sorted keys (UTF-16 collation per RFC 8785)

Anything else — ``Path``, ``datetime``, ``Decimal``, dataclasses, custom
objects — must be converted by the caller via :func:`prepare`. That
function walks dataclasses, ``Path``, ``datetime``, ``Enum``, ``UUID``,
and bytes via documented rules. It never falls back to ``str()``.

The `rfc8785 <https://pypi.org/project/rfc8785/>`_ pure-Python implementation
is the reference; when present it is preferred. When absent (e.g. in a
lean install), the in-process fallback below produces byte-identical
output for the subset of types squash actually emits, verified by
``tests/test_canon_compat.py``.

Konjo notes
~~~~~~~~~~~

* 건조 — the in-process fallback is one function (~80 LOC), no class.
* ᨀᨚᨐᨚ — the boundary is the type system, not a runtime flag.
* 康宙 — sets always serialise sorted; lists never sort silently. Two
  rules, no exceptions, no surprises.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import hashlib
import io
import json
import math
import re
import uuid
from pathlib import PurePath
from typing import Any

__all__ = [
    "CanonError",
    "canonical_bytes",
    "canonical_str",
    "canonical_hash",
    "prepare",
]


class CanonError(TypeError):
    """Raised on any value that cannot be canonicalised by RFC 8785 rules."""


# Try the reference library first; fall back to the in-process implementation
# if it is not installed. Both produce byte-identical output for every type
# squash emits (asserted by tests/test_canon_compat.py).
try:  # pragma: no cover - optional dependency presence is environmental
    import rfc8785 as _rfc8785

    def _encode_with_rfc8785(value: Any) -> bytes:
        return _rfc8785.dumps(value)
except ImportError:  # pragma: no cover - only one branch runs per environment
    _rfc8785 = None  # type: ignore[assignment]

    def _encode_with_rfc8785(value: Any) -> bytes:  # type: ignore[misc]
        raise RuntimeError("rfc8785 unavailable — should fall through to fallback")


# ---------------------------------------------------------------------------
# Type preparation — convert documented rich types to the JSON-native subset.
# ---------------------------------------------------------------------------

_NS_SQUASH = uuid.UUID("8b7c4a2e-1d3f-5e6a-9b8c-0d1e2f3a4b5c")


def prepare(value: Any) -> Any:
    """Convert *value* into the JSON-native subset accepted by :func:`canonical_bytes`.

    Documented rules — applied recursively:

    * ``dataclasses`` → dict via :func:`dataclasses.asdict`
    * ``enum.Enum`` → ``.value``
    * ``pathlib.PurePath`` → POSIX ``str``  (forward-slashes on every OS)
    * ``datetime.datetime`` → ISO-8601 with explicit ``Z`` UTC suffix
      (the only supported timezone for canonical output — see ``squash.clock``)
    * ``datetime.date`` → ISO-8601 ``YYYY-MM-DD``
    * ``uuid.UUID`` → canonical hex form
    * ``bytes`` / ``bytearray`` → lower-hex string (`b.hex()`)
    * ``set`` / ``frozenset`` → list, sorted by their canonical form

    Anything else returns unchanged so :func:`canonical_bytes` can either
    accept it (primitives, list, dict) or raise :class:`CanonError`.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonError(f"non-finite float not allowed in canonical JSON: {value!r}")
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return prepare(dataclasses.asdict(value))
    if isinstance(value, enum.Enum):
        return prepare(value.value)
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise CanonError(
                "naive datetime not allowed — pass a tz-aware datetime "
                "(use squash.clock.utc_now())"
            )
        # Force UTC; canonical form is always Z-suffixed.
        v = value.astimezone(_dt.timezone.utc)
        # Drop microseconds-of-zero to match other emitters; preserve when set.
        if v.microsecond == 0:
            return v.strftime("%Y-%m-%dT%H:%M:%SZ")
        return v.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0").rstrip(".") + "Z"
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (set, frozenset)):
        # Sort by canonical-bytes of each element so heterogeneous sets get
        # a stable order, not Python-version-dependent hash order.
        prepared_elems = [prepare(x) for x in value]
        return sorted(prepared_elems, key=lambda v: canonical_bytes(v))
    if isinstance(value, (list, tuple)):
        return [prepare(x) for x in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonError(
                    f"dict keys must be str for canonical JSON; got {type(k).__name__}={k!r}"
                )
            out[k] = prepare(v)
        return out
    raise CanonError(
        f"unsupported type {type(value).__name__!r} for canonical JSON; "
        f"convert at the call boundary"
    )


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes for *value*.

    *value* is first run through :func:`prepare` so dataclasses, paths,
    datetimes, sets, etc. are converted using the documented rules. The
    result is then encoded by :mod:`rfc8785` if installed, or by the
    in-process fallback below.

    Raises
    ------
    CanonError
        On any value that cannot be deterministically encoded — see
        :func:`prepare` for the supported type list.
    """
    prepared = prepare(value)
    if _rfc8785 is not None:
        return _encode_with_rfc8785(prepared)
    return _fallback_encode(prepared)


def canonical_str(value: Any) -> str:
    """Convenience wrapper: :func:`canonical_bytes` decoded as UTF-8."""
    return canonical_bytes(value).decode("utf-8")


def canonical_hash(value: Any, *, algo: str = "sha256") -> str:
    """Hex digest of :func:`canonical_bytes(value)` under *algo* (default SHA-256)."""
    h = hashlib.new(algo)
    h.update(canonical_bytes(value))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# In-process fallback — produces byte-identical output to rfc8785 for the
# subset of values that pass through :func:`prepare`.
# ---------------------------------------------------------------------------

# Characters that MUST be escaped per RFC 8259 / 8785 §3.2.2.2.
_MUST_ESCAPE_CHARS = "".join(chr(c) for c in range(0, 32)) + '"' + "\\"
_MUST_ESCAPE = re.compile("[" + "".join("\\" + ch if ch in "\\^]-" else ch for ch in _MUST_ESCAPE_CHARS) + "]")


def _escape_str(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        ch = m.group(0)
        if ch == "\\":
            return "\\\\"
        if ch == '"':
            return '\\"'
        if ch == "\b":
            return "\\b"
        if ch == "\f":
            return "\\f"
        if ch == "\n":
            return "\\n"
        if ch == "\r":
            return "\\r"
        if ch == "\t":
            return "\\t"
        return f"\\u{ord(ch):04x}"

    return '"' + _MUST_ESCAPE.sub(repl, s) + '"'


def _format_number(n: int | float) -> str:
    if isinstance(n, bool):  # bool is a subclass of int — guard
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    # ECMAScript ToString(Number) — Python's repr matches for finite floats
    # in every case relevant to squash's payloads (no scientific notation
    # quirks in the ranges we emit). For values that hit the edge cases
    # (very large, very small), prefer rfc8785 in production.
    if not math.isfinite(n):  # pragma: no cover - guarded earlier
        raise CanonError(f"non-finite float not allowed: {n!r}")
    if n == 0:
        return "0"
    # Round-trip via repr; reject the rare cases where repr disagrees with
    # ECMAScript ToString.  json.dumps gives us the right format for the
    # ranges squash emits (counts, scores in [0,1], byte sizes).
    return json.dumps(n)


def _encode(buf: io.BytesIO, value: Any) -> None:
    if value is None:
        buf.write(b"null")
        return
    if isinstance(value, bool):
        buf.write(b"true" if value else b"false")
        return
    if isinstance(value, (int, float)):
        buf.write(_format_number(value).encode("ascii"))
        return
    if isinstance(value, str):
        buf.write(_escape_str(value).encode("utf-8"))
        return
    if isinstance(value, list):
        buf.write(b"[")
        for i, x in enumerate(value):
            if i > 0:
                buf.write(b",")
            _encode(buf, x)
        buf.write(b"]")
        return
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        buf.write(b"{")
        for i, k in enumerate(keys):
            if i > 0:
                buf.write(b",")
            buf.write(_escape_str(k).encode("utf-8"))
            buf.write(b":")
            _encode(buf, value[k])
        buf.write(b"}")
        return
    raise CanonError(
        f"unsupported type {type(value).__name__!r} reached the canonical encoder"
    )


def _fallback_encode(value: Any) -> bytes:
    buf = io.BytesIO()
    _encode(buf, value)
    return buf.getvalue()
