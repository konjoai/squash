"""Phase G.4 — atheris fuzz harness for the canonical encoder.

Run via:  python tests/fuzz/fuzz_canon.py -atheris_runs=100000

The harness drives random JSON-shaped inputs through canonical_bytes,
re-parses the result, and re-encodes — any bytes-mismatch crashes the
fuzzer. A genuine CanonError on unsupported types is the documented
contract and is caught silently.
"""

from __future__ import annotations

import json
import sys

try:
    import atheris  # type: ignore[import]
except ImportError:  # pragma: no cover
    print("atheris is required: pip install atheris", file=sys.stderr)
    sys.exit(0)

with atheris.instrument_imports():
    from squash.canon import CanonError, canonical_bytes


def TestOneInput(data: bytes) -> None:
    """Drive canonical_bytes with random structured input."""
    if len(data) < 4:
        return
    fdp = atheris.FuzzedDataProvider(data)
    # Build a small dict from random tokens; alternative: parse fuzz JSON.
    obj: dict = {}
    for _ in range(fdp.ConsumeIntInRange(0, 6)):
        kind = fdp.ConsumeIntInRange(0, 4)
        key = fdp.ConsumeUnicodeNoSurrogates(8) or "k"
        if kind == 0:
            obj[key] = fdp.ConsumeIntInRange(-(2**31), (2**31) - 1)
        elif kind == 1:
            obj[key] = fdp.ConsumeFloatInRange(-1e6, 1e6)
        elif kind == 2:
            obj[key] = fdp.ConsumeUnicodeNoSurrogates(16)
        elif kind == 3:
            obj[key] = bool(fdp.ConsumeIntInRange(0, 1))
        else:
            obj[key] = None
    try:
        a = canonical_bytes(obj)
    except CanonError:
        return  # documented rejection
    parsed = json.loads(a.decode("utf-8"))
    b = canonical_bytes(parsed)
    assert a == b, f"round-trip drift: {a!r} != {b!r}"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
