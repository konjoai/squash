"""Phase G.4 — atheris fuzz harness for input_manifest.

Drives synthetic file trees through build_input_manifest +
verify_manifest. Asserts the build/verify round-trip never raises an
unexpected exception and that the manifest_sha256 always re-verifies.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

try:
    import atheris  # type: ignore[import]
except ImportError:  # pragma: no cover
    print("atheris is required: pip install atheris", file=sys.stderr)
    sys.exit(0)

with atheris.instrument_imports():
    from squash.input_manifest import (
        build_input_manifest,
        manifest_hash,
        verify_manifest,
    )


def TestOneInput(data: bytes) -> None:
    if len(data) < 4:
        return
    fdp = atheris.FuzzedDataProvider(data)
    # Generate up to 4 files with controlled name length + body length.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        n_files = fdp.ConsumeIntInRange(0, 4)
        for i in range(n_files):
            name = (fdp.ConsumeUnicodeNoSurrogates(8) or f"f{i}").replace("/", "_")
            body = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 256))
            try:
                (root / f"{name}.bin").write_bytes(body)
            except (OSError, ValueError):
                return
        try:
            m = build_input_manifest(root)
        except Exception as exc:
            # Anything outside the documented exceptions is a bug.
            assert isinstance(exc, (FileNotFoundError, OSError)), exc
            return
        # Self-hash always recomputes.
        assert m.manifest_sha256 == manifest_hash(m)
        ok, errors = verify_manifest(m, root)
        assert ok, errors


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
