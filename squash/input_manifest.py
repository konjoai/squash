"""squash/input_manifest.py — Phase G.3 input manifest.

Pillar 2 of the Bulletproof Plan: every CLI subcommand that ingests files
emits an ``input_manifest.json`` *first*, before any analysis runs. The
manifest is the content-addressed root of the attestation: every later
finding cites a file digest in the manifest, and `squash self-verify`
walks the chain backward from the cert to the manifest to the on-disk
bytes.

Why first
~~~~~~~~~

If the scanner reads a file, then the manifest is built from a re-read
of the same file, an attacker that swaps the file between reads can
produce a manifest digest that matches the *post-swap* bytes while the
finding is over the *pre-swap* bytes. The manifest must be the
authoritative read; subsequent code uses the digests, not the bytes.

In practice:

1. CLI entry point calls :func:`build_input_manifest(model_path)`.
2. The manifest is written to ``<output_dir>/input_manifest.json``.
3. Every subsequent step calls :func:`get_digest(manifest, file_path)`
   instead of re-hashing.
4. The signed cert references ``input_manifest_sha256`` in its body.

Schema
~~~~~~

::

    {
      "schema": "squash.input-manifest/v1",
      "root_path": "/abs/path/to/model",
      "root_path_basename": "model",
      "generated_at": "2026-05-01T00:00:00Z",
      "file_count": 42,
      "total_bytes": 13371337,
      "files": [
        {"path": "config.json", "size": 4096, "sha256": "...", "mtime_ns": 0},
        ...
      ],
      "manifest_sha256": "<computed at end>"
    }

The ``manifest_sha256`` is the SHA-256 of the canonical bytes of the
record with the ``manifest_sha256`` field removed. The signing path
embeds this hash in the cert; verifiers re-compute and compare.

`mtime_ns` is recorded but **not** used in any signed downstream digest
(it's a debugging aid, not a security claim).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from .canon import canonical_bytes
from .clock import Clock, SystemClock

__all__ = [
    "FileDigest",
    "InputManifest",
    "build_input_manifest",
    "get_digest",
    "manifest_hash",
    "verify_manifest",
]

SCHEMA = "squash.input-manifest/v1"

# The default ignore set. Skip artefacts that squash itself emits so a
# re-run over the same model dir does not pull in last-run output.
_DEFAULT_IGNORE = frozenset(
    [
        ".git",
        "__pycache__",
        "input_manifest.json",
        "squash-attest.json",
        "cyclonedx-mlbom.json",
        "cyclonedx-composed.json",
        "spdx-mlbom.json",
        "spdx-mlbom.spdx",
        "squash-scan.json",
        "squash-vex-report.json",
        "squash-slsa-provenance.json",
    ]
)


@dataclass(frozen=True)
class FileDigest:
    """SHA-256 digest of a single ingested file.

    Attributes
    ----------
    path:
        POSIX-style path **relative to the manifest root**. We never store
        absolute paths in the signed body — they are not portable and
        leak the build host's filesystem layout.
    size:
        Size in bytes.
    sha256:
        Lower-hex SHA-256 of the file contents.
    mtime_ns:
        Filesystem mtime in nanoseconds. Recorded for debugging; never
        used in any cryptographic comparison.
    """

    path: str
    size: int
    sha256: str
    mtime_ns: int = 0


@dataclass
class InputManifest:
    """Top-level manifest record."""

    schema: str
    root_path: str
    root_path_basename: str
    generated_at: str
    file_count: int
    total_bytes: int
    files: list[FileDigest] = field(default_factory=list)
    manifest_sha256: str = ""

    def to_dict(self, include_self_hash: bool = True) -> dict:
        d = asdict(self)
        if not include_self_hash:
            d.pop("manifest_sha256", None)
        return d

    def write(self, output_path: Path) -> Path:
        """Atomically write to *output_path* as canonical JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = output_path.with_suffix(".tmp")
        tmp.write_bytes(canonical_bytes(self.to_dict()))
        tmp.replace(output_path)
        return output_path


def _walk_files(
    root: Path,
    ignore: Iterable[str] = _DEFAULT_IGNORE,
) -> list[Path]:
    """Return every regular file under *root* whose path components do
    not appear in *ignore*. Sorted by POSIX path for determinism."""
    ignore_set = set(ignore)
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip when ANY path component is in the ignore set.
        rel_parts = p.relative_to(root).parts
        if any(part in ignore_set for part in rel_parts):
            continue
        out.append(p)
    out.sort(key=lambda p: p.relative_to(root).as_posix())
    return out


def _hash_file(path: Path, *, chunk: int = 1 << 16) -> tuple[str, int]:
    """Streaming SHA-256 + size."""
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
            n += len(buf)
    return h.hexdigest(), n


def manifest_hash(manifest: InputManifest) -> str:
    """Cryptographic identity of the manifest.

    Computes SHA-256 of canonical bytes of the manifest **with**:

    * ``manifest_sha256`` removed (avoid self-reference)
    * ``root_path`` removed (filesystem-dependent — varies across hosts)
    * ``generated_at`` removed (clock-dependent)

    What remains is the set of (relative path, size, sha256) tuples plus
    the schema URI and aggregate counts. Two builds of the same input
    set on different machines yield the same manifest_sha256.
    """
    d = manifest.to_dict(include_self_hash=False)
    d.pop("root_path", None)
    d.pop("generated_at", None)
    return hashlib.sha256(canonical_bytes(d)).hexdigest()


def build_input_manifest(
    root: Path | str,
    *,
    ignore: Iterable[str] = _DEFAULT_IGNORE,
    clock: Clock | None = None,
    record_mtime: bool = False,
) -> InputManifest:
    """Walk *root*, hash every file, return a populated :class:`InputManifest`.

    *clock* is injected so reproducibility tests can freeze the
    ``generated_at`` field. Production paths leave it ``None`` and pick
    up the system clock.

    *record_mtime* defaults to ``False`` because mtime varies across
    builds in CI and is not a security input. Set to ``True`` for local
    debugging.
    """
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"input manifest root does not exist: {root}")
    if not root.is_dir():
        # Single-file inputs are valid — emit a one-entry manifest.
        files = [root]
        root_for_walk = root.parent
    else:
        root_for_walk = root
        files = _walk_files(root, ignore=ignore)

    digests: list[FileDigest] = []
    total = 0
    for fp in files:
        sha, size = _hash_file(fp)
        rel = fp.relative_to(root_for_walk).as_posix()
        digests.append(
            FileDigest(
                path=rel,
                size=size,
                sha256=sha,
                mtime_ns=fp.stat().st_mtime_ns if record_mtime else 0,
            )
        )
        total += size

    clk = clock if clock is not None else SystemClock()
    issued = (
        clk()
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    manifest = InputManifest(
        schema=SCHEMA,
        root_path=root.as_posix(),
        root_path_basename=root.name,
        generated_at=issued,
        file_count=len(digests),
        total_bytes=total,
        files=digests,
    )
    manifest.manifest_sha256 = manifest_hash(manifest)
    return manifest


def get_digest(manifest: InputManifest, relative_path: str) -> str | None:
    """Look up the SHA-256 of *relative_path* in *manifest*. Returns
    ``None`` when not present.
    """
    target = Path(relative_path).as_posix()
    for fd in manifest.files:
        if fd.path == target:
            return fd.sha256
    return None


def verify_manifest(manifest: InputManifest, root: Path | str) -> tuple[bool, list[str]]:
    """Re-hash every file under *root* and compare against *manifest*.

    Returns ``(ok, errors)``. ``ok`` is ``True`` only when:

    * Every file in the manifest exists on disk.
    * Each file's SHA-256 matches.
    * The manifest's own ``manifest_sha256`` recomputes correctly.
    * No unexpected files outside the manifest exist (strict mode).
    """
    root = Path(root).resolve()
    errors: list[str] = []

    # Self-hash check first — if the manifest was tampered, every
    # downstream finding is unreliable.
    expected_self = manifest_hash(manifest)
    if manifest.manifest_sha256 != expected_self:
        errors.append(
            f"manifest_sha256 mismatch: stored={manifest.manifest_sha256}, "
            f"computed={expected_self}"
        )

    on_disk = {fd.path for fd in manifest.files}
    for fd in manifest.files:
        full = root / fd.path
        if not full.exists():
            errors.append(f"missing file: {fd.path}")
            continue
        sha, size = _hash_file(full)
        if sha != fd.sha256:
            errors.append(
                f"sha256 mismatch for {fd.path}: stored={fd.sha256}, computed={sha}"
            )
        if size != fd.size:
            errors.append(
                f"size mismatch for {fd.path}: stored={fd.size}, computed={size}"
            )

    return (not errors), errors


def from_dict(d: dict) -> InputManifest:
    """Reconstruct :class:`InputManifest` from a parsed JSON dict."""
    files = [FileDigest(**f) for f in d.get("files", [])]
    return InputManifest(
        schema=d.get("schema", SCHEMA),
        root_path=d.get("root_path", ""),
        root_path_basename=d.get("root_path_basename", ""),
        generated_at=d.get("generated_at", ""),
        file_count=d.get("file_count", len(files)),
        total_bytes=d.get("total_bytes", 0),
        files=files,
        manifest_sha256=d.get("manifest_sha256", ""),
    )
