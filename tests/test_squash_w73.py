"""W73: Version bump — release seal tests for squash-ai 1.3.0."""
import re
from pathlib import Path

import pytest

_PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def _read_version() -> str:
    text = _PYPROJECT.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version field not found in pyproject.toml"
    return m.group(1)


class TestSquashVersion:
    def test_version_is_3_0_0(self):
        # v3.6.0 — Sprint 29: Demo polish (interactive /demo page with
        # one-click /quick-check, /share/{hash} HTML view, demo/result.html,
        # bundled sample-policy serving, <1500ms perf gate). Bumped from 3.5.0.
        version = _read_version()
        assert version == "3.6.0", f"Expected version 3.6.0, got {version}"

    def test_version_follows_semver(self):
        version = _read_version()
        parts = version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_no_prerelease_suffix(self):
        version = _read_version()
        for suffix in ("dev", "rc", "alpha", "beta", "a0", "b0"):
            assert suffix not in version, f"Unexpected prerelease suffix in {version}"

    def test_version_major_is_3(self):
        # v3 = Bulletproof Edition. Major bump driven by the cryptographic
        # chain primitives (canon, clock, ids, input_manifest, tsa,
        # self_verify) and the determinism-by-default contract.
        version = _read_version()
        assert version.split(".")[0] == "3"

    def test_init_version_matches_pyproject(self):
        # Phase G closure: kill the version drift between
        # squash/__init__.py and pyproject.toml.
        import importlib

        squash = importlib.import_module("squash")
        assert squash.__version__ == _read_version(), (
            f"Version drift: __init__.py={squash.__version__} pyproject={_read_version()}"
        )
