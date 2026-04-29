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
    def test_version_is_1_3_0(self):
        version = _read_version()
        assert version == "1.3.0", f"Expected version 1.3.0, got {version}"

    def test_version_follows_semver(self):
        version = _read_version()
        parts = version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_no_prerelease_suffix(self):
        version = _read_version()
        for suffix in ("dev", "rc", "alpha", "beta", "a0", "b0"):
            assert suffix not in version, f"Unexpected prerelease suffix in {version}"

    def test_version_major_is_1(self):
        version = _read_version()
        assert version.split(".")[0] == "1"
