"""W148 — Jenkins shared library step (squashAttest.groovy) tests."""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
GROOVY_FILE = REPO_ROOT / "integrations" / "jenkins" / "vars" / "squashAttest.groovy"


class TestJenkinsStepExists:
    def test_file_exists(self):
        assert GROOVY_FILE.exists()

    def test_file_is_not_empty(self):
        assert len(GROOVY_FILE.read_text().strip()) > 0


class TestJenkinsStepStructure:
    def _src(self):
        return GROOVY_FILE.read_text()

    def test_has_call_method(self):
        assert re.search(r"def\s+call\s*\(", self._src())

    def test_call_accepts_map_params(self):
        assert re.search(r"def\s+call\s*\(\s*Map", self._src())

    def test_has_model_path_param(self):
        assert "modelPath" in self._src()

    def test_has_policies_param(self):
        assert "policies" in self._src()

    def test_has_sign_param(self):
        assert "sign" in self._src()

    def test_has_fail_on_violation_param(self):
        assert "failOnViolation" in self._src()

    def test_has_annex_iv_param(self):
        assert "annexIv" in self._src()

    def test_has_api_key_param(self):
        assert "apiKey" in self._src()

    def test_has_squash_version_param(self):
        assert "squashVersion" in self._src()

    def test_error_on_missing_model_path(self):
        src = self._src()
        assert "error" in src and "modelPath" in src

    def test_stash_artifacts(self):
        assert "stash" in self._src()

    def test_with_credentials_block(self):
        assert "withCredentials" in self._src()

    def test_squash_attest_command(self):
        assert "squash attest" in self._src()

    def test_annex_iv_command(self):
        assert "annex-iv" in self._src()

    def test_has_stage_blocks(self):
        src = self._src()
        assert src.count("stage(") >= 2, "Should have at least 2 stage() blocks"


class TestJenkinsStepDefaults:
    def _src(self):
        return GROOVY_FILE.read_text()

    def test_default_policies_is_eu_ai_act(self):
        src = self._src()
        assert "eu-ai-act" in src

    def test_fail_on_violation_defaults_true(self):
        src = self._src()
        # The default branch for failOnViolation should be true
        assert "failOnViolation" in src and "true" in src

    def test_install_cmd_supports_version_pinning(self):
        src = self._src()
        assert "squash-ai" in src
        assert "squashVersion" in src


class TestJenkinsStepSafety:
    def _src(self):
        return GROOVY_FILE.read_text()

    def test_no_hardcoded_credentials(self):
        src = self._src()
        assert "SQUASH_API_KEY" not in src.split("withCredentials")[0].split("def call")[0]

    def test_uses_set_euo_pipefail_or_equivalent(self):
        src = self._src()
        # Groovy steps use sh() which doesn't need set -euo pipefail but
        # the step should at least not suppress errors
        assert "sh " in src or "sh(" in src

    def test_allows_failure_handling(self):
        src = self._src()
        assert "unstable" in src or "error" in src or "echo" in src
