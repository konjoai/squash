"""W147 — GitLab CI template tests."""
from __future__ import annotations

import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
GITLAB_TEMPLATE = REPO_ROOT / "integrations" / "gitlab-ci" / "squash.gitlab-ci.yml"


class TestGitlabTemplateExists:
    def test_file_exists(self):
        assert GITLAB_TEMPLATE.exists()

    def test_is_valid_yaml(self):
        doc = yaml.safe_load(GITLAB_TEMPLATE.read_text())
        assert doc is not None


class TestGitlabTemplateStructure:
    def _doc(self):
        return yaml.safe_load(GITLAB_TEMPLATE.read_text())

    def test_has_squash_attest_job(self):
        assert ".squash_attest" in self._doc()

    def test_has_squash_attest_soft_variant(self):
        assert ".squash_attest_soft" in self._doc()

    def test_has_squash_attest_full_variant(self):
        assert ".squash_attest_full" in self._doc()

    def test_main_job_has_image(self):
        job = self._doc()[".squash_attest"]
        assert "image" in job

    def test_main_job_has_stage(self):
        job = self._doc()[".squash_attest"]
        assert "stage" in job

    def test_main_job_has_variables(self):
        job = self._doc()[".squash_attest"]
        assert "variables" in job

    def test_main_job_has_script(self):
        job = self._doc()[".squash_attest"]
        assert "script" in job
        assert len(job["script"]) >= 1

    def test_main_job_has_artifacts(self):
        job = self._doc()[".squash_attest"]
        assert "artifacts" in job

    def test_main_job_has_before_script(self):
        job = self._doc()[".squash_attest"]
        assert "before_script" in job

    def test_artifacts_has_paths(self):
        job = self._doc()[".squash_attest"]
        assert "paths" in job["artifacts"]

    def test_artifacts_has_expiry(self):
        job = self._doc()[".squash_attest"]
        assert "expire_in" in job["artifacts"]


class TestGitlabTemplateVariables:
    def _vars(self):
        return yaml.safe_load(GITLAB_TEMPLATE.read_text())[".squash_attest"]["variables"]

    def test_has_policies_variable(self):
        assert "SQUASH_POLICIES" in self._vars()

    def test_has_sign_variable(self):
        assert "SQUASH_SIGN" in self._vars()

    def test_has_fail_hard_variable(self):
        assert "SQUASH_FAIL_HARD" in self._vars()

    def test_has_annex_iv_variable(self):
        assert "SQUASH_ANNEX_IV" in self._vars()

    def test_policies_default_is_eu_ai_act(self):
        assert "eu-ai-act" in str(self._vars().get("SQUASH_POLICIES", ""))

    def test_sign_default_is_false(self):
        assert str(self._vars().get("SQUASH_SIGN", "")).lower() == "false"

    def test_fail_hard_default_is_true(self):
        assert str(self._vars().get("SQUASH_FAIL_HARD", "")).lower() == "true"


class TestGitlabTemplateVariants:
    def _doc(self):
        return yaml.safe_load(GITLAB_TEMPLATE.read_text())

    def test_soft_extends_main(self):
        soft = self._doc()[".squash_attest_soft"]
        assert soft.get("extends") == ".squash_attest"

    def test_soft_sets_fail_false(self):
        soft = self._doc()[".squash_attest_soft"]
        assert str(soft.get("variables", {}).get("SQUASH_FAIL_HARD", "")).lower() == "false"

    def test_full_extends_main(self):
        full = self._doc()[".squash_attest_full"]
        assert full.get("extends") == ".squash_attest"

    def test_full_enables_signing(self):
        full = self._doc()[".squash_attest_full"]
        assert str(full.get("variables", {}).get("SQUASH_SIGN", "")).lower() == "true"

    def test_full_enables_annex_iv(self):
        full = self._doc()[".squash_attest_full"]
        assert str(full.get("variables", {}).get("SQUASH_ANNEX_IV", "")).lower() == "true"

    def test_full_has_multiple_policies(self):
        full = self._doc()[".squash_attest_full"]
        policies = full.get("variables", {}).get("SQUASH_POLICIES", "")
        assert "," in str(policies), "Full variant should define multiple comma-separated policies"
