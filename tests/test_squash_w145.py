"""W145 — GitHub Actions composite action (action.yml) tests."""
from __future__ import annotations

import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ACTION_YML = REPO_ROOT / "action.yml"


class TestActionYmlExists:
    def test_action_yml_exists(self):
        assert ACTION_YML.exists(), "action.yml must exist at repo root"

    def test_action_yml_is_valid_yaml(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        assert doc is not None

    def test_action_yml_has_name(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        assert "name" in doc
        assert doc["name"]

    def test_action_yml_has_description(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        assert "description" in doc

    def test_action_yml_has_branding(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        assert "branding" in doc
        assert "icon" in doc["branding"]
        assert "color" in doc["branding"]

    def test_action_yml_runs_composite(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        assert doc["runs"]["using"] == "composite"

    def test_action_yml_has_steps(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        assert len(doc["runs"]["steps"]) >= 1


class TestActionYmlInputs:
    def _inputs(self):
        return yaml.safe_load(ACTION_YML.read_text()).get("inputs", {})

    def test_has_model_path_input(self):
        assert "model-path" in self._inputs()

    def test_model_path_is_required(self):
        assert self._inputs()["model-path"]["required"] is True

    def test_has_policies_input(self):
        assert "policies" in self._inputs()

    def test_has_sign_input(self):
        assert "sign" in self._inputs()

    def test_has_fail_on_violation_input(self):
        assert "fail-on-violation" in self._inputs()

    def test_has_api_key_input(self):
        assert "api-key" in self._inputs()

    def test_has_output_dir_input(self):
        assert "output-dir" in self._inputs()

    def test_has_annex_iv_input(self):
        assert "annex-iv" in self._inputs()

    def test_default_policies_is_eu_ai_act(self):
        assert "eu-ai-act" in str(self._inputs()["policies"].get("default", ""))

    def test_sign_default_is_false(self):
        assert str(self._inputs()["sign"].get("default", "")).lower() in ("false", "")

    def test_fail_on_violation_default_is_true(self):
        assert str(self._inputs()["fail-on-violation"].get("default", "")).lower() == "true"


class TestActionYmlOutputs:
    def _outputs(self):
        return yaml.safe_load(ACTION_YML.read_text()).get("outputs", {})

    def test_has_passed_output(self):
        assert "passed" in self._outputs()

    def test_has_score_output(self):
        assert "score" in self._outputs()

    def test_has_artifacts_dir_output(self):
        assert "artifacts-dir" in self._outputs()

    def test_has_bom_digest_output(self):
        assert "bom-digest" in self._outputs()

    def test_passed_output_has_description(self):
        assert self._outputs()["passed"].get("description")

    def test_score_output_has_description(self):
        assert self._outputs()["score"].get("description")


class TestActionYmlSteps:
    def _steps(self):
        return yaml.safe_load(ACTION_YML.read_text())["runs"]["steps"]

    def test_has_install_step(self):
        steps = self._steps()
        install_steps = [s for s in steps if "install" in str(s).lower()]
        assert len(install_steps) >= 1

    def test_has_attest_step(self):
        steps = self._steps()
        attest_steps = [s for s in steps if "attest" in str(s).lower()]
        assert len(attest_steps) >= 1

    def test_attest_step_has_id(self):
        steps = self._steps()
        ids = [s.get("id") for s in steps if s.get("id")]
        assert "attest" in ids

    def test_has_upload_artifacts_step(self):
        steps = self._steps()
        upload_steps = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]
        assert len(upload_steps) >= 1

    def test_all_shell_steps_are_bash(self):
        steps = self._steps()
        for step in steps:
            if step.get("run") and step.get("shell"):
                assert step["shell"] in ("bash", "sh", "pwsh", "powershell"), \
                    f"Unexpected shell in step '{step.get('name', '?')}': {step['shell']}"
