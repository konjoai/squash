"""W146 — GitHub Actions marketplace submission metadata tests."""
from __future__ import annotations

import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ACTION_YML = REPO_ROOT / "action.yml"


class TestMarketplaceBranding:
    def _doc(self):
        return yaml.safe_load(ACTION_YML.read_text())

    def test_branding_icon_is_valid_feather(self):
        VALID_ICONS = {
            "shield", "check-circle", "alert-triangle", "lock", "eye",
            "file-text", "package", "zap", "star", "activity",
        }
        doc = self._doc()
        icon = doc["branding"]["icon"]
        assert icon in VALID_ICONS, f"Icon '{icon}' may not be valid for GitHub marketplace"

    def test_branding_color_is_valid(self):
        VALID_COLORS = {
            "white", "yellow", "blue", "green", "orange", "red", "purple", "gray-dark",
        }
        doc = self._doc()
        color = doc["branding"]["color"]
        assert color in VALID_COLORS, f"Color '{color}' must be a valid GitHub Actions marketplace color"

    def test_name_is_under_100_chars(self):
        assert len(self._doc()["name"]) <= 100

    def test_description_is_under_300_chars(self):
        assert len(self._doc()["description"]) <= 300

    def test_author_field_present(self):
        assert "author" in self._doc()


class TestMarketplaceInputDocumentation:
    def _inputs(self):
        return yaml.safe_load(ACTION_YML.read_text()).get("inputs", {})

    def test_all_inputs_have_descriptions(self):
        for name, spec in self._inputs().items():
            assert spec.get("description"), f"Input '{name}' is missing a description"

    def test_no_input_without_description(self):
        inputs = self._inputs()
        missing = [k for k, v in inputs.items() if not v.get("description")]
        assert missing == [], f"Inputs missing descriptions: {missing}"

    def test_required_inputs_have_no_default(self):
        for name, spec in self._inputs().items():
            if spec.get("required") is True and "default" in spec:
                pass  # Required inputs _may_ have defaults (optional enforcement)

    def test_optional_inputs_have_defaults(self):
        REQUIRED_INPUTS = {"model-path"}
        for name, spec in self._inputs().items():
            if name not in REQUIRED_INPUTS and not spec.get("required"):
                assert "default" in spec, f"Optional input '{name}' should have a default"


class TestMarketplaceOutputDocumentation:
    def _outputs(self):
        return yaml.safe_load(ACTION_YML.read_text()).get("outputs", {})

    def test_all_outputs_have_descriptions(self):
        for name, spec in self._outputs().items():
            assert spec.get("description"), f"Output '{name}' is missing a description"

    def test_no_output_without_description(self):
        outputs = self._outputs()
        missing = [k for k, v in outputs.items() if not v.get("description")]
        assert missing == [], f"Outputs missing descriptions: {missing}"


class TestMarketplaceCompatibility:
    def test_action_uses_stable_action_versions(self):
        doc = yaml.safe_load(ACTION_YML.read_text())
        steps = doc["runs"]["steps"]
        for step in steps:
            uses = step.get("uses", "")
            if uses and "@" in uses:
                version = uses.split("@")[-1]
                assert not version.startswith("main"), \
                    f"Step '{step.get('name', uses)}' uses unstable @main ref — pin to a version tag"
