"""W139 — Dockerfile, fly.toml, and GitHub Actions deploy workflow tests."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

DOCKERFILE = REPO_ROOT / "Dockerfile"
FLY_TOML = REPO_ROOT / "fly.toml"
DEPLOY_YML = REPO_ROOT / ".github" / "workflows" / "deploy.yml"


class TestDockerfile:
    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists()

    def test_uses_python_312(self):
        content = DOCKERFILE.read_text()
        assert "python:3.12" in content

    def test_has_builder_stage(self):
        content = DOCKERFILE.read_text()
        assert "AS builder" in content

    def test_has_non_root_user(self):
        content = DOCKERFILE.read_text()
        assert "useradd" in content or "USER squash" in content

    def test_exposes_port_4444(self):
        content = DOCKERFILE.read_text()
        assert "EXPOSE 4444" in content

    def test_has_healthcheck(self):
        content = DOCKERFILE.read_text()
        assert "HEALTHCHECK" in content

    def test_runs_uvicorn(self):
        content = DOCKERFILE.read_text()
        assert "uvicorn" in content

    def test_cmd_uses_squash_api(self):
        content = DOCKERFILE.read_text()
        assert "squash.api:app" in content

    def test_installs_squash_wheel(self):
        content = DOCKERFILE.read_text()
        assert "squash" in content.lower() and "pip install" in content

    def test_has_python_unbuffered(self):
        content = DOCKERFILE.read_text()
        assert "PYTHONUNBUFFERED" in content

    def test_multistage_build(self):
        content = DOCKERFILE.read_text()
        # Two FROM statements = multi-stage
        assert content.count("\nFROM ") >= 1


class TestFlyToml:
    def test_fly_toml_exists(self):
        assert FLY_TOML.exists()

    def test_app_name_set(self):
        content = FLY_TOML.read_text()
        assert 'app = "squash' in content

    def test_primary_region(self):
        content = FLY_TOML.read_text()
        assert "primary_region" in content

    def test_internal_port_4444(self):
        content = FLY_TOML.read_text()
        assert "4444" in content

    def test_force_https(self):
        content = FLY_TOML.read_text()
        assert "force_https" in content

    def test_health_check_path(self):
        content = FLY_TOML.read_text()
        assert "/health" in content

    def test_auto_stop_machines(self):
        content = FLY_TOML.read_text()
        assert "auto_stop_machines" in content

    def test_vm_memory_defined(self):
        content = FLY_TOML.read_text()
        assert "memory" in content

    def test_rolling_deploy(self):
        content = FLY_TOML.read_text()
        assert "rolling" in content

    def test_references_dockerfile(self):
        content = FLY_TOML.read_text()
        assert "Dockerfile" in content or "dockerfile" in content


class TestDeployWorkflow:
    def test_deploy_yml_exists(self):
        assert DEPLOY_YML.exists()

    def test_triggers_on_push_to_main(self):
        content = DEPLOY_YML.read_text()
        assert "main" in content
        assert "push" in content

    def test_has_test_job(self):
        content = DEPLOY_YML.read_text()
        assert "pytest" in content or "test" in content.lower()

    def test_has_deploy_job(self):
        content = DEPLOY_YML.read_text()
        assert "deploy" in content.lower()

    def test_uses_flyctl(self):
        content = DEPLOY_YML.read_text()
        assert "flyctl" in content or "fly" in content.lower()

    def test_fly_api_token_from_secrets(self):
        content = DEPLOY_YML.read_text()
        assert "FLY_API_TOKEN" in content
        assert "secrets" in content

    def test_deploy_depends_on_tests(self):
        content = DEPLOY_YML.read_text()
        assert "needs:" in content

    def test_python_312_in_ci(self):
        content = DEPLOY_YML.read_text()
        assert "3.12" in content

    def test_has_workflow_dispatch(self):
        content = DEPLOY_YML.read_text()
        assert "workflow_dispatch" in content

    def test_has_concurrency_control(self):
        content = DEPLOY_YML.read_text()
        assert "concurrency" in content
