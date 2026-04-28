"""W149 — GHCR Docker image publish workflow tests."""
from __future__ import annotations

import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "publish-image.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"


class TestPublishImageWorkflowExists:
    def test_workflow_file_exists(self):
        assert WORKFLOW_FILE.exists()

    def test_workflow_is_valid_yaml(self):
        doc = yaml.safe_load(WORKFLOW_FILE.read_text())
        assert doc is not None

    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists()


class TestPublishImageWorkflowTriggers:
    def _content(self):
        return WORKFLOW_FILE.read_text()

    def test_triggers_on_release(self):
        assert "release:" in self._content()

    def test_triggers_on_push(self):
        assert "push:" in self._content()

    def test_supports_workflow_dispatch(self):
        assert "workflow_dispatch" in self._content()


class TestPublishImageWorkflowJobs:
    def _jobs(self):
        doc = yaml.safe_load(WORKFLOW_FILE.read_text())
        return doc.get("jobs", {})

    def test_has_build_push_job(self):
        jobs = self._jobs()
        assert len(jobs) >= 1

    def test_job_has_permissions(self):
        jobs = self._jobs()
        for job in jobs.values():
            if "steps" in job:
                assert "permissions" in job

    def test_job_uses_ubuntu(self):
        jobs = self._jobs()
        for job in jobs.values():
            if "steps" in job:
                assert "ubuntu" in str(job.get("runs-on", ""))

    def test_job_has_login_step(self):
        jobs = self._jobs()
        for job in jobs.values():
            steps = job.get("steps", [])
            login_steps = [s for s in steps if "login" in str(s.get("uses", "")).lower()]
            if steps:
                assert len(login_steps) >= 1, "Job must have a registry login step"

    def test_job_has_metadata_step(self):
        jobs = self._jobs()
        for job in jobs.values():
            steps = job.get("steps", [])
            meta_steps = [s for s in steps if "metadata" in str(s.get("uses", "")).lower()]
            if steps:
                assert len(meta_steps) >= 1, "Job must have a metadata extraction step"

    def test_job_has_build_push_step(self):
        jobs = self._jobs()
        for job in jobs.values():
            steps = job.get("steps", [])
            build_steps = [s for s in steps if "build-push" in str(s.get("uses", "")).lower()]
            if steps:
                assert len(build_steps) >= 1, "Job must have a docker build-push step"


class TestPublishImageWorkflowSecurity:
    def _doc(self):
        return yaml.safe_load(WORKFLOW_FILE.read_text())

    def test_uses_github_token_not_pat(self):
        content = WORKFLOW_FILE.read_text()
        assert "secrets.GITHUB_TOKEN" in content, "Use GITHUB_TOKEN, not a PAT, for GHCR"

    def test_uses_ghcr_registry(self):
        content = WORKFLOW_FILE.read_text()
        assert "ghcr.io" in content

    def test_has_concurrency_guard(self):
        doc = self._doc()
        assert "concurrency" in doc

    def test_image_tagging_includes_latest(self):
        content = WORKFLOW_FILE.read_text()
        assert "latest" in content


class TestDockerfileStructure:
    def _src(self):
        return DOCKERFILE.read_text()

    def test_has_from_directive(self):
        assert self._src().startswith("FROM") or "FROM " in self._src()

    def test_uses_python_base(self):
        assert "python" in self._src().lower()

    def test_exposes_port(self):
        assert "EXPOSE" in self._src()

    def test_has_healthcheck(self):
        assert "HEALTHCHECK" in self._src()

    def test_runs_as_non_root(self):
        src = self._src()
        assert "USER" in src and "root" not in src.split("USER")[-1].lower()

    def test_has_cmd_entrypoint(self):
        src = self._src()
        assert "CMD" in src or "ENTRYPOINT" in src
