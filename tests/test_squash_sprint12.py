"""tests/test_squash_sprint12.py — Sprint 12 (W198–W201) tests.

Sprint 12: Model Registry Auto-Attest Gates (Tier 2 #18).

W198 — MLflow.register_attested(): refuses register_model on policy fail
W199 — Wandb.log_artifact_attested(): refuses log_artifact on policy fail
W200 — SageMaker.register_model_package_attested(): blocks Approved on fail
W201 — squash registry-gate CLI: unified pre-registration policy gate

The backend SDKs (mlflow / wandb / boto3) are mocked at the import boundary
via `patch.dict("sys.modules", ...)` matching the W151–W152 test pattern.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


# ── Shared fixture helpers ───────────────────────────────────────────────────


def _make_passing_result() -> MagicMock:
    """Build a fake AttestResult that 'passed'."""
    r = MagicMock()
    r.passed = True
    r.model_id = "test-model"
    r.scan_result = MagicMock(status="clean")
    r.policy_results = {
        "eu-ai-act": MagicMock(passed=True, error_count=0, warning_count=0),
    }
    r.cyclonedx_path = Path("/tmp/cyclonedx-mlbom.json")
    r.summary = MagicMock(return_value="[PASS] test-model: …")
    return r


def _make_failing_result() -> MagicMock:
    """Build a fake AttestResult that failed policy."""
    r = MagicMock()
    r.passed = False
    r.model_id = "test-model"
    r.scan_result = MagicMock(status="clean")
    r.policy_results = {
        "eu-ai-act": MagicMock(passed=False, error_count=2, warning_count=1),
    }
    r.cyclonedx_path = Path("/tmp/cyclonedx-mlbom.json")
    r.summary = MagicMock(return_value="[FAIL] test-model: 2 errors, 1 warning")
    return r


# ── W198 — MLflowSquash.register_attested ────────────────────────────────────


class TestW198MLflowRegisterAttested(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        self.model_dir = self.tmp / "model"
        self.model_dir.mkdir()

    def _make_mock_mlflow(self) -> MagicMock:
        m = MagicMock()
        version = MagicMock()
        version.version = "1"
        version.name = "MyModel"
        m.register_model.return_value = version
        client_inst = MagicMock()
        m.tracking.MlflowClient.return_value = client_inst
        return m

    def test_raises_import_error_when_mlflow_missing(self) -> None:
        from squash.integrations.mlflow import MLflowSquash
        with patch.dict("sys.modules", {"mlflow": None}):
            with self.assertRaises(ImportError) as ctx:
                MLflowSquash.register_attested(
                    model_uri="runs:/abc/model",
                    name="MyModel",
                    model_path=self.model_dir,
                )
            self.assertIn("mlflow", str(ctx.exception).lower())

    def test_passing_run_calls_register_model(self) -> None:
        from squash.integrations.mlflow import MLflowSquash
        m = self._make_mock_mlflow()
        with patch.dict("sys.modules", {"mlflow": m}), \
             patch("squash.integrations.mlflow.AttestPipeline.run",
                   return_value=_make_passing_result()):
            result, version = MLflowSquash.register_attested(
                model_uri="runs:/abc/model",
                name="MyModel",
                model_path=self.model_dir,
            )
        m.register_model.assert_called_once()
        self.assertTrue(result.passed)
        self.assertEqual(version.version, "1")

    def test_passing_run_sets_attestation_tag(self) -> None:
        from squash.integrations.mlflow import MLflowSquash
        m = self._make_mock_mlflow()
        with patch.dict("sys.modules", {"mlflow": m}), \
             patch("squash.integrations.mlflow.AttestPipeline.run",
                   return_value=_make_passing_result()):
            MLflowSquash.register_attested(
                model_uri="runs:/abc/model",
                name="MyModel",
                model_path=self.model_dir,
            )
        client = m.tracking.MlflowClient.return_value
        # Should have set squash.passed and squash.attestation_id at minimum
        tag_keys = [c.args[2] for c in client.set_model_version_tag.call_args_list]
        self.assertIn("squash.passed", tag_keys)
        self.assertIn("squash.attestation_id", tag_keys)

    def test_failing_policy_refuses_registration(self) -> None:
        from squash.attest import AttestationViolationError
        from squash.integrations.mlflow import MLflowSquash
        m = self._make_mock_mlflow()
        with patch.dict("sys.modules", {"mlflow": m}), \
             patch("squash.integrations.mlflow.AttestPipeline.run",
                   return_value=_make_failing_result()):
            with self.assertRaises(AttestationViolationError):
                MLflowSquash.register_attested(
                    model_uri="runs:/abc/model",
                    name="MyModel",
                    model_path=self.model_dir,
                    fail_on_violation=True,
                )
        # Must NOT have called register_model on refuse
        m.register_model.assert_not_called()

    def test_fail_on_violation_false_still_registers(self) -> None:
        """With fail_on_violation=False, MLflow registration proceeds even on policy fail."""
        from squash.integrations.mlflow import MLflowSquash
        m = self._make_mock_mlflow()
        with patch.dict("sys.modules", {"mlflow": m}), \
             patch("squash.integrations.mlflow.AttestPipeline.run",
                   return_value=_make_failing_result()):
            result, version = MLflowSquash.register_attested(
                model_uri="runs:/abc/model",
                name="MyModel",
                model_path=self.model_dir,
                fail_on_violation=False,
            )
        m.register_model.assert_called_once()
        self.assertFalse(result.passed)

    def test_extra_tags_merged(self) -> None:
        from squash.integrations.mlflow import MLflowSquash
        m = self._make_mock_mlflow()
        with patch.dict("sys.modules", {"mlflow": m}), \
             patch("squash.integrations.mlflow.AttestPipeline.run",
                   return_value=_make_passing_result()):
            MLflowSquash.register_attested(
                model_uri="runs:/abc/model",
                name="MyModel",
                model_path=self.model_dir,
                tags={"team": "platform-ml", "env": "prod"},
            )
        client = m.tracking.MlflowClient.return_value
        tag_keys = [c.args[2] for c in client.set_model_version_tag.call_args_list]
        self.assertIn("team", tag_keys)
        self.assertIn("env", tag_keys)


# ── W199 — WandbSquash.log_artifact_attested ─────────────────────────────────


class TestW199WandbLogArtifactAttested(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        self.model_dir = self.tmp / "model"
        self.model_dir.mkdir()
        (self.model_dir / "weights.bin").write_bytes(b"FAKE")

    def _make_mock_wandb(self) -> MagicMock:
        w = MagicMock()
        artifact = MagicMock()
        w.Artifact.return_value = artifact
        return w

    def test_raises_import_error_when_wandb_missing(self) -> None:
        from squash.integrations.wandb import WandbSquash
        with patch.dict("sys.modules", {"wandb": None}):
            with self.assertRaises(ImportError) as ctx:
                WandbSquash.log_artifact_attested(
                    run=MagicMock(),
                    artifact_name="my-artifact",
                    model_path=self.model_dir,
                )
            self.assertIn("wandb", str(ctx.exception).lower())

    def test_passing_run_calls_log_artifact(self) -> None:
        from squash.integrations.wandb import WandbSquash
        run = MagicMock()
        w = self._make_mock_wandb()
        with patch.dict("sys.modules", {"wandb": w}), \
             patch("squash.integrations.wandb.AttestPipeline.run",
                   return_value=_make_passing_result()):
            result, artifact = WandbSquash.log_artifact_attested(
                run=run,
                artifact_name="my-artifact",
                model_path=self.model_dir,
            )
        run.log_artifact.assert_called_once()
        self.assertTrue(result.passed)

    def test_passing_run_records_attestation_metadata(self) -> None:
        from squash.integrations.wandb import WandbSquash
        run = MagicMock()
        w = self._make_mock_wandb()
        with patch.dict("sys.modules", {"wandb": w}), \
             patch("squash.integrations.wandb.AttestPipeline.run",
                   return_value=_make_passing_result()):
            WandbSquash.log_artifact_attested(
                run=run,
                artifact_name="my-artifact",
                model_path=self.model_dir,
            )
        # wandb.Artifact must be constructed with metadata containing
        # squash.attestation_id and squash.passed
        call_kwargs = w.Artifact.call_args.kwargs
        meta = call_kwargs["metadata"]
        self.assertIn("squash.attestation_id", meta)
        self.assertIn("squash.passed", meta)
        self.assertEqual(meta["squash.passed"], True)

    def test_failing_policy_refuses_log(self) -> None:
        from squash.attest import AttestationViolationError
        from squash.integrations.wandb import WandbSquash
        run = MagicMock()
        w = self._make_mock_wandb()
        with patch.dict("sys.modules", {"wandb": w}), \
             patch("squash.integrations.wandb.AttestPipeline.run",
                   return_value=_make_failing_result()):
            with self.assertRaises(AttestationViolationError):
                WandbSquash.log_artifact_attested(
                    run=run,
                    artifact_name="my-artifact",
                    model_path=self.model_dir,
                    fail_on_violation=True,
                )
        run.log_artifact.assert_not_called()

    def test_aliases_are_forwarded(self) -> None:
        from squash.integrations.wandb import WandbSquash
        run = MagicMock()
        w = self._make_mock_wandb()
        with patch.dict("sys.modules", {"wandb": w}), \
             patch("squash.integrations.wandb.AttestPipeline.run",
                   return_value=_make_passing_result()):
            WandbSquash.log_artifact_attested(
                run=run,
                artifact_name="my-artifact",
                model_path=self.model_dir,
                aliases=["latest", "production"],
            )
        # Check the call_args of run.log_artifact for the aliases kwarg
        kwargs = run.log_artifact.call_args.kwargs
        self.assertEqual(kwargs.get("aliases"), ["latest", "production"])

    def test_fail_on_violation_false_still_logs(self) -> None:
        from squash.integrations.wandb import WandbSquash
        run = MagicMock()
        w = self._make_mock_wandb()
        with patch.dict("sys.modules", {"wandb": w}), \
             patch("squash.integrations.wandb.AttestPipeline.run",
                   return_value=_make_failing_result()):
            result, artifact = WandbSquash.log_artifact_attested(
                run=run,
                artifact_name="my-artifact",
                model_path=self.model_dir,
                fail_on_violation=False,
            )
        run.log_artifact.assert_called_once()
        self.assertFalse(result.passed)


# ── W200 — SageMakerSquash.register_model_package_attested ───────────────────


class TestW200SageMakerRegisterAttested(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        self.model_dir = self.tmp / "model"
        self.model_dir.mkdir()

    def _make_mock_boto3(self) -> MagicMock:
        b = MagicMock()
        sm_client = MagicMock()
        sm_client.create_model_package.return_value = {
            "ModelPackageArn":
                "arn:aws:sagemaker:us-east-1:123:model-package/MyMPG/1",
        }
        b.client.return_value = sm_client
        return b

    def test_raises_import_error_when_boto3_missing(self) -> None:
        from squash.integrations.sagemaker import SageMakerSquash
        with patch.dict("sys.modules", {"boto3": None}):
            with self.assertRaises(ImportError) as ctx:
                SageMakerSquash.register_model_package_attested(
                    model_path=self.model_dir,
                    model_package_group_name="MyMPG",
                    image_uri="123.dkr.ecr.us-east-1.amazonaws.com/img:1",
                    model_data_url="s3://bucket/model.tar.gz",
                )
            self.assertIn("boto3", str(ctx.exception).lower())

    def test_passing_run_creates_model_package_approved(self) -> None:
        from squash.integrations.sagemaker import SageMakerSquash
        b = self._make_mock_boto3()
        with patch.dict("sys.modules", {"boto3": b}), \
             patch("squash.integrations.sagemaker.AttestPipeline.run",
                   return_value=_make_passing_result()):
            result, response = SageMakerSquash.register_model_package_attested(
                model_path=self.model_dir,
                model_package_group_name="MyMPG",
                image_uri="123.dkr.ecr.us-east-1.amazonaws.com/img:1",
                model_data_url="s3://bucket/model.tar.gz",
            )
        sm = b.client.return_value
        sm.create_model_package.assert_called_once()
        kwargs = sm.create_model_package.call_args.kwargs
        self.assertEqual(kwargs["ModelApprovalStatus"], "Approved")
        self.assertEqual(kwargs["ModelPackageGroupName"], "MyMPG")
        self.assertTrue(result.passed)
        self.assertIn("ModelPackageArn", response)

    def test_failing_policy_refuses_creation(self) -> None:
        from squash.attest import AttestationViolationError
        from squash.integrations.sagemaker import SageMakerSquash
        b = self._make_mock_boto3()
        with patch.dict("sys.modules", {"boto3": b}), \
             patch("squash.integrations.sagemaker.AttestPipeline.run",
                   return_value=_make_failing_result()):
            with self.assertRaises(AttestationViolationError):
                SageMakerSquash.register_model_package_attested(
                    model_path=self.model_dir,
                    model_package_group_name="MyMPG",
                    image_uri="img:1",
                    model_data_url="s3://bucket/model.tar.gz",
                    fail_on_violation=True,
                )
        sm = b.client.return_value
        sm.create_model_package.assert_not_called()

    def test_fail_on_violation_false_creates_with_rejected_status(self) -> None:
        from squash.integrations.sagemaker import SageMakerSquash
        b = self._make_mock_boto3()
        with patch.dict("sys.modules", {"boto3": b}), \
             patch("squash.integrations.sagemaker.AttestPipeline.run",
                   return_value=_make_failing_result()):
            result, response = SageMakerSquash.register_model_package_attested(
                model_path=self.model_dir,
                model_package_group_name="MyMPG",
                image_uri="img:1",
                model_data_url="s3://bucket/model.tar.gz",
                fail_on_violation=False,
            )
        sm = b.client.return_value
        sm.create_model_package.assert_called_once()
        kwargs = sm.create_model_package.call_args.kwargs
        self.assertEqual(kwargs["ModelApprovalStatus"], "Rejected")

    def test_custom_fail_status_pending_manual_approval(self) -> None:
        from squash.integrations.sagemaker import SageMakerSquash
        b = self._make_mock_boto3()
        with patch.dict("sys.modules", {"boto3": b}), \
             patch("squash.integrations.sagemaker.AttestPipeline.run",
                   return_value=_make_failing_result()):
            SageMakerSquash.register_model_package_attested(
                model_path=self.model_dir,
                model_package_group_name="MyMPG",
                image_uri="img:1",
                model_data_url="s3://bucket/model.tar.gz",
                fail_on_violation=False,
                approval_status_on_fail="PendingManualApproval",
            )
        sm = b.client.return_value
        kwargs = sm.create_model_package.call_args.kwargs
        self.assertEqual(kwargs["ModelApprovalStatus"], "PendingManualApproval")

    def test_passing_run_attaches_attestation_tag(self) -> None:
        from squash.integrations.sagemaker import SageMakerSquash
        b = self._make_mock_boto3()
        with patch.dict("sys.modules", {"boto3": b}), \
             patch("squash.integrations.sagemaker.AttestPipeline.run",
                   return_value=_make_passing_result()):
            SageMakerSquash.register_model_package_attested(
                model_path=self.model_dir,
                model_package_group_name="MyMPG",
                image_uri="img:1",
                model_data_url="s3://bucket/model.tar.gz",
            )
        sm = b.client.return_value
        kwargs = sm.create_model_package.call_args.kwargs
        tag_keys = [t["Key"] for t in kwargs["Tags"]]
        self.assertIn("squash:passed", tag_keys)
        self.assertIn("squash:attestation_id", tag_keys)
        self.assertIn("squash:gate_decision", tag_keys)


# ── W201 — `squash registry-gate` CLI ────────────────────────────────────────


class TestW201RegistryGateCLI(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        self.model_dir = self.tmp / "model"
        self.model_dir.mkdir()
        (self.model_dir / "weights.bin").write_bytes(b"FAKE")

    def test_help_lists_flags(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--backend", "--model-path", "--uri", "--policy",
                     "--output-dir", "--allow-on-fail", "--json", "--sign"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing")

    def test_local_backend_runs(self) -> None:
        out = self.tmp / "out"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "local", "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        # Default policy is enterprise-strict, which fails on a fake model
        # → exit 1, no allow-on-fail
        self.assertEqual(result.returncode, 1, msg=result.stderr)
        self.assertTrue((out / "registry-gate.json").exists())

    def test_local_backend_allow_on_fail_returns_zero(self) -> None:
        out = self.tmp / "out2"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "local", "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--allow-on-fail", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        gate = json.loads((out / "registry-gate.json").read_text())
        self.assertEqual(gate["decision"], "record-only")
        self.assertFalse(gate["passed"])

    def test_json_emits_structured_output(self) -> None:
        out = self.tmp / "out3"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "local", "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--allow-on-fail", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["squash_version"], "registry_gate_v1")
        self.assertEqual(payload["backend"], "local")
        self.assertIn("policies", payload)

    def test_invalid_mlflow_uri_returns_2(self) -> None:
        out = self.tmp / "out4"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "mlflow", "--uri", "not-a-real-uri",
             "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("mlflow", result.stderr)

    def test_invalid_wandb_uri_returns_2(self) -> None:
        out = self.tmp / "out5"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "wandb", "--uri", "https://example.com",
             "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("wandb", result.stderr)

    def test_invalid_sagemaker_uri_returns_2(self) -> None:
        out = self.tmp / "out6"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "sagemaker", "--uri", "models:/Foo",
             "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("sagemaker", result.stderr)

    def test_valid_mlflow_uri_proceeds(self) -> None:
        out = self.tmp / "out7"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "mlflow", "--uri", "models:/MyModel/Production",
             "--model-path", str(self.model_dir),
             "--output-dir", str(out), "--allow-on-fail", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        gate = json.loads((out / "registry-gate.json").read_text())
        self.assertEqual(gate["uri"], "models:/MyModel/Production")
        self.assertEqual(gate["backend"], "mlflow")

    def test_missing_model_path_returns_2(self) -> None:
        out = self.tmp / "out8"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "registry-gate",
             "--backend", "local",
             "--model-path", str(self.tmp / "no-such-model"),
             "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)


# ── Module count gate (Sprint 12 added 0 new modules — extensions only) ──────


class TestSprint12ModuleCountUnchanged(unittest.TestCase):
    """Sprint 12 itself added 0 modules (extensions only); count was 71 at
    Sprint 12 ship. Sprint 14 W205 (B1) since added hf_scanner.py — current 72."""

    def test_squash_module_count_is_71(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        self.assertEqual(
            len(py_files), 72,
            msg="Sprint 12 added 0 modules; B1 (Sprint 14 W205) added hf_scanner.py.",
        )


if __name__ == "__main__":
    unittest.main()
