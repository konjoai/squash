"""squish.squash.integrations.mlflow — MLflow adapter for Squash attestation.

Attests a local model directory immediately after logging a run, then:
1. Uploads every Squash artifact (BOM, SPDX, policy reports, …) as MLflow
   run artifacts.
2. Sets MLflow tags that downstream dashboards and quality gates can query.

Usage::

    import mlflow
    from squash.integrations.mlflow import MLflowSquash

    with mlflow.start_run() as run:
        # … your training / fine-tuning …
        mlflow.pytorch.log_model(model, "model")

        result = MLflowSquash.attest_run(
            run=run,
            model_path=Path("./output/llama-3.1-8b"),
            policies=["eu-ai-act", "nist-ai-rmf"],
        )
        # Tags squash.passed=true/false, squash.scan_status=clean, …
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import mlflow

from squash.attest import (
    AttestConfig, AttestPipeline, AttestResult, AttestationViolationError,
)

log = logging.getLogger(__name__)

# MLflow tag namespace
_TAG_PREFIX = "squash."


class MLflowSquash:
    """Attach Squash attestation artifacts and tags to an MLflow run."""

    @staticmethod
    def attest_run(
        run: "mlflow.ActiveRun | mlflow.entities.Run",
        model_path: Path,
        *,
        output_dir: Path | None = None,
        policies: list[str] | None = None,
        sign: bool = False,
        fail_on_violation: bool = False,
        artifact_prefix: str = "squash",
        **attest_kwargs,
    ) -> AttestResult:
        """Attest *model_path* and upload artifacts to the active MLflow run.

        Parameters
        ----------
        run:
            Active MLflow run context or a resolved
            :class:`mlflow.entities.Run` object.
        model_path:
            Local path to the model directory or file being attested.
        output_dir:
            Where Squash writes its artifacts; defaults to a ``squash/``
            subdirectory under *model_path*'s parent so they can be uploaded
            with a tidy prefix.
        policies:
            Policy templates to evaluate; defaults to ``["enterprise-strict"]``.
        sign:
            Sign the CycloneDX BOM with Sigstore.
        fail_on_violation:
            Raise on policy/scan failure.
        artifact_prefix:
            MLflow artifact path prefix, defaults to ``"squash"``.

        Returns
        -------
        AttestResult
        """
        try:
            import mlflow as _mlflow
        except ImportError as e:
            raise ImportError(
                "mlflow is required for MLflowSquash. "
                "Install with: pip install mlflow"
            ) from e

        out = output_dir or (model_path.parent / "squash")

        config = AttestConfig(
            model_path=model_path,
            output_dir=out,
            policies=policies if policies is not None else ["enterprise-strict"],
            sign=sign,
            fail_on_violation=fail_on_violation,
            **attest_kwargs,
        )
        result = AttestPipeline.run(config)

        # Upload every artifact in output_dir
        _mlflow.log_artifacts(str(out), artifact_path=artifact_prefix)

        # Set structured tags for dashboards and downstream quality gates
        tags = {
            f"{_TAG_PREFIX}passed": str(result.passed).lower(),
            f"{_TAG_PREFIX}scan_status": (
                result.scan_result.status if result.scan_result else "skipped"
            ),
        }
        for policy_name, pr in result.policy_results.items():
            tags[f"{_TAG_PREFIX}policy.{policy_name}.passed"] = str(pr.passed).lower()
            tags[f"{_TAG_PREFIX}policy.{policy_name}.errors"] = str(pr.error_count)
        _mlflow.set_tags(tags)

        if result.cyclonedx_path:
            log.info(
                "MLflow: tagged run %s with squash.passed=%s, artifacts at '%s/'",
                _mlflow.active_run().info.run_id if _mlflow.active_run() else "?",
                result.passed,
                artifact_prefix,
            )
        return result

    # ── W198 (Sprint 12) — register_attested: gated MLflow registration ───────

    @staticmethod
    def register_attested(
        model_uri: str,
        name: str,
        *,
        model_path: Path,
        policies: list[str] | None = None,
        fail_on_violation: bool = True,
        sign: bool = False,
        output_dir: Path | None = None,
        tags: dict[str, str] | None = None,
        await_registration_for: int = 300,
        **attest_kwargs,
    ) -> tuple[AttestResult, "Any"]:  # noqa: F821
        """Attest *model_path* and only register it on policy success.

        This is the **gate** version of :meth:`attest_run`. It runs the full
        attestation pipeline first; if any error-severity policy rule fails
        (and ``fail_on_violation=True``), it raises
        :class:`~squash.attest.AttestationViolationError` and the model is
        **never registered** in MLflow.

        On success, MLflow's ``register_model`` is called with the supplied
        ``model_uri`` and ``name``. The squash attestation ID and composite
        compliance posture are attached to the new ModelVersion as registry
        tags.

        Parameters
        ----------
        model_uri:
            MLflow model URI to register. Typically ``"runs:/<run_id>/model"``
            or ``"models:/<name>/<version>"``.
        name:
            Registered-model name. Created if it does not exist.
        model_path:
            Local filesystem path to the model artefact, used for attestation
            (the URI alone is not enough — squash needs the bytes on disk).
        policies:
            Policies to evaluate; defaults to ``["enterprise-strict"]``.
        fail_on_violation:
            When ``True`` (default), a policy violation raises
            ``AttestationViolationError`` and registration is **refused**.
        sign:
            Sigstore-sign the CycloneDX BOM during attest.
        output_dir:
            Where attestation artifacts are written. Defaults to
            ``model_path.parent / "squash"``.
        tags:
            Extra registry tags to attach to the ModelVersion.
        await_registration_for:
            Forwarded to MLflow ``register_model``.
        **attest_kwargs:
            Additional ``AttestConfig`` keyword arguments.

        Returns
        -------
        tuple[AttestResult, mlflow.entities.model_registry.ModelVersion]
            The attestation result and the freshly registered ModelVersion.

        Raises
        ------
        AttestationViolationError
            When ``fail_on_violation=True`` and a policy violation is found.
            Registration is refused — no MLflow side-effect occurs.
        ImportError
            When the ``mlflow`` package is not installed.
        """
        try:
            import mlflow as _mlflow
        except ImportError as e:
            raise ImportError(
                "mlflow is required for register_attested. "
                "Install with: pip install mlflow"
            ) from e

        out = output_dir or (model_path.parent / "squash")

        config = AttestConfig(
            model_path=model_path,
            output_dir=out,
            policies=policies if policies is not None else ["enterprise-strict"],
            sign=sign,
            fail_on_violation=False,  # we decide ourselves whether to raise
            **attest_kwargs,
        )
        result = AttestPipeline.run(config)

        # ── Gate decision ───────────────────────────────────────────────
        if not result.passed and fail_on_violation:
            log.warning(
                "MLflow: register_model REFUSED for %s — squash policy violations: %s",
                name,
                ", ".join(
                    f"{n}({pr.error_count}e)" for n, pr in result.policy_results.items()
                    if pr.error_count > 0
                ) or "scan failed",
            )
            raise AttestationViolationError(
                f"squash refused MLflow registration of {name!r} from {model_uri!r}: "
                f"{result.summary()}"
            )

        # ── Register ────────────────────────────────────────────────────
        version = _mlflow.register_model(
            model_uri=model_uri,
            name=name,
            await_registration_for=await_registration_for,
        )

        # ── Tag the new ModelVersion ────────────────────────────────────
        version_number = getattr(version, "version", "") or getattr(version, "name", "")
        client = _mlflow.tracking.MlflowClient()
        registry_tags: dict[str, str] = {
            f"{_TAG_PREFIX}passed": str(result.passed).lower(),
            f"{_TAG_PREFIX}attestation_id": result.model_id,
            f"{_TAG_PREFIX}scan_status": (
                result.scan_result.status if result.scan_result else "skipped"
            ),
        }
        for policy_name, pr in result.policy_results.items():
            registry_tags[f"{_TAG_PREFIX}policy.{policy_name}.passed"] = (
                str(pr.passed).lower()
            )
        if tags:
            registry_tags.update(tags)

        for k, v in registry_tags.items():
            try:
                client.set_model_version_tag(name, version_number, k, v)
            except Exception as exc:  # noqa: BLE001 — surface but don't roll back
                log.warning("MLflow: tag %s failed: %s", k, exc)

        log.info(
            "MLflow: registered %s v%s with squash.passed=%s",
            name, version_number, result.passed,
        )
        return result, version
