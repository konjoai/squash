"""squish.squash.integrations.wandb — Weights & Biases adapter for Squash.

Attests a model artifact after it has been logged to W&B, then adds Squash
attestation files as additional artifact files and logs compliance metrics as
W&B summary values and artifact metadata.

Usage::

    import wandb
    from squash.integrations.wandb import WandbSquash

    with wandb.init(project="my-llm") as run:
        artifact = wandb.Artifact("llama-3.1-8b-int4", type="model")
        artifact.add_dir("./output/llama-3.1-8b")
        run.log_artifact(artifact)

        result = WandbSquash.attest_artifact(
            artifact=artifact,
            model_path=Path("./output/llama-3.1-8b"),
            policies=["eu-ai-act"],
        )
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    import wandb as _wandb_mod

from squash.attest import (
    AttestConfig, AttestPipeline, AttestResult, AttestationViolationError,
)

log = logging.getLogger(__name__)


class WandbSquash:
    """Attach Squash attestation to a W&B artifact."""

    @staticmethod
    def attest_artifact(
        artifact: "_wandb_mod.Artifact",
        model_path: Path,
        *,
        output_dir: Path | None = None,
        policies: list[str] | None = None,
        sign: bool = False,
        fail_on_violation: bool = False,
        **attest_kwargs,
    ) -> AttestResult:
        """Run attestation and attach results to *artifact*.

        The attestation artifacts are added as files to the W&B artifact so
        they travel with the model through all downstream usages.  Compliance
        metrics are also logged to the active run's summary.

        Parameters
        ----------
        artifact:
            An already-created :class:`wandb.Artifact` (before or after
            ``log_artifact`` — W&B allows late file additions).
        model_path:
            Local path to the model directory or file.
        output_dir:
            Where Squash writes artifacts; defaults to ``model_path.parent/squash``.
        policies:
            Policy templates to evaluate.
        sign:
            Sign via Sigstore.
        fail_on_violation:
            Raise on compliance failure.
        """
        try:
            import wandb
        except ImportError as e:
            raise ImportError(
                "wandb is required. Install with: pip install wandb"
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

        # Add every generated file to the artifact
        for p in out.glob("squash-*"):
            artifact.add_file(str(p), name=f"squash/{p.name}")
        if result.cyclonedx_path and result.cyclonedx_path.exists():
            artifact.add_file(
                str(result.cyclonedx_path), name="squash/cyclonedx-mlbom.json"
            )

        # Log compliance metrics in run summary
        run = wandb.run
        if run is not None:
            run.summary.update(
                {
                    "squash/passed": result.passed,
                    "squash/scan_status": (
                        result.scan_result.status if result.scan_result else "skipped"
                    ),
                    **{
                        f"squash/policy/{name}/passed": pr.passed
                        for name, pr in result.policy_results.items()
                    },
                }
            )

        return result

    # ── W199 (Sprint 12) — log_artifact_attested: gated W&B artifact log ──────

    @staticmethod
    def log_artifact_attested(
        run: "Any",  # noqa: F821 — wandb.run-like
        artifact_name: str,
        model_path: Path,
        *,
        artifact_type: str = "model",
        policies: list[str] | None = None,
        fail_on_violation: bool = True,
        sign: bool = False,
        output_dir: Path | None = None,
        aliases: list[str] | None = None,
        description: str | None = None,
        **attest_kwargs,
    ) -> tuple[AttestResult, "Any"]:  # noqa: F821
        """Attest *model_path* and only log to W&B on policy success.

        This is the **gate** version of :meth:`attest_artifact`. The squash
        attestation runs first; on policy fail, ``run.log_artifact()`` is
        **never called** and :class:`~squash.attest.AttestationViolationError`
        is raised.

        On success, a fresh ``wandb.Artifact`` is built with both the model
        files and the squash attestation files, then logged. The artifact's
        metadata block carries the attestation ID, score breakdown, and
        per-policy pass/fail.

        Parameters
        ----------
        run:
            Active W&B run (returned by ``wandb.init``).
        artifact_name:
            Logical artifact name registered in W&B.
        model_path:
            Local filesystem path to the model artefact (file or directory).
        artifact_type:
            W&B artifact type. Defaults to ``"model"``.
        policies:
            Policies to evaluate; defaults to ``["enterprise-strict"]``.
        fail_on_violation:
            When ``True`` (default), a policy violation raises
            ``AttestationViolationError`` and the artifact is **never logged**.
        sign:
            Sigstore-sign the CycloneDX BOM during attest.
        output_dir:
            Where attestation artifacts are written.
        aliases:
            W&B artifact aliases (e.g. ``["latest", "production"]``).
        description:
            Free-text description attached to the W&B artifact.
        **attest_kwargs:
            Additional ``AttestConfig`` keyword arguments.

        Returns
        -------
        tuple[AttestResult, wandb.Artifact]
            The attestation result and the freshly logged Artifact.

        Raises
        ------
        AttestationViolationError
            When ``fail_on_violation=True`` and a policy violation is found.
            The artifact is never logged.
        ImportError
            When the ``wandb`` package is not installed.
        """
        try:
            import wandb
        except ImportError as e:
            raise ImportError(
                "wandb is required for log_artifact_attested. "
                "Install with: pip install wandb"
            ) from e

        out = output_dir or (model_path.parent / "squash")
        config = AttestConfig(
            model_path=model_path,
            output_dir=out,
            policies=policies if policies is not None else ["enterprise-strict"],
            sign=sign,
            fail_on_violation=False,  # gate decision is local
            **attest_kwargs,
        )
        result = AttestPipeline.run(config)

        # ── Gate decision ───────────────────────────────────────────────
        if not result.passed and fail_on_violation:
            log.warning(
                "W&B: log_artifact REFUSED for %s — %s",
                artifact_name, result.summary(),
            )
            raise AttestationViolationError(
                f"squash refused W&B artifact log of {artifact_name!r}: "
                f"{result.summary()}"
            )

        # ── Build & log the artifact ────────────────────────────────────
        metadata: dict[str, Any] = {
            "squash.passed": result.passed,
            "squash.attestation_id": result.model_id,
            "squash.scan_status": (
                result.scan_result.status if result.scan_result else "skipped"
            ),
            "squash.policies": {
                name: {"passed": pr.passed, "errors": pr.error_count,
                       "warnings": pr.warning_count}
                for name, pr in result.policy_results.items()
            },
        }
        artifact = wandb.Artifact(
            name=artifact_name,
            type=artifact_type,
            metadata=metadata,
            description=description,
        )

        # Add model files
        if model_path.is_dir():
            artifact.add_dir(str(model_path))
        else:
            artifact.add_file(str(model_path))

        # Add squash attestation files
        for p in out.glob("squash-*"):
            artifact.add_file(str(p), name=f"squash/{p.name}")
        if result.cyclonedx_path and result.cyclonedx_path.exists():
            artifact.add_file(
                str(result.cyclonedx_path),
                name="squash/cyclonedx-mlbom.json",
            )

        run.log_artifact(artifact, aliases=aliases or [])

        log.info(
            "W&B: logged artifact %s with squash.passed=%s, attestation_id=%s",
            artifact_name, result.passed, result.model_id,
        )
        return result, artifact
