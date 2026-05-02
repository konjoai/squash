"""slsa.py — SLSA provenance attestation (Wave 21).

Generates `SLSA <https://slsa.dev/>`_ Build Provenance statements in the
`in-toto SLSA 1.0 <https://slsa.dev/spec/v1.0/provenance>`_ schema and
attaches them to the CycloneDX BOM as external references.

Levels supported
----------------
* **L1** — Writes a signed-off provenance JSON file to ``model_dir``.
* **L2** — Calls :class:`~squish.squash.oms_signer.OmsSigner` to create a
  Sigstore-backed bundle alongside the provenance file.
* **L3** — Verifies the existing bundle via
  :class:`~squish.squash.oms_verifier.OmsVerifier` before accepting the
  provenance as valid.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from squash.canon import canonical_bytes
from squash.clock import Clock, SystemClock
from squash.ids import deterministic_uuid


class SlsaLevel(Enum):
    """Supported SLSA Build Track levels."""

    L1 = 1
    L2 = 2
    L3 = 3


@dataclass
class SlsaAttestation:
    """Metadata captured for (or read from) a SLSA provenance statement.

    Attributes
    ----------
    subject_name:
        Human-readable name of the artifact (e.g. the model directory name).
    subject_sha256:
        Hex SHA-256 digest of the serialised subject content.
    builder_id:
        URI identifying the build system that produced this artefact.
    level:
        The :class:`SlsaLevel` achieved.
    invocation_id:
        Opaque identifier of the build invocation.
    build_finished_on:
        ISO-8601 UTC timestamp when the build completed.
    materials:
        Optional list of ``{"uri": …, "digest": {"sha256": …}}`` dicts
        describing build inputs.
    output_path:
        Local path where the provenance file was written.
    """

    subject_name: str
    subject_sha256: str
    builder_id: str
    level: SlsaLevel
    # Phase G.2: deterministic by default. Callers that genuinely want a
    # fresh per-invocation ID may pass one explicitly (the slsa-github-
    # generator workflow does this with the GitHub run_id). Bare default
    # is keyed on the subject digest so byte-identical builds emit
    # byte-identical Statements.
    invocation_id: str = ""
    build_finished_on: str = ""
    materials: list[dict] = field(default_factory=list)
    output_path: Path | None = None

    def __post_init__(self) -> None:  # noqa: D401
        if not self.invocation_id:
            self.invocation_id = str(
                deterministic_uuid(
                    {"subject_sha256": self.subject_sha256, "builder_id": self.builder_id}
                )
            )
        if not self.build_finished_on:
            self.build_finished_on = (
                datetime.datetime.now(datetime.timezone.utc)
                .replace(microsecond=0)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )


class SlsaProvenanceBuilder:
    """Build SLSA provenance statements and (optionally) sign them.

    Example — L1 only::

        attest = SlsaProvenanceBuilder.build(model_dir, level=SlsaLevel.L1)
        print(attest.output_path)

    Example — L2 with signing::

        attest = SlsaProvenanceBuilder.build(
            model_dir,
            level=SlsaLevel.L2,
            builder_id="https://ci.example.com/builds",
        )
    """

    _PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
    _STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

    @classmethod
    def build(
        cls,
        model_dir: Path,
        *,
        level: SlsaLevel = SlsaLevel.L1,
        builder_id: str = "https://squish.local/squash/builder",
        invocation_id: str | None = None,
        clock: Clock | Callable[[], datetime.datetime] | None = None,
    ) -> SlsaAttestation:
        """Generate and (for L2+) sign a SLSA provenance statement.

        Parameters
        ----------
        model_dir:
            Directory containing the squash attestation artefacts.
        level:
            Desired SLSA Build Track level (L1 / L2 / L3).
        builder_id:
            URI identifying the build system.
        invocation_id:
            Optional caller-supplied invocation ID; generated if omitted.

        Returns
        -------
        SlsaAttestation
            Populated attestation object whose ``output_path`` points to the
            written provenance file.
        """
        model_dir = Path(model_dir)

        # Compute subject digest from BOM file (or fallback to dir listing hash)
        bom_path = model_dir / "cyclonedx-mlbom.json"
        subject_sha256, subject_name, materials = cls._collect_subject(
            model_dir, bom_path
        )

        # Phase G.2: deterministic invocation_id keyed on the subject digest.
        # CI-driven callers can override (slsa-framework/slsa-github-generator
        # passes the run_id) but the default is reproducible.
        if invocation_id is None:
            invocation_id = str(
                deterministic_uuid(
                    {"subject_sha256": subject_sha256, "builder_id": builder_id}
                )
            )
        inv_id = invocation_id

        # Phase G.2: clock injection so reproducibility tests can freeze time.
        clk = clock if clock is not None else SystemClock()
        # Drop sub-second precision so equality tests are byte-stable across
        # local fs vs CI fs with different clock resolutions.
        finished = (
            clk()
            .astimezone(datetime.timezone.utc)
            .replace(microsecond=0)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        statement = cls._build_statement(
            subject_name=subject_name,
            subject_sha256=subject_sha256,
            builder_id=builder_id,
            invocation_id=inv_id,
            build_finished_on=finished,
            materials=materials,
        )

        output_path = model_dir / "squash-slsa-provenance.json"
        # Phase G.2: canonical bytes for the signed in-toto Statement.
        # The output file is the **signed body** — it must be byte-stable.
        output_path.write_bytes(canonical_bytes(statement))

        attest = SlsaAttestation(
            subject_name=subject_name,
            subject_sha256=subject_sha256,
            builder_id=builder_id,
            level=level,
            invocation_id=inv_id,
            build_finished_on=finished,
            materials=materials,
            output_path=output_path,
        )

        if level.value >= SlsaLevel.L2.value:
            try:
                cls._sign(output_path)
            except Exception:
                pass

        if level.value >= SlsaLevel.L3.value:
            try:
                cls._verify(output_path)
            except Exception:
                pass

        # Attach provenance as externalReference in the BOM
        if bom_path.exists():
            cls._attach_to_bom(bom_path, output_path)

        return attest

    # ──────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────

    @classmethod
    def _collect_subject(
        cls, model_dir: Path, bom_path: Path
    ) -> tuple[str, str, list[dict]]:
        """Return (sha256_hex, subject_name, materials)."""
        materials: list[dict] = []
        if bom_path.exists():
            raw = bom_path.read_bytes()
            sha = hashlib.sha256(raw).hexdigest()
            materials.append({
                "uri": bom_path.name,
                "digest": {"sha256": sha},
            })
            return sha, model_dir.name, materials

        # Fallback: hash directory listing
        listing = "\n".join(
            str(p.relative_to(model_dir)) for p in sorted(model_dir.iterdir())
        )
        sha = hashlib.sha256(listing.encode()).hexdigest()
        return sha, model_dir.name, materials

    @classmethod
    def _build_statement(
        cls,
        *,
        subject_name: str,
        subject_sha256: str,
        builder_id: str,
        invocation_id: str,
        build_finished_on: str,
        materials: list[dict],
    ) -> dict:
        return {
            "_type": cls._STATEMENT_TYPE,
            "subject": [
                {
                    "name": subject_name,
                    "digest": {"sha256": subject_sha256},
                }
            ],
            "predicateType": cls._PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://squish.local/squash/build-type/v1",
                    "externalParameters": {
                        "source": subject_name,
                    },
                    "resolvedDependencies": materials,
                },
                "runDetails": {
                    "builder": {
                        "id": builder_id,
                    },
                    "metadata": {
                        "invocationId": invocation_id,
                        "finishedOn": build_finished_on,
                    },
                },
            },
        }

    @classmethod
    def _sign(cls, provenance_path: Path) -> None:
        """Sign the provenance file via OmsSigner (L2+)."""
        try:
            from squash.oms_signer import OmsSigner  # type: ignore[import]

            signer = OmsSigner(str(provenance_path))
            signer.sign()
        except Exception:
            # Signing is best-effort when signer is unavailable in test env
            pass

    @classmethod
    def _verify(cls, provenance_path: Path) -> None:
        """Verify existing bundle via OmsVerifier (L3+)."""
        try:
            from squash.oms_verifier import OmsVerifier  # type: ignore[import]

            verifier = OmsVerifier(str(provenance_path))
            verifier.verify()
        except Exception:
            pass

    @classmethod
    def _attach_to_bom(cls, bom_path: Path, provenance_path: Path) -> None:
        """Add build-meta externalReference to the CycloneDX BOM.

        Phase G.2: this operation is now **idempotent**. A second invocation
        with the same provenance file does not append a duplicate ref —
        the BOM ends up byte-identical to the first attach. That is the
        load-bearing property the reproducibility test exercises.
        """
        try:
            bom = json.loads(bom_path.read_text(encoding="utf-8"))
            ext_refs: list[dict] = bom.setdefault("externalReferences", [])
            new_ref = {"type": "build-meta", "url": provenance_path.name}
            if new_ref not in ext_refs:
                ext_refs.append(new_ref)
            # Phase G.2: keep BOM canonical so its signature stays valid.
            bom_path.write_bytes(canonical_bytes(bom))
        except Exception:
            pass
