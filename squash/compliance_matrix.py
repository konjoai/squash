"""squash/compliance_matrix.py — Multi-Jurisdiction Compliance Matrix (Track D / D4).

A multinational LLM deployment touches 6+ jurisdictions on average. Today
the legal compliance mapping is a one-week consulting engagement per
deployment.  This module compresses that into a single command:

    squash compliance-matrix --regions eu,us,uk,sg,ca --models ./model

It produces a 2-D matrix of ``(requirement × jurisdiction) → status``,
identifies gaps, and emits a sequenced remediation plan that maximises
coverage per fix.  The HTML output is colour-coded, sortable, and has
zero JavaScript dependencies — it round-trips through legal-review email
intact.

Architecture
------------
* :class:`Jurisdiction` — canonical region codes (EU, US, UK, SG, CA, AU,
  CN, US-CO, US-NYC, US-FED, GLOBAL).
* :class:`Requirement` — one row of the matrix.  Has a list of
  jurisdictions it applies to, an evidence rule (``must_exist`` /
  ``must_be_truthy`` / ``must_be_at_least`` / ``custom``), the squash
  control that addresses it, and the source regulation IDs.
* :class:`MatrixCell` — one (requirement, jurisdiction) pair with a
  :class:`CellStatus`.
* :class:`ComplianceMatrix` — build / render / summarise.
* :class:`GapAnalyser` — sequenced remediation plan, ordered by
  *coverage_per_fix* (one fix that satisfies four cells beats four
  one-cell fixes).
* :func:`render_html` — pure Python, no JavaScript.

The requirement catalogue covers the 9 frameworks already in
``regulatory_feed.py`` plus UK ICO AI guidance and Singapore Model AI
Governance Framework v2 — that is 11 frameworks across 8 jurisdictions.
"""

from __future__ import annotations

import dataclasses
import datetime
import html
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Jurisdictions
# ──────────────────────────────────────────────────────────────────────────────


class Jurisdiction(str, Enum):
    GLOBAL = "global"
    EU = "eu"
    US = "us"          # alias / umbrella for US federal scope
    US_FED = "us-fed"
    US_CO = "us-co"     # Colorado
    US_NYC = "us-nyc"   # New York City Local Law 144
    UK = "uk"
    SG = "sg"
    CA = "ca"
    AU = "au"
    CN = "cn"

    @property
    def display(self) -> str:
        return _JURISDICTION_NAMES[self]


_JURISDICTION_NAMES: dict[Jurisdiction, str] = {
    Jurisdiction.GLOBAL: "Global",
    Jurisdiction.EU: "European Union",
    Jurisdiction.US: "United States",
    Jurisdiction.US_FED: "United States (Federal)",
    Jurisdiction.US_CO: "Colorado, USA",
    Jurisdiction.US_NYC: "New York City, USA",
    Jurisdiction.UK: "United Kingdom",
    Jurisdiction.SG: "Singapore",
    Jurisdiction.CA: "Canada",
    Jurisdiction.AU: "Australia",
    Jurisdiction.CN: "China",
}


_JURISDICTION_ALIASES: dict[str, Jurisdiction] = {
    "global": Jurisdiction.GLOBAL,
    "world": Jurisdiction.GLOBAL,
    "eu": Jurisdiction.EU,
    "europe": Jurisdiction.EU,
    "ec": Jurisdiction.EU,
    "us": Jurisdiction.US,
    "usa": Jurisdiction.US,
    "united-states": Jurisdiction.US,
    "us-fed": Jurisdiction.US_FED,
    "us-federal": Jurisdiction.US_FED,
    "us-co": Jurisdiction.US_CO,
    "colorado": Jurisdiction.US_CO,
    "us-nyc": Jurisdiction.US_NYC,
    "nyc": Jurisdiction.US_NYC,
    "uk": Jurisdiction.UK,
    "gb": Jurisdiction.UK,
    "britain": Jurisdiction.UK,
    "sg": Jurisdiction.SG,
    "singapore": Jurisdiction.SG,
    "ca": Jurisdiction.CA,
    "canada": Jurisdiction.CA,
    "au": Jurisdiction.AU,
    "australia": Jurisdiction.AU,
    "cn": Jurisdiction.CN,
    "china": Jurisdiction.CN,
}


def parse_region(value: str) -> Jurisdiction:
    """Resolve a string to a :class:`Jurisdiction`.  Raises on unknown."""

    key = value.strip().lower()
    if key in _JURISDICTION_ALIASES:
        return _JURISDICTION_ALIASES[key]
    raise ValueError(
        f"unknown jurisdiction: {value!r} — supported: "
        + ", ".join(sorted({j.value for j in Jurisdiction}))
    )


def parse_regions(spec: str | Iterable[str]) -> list[Jurisdiction]:
    """Accept ``"eu,us,uk"`` or ``["eu", "us"]`` and return ordered uniques."""

    if isinstance(spec, str):
        items = [s for s in re.split(r"[,\s]+", spec) if s]
    else:
        items = list(spec)
    seen: list[Jurisdiction] = []
    for item in items:
        j = parse_region(item)
        if j not in seen:
            seen.append(j)
    return seen


# ──────────────────────────────────────────────────────────────────────────────
# Cell status
# ──────────────────────────────────────────────────────────────────────────────


class CellStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "n/a"
    UNKNOWN = "unknown"

    @property
    def is_failing(self) -> bool:
        return self in (CellStatus.FAIL, CellStatus.PARTIAL)

    @property
    def severity_rank(self) -> int:
        """Higher == worse (used for ordering in remediation plans)."""

        return {
            CellStatus.PASS: 0,
            CellStatus.NOT_APPLICABLE: 0,
            CellStatus.UNKNOWN: 1,
            CellStatus.PARTIAL: 2,
            CellStatus.FAIL: 3,
        }[self]


# ──────────────────────────────────────────────────────────────────────────────
# Requirement model
# ──────────────────────────────────────────────────────────────────────────────


EvidencePredicate = Callable[[Mapping[str, Any], Path | None], "EvidenceCheck"]


@dataclass
class EvidenceCheck:
    passed: bool
    detail: str
    matched_path: str = ""
    found_value: Any = None
    partial: bool = False


@dataclass
class Requirement:
    requirement_id: str
    title: str
    description: str
    jurisdictions: list[Jurisdiction]
    regulations: list[str]               # reg_id list (matches regulatory_feed)
    squash_control: str                  # CLI command that addresses this
    evidence_paths: list[str] = field(default_factory=list)
    evidence_files: list[str] = field(default_factory=list)
    severity: str = "high"               # high / medium / low
    rule: str = "must_exist"             # must_exist / must_be_truthy / must_be_at_least / custom
    threshold: float | None = None
    custom_check: EvidencePredicate | None = None

    def applies_to(self, jurisdiction: Jurisdiction) -> bool:
        if jurisdiction in self.jurisdictions:
            return True
        if Jurisdiction.GLOBAL in self.jurisdictions:
            return True
        # Federal-level US requirements also apply when "us" is requested.
        if jurisdiction == Jurisdiction.US and Jurisdiction.US_FED in self.jurisdictions:
            return True
        if jurisdiction == Jurisdiction.US_FED and Jurisdiction.US in self.jurisdictions:
            return True
        return False

    # ── evaluation ─────────────────────────────────────────────────────────
    def evaluate(
        self,
        attestation: Mapping[str, Any],
        model_dir: Path | None,
    ) -> EvidenceCheck:
        if self.custom_check is not None:
            return self.custom_check(attestation, model_dir)

        if self.rule == "must_exist":
            return self._check_must_exist(attestation, model_dir)
        if self.rule == "must_be_truthy":
            return self._check_must_be_truthy(attestation)
        if self.rule == "must_be_at_least":
            return self._check_must_be_at_least(attestation)
        return EvidenceCheck(
            passed=False, detail=f"unknown rule: {self.rule}",
        )

    # ── evidence helpers ───────────────────────────────────────────────────
    def _check_must_exist(
        self,
        attestation: Mapping[str, Any],
        model_dir: Path | None,
    ) -> EvidenceCheck:
        for fp in self.evidence_files:
            if model_dir and (model_dir / fp).exists():
                return EvidenceCheck(
                    passed=True, detail=f"file present: {fp}",
                    matched_path=fp,
                )
        for path in self.evidence_paths:
            value = _resolve_dotted(attestation, path)
            if value is not None and value != "" and value != []:
                return EvidenceCheck(
                    passed=True,
                    detail=f"attestation field {path!r} present",
                    matched_path=path, found_value=value,
                )
        return EvidenceCheck(
            passed=False,
            detail=(
                "no evidence — expected "
                + ("file: " + ", ".join(self.evidence_files) if self.evidence_files else "")
                + (" or " if self.evidence_files and self.evidence_paths else "")
                + ("field: " + ", ".join(self.evidence_paths) if self.evidence_paths else "")
            ),
        )

    def _check_must_be_truthy(
        self, attestation: Mapping[str, Any],
    ) -> EvidenceCheck:
        for path in self.evidence_paths:
            value = _resolve_dotted(attestation, path)
            if value is True or (isinstance(value, (int, float)) and value > 0) \
                    or (isinstance(value, str) and value.strip() not in ("", "false", "0", "no")):
                return EvidenceCheck(
                    passed=True, detail=f"{path}={value!r}",
                    matched_path=path, found_value=value,
                )
        return EvidenceCheck(
            passed=False,
            detail=f"no truthy value at {self.evidence_paths!r}",
        )

    def _check_must_be_at_least(
        self, attestation: Mapping[str, Any],
    ) -> EvidenceCheck:
        threshold = self.threshold or 0.0
        best = float("-inf")
        best_path = ""
        for path in self.evidence_paths:
            value = _resolve_dotted(attestation, path)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if value > best:
                    best = float(value)
                    best_path = path
        if best == float("-inf"):
            return EvidenceCheck(
                passed=False,
                detail=f"no numeric value at {self.evidence_paths!r}",
            )
        if best >= threshold:
            return EvidenceCheck(
                passed=True,
                detail=f"{best_path}={best} ≥ {threshold}",
                matched_path=best_path, found_value=best,
            )
        return EvidenceCheck(
            passed=False, partial=True,
            detail=f"{best_path}={best} < {threshold}",
            matched_path=best_path, found_value=best,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Built-in catalogue
# ──────────────────────────────────────────────────────────────────────────────


def _build_catalogue() -> list[Requirement]:
    return [
        Requirement(
            requirement_id="annex_iv_docs",
            title="Technical documentation (Annex IV / equivalent)",
            description=(
                "Detailed technical documentation including model architecture, "
                "training data lineage, evaluation metrics, and intended purpose."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.UK, Jurisdiction.SG,
                Jurisdiction.CA, Jurisdiction.AU,
            ],
            regulations=["EU_AI_ACT", "ISO_42001"],
            squash_control="squash annex-iv generate",
            evidence_files=["annex_iv_documentation.json", "annex_iv_documentation.md"],
            evidence_paths=["annex_iv.generated", "documentation.annex_iv"],
            severity="high",
        ),
        Requirement(
            requirement_id="human_oversight",
            title="Human oversight mechanisms (Art. 14 / equivalent)",
            description=(
                "Documented procedures for human-in-the-loop control, override, "
                "and stop-button capability for high-risk AI systems."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.UK, Jurisdiction.SG,
                Jurisdiction.AU, Jurisdiction.CA,
            ],
            regulations=["EU_AI_ACT", "ISO_42001"],
            squash_control="squash attest --policy eu-ai-act",
            evidence_paths=[
                "policies.human_oversight",
                "governance.human_in_the_loop",
                "model_card.human_oversight",
            ],
            severity="high",
        ),
        Requirement(
            requirement_id="incident_response_plan",
            title="Serious incident response plan",
            description=(
                "Tested incident-response plan covering revocation, disclosure "
                "(EU Art. 73 — 15 working days), and remediation."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.US_FED, Jurisdiction.UK,
                Jurisdiction.CA, Jurisdiction.SG,
            ],
            regulations=["EU_AI_ACT", "FDA_AI_ML"],
            squash_control="squash freeze",
            evidence_files=["incident_response_plan.md", "INCIDENT_SUMMARY.txt"],
            evidence_paths=["incident.response_plan_present", "incident.tested"],
            severity="high",
        ),
        Requirement(
            requirement_id="risk_management",
            title="Risk management plan / framework",
            description=(
                "Documented AI risk-management process aligned with NIST AI RMF "
                "GOVERN/MAP/MEASURE/MANAGE or ISO 42001 §6."
            ),
            jurisdictions=[
                Jurisdiction.GLOBAL, Jurisdiction.EU, Jurisdiction.US_FED,
                Jurisdiction.UK, Jurisdiction.SG, Jurisdiction.CA,
                Jurisdiction.AU,
            ],
            regulations=["NIST_AI_RMF", "ISO_42001", "EU_AI_ACT"],
            squash_control="squash risk-assess",
            evidence_files=["risk_assessment.json", "risk_assessment.md"],
            evidence_paths=["risk.score", "risk_assessment.summary"],
            severity="high",
        ),
        Requirement(
            requirement_id="bias_audit",
            title="Bias / fairness audit (Colorado AI Act, NYC LL144 §1894)",
            description=(
                "Independent bias audit with disparate-impact analysis across "
                "protected classes; required annually for automated employment "
                "decision tools (NYC) and high-risk AI (Colorado)."
            ),
            jurisdictions=[
                Jurisdiction.US_CO, Jurisdiction.US_NYC, Jurisdiction.EU,
                Jurisdiction.UK,
            ],
            regulations=["COLORADO_AI_ACT", "NYC_LOCAL_LAW_144", "EU_AI_ACT"],
            squash_control="squash bias-audit",
            evidence_files=["bias_audit.json", "bias_audit_report.md"],
            evidence_paths=["bias.audit_passed", "fairness.audit"],
            severity="high",
        ),
        Requirement(
            requirement_id="data_governance",
            title="Data governance and lineage (GDPR Art. 30)",
            description=(
                "Documented training data provenance, licensing, deduplication, "
                "and processing records (GDPR Art. 30 / UK GDPR / SG PDPA)."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.UK, Jurisdiction.SG,
                Jurisdiction.CA,
            ],
            regulations=["EU_GDPR_AI"],
            squash_control="squash data-lineage",
            evidence_files=["data_lineage_certificate.json", "data_lineage.json"],
            evidence_paths=[
                "data_lineage.datasets",
                "training.dataset_ids",
            ],
            severity="high",
        ),
        Requirement(
            requirement_id="transparency_disclosure",
            title="Transparency / model card disclosure",
            description=(
                "User-visible disclosure of AI system capabilities, limitations, "
                "and intended purpose (EU AI Act Art. 13 / SEC AI Disclosure / "
                "ISO 42001 §7)."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.US_FED, Jurisdiction.UK,
                Jurisdiction.SG, Jurisdiction.AU, Jurisdiction.CA,
            ],
            regulations=["EU_AI_ACT", "SEC_AI_DISCLOSURE", "ISO_42001"],
            squash_control="squash model-card generate",
            evidence_files=[
                "squash-model-card-hf.md", "squash-model-card-euaiact.md",
                "MODEL_CARD.md", "model_card.md",
            ],
            evidence_paths=["model_card.path", "transparency.disclosure"],
            severity="medium",
        ),
        Requirement(
            requirement_id="post_market_monitoring",
            title="Post-market monitoring (EU Art. 9 / FDA SaMD)",
            description=(
                "Continuous monitoring of model performance, drift, and "
                "hallucination rate after deployment."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.US_FED, Jurisdiction.UK,
            ],
            regulations=["EU_AI_ACT", "FDA_AI_ML"],
            squash_control="squash hallucination-monitor run",
            evidence_files=[
                "drift_certificate.json", "hallucination_monitor.json",
            ],
            evidence_paths=[
                "monitoring.enabled", "drift.tracked",
                "hallucination_monitor.enabled",
            ],
            severity="high",
        ),
        Requirement(
            requirement_id="carbon_attestation",
            title="Carbon / energy attestation (CSRD / SECR / SG Green Plan)",
            description=(
                "Reportable training-energy and inference-energy disclosures "
                "(EU CSRD Art. 19a, UK SECR, Singapore Green Plan 2030)."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.UK, Jurisdiction.SG,
            ],
            regulations=["EU_AI_ACT"],
            squash_control="squash attest-carbon",
            evidence_files=["carbon_certificate.json", "energy_attestation.json"],
            evidence_paths=["carbon.kgco2e", "energy.training_kwh"],
            severity="medium",
        ),
        Requirement(
            requirement_id="identity_least_privilege",
            title="AI agent identity & least-privilege",
            description=(
                "Service-account scopes, MFA, and credential rotation for "
                "AI agents (FedRAMP AC-2, NIST 800-53, ISO 42001 §6.5)."
            ),
            jurisdictions=[
                Jurisdiction.US_FED, Jurisdiction.GLOBAL, Jurisdiction.UK,
                Jurisdiction.AU,
            ],
            regulations=["FEDRAMP_AI", "NIST_AI_RMF"],
            squash_control="squash attest-identity attest",
            evidence_files=["identity_attestation.json"],
            evidence_paths=["identity.score", "identity.attestation_passed"],
            severity="high",
        ),
        Requirement(
            requirement_id="hallucination_rate",
            title="Hallucination rate certificate (EU Art. 13 / domain-specific)",
            description=(
                "Signed, CI-bounded hallucination rate within domain-calibrated "
                "thresholds (legal 2%, medical 2%, financial 3%, code 5%)."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.US_FED, Jurisdiction.UK,
            ],
            regulations=["EU_AI_ACT"],
            squash_control="squash hallucination-attest attest",
            evidence_files=[
                "hallucination_certificate.json",
                "hallucination_attest.json",
            ],
            evidence_paths=["hallucination.rate", "hallucination.passed"],
            severity="medium",
        ),
        Requirement(
            requirement_id="conformity_assessment",
            title="Conformity assessment / pre-deployment review",
            description=(
                "Formal conformity assessment for high-risk AI before market "
                "placement (EU AI Act Art. 43; UK MHRA for AI as medical device)."
            ),
            jurisdictions=[Jurisdiction.EU, Jurisdiction.UK],
            regulations=["EU_AI_ACT"],
            squash_control="squash request-approval",
            evidence_files=["approval_record.json"],
            evidence_paths=["approval.granted_at"],
            severity="high",
        ),
        Requirement(
            requirement_id="model_card_validator",
            title="Model card validator (HuggingFace card-spec / ISO 42001 §7.2)",
            description="Validated model card metadata (license, base_model, datasets).",
            jurisdictions=[
                Jurisdiction.GLOBAL, Jurisdiction.EU, Jurisdiction.UK,
                Jurisdiction.SG, Jurisdiction.AU, Jurisdiction.CA,
            ],
            regulations=["ISO_42001"],
            squash_control="squash model-card validate",
            evidence_paths=["model_card.validated"],
            severity="low",
        ),
        Requirement(
            requirement_id="financial_disclosure",
            title="SEC AI disclosure (10-K Item 1A)",
            description=(
                "Public-company disclosure of material AI-related risks in "
                "annual 10-K filings (SEC AI Operation Comply)."
            ),
            jurisdictions=[Jurisdiction.US_FED, Jurisdiction.US],
            regulations=["SEC_AI_DISCLOSURE"],
            squash_control="squash detect-washing scan",
            evidence_files=["ai_washing_report.json", "sec_disclosure.json"],
            evidence_paths=["sec_disclosure.filed"],
            severity="medium",
        ),
        Requirement(
            requirement_id="copyright_attestation",
            title="Copyright / training-data licence attestation",
            description=(
                "Signed certificate confirming training data licence "
                "compatibility with the deployment use case (EU AI Act Art. 53, "
                "Canada AIDA s.39)."
            ),
            jurisdictions=[
                Jurisdiction.EU, Jurisdiction.UK, Jurisdiction.CA,
                Jurisdiction.US_FED,
            ],
            regulations=["EU_AI_ACT"],
            squash_control="squash copyright-check",
            evidence_files=[
                "copyright_certificate.json", "license_check_report.json",
            ],
            evidence_paths=["copyright.verdict", "license.compatible"],
            severity="high",
        ),
    ]


_CATALOGUE: list[Requirement] = _build_catalogue()


def builtin_requirements() -> list[Requirement]:
    """Return a copy of the built-in requirement catalogue."""

    return list(_CATALOGUE)


# ──────────────────────────────────────────────────────────────────────────────
# Matrix model
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class MatrixCell:
    requirement_id: str
    requirement_title: str
    jurisdiction: Jurisdiction
    status: CellStatus
    detail: str = ""
    evidence: str = ""
    squash_control: str = ""
    severity: str = "high"
    regulations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "requirement_title": self.requirement_title,
            "jurisdiction": self.jurisdiction.value,
            "status": self.status.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "squash_control": self.squash_control,
            "severity": self.severity,
            "regulations": list(self.regulations),
        }


@dataclass
class MatrixSummary:
    total_cells: int = 0
    pass_count: int = 0
    fail_count: int = 0
    partial_count: int = 0
    not_applicable_count: int = 0
    unknown_count: int = 0

    @property
    def applicable_cells(self) -> int:
        return self.total_cells - self.not_applicable_count

    @property
    def coverage_pct(self) -> float:
        a = self.applicable_cells
        return (self.pass_count / a * 100.0) if a else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_cells": self.total_cells,
            "pass": self.pass_count,
            "fail": self.fail_count,
            "partial": self.partial_count,
            "not_applicable": self.not_applicable_count,
            "unknown": self.unknown_count,
            "coverage_pct": round(self.coverage_pct, 1),
        }


@dataclass
class ComplianceMatrix:
    jurisdictions: list[Jurisdiction]
    requirements: list[Requirement]
    cells: list[MatrixCell]
    summary: MatrixSummary
    generated_at: str = ""
    model_id: str = ""
    model_path: str = ""

    # ── construction ───────────────────────────────────────────────────────
    @staticmethod
    def build(
        regions: Iterable[Jurisdiction] | str | Iterable[str],
        attestation: Mapping[str, Any] | None = None,
        model_dir: str | Path | None = None,
        *,
        requirements: Iterable[Requirement] | None = None,
        model_id: str = "",
    ) -> "ComplianceMatrix":
        if isinstance(regions, str) or (
            not isinstance(regions, list)
            and not all(isinstance(x, Jurisdiction) for x in regions)  # type: ignore[arg-type]
        ):
            jurs = parse_regions(regions)  # type: ignore[arg-type]
        else:
            jurs = list(regions)  # type: ignore[arg-type]
            if not all(isinstance(j, Jurisdiction) for j in jurs):
                jurs = parse_regions(jurs)  # type: ignore[arg-type]

        reqs = list(requirements) if requirements is not None else builtin_requirements()
        att = dict(attestation or {})
        model_path = Path(model_dir) if model_dir else None
        if model_path is not None and not model_path.exists():
            log.warning("model_dir %s does not exist", model_path)
            model_path = None

        cells: list[MatrixCell] = []
        summary = MatrixSummary()
        for r in reqs:
            for j in jurs:
                summary.total_cells += 1
                if not r.applies_to(j):
                    cells.append(MatrixCell(
                        requirement_id=r.requirement_id,
                        requirement_title=r.title,
                        jurisdiction=j,
                        status=CellStatus.NOT_APPLICABLE,
                        detail="not required in this jurisdiction",
                        squash_control=r.squash_control,
                        severity=r.severity,
                        regulations=list(r.regulations),
                    ))
                    summary.not_applicable_count += 1
                    continue

                check = r.evaluate(att, model_path)
                if check.passed:
                    status = CellStatus.PASS
                    summary.pass_count += 1
                elif check.partial:
                    status = CellStatus.PARTIAL
                    summary.partial_count += 1
                elif not r.evidence_files and not r.evidence_paths:
                    status = CellStatus.UNKNOWN
                    summary.unknown_count += 1
                else:
                    status = CellStatus.FAIL
                    summary.fail_count += 1

                cells.append(MatrixCell(
                    requirement_id=r.requirement_id,
                    requirement_title=r.title,
                    jurisdiction=j,
                    status=status,
                    detail=check.detail,
                    evidence=check.matched_path,
                    squash_control=r.squash_control,
                    severity=r.severity,
                    regulations=list(r.regulations),
                ))

        return ComplianceMatrix(
            jurisdictions=jurs,
            requirements=reqs,
            cells=cells,
            summary=summary,
            generated_at=_utc_iso(),
            model_id=model_id,
            model_path=str(model_path) if model_path else "",
        )

    # ── accessors ──────────────────────────────────────────────────────────
    def cells_for_requirement(self, requirement_id: str) -> list[MatrixCell]:
        return [c for c in self.cells if c.requirement_id == requirement_id]

    def cells_for_jurisdiction(self, jurisdiction: Jurisdiction) -> list[MatrixCell]:
        return [c for c in self.cells if c.jurisdiction == jurisdiction]

    def failing_cells(self) -> list[MatrixCell]:
        return [c for c in self.cells if c.status.is_failing]

    def coverage_by_jurisdiction(self) -> dict[Jurisdiction, float]:
        out: dict[Jurisdiction, float] = {}
        for j in self.jurisdictions:
            cells = [c for c in self.cells if c.jurisdiction == j
                     and c.status != CellStatus.NOT_APPLICABLE]
            if not cells:
                out[j] = 0.0
                continue
            passing = sum(1 for c in cells if c.status == CellStatus.PASS)
            out[j] = round(passing / len(cells) * 100.0, 1)
        return out

    # ── serialisation ──────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "squash.compliance_matrix/v1",
            "generated_at": self.generated_at,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "jurisdictions": [j.value for j in self.jurisdictions],
            "requirements": [r.requirement_id for r in self.requirements],
            "summary": self.summary.to_dict(),
            "coverage_by_jurisdiction": {
                j.value: pct for j, pct in self.coverage_by_jurisdiction().items()
            },
            "cells": [c.to_dict() for c in self.cells],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        return _render_markdown(self)

    def to_text(self) -> str:
        return _render_text(self)

    def to_html(self) -> str:
        return render_html(self)


# ──────────────────────────────────────────────────────────────────────────────
# Gap analyser & remediation plan
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class RemediationStep:
    squash_control: str
    addresses_requirement_ids: list[str]
    addresses_jurisdictions: list[Jurisdiction]
    coverage_count: int
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "squash_control": self.squash_control,
            "addresses_requirement_ids": list(self.addresses_requirement_ids),
            "addresses_jurisdictions": [j.value for j in self.addresses_jurisdictions],
            "coverage_count": self.coverage_count,
            "severity": self.severity,
            "detail": self.detail,
        }


class GapAnalyser:
    """Build a sequenced remediation plan, ordered by coverage_per_fix.

    The greedy ordering: each step is the squash control that addresses the
    largest number of currently-failing cells.  After applying a step, those
    cells are marked covered, and the next step is recomputed.
    """

    def __init__(self, matrix: ComplianceMatrix) -> None:
        self._matrix = matrix

    def plan(self) -> list[RemediationStep]:
        failing = list(self._matrix.failing_cells())
        steps: list[RemediationStep] = []
        # group failing cells by squash_control
        while failing:
            buckets: dict[str, list[MatrixCell]] = {}
            for c in failing:
                buckets.setdefault(c.squash_control, []).append(c)
            best_ctl = max(buckets.keys(), key=lambda k: len(buckets[k]))
            cells = buckets[best_ctl]
            req_ids = sorted({c.requirement_id for c in cells})
            jurs: list[Jurisdiction] = []
            for c in cells:
                if c.jurisdiction not in jurs:
                    jurs.append(c.jurisdiction)
            severity = (
                "high" if any(c.severity == "high" for c in cells)
                else "medium" if any(c.severity == "medium" for c in cells)
                else "low"
            )
            steps.append(RemediationStep(
                squash_control=best_ctl,
                addresses_requirement_ids=req_ids,
                addresses_jurisdictions=jurs,
                coverage_count=len(cells),
                severity=severity,
                detail=(
                    f"{len(cells)} failing cell(s) across "
                    f"{len(req_ids)} requirement(s) and "
                    f"{len(jurs)} jurisdiction(s)"
                ),
            ))
            failing = [c for c in failing if c.squash_control != best_ctl]
        return steps


# ──────────────────────────────────────────────────────────────────────────────
# Renderers
# ──────────────────────────────────────────────────────────────────────────────


_STATUS_GLYPH = {
    CellStatus.PASS: "✓",
    CellStatus.FAIL: "✗",
    CellStatus.PARTIAL: "◑",
    CellStatus.NOT_APPLICABLE: "—",
    CellStatus.UNKNOWN: "?",
}


def _render_text(matrix: ComplianceMatrix) -> str:
    lines = [
        "SQUASH COMPLIANCE MATRIX",
        "=" * 60,
        f"Generated: {matrix.generated_at}",
        f"Model:     {matrix.model_id or '(unspecified)'}",
        f"Region(s): {', '.join(j.value for j in matrix.jurisdictions)}",
        "",
        f"Summary: {matrix.summary.pass_count} pass · "
        f"{matrix.summary.fail_count} fail · "
        f"{matrix.summary.partial_count} partial · "
        f"{matrix.summary.not_applicable_count} n/a · "
        f"{matrix.summary.unknown_count} unknown — "
        f"{matrix.summary.coverage_pct:.1f}% coverage",
        "",
    ]
    # header row
    j_codes = [j.value for j in matrix.jurisdictions]
    width = max(36, max((len(r.title) for r in matrix.requirements), default=20))
    j_width = max(6, max(len(c) for c in j_codes))
    lines.append(
        "Requirement".ljust(width) + " | "
        + " | ".join(c.center(j_width) for c in j_codes)
    )
    lines.append("-" * (width + (j_width + 3) * len(j_codes)))
    by_req: dict[str, dict[Jurisdiction, MatrixCell]] = {}
    for c in matrix.cells:
        by_req.setdefault(c.requirement_id, {})[c.jurisdiction] = c
    for r in matrix.requirements:
        row = r.title[:width].ljust(width)
        for j in matrix.jurisdictions:
            cell = by_req.get(r.requirement_id, {}).get(j)
            glyph = _STATUS_GLYPH[cell.status] if cell else "?"
            row += " | " + glyph.center(j_width)
        lines.append(row)
    return "\n".join(lines) + "\n"


def _render_markdown(matrix: ComplianceMatrix) -> str:
    lines = [
        "# squash compliance matrix",
        "",
        f"- **Generated:** {matrix.generated_at}",
        f"- **Model:** {matrix.model_id or '_(unspecified)_'}",
        f"- **Jurisdictions:** {', '.join(j.value for j in matrix.jurisdictions)}",
        f"- **Coverage:** {matrix.summary.coverage_pct:.1f}% "
        f"({matrix.summary.pass_count}/"
        f"{matrix.summary.applicable_cells} applicable cells)",
        "",
        "| Requirement | " + " | ".join(j.value for j in matrix.jurisdictions) + " |",
        "| --- | " + " | ".join("---" for _ in matrix.jurisdictions) + " |",
    ]
    by_req: dict[str, dict[Jurisdiction, MatrixCell]] = {}
    for c in matrix.cells:
        by_req.setdefault(c.requirement_id, {})[c.jurisdiction] = c
    for r in matrix.requirements:
        row = [r.title]
        for j in matrix.jurisdictions:
            cell = by_req.get(r.requirement_id, {}).get(j)
            row.append(_STATUS_GLYPH[cell.status] if cell else "?")
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


_HTML_STATUS_CLASS = {
    CellStatus.PASS: "pass",
    CellStatus.FAIL: "fail",
    CellStatus.PARTIAL: "partial",
    CellStatus.NOT_APPLICABLE: "na",
    CellStatus.UNKNOWN: "unknown",
}


_HTML_CSS = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
       margin: 2rem; line-height: 1.5; color: #1f2328; background: #ffffff; }
h1 { margin-top: 0; }
.meta { color: #57606a; margin-bottom: 1.5rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.summary div { padding: .5rem .75rem; border-radius: 6px; border: 1px solid #d0d7de; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { border: 1px solid #d0d7de; padding: .5rem .75rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; position: sticky; top: 0; }
td.cell { text-align: center; font-weight: 600; }
td.cell.pass    { background: #dcfce7; color: #14532d; }
td.cell.fail    { background: #fee2e2; color: #7f1d1d; }
td.cell.partial { background: #fef3c7; color: #78350f; }
td.cell.na      { background: #f3f4f6; color: #4b5563; }
td.cell.unknown { background: #e5e7eb; color: #1f2937; }
.severity-high   { border-left: 3px solid #dc2626; }
.severity-medium { border-left: 3px solid #d97706; }
.severity-low    { border-left: 3px solid #2563eb; }
.legend { margin-top: 1rem; font-size: 13px; color: #57606a; }
.remediation { margin-top: 2rem; }
.remediation li { margin-bottom: .5rem; }
"""


def render_html(matrix: ComplianceMatrix) -> str:
    """Pure-Python HTML renderer. No JavaScript dependencies."""

    e = html.escape
    by_req: dict[str, dict[Jurisdiction, MatrixCell]] = {}
    for c in matrix.cells:
        by_req.setdefault(c.requirement_id, {})[c.jurisdiction] = c

    head = (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>squash compliance matrix — {e(matrix.model_id or 'unspecified')}</title>"
        f"<style>{_HTML_CSS}</style></head><body>"
    )
    body = [
        f"<h1>squash compliance matrix</h1>",
        f"<p class='meta'>"
        f"Generated <strong>{e(matrix.generated_at)}</strong> · "
        f"Model <strong>{e(matrix.model_id or '(unspecified)')}</strong> · "
        f"Jurisdictions <strong>"
        f"{e(', '.join(j.value for j in matrix.jurisdictions))}</strong>"
        f"</p>",
        "<div class='summary'>",
        f"<div>{matrix.summary.pass_count} pass</div>",
        f"<div>{matrix.summary.fail_count} fail</div>",
        f"<div>{matrix.summary.partial_count} partial</div>",
        f"<div>{matrix.summary.not_applicable_count} n/a</div>",
        f"<div>{matrix.summary.unknown_count} unknown</div>",
        f"<div><strong>{matrix.summary.coverage_pct:.1f}%</strong> coverage</div>",
        "</div>",
        "<table>",
        "<thead><tr><th>Requirement</th>",
    ]
    for j in matrix.jurisdictions:
        body.append(f"<th>{e(j.display)}</th>")
    body.append("<th>Squash control</th></tr></thead><tbody>")

    for r in matrix.requirements:
        sev_class = f"severity-{e(r.severity)}"
        body.append(
            f"<tr class='{sev_class}'><td>"
            f"<strong>{e(r.title)}</strong><br>"
            f"<small>{e(r.description)}</small></td>"
        )
        for j in matrix.jurisdictions:
            cell = by_req.get(r.requirement_id, {}).get(j)
            if cell is None:
                body.append("<td class='cell unknown'>?</td>")
                continue
            cls = _HTML_STATUS_CLASS[cell.status]
            tooltip = e(cell.detail)
            glyph = _STATUS_GLYPH[cell.status]
            body.append(
                f"<td class='cell {cls}' title='{tooltip}'>"
                f"{glyph} {e(cell.status.value)}</td>"
            )
        body.append(f"<td><code>{e(r.squash_control)}</code></td>")
        body.append("</tr>")
    body.append("</tbody></table>")

    body.append(
        "<p class='legend'>Legend: ✓ pass · ✗ fail · ◑ partial · "
        "— not applicable · ? unknown</p>"
    )

    plan = GapAnalyser(matrix).plan()
    if plan:
        body.append("<div class='remediation'>")
        body.append("<h2>Remediation plan (greedy coverage-per-fix)</h2>")
        body.append("<ol>")
        for s in plan:
            body.append(
                "<li><code>" + e(s.squash_control) + "</code> — "
                + e(s.detail) + "</li>"
            )
        body.append("</ol></div>")

    body.append("</body></html>")
    return head + "\n".join(body)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _resolve_dotted(doc: Mapping[str, Any], path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _utc_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load_attestation_dir(model_dir: str | Path) -> dict[str, Any]:
    """Best-effort: load every ``*.json`` file under ``model_dir`` into a flat
    namespace keyed by the file stem.  Returns an empty dict if the dir does
    not exist."""

    p = Path(model_dir)
    if not p.exists() or not p.is_dir():
        return {}
    out: dict[str, Any] = {}
    for child in sorted(p.glob("*.json")):
        try:
            out[child.stem] = json.loads(child.read_text())
        except Exception:  # noqa: BLE001
            log.warning("could not parse %s as JSON", child)
    return out


__all__ = [
    "CellStatus",
    "ComplianceMatrix",
    "EvidenceCheck",
    "GapAnalyser",
    "Jurisdiction",
    "MatrixCell",
    "MatrixSummary",
    "RemediationStep",
    "Requirement",
    "builtin_requirements",
    "load_attestation_dir",
    "parse_region",
    "parse_regions",
    "render_html",
]
