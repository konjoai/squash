"""squash/iso42001.py — ISO/IEC 42001:2023 AI Management System readiness assessment.

Maps squash attestation artifacts to the 38 controls of ISO/IEC 42001:2023 —
the first internationally certified AI Management System standard (the AI
equivalent of ISO 27001).  Produces a gap analysis and remediation roadmap.

ISO 42001 structure
-------------------
Clause 4: Context of the organization
Clause 5: Leadership
Clause 6: Planning
Clause 7: Support
Clause 8: Operation
Clause 9: Performance evaluation
Clause 10: Improvement
Annex A: Controls (A.2–A.9)

Usage::

    from squash.iso42001 import Iso42001Assessor
    from pathlib import Path

    result = Iso42001Assessor.assess(Path("./my-model"))
    print(result.summary())
    result.save(Path("./iso42001-report.json"))

References
----------
* ISO/IEC 42001:2023 — https://www.iso.org/standard/81230.html
* ISO/IEC 42001 Overview — https://artificialintelligenceact.eu/iso-42001/
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class ControlStatus(str, Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    NOT_APPLICABLE = "N/A"


class ReadinessLevel(str, Enum):
    CERTIFIED_READY = "CERTIFIED_READY"       # ≥90% controls passing
    SUBSTANTIALLY_COMPLIANT = "SUBSTANTIALLY_COMPLIANT"  # 70–89%
    PARTIAL = "PARTIAL"                       # 40–69%
    EARLY_STAGE = "EARLY_STAGE"               # <40%


@dataclass
class ControlResult:
    control_id: str          # e.g. "A.6.1.1"
    clause: str              # e.g. "Clause 8" or "Annex A"
    title: str
    description: str
    status: ControlStatus
    evidence: list[str]      # artifacts that satisfy this control
    gap: str                 # what's missing (empty if PASS)
    remediation: str         # recommended action (empty if PASS)
    priority: str            # "High" / "Medium" / "Low"


@dataclass
class Iso42001Report:
    model_path: str
    assessed_at: str
    controls: list[ControlResult] = field(default_factory=list)
    readiness_level: ReadinessLevel = ReadinessLevel.EARLY_STAGE
    overall_score: float = 0.0
    passing: int = 0
    partial: int = 0
    failing: int = 0
    not_applicable: int = 0
    high_priority_gaps: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "ISO/IEC 42001:2023 AI Management System Readiness Assessment",
            "=" * 62,
            f"Model:      {self.model_path}",
            f"Assessed:   {self.assessed_at}",
            f"Readiness:  {self.readiness_level.value}",
            f"Score:      {self.overall_score:.1f}%",
            f"Controls:   {self.passing} PASS · {self.partial} PARTIAL · "
            f"{self.failing} FAIL · {self.not_applicable} N/A",
            "",
        ]
        if self.high_priority_gaps:
            lines.append("High-Priority Gaps:")
            for gap in self.high_priority_gaps:
                lines.append(f"  ⚠  {gap}")
            lines.append("")
        failing_controls = [c for c in self.controls if c.status == ControlStatus.FAIL]
        if failing_controls:
            lines.append("Remediation Roadmap:")
            for c in sorted(failing_controls, key=lambda x: ("High", "Medium", "Low").index(x.priority)):
                lines.append(f"  [{c.priority:6s}] {c.control_id} — {c.title}")
                lines.append(f"           → {c.remediation}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "ISO/IEC 42001:2023",
            "model_path": self.model_path,
            "assessed_at": self.assessed_at,
            "readiness_level": self.readiness_level.value,
            "overall_score": round(self.overall_score, 2),
            "controls_summary": {
                "passing": self.passing,
                "partial": self.partial,
                "failing": self.failing,
                "not_applicable": self.not_applicable,
            },
            "high_priority_gaps": self.high_priority_gaps,
            "controls": [
                {
                    "control_id": c.control_id,
                    "clause": c.clause,
                    "title": c.title,
                    "status": c.status.value,
                    "evidence": c.evidence,
                    "gap": c.gap,
                    "remediation": c.remediation,
                    "priority": c.priority,
                }
                for c in self.controls
            ],
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))
        log.info("ISO 42001 report written to %s", path)


# ── Control definitions ────────────────────────────────────────────────────────
# Each entry: (control_id, clause, title, description, evidence_files, priority)
# evidence_files: list of filenames that, if present, provide evidence for the control

_CONTROLS: list[tuple[str, str, str, str, list[str], str]] = [
    # Clause 4: Context
    ("4.1", "Clause 4", "Understanding the organization and its context",
     "Identify internal/external issues relevant to AI purpose and objectives.",
     ["squash_attestation.json", "model_card.md", "risk_assessment.json"],
     "High"),
    ("4.2", "Clause 4", "Understanding needs and expectations of interested parties",
     "Identify stakeholders and their AI-related requirements.",
     ["squash_attestation.json", "nist_rmf_report.json"],
     "High"),
    ("4.3", "Clause 4", "Determining the scope of the AI management system",
     "Define and document the AIMS scope boundary.",
     ["squash_attestation.json", ".squash.yml"],
     "Medium"),
    ("4.4", "Clause 4", "AI management system",
     "Establish, implement, maintain, and continually improve the AIMS.",
     ["squash_attestation.json"],
     "High"),
    # Clause 5: Leadership
    ("5.1", "Clause 5", "Leadership and commitment",
     "Top management demonstrates leadership and commitment to the AIMS.",
     ["squash_attestation.json"],
     "Medium"),
    ("5.2", "Clause 5", "AI policy",
     "Establish an AI policy that is appropriate to the organization's purpose.",
     [".squash.yml", "squash_attestation.json"],
     "High"),
    ("5.3", "Clause 5", "Organizational roles, responsibilities and authorities",
     "Assign and communicate AIMS roles and responsibilities.",
     ["squash_attestation.json", "model_card.md"],
     "Medium"),
    # Clause 6: Planning
    ("6.1.1", "Clause 6", "Actions to address risks and opportunities",
     "Determine risks and opportunities for the AIMS.",
     ["risk_assessment.json", "squash_attestation.json"],
     "High"),
    ("6.1.2", "Clause 6", "AI risk assessment",
     "Conduct AI-specific risk assessments and document results.",
     ["risk_assessment.json", "nist_rmf_report.json"],
     "High"),
    ("6.1.3", "Clause 6", "AI risk treatment",
     "Determine and implement risk treatment options.",
     ["risk_assessment.json", "remediation_plan.json"],
     "High"),
    ("6.2", "Clause 6", "AI objectives and planning",
     "Establish AI objectives at relevant functions and plan to achieve them.",
     ["squash_attestation.json", ".squash.yml"],
     "Medium"),
    # Clause 7: Support
    ("7.1", "Clause 7", "Resources",
     "Determine and provide resources needed for the AIMS.",
     ["squash_attestation.json"],
     "Low"),
    ("7.2", "Clause 7", "Competence",
     "Ensure persons doing AI work are competent.",
     ["model_card.md", "squash_attestation.json"],
     "Medium"),
    ("7.3", "Clause 7", "Awareness",
     "Ensure persons are aware of the AI policy and AIMS.",
     ["squash_attestation.json"],
     "Low"),
    ("7.4", "Clause 7", "Communication",
     "Determine internal/external communications relevant to the AIMS.",
     ["squash_attestation.json"],
     "Low"),
    ("7.5", "Clause 7", "Documented information",
     "Include required documented information in the AIMS.",
     ["squash_attestation.json", "cyclonedx-mlbom.json", "spdx.json",
      "slsa_provenance.json", "model_card.md"],
     "High"),
    # Clause 8: Operation
    ("8.1", "Clause 8", "Operational planning and control",
     "Plan, implement, control, and maintain AI system processes.",
     ["squash_attestation.json", "cicd_report.json"],
     "High"),
    ("8.2", "Clause 8", "AI system impact assessment",
     "Assess and document potential impacts of AI systems on individuals and society.",
     ["risk_assessment.json", "annex_iv.json", "nist_rmf_report.json"],
     "High"),
    ("8.3", "Clause 8", "AI system objectives and planning",
     "Define objectives for each AI system and plan measures to achieve them.",
     ["squash_attestation.json", "annex_iv.json"],
     "Medium"),
    ("8.4", "Clause 8", "AI system lifecycle",
     "Control all lifecycle phases: design, development, testing, deployment, retirement.",
     ["slsa_provenance.json", "squash_attestation.json", "annex_iv.json"],
     "High"),
    ("8.5", "Clause 8", "Data for AI systems",
     "Manage data quality, provenance, and lineage for AI system inputs.",
     ["dataset_provenance.json", "spdx.json", "annex_iv.json"],
     "High"),
    # Clause 9: Performance evaluation
    ("9.1", "Clause 9", "Monitoring, measurement, analysis and evaluation",
     "Monitor and evaluate the AIMS and AI system performance.",
     ["squash_attestation.json", "drift_report.json", "vex_report.json"],
     "High"),
    ("9.2", "Clause 9", "Internal audit",
     "Conduct internal audits of the AIMS at planned intervals.",
     ["squash_attestation.json", "audit_trail.json"],
     "Medium"),
    ("9.3", "Clause 9", "Management review",
     "Top management reviews the AIMS at planned intervals.",
     ["squash_attestation.json"],
     "Low"),
    # Clause 10: Improvement
    ("10.1", "Clause 10", "Nonconformity and corrective action",
     "React to nonconformities and take corrective actions.",
     ["remediation_plan.json", "squash_attestation.json"],
     "High"),
    ("10.2", "Clause 10", "Continual improvement",
     "Continually improve the suitability, adequacy and effectiveness of the AIMS.",
     ["squash_attestation.json", "drift_report.json"],
     "Medium"),
    # Annex A controls
    ("A.2.1", "Annex A", "Policies for AI",
     "Establish AI-specific policies covering development and deployment.",
     [".squash.yml", "squash_attestation.json"],
     "High"),
    ("A.2.2", "Annex A", "Internal organization for AI",
     "Define roles and responsibilities for AI governance.",
     ["model_card.md", "squash_attestation.json"],
     "Medium"),
    ("A.4.1", "Annex A", "AI system resources",
     "Identify and manage computational, data, and human resources.",
     ["squash_attestation.json", "annex_iv.json"],
     "Medium"),
    ("A.5.1", "Annex A", "Assessing impacts on individuals",
     "Assess AI system impacts on fundamental rights and individual wellbeing.",
     ["risk_assessment.json", "annex_iv.json"],
     "High"),
    ("A.5.2", "Annex A", "Assessing impacts on society",
     "Assess broader societal impacts including environmental and economic effects.",
     ["risk_assessment.json", "annex_iv.json"],
     "High"),
    ("A.6.1.1", "Annex A", "AI system design and development documentation",
     "Maintain documentation of design decisions and development procedures.",
     ["annex_iv.json", "model_card.md", "cyclonedx-mlbom.json"],
     "High"),
    ("A.6.1.2", "Annex A", "AI system testing and validation",
     "Test and validate AI systems before deployment and after updates.",
     ["squash_attestation.json", "nist_rmf_report.json"],
     "High"),
    ("A.6.1.3", "Annex A", "AI system deployment controls",
     "Control AI system deployment with approval gates and monitoring.",
     ["slsa_provenance.json", "squash_attestation.json"],
     "High"),
    ("A.7.1", "Annex A", "Data for AI — acquisition and processing",
     "Control data acquisition, labelling, and pre-processing.",
     ["dataset_provenance.json", "annex_iv.json"],
     "High"),
    ("A.7.2", "Annex A", "Data quality and integrity",
     "Assess and document data quality across AI system lifecycle.",
     ["dataset_provenance.json", "spdx.json"],
     "High"),
    ("A.8.1", "Annex A", "Monitoring AI systems in production",
     "Monitor AI system behavior, performance, and anomalies in production.",
     ["drift_report.json", "vex_report.json", "squash_attestation.json"],
     "High"),
    ("A.9.1", "Annex A", "Verifying AI system impacts",
     "Verify that actual AI system impacts match assessed impacts.",
     ["risk_assessment.json", "squash_attestation.json", "drift_report.json"],
     "Medium"),
]


# ── Assessor ──────────────────────────────────────────────────────────────────

class Iso42001Assessor:
    """Assess a model directory against ISO/IEC 42001:2023 controls."""

    @staticmethod
    def assess(model_path: Path) -> Iso42001Report:
        """Run the full 38-control ISO 42001 readiness assessment."""
        model_path = Path(model_path)
        present = _collect_artifacts(model_path)

        results: list[ControlResult] = []
        for ctrl_id, clause, title, description, evidence_files, priority in _CONTROLS:
            matched = [f for f in evidence_files if f in present]
            if not evidence_files:
                status = ControlStatus.PASS
                gap = ""
                remediation = ""
                evidence = []
            elif len(matched) == len(evidence_files):
                status = ControlStatus.PASS
                gap = ""
                remediation = ""
                evidence = matched
            elif matched:
                status = ControlStatus.PARTIAL
                missing = [f for f in evidence_files if f not in present]
                gap = f"Missing artifacts: {', '.join(missing)}"
                remediation = _remediation_for(ctrl_id)
                evidence = matched
            else:
                status = ControlStatus.FAIL
                gap = f"No supporting artifacts found. Expected: {', '.join(evidence_files)}"
                remediation = _remediation_for(ctrl_id)
                evidence = []

            results.append(ControlResult(
                control_id=ctrl_id,
                clause=clause,
                title=title,
                description=description,
                status=status,
                evidence=evidence,
                gap=gap,
                remediation=remediation,
                priority=priority,
            ))

        return _build_report(model_path, results)

    @staticmethod
    def assess_from_dict(artifacts: dict[str, Any], model_id: str = "model") -> Iso42001Report:
        """Assess from a pre-collected artifact dict (keys are filenames)."""
        present = set(artifacts.keys())

        results: list[ControlResult] = []
        for ctrl_id, clause, title, description, evidence_files, priority in _CONTROLS:
            matched = [f for f in evidence_files if f in present]
            if not evidence_files:
                status = ControlStatus.PASS
                gap = ""
                remediation = ""
                evidence = []
            elif len(matched) == len(evidence_files):
                status = ControlStatus.PASS
                gap = ""
                remediation = ""
                evidence = matched
            elif matched:
                status = ControlStatus.PARTIAL
                missing = [f for f in evidence_files if f not in present]
                gap = f"Missing artifacts: {', '.join(missing)}"
                remediation = _remediation_for(ctrl_id)
                evidence = matched
            else:
                status = ControlStatus.FAIL
                gap = f"No supporting artifacts found. Expected: {', '.join(evidence_files)}"
                remediation = _remediation_for(ctrl_id)
                evidence = []

            results.append(ControlResult(
                control_id=ctrl_id,
                clause=clause,
                title=title,
                description=description,
                status=status,
                evidence=evidence,
                gap=gap,
                remediation=remediation,
                priority=priority,
            ))

        # Use a mock path
        report = _build_report(Path(model_id), results)
        report.model_path = model_id
        return report


def _collect_artifacts(model_path: Path) -> set[str]:
    """Collect names of squash artifact files present in model_path."""
    present: set[str] = set()
    _KNOWN = {
        "squash_attestation.json", "cyclonedx-mlbom.json", "spdx.json",
        "slsa_provenance.json", "model_card.md", "risk_assessment.json",
        "nist_rmf_report.json", "annex_iv.json", "audit_trail.json",
        "drift_report.json", "vex_report.json", "dataset_provenance.json",
        "remediation_plan.json", "cicd_report.json", ".squash.yml",
    }
    if model_path.is_dir():
        for child in model_path.iterdir():
            if child.name in _KNOWN:
                present.add(child.name)
        # Also check for squash subdirectory
        squash_dir = model_path / "squash"
        if squash_dir.is_dir():
            for child in squash_dir.iterdir():
                if child.name in _KNOWN:
                    present.add(child.name)
    return present


def _remediation_for(ctrl_id: str) -> str:
    """Return a remediation recommendation for a specific control."""
    _REMEDIATIONS: dict[str, str] = {
        "4.1": "Run `squash attest` to generate the base attestation record documenting context.",
        "4.2": "Add stakeholder mapping to `.squash.yml` under `stakeholders:` key.",
        "4.3": "Define AIMS scope in `.squash.yml` under `scope:` and run `squash init`.",
        "4.4": "Run `squash attest --policy iso-42001` to establish AIMS baseline.",
        "5.1": "Document leadership commitment in `.squash.yml` under `governance.leadership:`.",
        "5.2": "Define AI policy in `.squash.yml` under `policy:` block.",
        "5.3": "Add role assignments to model card: `squash model-card --add-roles`.",
        "6.1.1": "Run `squash risk-assess` to identify and document risks and opportunities.",
        "6.1.2": "Run `squash risk-assess --framework iso-42001` for ISO-specific risk assessment.",
        "6.1.3": "Run `squash remediate` to generate and track risk treatment plans.",
        "6.2": "Add objectives to `.squash.yml` under `objectives:` and run `squash attest`.",
        "7.1": "Resources are documented during attestation — run `squash attest`.",
        "7.2": "Add team competencies to model card.",
        "7.3": "Awareness is demonstrated by CI/CD integration — run `squash install-hook`.",
        "7.4": "Communication artifacts generated by `squash attest` and webhook notifications.",
        "7.5": "Run full `squash attest --sign --policy eu-ai-act` to generate all required docs.",
        "8.1": "Integrate squash into CI/CD: `squash install-hook` and GitHub Actions integration.",
        "8.2": "Run `squash annex-iv generate` and `squash risk-assess` for impact assessment.",
        "8.3": "Document AI system objectives in `annex_iv.json` section 1.",
        "8.4": "Run `squash slsa-attest` for lifecycle provenance documentation.",
        "8.5": "Run `squash annex-iv generate` — includes dataset provenance section.",
        "9.1": "Run `squash drift-check` and `squash vex update` for continuous monitoring.",
        "9.2": "Schedule regular `squash attest` runs in CI/CD as audit evidence.",
        "9.3": "Generate board report with `squash board-report` for management review.",
        "10.1": "Run `squash remediate` when violations found to generate corrective action plan.",
        "10.2": "Enable `squash watch` for continuous improvement feedback loop.",
        "A.2.1": "Define AI policies in `.squash.yml` and run `squash attest --policy iso-42001`.",
        "A.2.2": "Add organizational roles to model card and squash configuration.",
        "A.4.1": "Resource information is captured in Annex IV — run `squash annex-iv generate`.",
        "A.5.1": "Run `squash risk-assess` for individual impact assessment documentation.",
        "A.5.2": "Include societal impact analysis in `squash risk-assess --include-societal`.",
        "A.6.1.1": "Run `squash annex-iv generate` for design and development documentation.",
        "A.6.1.2": "Attestation test results in `squash attest` output satisfy this control.",
        "A.6.1.3": "Use `squash slsa-attest` and CI/CD gate for deployment control evidence.",
        "A.7.1": "Run `squash annex-iv generate` — extracts data acquisition documentation.",
        "A.7.2": "Dataset provenance in `squash annex-iv generate` covers data quality.",
        "A.8.1": "Run `squash drift-check` and enable `squash watch` for production monitoring.",
        "A.9.1": "Compare `squash risk-assess` outputs pre/post deployment to verify impact.",
    }
    return _REMEDIATIONS.get(ctrl_id, f"Refer to ISO/IEC 42001:2023 control {ctrl_id} for requirements.")


def _build_report(model_path: Path, results: list[ControlResult]) -> Iso42001Report:
    passing = sum(1 for r in results if r.status == ControlStatus.PASS)
    partial = sum(1 for r in results if r.status == ControlStatus.PARTIAL)
    failing = sum(1 for r in results if r.status == ControlStatus.FAIL)
    na = sum(1 for r in results if r.status == ControlStatus.NOT_APPLICABLE)

    scored = len(results) - na
    score = (passing + 0.5 * partial) / max(scored, 1) * 100

    if score >= 90:
        level = ReadinessLevel.CERTIFIED_READY
    elif score >= 70:
        level = ReadinessLevel.SUBSTANTIALLY_COMPLIANT
    elif score >= 40:
        level = ReadinessLevel.PARTIAL
    else:
        level = ReadinessLevel.EARLY_STAGE

    high_gaps = [
        f"{r.control_id} — {r.title}: {r.gap}"
        for r in results
        if r.status == ControlStatus.FAIL and r.priority == "High"
    ]

    return Iso42001Report(
        model_path=str(model_path),
        assessed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        controls=results,
        readiness_level=level,
        overall_score=score,
        passing=passing,
        partial=partial,
        failing=failing,
        not_applicable=na,
        high_priority_gaps=high_gaps,
    )
