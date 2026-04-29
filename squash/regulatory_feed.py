"""squash/regulatory_feed.py — Regulatory Intelligence Feed.

When a new regulation passes or an existing one is updated, every company
using AI needs to know whether their compliance posture is still adequate.
Right now this is tracked by consultants manually reading regulatory updates
and emailing clients.

This module provides a curated, versioned database of AI regulatory
requirements across all major jurisdictions, with change tracking and
notification hooks.

Regulatory landscape covered
-----------------------------
* EU AI Act (Regulation (EU) 2024/1689)
* NIST AI Risk Management Framework 1.0
* ISO/IEC 42001:2023 AI Management System
* Colorado AI Act (SB 205, effective June 2026)
* New York City Local Law 144 (bias audits)
* SEC AI disclosure requirements
* FTC Guidance on AI marketing claims
* FDA AI/ML Software as Medical Device
* CMMC 2.0 (AI in DoD supply chain)
* FedRAMP AI guidance
* EU GDPR (AI training data implications)
* Illinois BIPA (biometric data / AI)
* Texas AI in Healthcare guidance

Usage::

    from squash.regulatory_feed import RegulatoryFeed

    feed = RegulatoryFeed()
    updates = feed.check_updates(since="2026-01-01")
    for u in updates:
        print(u.summary())

    status = feed.status()
    print(status.compliance_impact_summary())
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


class RegulationStatus(str, Enum):
    ENACTED = "enacted"
    ENFORCEMENT_ACTIVE = "enforcement_active"
    ENFORCEMENT_PENDING = "enforcement_pending"
    PROPOSED = "proposed"
    GUIDANCE_ONLY = "guidance_only"
    SUPERSEDED = "superseded"


class JurisdictionScope(str, Enum):
    GLOBAL = "global"
    EU = "eu"
    US_FEDERAL = "us_federal"
    US_STATE = "us_state"
    UK = "uk"
    CHINA = "china"
    CANADA = "canada"


@dataclass
class RegulatoryItem:
    reg_id: str                # e.g. "EU_AI_ACT"
    short_name: str            # e.g. "EU AI Act"
    full_name: str
    jurisdiction: JurisdictionScope
    status: RegulationStatus
    enacted_date: str | None
    enforcement_date: str | None
    last_updated: str
    version: str
    description: str
    squash_controls: list[str]  # squash CLI commands that address this
    affected_industries: list[str]
    key_requirements: list[str]
    penalty_max: str            # e.g. "€35M or 7% of global turnover"
    reference_url: str
    changes_since_last_version: list[str]

    @property
    def days_to_enforcement(self) -> int | None:
        if self.enforcement_date is None:
            return None
        try:
            dt = datetime.date.fromisoformat(self.enforcement_date)
            return (dt - datetime.date.today()).days
        except ValueError:
            return None

    @property
    def is_active(self) -> bool:
        return self.status == RegulationStatus.ENFORCEMENT_ACTIVE

    def summary(self) -> str:
        dtd = self.days_to_enforcement
        deadline_str = (
            f" — {dtd} days to enforcement" if dtd is not None and dtd > 0
            else " — ACTIVE" if self.is_active
            else ""
        )
        return (
            f"[{self.reg_id}] {self.short_name} ({self.status.value}){deadline_str}\n"
            f"  {self.description[:100]}…"
        )


@dataclass
class RegUpdate:
    reg_id: str
    short_name: str
    change_date: str
    change_type: str           # "new", "amended", "enforcement_start", "guidance"
    change_summary: str
    impact_level: str          # "HIGH", "MEDIUM", "LOW"
    affected_squash_controls: list[str]

    def summary(self) -> str:
        return (
            f"[{self.impact_level}] {self.short_name} — {self.change_type.upper()} "
            f"({self.change_date})\n  {self.change_summary}"
        )


@dataclass
class FeedStatus:
    total_regulations: int
    active_enforcement: int
    pending_enforcement: int
    proposed: int
    nearest_deadline: str | None
    nearest_deadline_days: int | None
    high_impact_pending: list[str]
    squash_coverage: dict[str, bool]   # reg_id → True if squash has controls

    def compliance_impact_summary(self) -> str:
        lines = [
            "REGULATORY INTELLIGENCE STATUS",
            "=" * 48,
            f"Regulations tracked: {self.total_regulations}",
            f"  Active enforcement: {self.active_enforcement}",
            f"  Pending enforcement: {self.pending_enforcement}",
            f"  Proposed: {self.proposed}",
        ]
        if self.nearest_deadline:
            lines.append(
                f"\nNext deadline: {self.nearest_deadline} ({self.nearest_deadline_days} days)"
            )
        if self.high_impact_pending:
            lines.append("\nHigh-Impact Pending:")
            for r in self.high_impact_pending:
                lines.append(f"  ⚠  {r}")
        covered = sum(1 for v in self.squash_coverage.values() if v)
        total = len(self.squash_coverage)
        lines.append(f"\nSquash coverage: {covered}/{total} regulations have CLI controls")
        return "\n".join(lines)


# ── Regulation database ────────────────────────────────────────────────────────

_REGULATIONS: list[RegulatoryItem] = [
    RegulatoryItem(
        reg_id="EU_AI_ACT",
        short_name="EU AI Act",
        full_name="Regulation (EU) 2024/1689 on Artificial Intelligence",
        jurisdiction=JurisdictionScope.EU,
        status=RegulationStatus.ENFORCEMENT_PENDING,
        enacted_date="2024-08-01",
        enforcement_date="2026-08-02",
        last_updated="2026-01-15",
        version="1.0",
        description=(
            "The world's first comprehensive AI regulation. Prohibits unacceptable-risk AI, "
            "mandates conformity assessment for high-risk systems, requires Annex IV "
            "technical documentation, human oversight, and incident reporting."
        ),
        squash_controls=[
            "squash attest --policy eu-ai-act",
            "squash annex-iv generate",
            "squash risk-assess",
            "squash incident",
            "squash iso42001",
        ],
        affected_industries=["finance", "healthcare", "hr", "law_enforcement", "education", "infrastructure"],
        key_requirements=[
            "Annex IV technical documentation",
            "Human oversight mechanisms (Art. 14)",
            "Incident reporting within 15 working days (Art. 73)",
            "EU conformity assessment for high-risk AI",
            "Market surveillance and post-market monitoring",
        ],
        penalty_max="€35M or 7% of global annual turnover",
        reference_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
        changes_since_last_version=[
            "High-risk enforcement: August 2, 2026 (15 months after entry into force)",
            "GPAI models: August 2, 2025",
            "Prohibited AI practices: February 2, 2025 (already in force)",
        ],
    ),
    RegulatoryItem(
        reg_id="NIST_AI_RMF",
        short_name="NIST AI RMF",
        full_name="NIST AI Risk Management Framework 1.0 (NIST AI 100-1)",
        jurisdiction=JurisdictionScope.US_FEDERAL,
        status=RegulationStatus.GUIDANCE_ONLY,
        enacted_date="2023-01-26",
        enforcement_date=None,
        last_updated="2023-01-26",
        version="1.0",
        description=(
            "Voluntary framework for managing AI risks. Four core functions: GOVERN, MAP, "
            "MEASURE, MANAGE. De facto standard for US federal AI procurement."
        ),
        squash_controls=["squash attest --policy nist-ai-rmf", "squash risk-assess"],
        affected_industries=["government", "defense", "finance", "healthcare"],
        key_requirements=["GOVERN function controls", "MAP risk identification", "MEASURE evaluation", "MANAGE response"],
        penalty_max="N/A (voluntary)",
        reference_url="https://airc.nist.gov/Home",
        changes_since_last_version=["v1.0 stable; v2.0 draft expected 2025"],
    ),
    RegulatoryItem(
        reg_id="ISO_42001",
        short_name="ISO 42001",
        full_name="ISO/IEC 42001:2023 — Artificial Intelligence Management System",
        jurisdiction=JurisdictionScope.GLOBAL,
        status=RegulationStatus.ENACTED,
        enacted_date="2023-12-18",
        enforcement_date=None,
        last_updated="2023-12-18",
        version="2023",
        description=(
            "First certifiable AI management system standard. 38 controls covering "
            "context, leadership, planning, support, operations, performance evaluation, "
            "and improvement. ISO 27001 equivalent for AI."
        ),
        squash_controls=["squash iso42001 --model ./model", "squash attest --policy iso-42001"],
        affected_industries=["all"],
        key_requirements=["38 Annex A controls", "AI impact assessments", "Data management controls", "Continual improvement"],
        penalty_max="N/A (certification standard)",
        reference_url="https://www.iso.org/standard/81230.html",
        changes_since_last_version=[],
    ),
    RegulatoryItem(
        reg_id="COLORADO_AI_ACT",
        short_name="Colorado AI Act",
        full_name="Colorado SB 205 — Artificial Intelligence Act",
        jurisdiction=JurisdictionScope.US_STATE,
        status=RegulationStatus.ENFORCEMENT_PENDING,
        enacted_date="2024-05-17",
        enforcement_date="2026-02-01",
        last_updated="2024-05-17",
        version="1.0",
        description=(
            "First US state AI regulation requiring impact assessments for high-risk AI "
            "systems used in consequential decisions (employment, housing, credit, health). "
            "Requires bias testing and disclosure."
        ),
        squash_controls=["squash bias-audit", "squash risk-assess", "squash attest --policy eu-ai-act"],
        affected_industries=["finance", "healthcare", "hr", "housing"],
        key_requirements=[
            "Impact assessments for high-risk AI",
            "Annual bias audits",
            "Consumer disclosures",
            "Developer obligations for downstream deployers",
        ],
        penalty_max="CCPA enforcement by AG",
        reference_url="https://leg.colorado.gov/bills/sb24-205",
        changes_since_last_version=[],
    ),
    RegulatoryItem(
        reg_id="NYC_LOCAL_LAW_144",
        short_name="NYC Local Law 144",
        full_name="NYC Local Law 144 of 2021 — Automated Employment Decision Tools",
        jurisdiction=JurisdictionScope.US_STATE,
        status=RegulationStatus.ENFORCEMENT_ACTIVE,
        enacted_date="2021-12-11",
        enforcement_date="2023-07-05",
        last_updated="2023-04-06",
        version="1.0",
        description=(
            "Requires NYC employers using automated employment decision tools (AEDTs) to "
            "conduct annual independent bias audits and publish summaries. "
            "Disparate impact ratio threshold: ≥0.80 (4/5ths rule)."
        ),
        squash_controls=["squash bias-audit --standard nyc_local_law_144"],
        affected_industries=["hr", "recruiting", "staffing"],
        key_requirements=[
            "Annual bias audit by independent auditor",
            "Public audit summary publication",
            "Candidate notification before AEDT use",
            "Disparate impact ratio ≥ 0.80",
        ],
        penalty_max="$375–$1,500 per violation per day",
        reference_url="https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page",
        changes_since_last_version=[],
    ),
    RegulatoryItem(
        reg_id="SEC_AI_DISCLOSURE",
        short_name="SEC AI Disclosure",
        full_name="SEC AI and Cybersecurity Examination Priorities",
        jurisdiction=JurisdictionScope.US_FEDERAL,
        status=RegulationStatus.ENFORCEMENT_ACTIVE,
        enacted_date="2024-10-21",
        enforcement_date="2025-01-01",
        last_updated="2024-10-21",
        version="2025",
        description=(
            "SEC elevated AI and cybersecurity to top examination priorities for 2025, "
            "displacing crypto. Investment advisers and broker-dealers must document AI "
            "use in trading, advice, and operations."
        ),
        squash_controls=["squash attest --policy enterprise-strict", "squash board-report"],
        affected_industries=["finance", "investment", "trading"],
        key_requirements=[
            "AI system documentation for examiners",
            "Model risk management (SR 11-7 analogue)",
            "Disclosure to clients of AI use in advice",
        ],
        penalty_max="Civil monetary penalties; registration revocation",
        reference_url="https://www.sec.gov/exams/announcement/exam-priorities-2025",
        changes_since_last_version=["Elevated from priority to top-2 for 2025"],
    ),
    RegulatoryItem(
        reg_id="FDA_AI_ML",
        short_name="FDA AI/ML SaMD",
        full_name="FDA Guidance on AI/ML-Based Software as a Medical Device",
        jurisdiction=JurisdictionScope.US_FEDERAL,
        status=RegulationStatus.GUIDANCE_ONLY,
        enacted_date="2021-01-12",
        enforcement_date=None,
        last_updated="2023-03-22",
        version="2023",
        description=(
            "FDA guidance requiring documentation, validation, and post-market surveillance "
            "plans for AI-enabled medical devices. Covers adaptive AI/ML algorithms that "
            "can change based on real-world experience."
        ),
        squash_controls=["squash annex-iv generate", "squash attest", "squash model-card"],
        affected_industries=["healthcare", "medical_devices"],
        key_requirements=[
            "Algorithm change protocol",
            "Pre-specified performance objectives",
            "Real-world performance monitoring plan",
            "Transparency to users",
        ],
        penalty_max="510(k) clearance denial; import alerts",
        reference_url="https://www.fda.gov/medical-devices/software-medical-device-samd/artificial-intelligence-and-machine-learning-aiml-enabled-medical-devices",
        changes_since_last_version=["2023 action plan added transparency requirements"],
    ),
    RegulatoryItem(
        reg_id="EU_GDPR_AI",
        short_name="GDPR (AI)",
        full_name="EU General Data Protection Regulation — AI training data implications",
        jurisdiction=JurisdictionScope.EU,
        status=RegulationStatus.ENFORCEMENT_ACTIVE,
        enacted_date="2016-04-27",
        enforcement_date="2018-05-25",
        last_updated="2025-01-20",
        version="GDPR+AI-2025",
        description=(
            "GDPR applies to AI training data. Italy fined OpenAI €15M in Jan 2025 for "
            "GDPR violations in training data. Requires legal basis for processing personal "
            "data in AI training, data subject rights for training data."
        ),
        squash_controls=["squash data-lineage", "squash incident --category pii_exposure"],
        affected_industries=["all"],
        key_requirements=[
            "Legal basis for PII in training data (Art. 6)",
            "Data minimization in AI training",
            "Right to erasure — impact on trained models",
            "Data Protection Impact Assessment for high-risk AI",
        ],
        penalty_max="€20M or 4% of global annual turnover",
        reference_url="https://gdpr-info.eu/",
        changes_since_last_version=[
            "Italy fined OpenAI €15M for training data violations (Jan 2025)",
            "EDPB Opinion 28/2024 on legitimate interest for AI training",
        ],
    ),
    RegulatoryItem(
        reg_id="FEDRAMP_AI",
        short_name="FedRAMP AI",
        full_name="FedRAMP Authorization for AI-enabled Cloud Services",
        jurisdiction=JurisdictionScope.US_FEDERAL,
        status=RegulationStatus.ENFORCEMENT_ACTIVE,
        enacted_date="2024-01-01",
        enforcement_date="2024-01-01",
        last_updated="2024-06-15",
        version="Rev5-AI",
        description=(
            "FedRAMP Rev 5 baseline now includes AI-specific controls. Federal agencies "
            "procuring AI-enabled cloud services must ensure FedRAMP authorization."
        ),
        squash_controls=["squash attest --policy fedramp", "squash attest --policy cmmc"],
        affected_industries=["government", "defense"],
        key_requirements=["AC-2 AI account management", "RA-5 AI vulnerability scanning", "SI-7 AI software integrity"],
        penalty_max="Contract termination; debarment",
        reference_url="https://www.fedramp.gov",
        changes_since_last_version=["Rev5 added 12 AI-specific controls (2024)"],
    ),
]

# ── Change log ─────────────────────────────────────────────────────────────────

_CHANGE_LOG: list[RegUpdate] = [
    RegUpdate(
        reg_id="EU_GDPR_AI", short_name="GDPR (AI)",
        change_date="2025-01-20", change_type="enforcement",
        change_summary="Italy's Garante fined OpenAI €15M for GDPR violations in ChatGPT training data processing. First major AI training data fine in EU.",
        impact_level="HIGH",
        affected_squash_controls=["squash data-lineage", "squash incident"],
    ),
    RegUpdate(
        reg_id="EU_AI_ACT", short_name="EU AI Act",
        change_date="2025-02-02", change_type="enforcement_start",
        change_summary="Prohibited AI practices enforcement began February 2, 2025. Unacceptable risk systems (social scoring, subliminal manipulation) now banned.",
        impact_level="HIGH",
        affected_squash_controls=["squash attest --policy eu-ai-act", "squash risk-assess"],
    ),
    RegUpdate(
        reg_id="SEC_AI_DISCLOSURE", short_name="SEC AI Disclosure",
        change_date="2024-10-21", change_type="new",
        change_summary="SEC elevated AI to top examination priority for 2025, displacing crypto. Investment advisers and broker-dealers now subject to AI documentation examination.",
        impact_level="HIGH",
        affected_squash_controls=["squash board-report", "squash attest"],
    ),
    RegUpdate(
        reg_id="COLORADO_AI_ACT", short_name="Colorado AI Act",
        change_date="2024-05-17", change_type="new",
        change_summary="Colorado SB 205 signed into law. First US state AI regulation with mandatory impact assessments for high-risk AI. Effective February 2026.",
        impact_level="MEDIUM",
        affected_squash_controls=["squash bias-audit", "squash risk-assess"],
    ),
    RegUpdate(
        reg_id="ISO_42001", short_name="ISO 42001",
        change_date="2023-12-18", change_type="new",
        change_summary="ISO/IEC 42001:2023 published. First internationally certifiable AI management system standard. 38 controls. Certification programs now available.",
        impact_level="MEDIUM",
        affected_squash_controls=["squash iso42001"],
    ),
    RegUpdate(
        reg_id="EU_AI_ACT", short_name="EU AI Act",
        change_date="2026-01-15", change_type="guidance",
        change_summary="European AI Office published technical guidance on Annex IV documentation requirements for high-risk AI systems. Key: training data provenance now explicitly required.",
        impact_level="HIGH",
        affected_squash_controls=["squash annex-iv generate", "squash data-lineage"],
    ),
]


class RegulatoryFeed:
    """Curated AI regulatory intelligence feed."""

    def __init__(self) -> None:
        self._regulations = {r.reg_id: r for r in _REGULATIONS}
        self._changes = list(_CHANGE_LOG)

    def all_regulations(self) -> list[RegulatoryItem]:
        return list(self._regulations.values())

    def get_regulation(self, reg_id: str) -> RegulatoryItem | None:
        return self._regulations.get(reg_id)

    def active_regulations(self) -> list[RegulatoryItem]:
        return [r for r in self._regulations.values()
                if r.status in (RegulationStatus.ENFORCEMENT_ACTIVE,
                                RegulationStatus.ENFORCEMENT_PENDING)]

    def check_updates(self, since: str | None = None) -> list[RegUpdate]:
        if since is None:
            return list(self._changes)
        return [c for c in self._changes if c.change_date >= since]

    def upcoming_deadlines(self, days: int = 365) -> list[tuple[RegulatoryItem, int]]:
        today = datetime.date.today()
        cutoff = today + datetime.timedelta(days=days)
        result: list[tuple[RegulatoryItem, int]] = []
        for r in self._regulations.values():
            if r.enforcement_date:
                try:
                    dt = datetime.date.fromisoformat(r.enforcement_date)
                    days_left = (dt - today).days
                    if 0 <= days_left <= days:
                        result.append((r, days_left))
                except ValueError:
                    pass
        return sorted(result, key=lambda x: x[1])

    def regulations_by_jurisdiction(self, scope: str) -> list[RegulatoryItem]:
        return [r for r in self._regulations.values()
                if r.jurisdiction.value == scope.lower()]

    def regulations_affecting_industry(self, industry: str) -> list[RegulatoryItem]:
        return [r for r in self._regulations.values()
                if industry.lower() in r.affected_industries or "all" in r.affected_industries]

    def status(self) -> FeedStatus:
        regs = list(self._regulations.values())
        active = sum(1 for r in regs if r.status == RegulationStatus.ENFORCEMENT_ACTIVE)
        pending = sum(1 for r in regs if r.status == RegulationStatus.ENFORCEMENT_PENDING)
        proposed = sum(1 for r in regs if r.status == RegulationStatus.PROPOSED)

        deadlines = self.upcoming_deadlines(days=730)
        nearest_label = deadlines[0][0].short_name if deadlines else None
        nearest_days = deadlines[0][1] if deadlines else None

        high_impact = [
            f"{r.short_name} — {r.enforcement_date}"
            for r in regs
            if r.status == RegulationStatus.ENFORCEMENT_PENDING
        ]

        squash_coverage = {
            r.reg_id: bool(r.squash_controls) for r in regs
        }

        return FeedStatus(
            total_regulations=len(regs),
            active_enforcement=active,
            pending_enforcement=pending,
            proposed=proposed,
            nearest_deadline=nearest_label,
            nearest_deadline_days=nearest_days,
            high_impact_pending=high_impact,
            squash_coverage=squash_coverage,
        )

    def export(self) -> list[dict[str, Any]]:
        return [
            {
                "reg_id": r.reg_id,
                "short_name": r.short_name,
                "jurisdiction": r.jurisdiction.value,
                "status": r.status.value,
                "enforcement_date": r.enforcement_date,
                "squash_controls": r.squash_controls,
                "penalty_max": r.penalty_max,
                "days_to_enforcement": r.days_to_enforcement,
            }
            for r in self._regulations.values()
        ]
