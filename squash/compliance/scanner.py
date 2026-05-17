"""squash/compliance/scanner.py — Multi-framework clause-level compliance scan.

Distinct from :mod:`squash.quick_check` (which scores a single policy document
against one framework's clause library): this module accepts a *list of
clauses* — typically extracted from a contract or a master compliance
policy — and scores them against any combination of the three frameworks
listed below in one pass. Each framework has a curated requirement
catalogue; each requirement has a set of phrase patterns plus per-pattern
weights so confidence is graded, not binary.

Supported frameworks
--------------------
* ``SOC2`` — Trust Services Criteria: Security, Availability, Processing
  Integrity, Confidentiality, Privacy.
* ``HIPAA`` — Privacy / Security / Breach Notification Rules.
* ``PCI_DSS`` — Payment Card Industry Data Security Standard v4.

Public surface (re-exported from ``squash.compliance``)
-------------------------------------------------------
:class:`ComplianceFramework` · :class:`RequirementMatch` ·
:class:`FrameworkResult` · :class:`ComplianceReport` ·
:class:`ComplianceScanner`

Zero new dependencies. Pure stdlib. Deterministic for a given input set.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

__all__ = [
    "ComplianceFramework",
    "ComplianceReport",
    "ComplianceScanner",
    "FrameworkResult",
    "Requirement",
    "RequirementMatch",
    "builtin_requirements",
]


# ──────────────────────────────────────────────────────────────────────────────
# Public framework enum
# ──────────────────────────────────────────────────────────────────────────────


class ComplianceFramework(str, Enum):
    SOC2 = "SOC2"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"

    @classmethod
    def parse(cls, value: "str | ComplianceFramework") -> "ComplianceFramework":
        if isinstance(value, ComplianceFramework):
            return value
        key = str(value).strip().upper().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value == key or member.name == key:
                return member
        raise ValueError(
            f"unknown compliance framework: {value!r} — "
            f"supported: {', '.join(m.value for m in cls)}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Requirement model
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Requirement:
    """One requirement inside a framework's catalogue."""

    requirement_id: str          # e.g. "SOC2-CC6.1"
    text: str                    # human-readable requirement text
    severity: str                # "critical" | "high" | "medium" | "low"
    # Each pattern carries a confidence contribution in [0, 1]. The pattern
    # with the largest contribution that fires wins; this keeps the
    # confidence score interpretable instead of additive-and-unbounded.
    patterns: tuple[tuple[str, float], ...]

    def compiled(self) -> list[tuple[re.Pattern[str], float]]:
        return [(re.compile(p, re.IGNORECASE), w) for p, w in self.patterns]


@dataclass
class RequirementMatch:
    requirement_id: str
    requirement_text: str
    matched_clause: str
    confidence: float
    severity: str = "medium"
    matched_phrase: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "requirement_text": self.requirement_text,
            "matched_clause": self.matched_clause,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "matched_phrase": self.matched_phrase,
        }


@dataclass
class FrameworkResult:
    framework: ComplianceFramework
    matched_requirements: list[RequirementMatch] = field(default_factory=list)
    coverage_pct: float = 0.0
    gaps: list[str] = field(default_factory=list)
    total_requirements: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "matched_requirements": [m.to_dict() for m in self.matched_requirements],
            "coverage_pct": round(self.coverage_pct, 2),
            "gaps": list(self.gaps),
            "total_requirements": self.total_requirements,
            "matched_requirement_count": len(self.matched_requirements),
        }


@dataclass
class ComplianceReport:
    framework_results: dict[ComplianceFramework, FrameworkResult] = field(
        default_factory=dict
    )
    overall_risk: str = "unknown"      # low | medium | high | critical
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    clause_count: int = 0
    min_confidence: float = 0.5

    def overall_coverage_pct(self) -> float:
        if not self.framework_results:
            return 0.0
        return round(
            sum(f.coverage_pct for f in self.framework_results.values())
            / len(self.framework_results),
            2,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework_results": {
                fw.value: result.to_dict()
                for fw, result in self.framework_results.items()
            },
            "overall_risk": self.overall_risk,
            "overall_coverage_pct": self.overall_coverage_pct(),
            "timestamp": self.timestamp.isoformat(),
            "clause_count": self.clause_count,
            "min_confidence": self.min_confidence,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Built-in framework catalogues
# ──────────────────────────────────────────────────────────────────────────────


_SOC2_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "SOC2-CC1.1", "Demonstrates commitment to integrity and ethical values",
        "high",
        (("code of conduct", 0.85),
         ("ethical (values|standards|behavior)", 0.80),
         ("commitment to integrity", 0.95)),
    ),
    Requirement(
        "SOC2-CC6.1", "Implements logical access security software & controls",
        "critical",
        (("logical access (control|security)", 0.92),
         ("role[-\\s]?based access", 0.90),
         ("least privilege", 0.88),
         ("multi[-\\s]?factor authentication|\\bmfa\\b", 0.85),
         ("access (control|management)", 0.70)),
    ),
    Requirement(
        "SOC2-CC6.7", "Restricts transmission, movement and removal of data",
        "high",
        (("encryption (in transit|in motion)", 0.90),
         ("\\btls\\b|\\bssl\\b", 0.75),
         ("data loss prevention|\\bdlp\\b", 0.80)),
    ),
    Requirement(
        "SOC2-CC7.2", "System monitoring detects anomalies",
        "high",
        (("continuous monitoring", 0.90),
         ("anomaly detection", 0.92),
         ("intrusion detection|\\bids\\b|\\bsiem\\b", 0.88),
         ("security event monitoring", 0.85)),
    ),
    Requirement(
        "SOC2-CC7.3", "Incident response procedures",
        "critical",
        (("incident response (plan|procedure)", 0.95),
         ("security incident", 0.80),
         ("breach response", 0.80),
         ("escalation procedure", 0.78)),
    ),
    Requirement(
        "SOC2-A1.2", "Availability — backup, recovery, business continuity",
        "high",
        (("disaster recovery", 0.92),
         ("business continuity", 0.92),
         ("backup (and|&)? ?(restore|recovery)", 0.88),
         ("\\brto\\b|\\brpo\\b", 0.80),
         ("availability (commitment|sla)", 0.75)),
    ),
    Requirement(
        "SOC2-C1.1", "Confidentiality of information",
        "high",
        (("confidentiality", 0.85),
         ("encryption at rest", 0.92),
         ("\\baes[-\\s]?256\\b", 0.88),
         ("key management", 0.80),
         ("data classification", 0.78)),
    ),
    Requirement(
        "SOC2-PI1.1", "Processing integrity — completeness & accuracy",
        "medium",
        (("processing integrity", 0.95),
         ("input validation", 0.80),
         ("data accuracy", 0.78),
         ("checksum|hash verification|integrity check", 0.82)),
    ),
    Requirement(
        "SOC2-P1.1", "Privacy notice & consent",
        "high",
        (("privacy notice", 0.90),
         ("consent (mechanism|management)", 0.85),
         ("data subject rights", 0.80),
         ("personal information|\\bpii\\b", 0.65)),
    ),
    Requirement(
        "SOC2-CC8.1", "Change management process",
        "medium",
        (("change management", 0.92),
         ("change advisory board|\\bcab\\b", 0.80),
         ("change approval", 0.78)),
    ),
)


_HIPAA_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "HIPAA-160.103-PHI", "Identifies and protects Protected Health Information",
        "critical",
        (("protected health information|\\bphi\\b", 0.95),
         ("individually identifiable health information", 0.92),
         ("health information", 0.65)),
    ),
    Requirement(
        "HIPAA-160.103-CE", "Covered entity definition / role",
        "high",
        (("covered entit(y|ies)", 0.95),
         ("health (plan|care provider|care clearinghouse)", 0.78)),
    ),
    Requirement(
        "HIPAA-160.103-BA", "Business associate agreement",
        "critical",
        (("business associate", 0.95),
         ("\\bbaa\\b|business associate agreement", 0.95),
         ("subcontractor", 0.55)),
    ),
    Requirement(
        "HIPAA-164.502(b)", "Minimum necessary standard",
        "high",
        (("minimum necessary", 0.95),
         ("limit (uses?|disclosures?) of (phi|protected health)", 0.88)),
    ),
    Requirement(
        "HIPAA-164.308", "Administrative safeguards",
        "critical",
        (("administrative safeguards?", 0.95),
         ("security officer|privacy officer", 0.85),
         ("workforce training", 0.80),
         ("security awareness training", 0.85)),
    ),
    Requirement(
        "HIPAA-164.310", "Physical safeguards",
        "high",
        (("physical safeguards?", 0.95),
         ("facility access (controls?|management)", 0.85),
         ("workstation (use|security)", 0.80)),
    ),
    Requirement(
        "HIPAA-164.312", "Technical safeguards",
        "critical",
        (("technical safeguards?", 0.95),
         ("audit (controls?|logs?)", 0.78),
         ("automatic logoff", 0.85),
         ("encryption (and|&)? ?decryption", 0.90)),
    ),
    Requirement(
        "HIPAA-164.404", "Breach notification — individuals",
        "critical",
        (("breach notification", 0.92),
         ("notify (affected )?individuals?", 0.85),
         ("60 days", 0.55)),
    ),
    Requirement(
        "HIPAA-164.524", "Right of access to PHI",
        "high",
        (("right of access", 0.92),
         ("designated record set", 0.85),
         ("access (your|to your) (medical|health) (record|information)", 0.85)),
    ),
    Requirement(
        "HIPAA-164.530", "Privacy practices documentation",
        "medium",
        (("notice of privacy practices|\\bnpp\\b", 0.90),
         ("privacy practices", 0.80),
         ("complaint (procedure|process)", 0.65)),
    ),
)


_PCI_DSS_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "PCI-DSS-1", "Network security controls",
        "high",
        (("firewall (configuration|rules)", 0.90),
         ("network segmentation", 0.88),
         ("\\bdmz\\b", 0.80),
         ("network security controls?", 0.82)),
    ),
    Requirement(
        "PCI-DSS-2", "Apply secure configurations",
        "medium",
        (("secure configurations?", 0.88),
         ("system hardening|hardening standards?", 0.92),
         ("\\bcis benchmarks?\\b", 0.85),
         ("default (passwords?|credentials?)", 0.75)),
    ),
    Requirement(
        "PCI-DSS-3", "Protect stored cardholder data",
        "critical",
        (("cardholder data", 0.95),
         ("\\bpan\\b|primary account number", 0.92),
         ("tokenization", 0.92),
         ("data retention (and|&) disposal", 0.78),
         ("encrypt(ion|ed)? (of )?cardholder data", 0.95)),
    ),
    Requirement(
        "PCI-DSS-3.2", "Sensitive authentication data not stored after auth",
        "critical",
        (("sensitive authentication data|\\bsad\\b", 0.90),
         ("\\bcvv\\b|\\bcvc\\b|card verification value", 0.95),
         ("\\bpin\\b block", 0.80),
         ("full track data", 0.92)),
    ),
    Requirement(
        "PCI-DSS-4", "Protect cardholder data with strong cryptography in transit",
        "critical",
        (("strong cryptography", 0.90),
         ("encryption in transit", 0.92),
         ("\\btls\\s*1\\.[23]\\b", 0.92),
         ("end[-\\s]?to[-\\s]?end encryption", 0.88)),
    ),
    Requirement(
        "PCI-DSS-6", "Develop and maintain secure systems and software",
        "high",
        (("secure (development|software development) lifecycle|\\bsdl(c)?\\b", 0.90),
         ("vulnerability management", 0.88),
         ("patch management", 0.85),
         ("application security testing|\\bsast\\b|\\bdast\\b", 0.85)),
    ),
    Requirement(
        "PCI-DSS-7", "Restrict access to cardholder data by business need",
        "high",
        (("\\bneed[-\\s]?to[-\\s]?know\\b", 0.92),
         ("least privilege", 0.85),
         ("role[-\\s]?based access (control)?", 0.85)),
    ),
    Requirement(
        "PCI-DSS-8", "Identify users and authenticate access",
        "critical",
        (("unique (user )?id(entifier)?s?", 0.85),
         ("multi[-\\s]?factor authentication|\\bmfa\\b", 0.92),
         ("password (complexity|policy)", 0.80),
         ("strong authentication", 0.85)),
    ),
    Requirement(
        "PCI-DSS-10", "Log and monitor access to system components",
        "high",
        (("audit (log|trail)", 0.90),
         ("log (review|retention|management)", 0.85),
         ("time synchronization|\\bntp\\b", 0.78),
         ("centralized log(ging|s)", 0.85)),
    ),
    Requirement(
        "PCI-DSS-11", "Test security regularly",
        "high",
        (("penetration test(ing)?", 0.92),
         ("vulnerability scan(ning|s)?", 0.90),
         ("intrusion detection (system|prevention)|\\bids\\b|\\bips\\b", 0.85),
         ("file integrity monitoring|\\bfim\\b", 0.88)),
    ),
    Requirement(
        "PCI-DSS-12", "Information security program",
        "medium",
        (("information security policy", 0.92),
         ("security awareness", 0.85),
         ("incident response plan", 0.88),
         ("risk assessment", 0.78)),
    ),
)


_BUILTIN: dict[ComplianceFramework, tuple[Requirement, ...]] = {
    ComplianceFramework.SOC2:    _SOC2_REQUIREMENTS,
    ComplianceFramework.HIPAA:   _HIPAA_REQUIREMENTS,
    ComplianceFramework.PCI_DSS: _PCI_DSS_REQUIREMENTS,
}


def builtin_requirements(
    framework: ComplianceFramework,
) -> tuple[Requirement, ...]:
    """Return the built-in requirement catalogue for *framework*."""
    return _BUILTIN[framework]


# ──────────────────────────────────────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────────────────────────────────────


_RISK_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (90.0, "low"),       # >=90% coverage of critical+high → low risk
    (70.0, "medium"),
    (40.0, "high"),
    (0.0,  "critical"),
)


class ComplianceScanner:
    """Score *clauses* against any combination of supported frameworks."""

    def __init__(
        self,
        catalogues: Mapping[ComplianceFramework, Iterable[Requirement]] | None = None,
    ) -> None:
        if catalogues is None:
            self._catalogues = {fw: list(reqs) for fw, reqs in _BUILTIN.items()}
        else:
            self._catalogues = {fw: list(reqs) for fw, reqs in catalogues.items()}
        # one-shot compile per requirement_id
        self._compiled: dict[str, list[tuple[re.Pattern[str], float]]] = {}
        for fw_reqs in self._catalogues.values():
            for req in fw_reqs:
                self._compiled[req.requirement_id] = req.compiled()

    # ── public api ─────────────────────────────────────────────────────────

    def supported_frameworks(self) -> list[ComplianceFramework]:
        return list(self._catalogues.keys())

    def scan(
        self,
        clauses: list[str],
        frameworks: list[ComplianceFramework] | None = None,
        *,
        min_confidence: float = 0.5,
    ) -> ComplianceReport:
        """Score every clause against every requirement in each framework.

        Each (clause, requirement) pair is evaluated independently. The
        clause's confidence for a requirement is the *max* pattern weight
        that fires (so a stronger phrase beats a weaker one without
        double-counting overlap). The strongest matching clause per
        requirement is recorded as the :class:`RequirementMatch`.
        """

        if not isinstance(clauses, list) or any(not isinstance(c, str) for c in clauses):
            raise TypeError("clauses must be list[str]")
        if min_confidence < 0.0 or min_confidence > 1.0:
            raise ValueError("min_confidence must be in [0.0, 1.0]")

        if frameworks is None:
            frameworks = self.supported_frameworks()
        else:
            frameworks = [ComplianceFramework.parse(f) for f in frameworks]
            # de-dupe, preserve order
            seen: list[ComplianceFramework] = []
            for f in frameworks:
                if f not in seen:
                    seen.append(f)
            frameworks = seen

        report = ComplianceReport(
            clause_count=len(clauses),
            min_confidence=min_confidence,
        )

        # weight critical+high doubly when computing the overall risk band —
        # missing a critical control matters more than missing a "medium" nice-to-have
        weighted_coverage_num = 0.0
        weighted_coverage_den = 0.0

        for fw in frameworks:
            reqs = self._catalogues.get(fw, [])
            if not reqs:
                report.framework_results[fw] = FrameworkResult(
                    framework=fw, total_requirements=0,
                )
                continue

            matches: list[RequirementMatch] = []
            unmatched_ids: list[str] = []

            for req in reqs:
                best = self._best_match_for(req, clauses)
                if best is not None and best.confidence >= min_confidence:
                    matches.append(best)
                else:
                    unmatched_ids.append(req.requirement_id)

            coverage = (len(matches) / len(reqs)) * 100.0 if reqs else 0.0
            report.framework_results[fw] = FrameworkResult(
                framework=fw,
                matched_requirements=matches,
                coverage_pct=round(coverage, 2),
                gaps=unmatched_ids,
                total_requirements=len(reqs),
            )

            for req in reqs:
                w = _severity_weight(req.severity)
                weighted_coverage_den += w
                if not any(m.requirement_id == req.requirement_id for m in matches):
                    continue
                weighted_coverage_num += w

        weighted_pct = (
            (weighted_coverage_num / weighted_coverage_den) * 100.0
            if weighted_coverage_den
            else 0.0
        )
        report.overall_risk = _bucket_risk(weighted_pct)
        return report

    # ── internal ───────────────────────────────────────────────────────────

    def _best_match_for(
        self,
        req: Requirement,
        clauses: list[str],
    ) -> RequirementMatch | None:
        compiled = self._compiled.get(req.requirement_id)
        if not compiled:
            return None
        best: RequirementMatch | None = None
        for clause in clauses:
            if not clause:
                continue
            for pattern, weight in compiled:
                hit = pattern.search(clause)
                if hit is None:
                    continue
                if best is None or weight > best.confidence:
                    best = RequirementMatch(
                        requirement_id=req.requirement_id,
                        requirement_text=req.text,
                        matched_clause=clause,
                        confidence=weight,
                        severity=req.severity,
                        matched_phrase=hit.group(0),
                    )
        return best


def _severity_weight(severity: str) -> float:
    return {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}.get(
        severity.lower(), 1.0,
    )


def _bucket_risk(weighted_pct: float) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if weighted_pct >= threshold:
            return label
    return "critical"
