"""squash/financial_risk.py — Clause-level financial exposure quantification.

For every clause the quick-check catalogue can flag as **missing**, this
module returns a defensible USD exposure band.  The bands are derived
from public regulator-fine ceilings and from settlement-data trends that
buyers (and their auditors) already cite.

The lookup table is intentionally conservative — the low end is the
typical small-org outcome, the high end is the documented worst case for
that clause category.  Each entry carries the rationale citation so the
GC reading the demo can defend the number to the CFO.

Public API
----------
* :data:`RISK_TABLE` — frozen dict mapping clause-id → :class:`RiskBand`.
* :func:`quantify` — return the band for a clause-id (None if untabled).
* :func:`aggregate_exposure` — sum bands across a list of clause-ids.

The numbers are *exposure estimates*, not legal advice.  The demo UI is
required to render the disclaimer next to any total.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class RiskBand:
    """Risk exposure band for a single clause-id."""

    low_usd: int
    high_usd: int
    rationale: str
    risk_level: str  # "low" | "medium" | "high" | "critical"
    citation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "low_usd": self.low_usd,
            "high_usd": self.high_usd,
            "rationale": self.rationale,
            "risk_level": self.risk_level,
            "citation": self.citation,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Catalogue — clause-id → band
# ──────────────────────────────────────────────────────────────────────────────
#
# Sources (all public):
#   • GDPR Art. 83  — administrative fines up to €20M or 4% global turnover
#   • CCPA §1798.155 — $2,500 per unintentional / $7,500 per intentional violation
#   • EU AI Act Art. 99 — fines up to €35M or 7% global turnover for prohibited;
#     €15M or 3% for high-risk obligations
#   • SOC 2 — driven by lost-deal cost; SaaS deal-data median $200K-$1.5M
#   • OWASP / industry breach reports — IBM Cost of a Data Breach 2024:
#     mean $4.88M, median $250K for sub-1000-record incidents
#
RISK_TABLE: Mapping[str, RiskBand] = {
    # ── GDPR ──────────────────────────────────────────────────────────────
    "GDPR-LAWFUL-BASIS": RiskBand(
        low_usd=50_000,
        high_usd=2_000_000,
        rationale="Processing without a lawful basis is a Tier-2 GDPR offence",
        risk_level="critical",
        citation="GDPR Art. 6 + Art. 83(5)(a)",
    ),
    "GDPR-DATA-SUBJECT-RIGHTS": RiskBand(
        low_usd=20_000,
        high_usd=1_500_000,
        rationale="DSAR non-compliance — Italian DPA, Spanish AEPD precedent",
        risk_level="high",
        citation="GDPR Art. 15-22 + Art. 83(5)(b)",
    ),
    "GDPR-RETENTION": RiskBand(
        low_usd=10_000,
        high_usd=500_000,
        rationale="Indefinite retention violates storage-limitation principle",
        risk_level="high",
        citation="GDPR Art. 5(1)(e)",
    ),
    "GDPR-DPO-CONTACT": RiskBand(
        low_usd=5_000,
        high_usd=100_000,
        rationale="Missing DPO contact blocks DSAR routing — Tier-1 fine",
        risk_level="medium",
        citation="GDPR Art. 37-39 + Art. 83(4)(a)",
    ),
    "GDPR-INTL-TRANSFER": RiskBand(
        low_usd=50_000,
        high_usd=1_200_000_000,
        rationale="Meta €1.2B (2023) was an international-transfer fine — high end",
        risk_level="critical",
        citation="GDPR Chapter V + Meta-IE DPC 2023",
    ),
    "GDPR-BREACH-NOTIFICATION": RiskBand(
        low_usd=20_000,
        high_usd=2_000_000,
        rationale="72-hour notification deadline — Uber UK fine £385K precedent",
        risk_level="high",
        citation="GDPR Art. 33 + Art. 83(4)(a)",
    ),
    # ── CCPA ──────────────────────────────────────────────────────────────
    "CCPA-RIGHT-TO-KNOW": RiskBand(
        low_usd=5_000,
        high_usd=500_000,
        rationale="$2,500 per unintentional violation, scaled by record count",
        risk_level="high",
        citation="CCPA §1798.155(a)",
    ),
    "CCPA-RIGHT-TO-DELETE": RiskBand(
        low_usd=5_000,
        high_usd=500_000,
        rationale="$2,500 / $7,500 per violation × deletion-request volume",
        risk_level="high",
        citation="CCPA §1798.105 + §1798.155",
    ),
    "CCPA-OPT-OUT": RiskBand(
        low_usd=10_000,
        high_usd=1_200_000,
        rationale="Sephora $1.2M (2022) was an opt-out enforcement",
        risk_level="critical",
        citation="CCPA §1798.135 + CA AG settlement",
    ),
    "CCPA-NON-DISCRIMINATION": RiskBand(
        low_usd=5_000,
        high_usd=200_000,
        rationale="Discrimination claim — class-action territory",
        risk_level="medium",
        citation="CCPA §1798.125",
    ),
    "CCPA-CATEGORIES": RiskBand(
        low_usd=2_500,
        high_usd=150_000,
        rationale="Required transparency item — $2,500 floor per violation",
        risk_level="medium",
        citation="CCPA §1798.110(c)",
    ),
    # ── EU AI Act ─────────────────────────────────────────────────────────
    "AIA-RISK-CLASS": RiskBand(
        low_usd=100_000,
        high_usd=15_000_000,
        rationale="Misclassifying high-risk system → Art. 99(4) tier",
        risk_level="critical",
        citation="EU AI Act Art. 99(4)",
    ),
    "AIA-HUMAN-OVERSIGHT": RiskBand(
        low_usd=100_000,
        high_usd=15_000_000,
        rationale="Art. 14 violation — same tier as risk-class mistakes",
        risk_level="critical",
        citation="EU AI Act Art. 14 + Art. 99(4)",
    ),
    "AIA-TRANSPARENCY": RiskBand(
        low_usd=50_000,
        high_usd=7_500_000,
        rationale="Art. 13 user disclosure — Tier-3 fine ceiling",
        risk_level="high",
        citation="EU AI Act Art. 13 + Art. 99(5)",
    ),
    "AIA-LOGGING": RiskBand(
        low_usd=50_000,
        high_usd=7_500_000,
        rationale="Art. 12 automatic logging absent → audit-trail gap",
        risk_level="high",
        citation="EU AI Act Art. 12 + Art. 99(5)",
    ),
    "AIA-ROBUSTNESS": RiskBand(
        low_usd=100_000,
        high_usd=15_000_000,
        rationale="Accuracy/robustness gap — direct user-harm exposure",
        risk_level="critical",
        citation="EU AI Act Art. 15 + Art. 99(4)",
    ),
    # ── SOC 2 ────────────────────────────────────────────────────────────
    "SOC2-CC1-CONTROL-ENV": RiskBand(
        low_usd=200_000,
        high_usd=1_500_000,
        rationale="Failed CC1 → blocked SaaS deal-cycle (median SaaS ACV impact)",
        risk_level="high",
        citation="AICPA TSC CC1 + deal-data 2024",
    ),
    "SOC2-CC6-LOGICAL-ACCESS": RiskBand(
        low_usd=250_000,
        high_usd=4_880_000,
        rationale="IBM 2024 mean breach cost when access control gaps drive incident",
        risk_level="critical",
        citation="AICPA TSC CC6 + IBM Cost of a Data Breach 2024",
    ),
    "SOC2-CC7-MONITORING": RiskBand(
        low_usd=100_000,
        high_usd=1_500_000,
        rationale="Detection-gap delay multiplies breach cost ~1.5×",
        risk_level="high",
        citation="AICPA TSC CC7",
    ),
    "SOC2-CC7-INCIDENT-RESPONSE": RiskBand(
        low_usd=150_000,
        high_usd=2_500_000,
        rationale="Missing IR plan → mean-time-to-contain rises 73 days",
        risk_level="high",
        citation="AICPA TSC CC7.4 + IBM 2024",
    ),
    "SOC2-A1-AVAILABILITY": RiskBand(
        low_usd=50_000,
        high_usd=1_000_000,
        rationale="Availability SLA gap — direct refund / customer-credit exposure",
        risk_level="medium",
        citation="AICPA TSC A1",
    ),
    "SOC2-C1-CONFIDENTIALITY": RiskBand(
        low_usd=100_000,
        high_usd=2_500_000,
        rationale="C1 trust-services failure — Type-II opinion at risk",
        risk_level="high",
        citation="AICPA TSC C1",
    ),
    # ── General privacy baseline ──────────────────────────────────────────
    "GEN-DATA-COLLECTION": RiskBand(
        low_usd=5_000,
        high_usd=250_000,
        rationale="Failure to disclose data collection — class-action precursor",
        risk_level="medium",
        citation="State UDAP statutes / FTC Section 5",
    ),
    "GEN-PURPOSE": RiskBand(
        low_usd=5_000,
        high_usd=250_000,
        rationale="Purpose-limitation breach drives most state-AG settlements",
        risk_level="medium",
        citation="FTC Section 5 / state UDAP",
    ),
    "GEN-THIRD-PARTIES": RiskBand(
        low_usd=10_000,
        high_usd=500_000,
        rationale="Undisclosed sharing — California Sephora-style risk",
        risk_level="high",
        citation="CCPA §1798.115 / FTC Section 5",
    ),
    "GEN-CONTACT": RiskBand(
        low_usd=2_500,
        high_usd=50_000,
        rationale="No privacy contact — minor procedural violation",
        risk_level="low",
        citation="FTC Section 5",
    ),
    "GEN-COOKIES": RiskBand(
        low_usd=5_000,
        high_usd=200_000,
        rationale="ePrivacy / GDPR consent-cookie territory — French CNIL pattern",
        risk_level="medium",
        citation="ePrivacy Directive Art. 5(3) + GDPR Art. 7",
    ),
}


# ──────────────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────────────


def quantify(clause_id: str) -> RiskBand | None:
    """Return the :class:`RiskBand` for *clause_id*, or ``None`` if untabled."""

    if not isinstance(clause_id, str):
        return None
    return RISK_TABLE.get(clause_id)


@dataclass(frozen=True)
class AggregateExposure:
    low_usd: int
    high_usd: int
    count: int
    by_risk_level: Mapping[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "low_usd": self.low_usd,
            "high_usd": self.high_usd,
            "count": self.count,
            "by_risk_level": dict(self.by_risk_level),
        }


def aggregate_exposure(clause_ids: Iterable[str]) -> AggregateExposure:
    """Sum the bands across *clause_ids*; unknown ids contribute zero."""

    low = 0
    high = 0
    n = 0
    by_level: dict[str, int] = {}
    for cid in clause_ids:
        band = quantify(cid)
        if band is None:
            continue
        low += band.low_usd
        high += band.high_usd
        n += 1
        by_level[band.risk_level] = by_level.get(band.risk_level, 0) + 1
    return AggregateExposure(low_usd=low, high_usd=high, count=n, by_risk_level=by_level)


def format_usd(amount: int) -> str:
    """Return ``$50K`` / ``$1.2M`` / ``$15M`` — display helper for the UI."""

    if amount >= 1_000_000_000:
        return f"${amount / 1_000_000_000:.1f}B"
    if amount >= 1_000_000:
        return f"${amount / 1_000_000:.1f}M"
    if amount >= 1_000:
        return f"${amount // 1_000}K"
    return f"${amount}"


def covered_clause_ids() -> list[str]:
    """Return the list of clause IDs the table knows about — used in tests."""

    return list(RISK_TABLE.keys())


__all__ = [
    "RISK_TABLE",
    "RiskBand",
    "AggregateExposure",
    "aggregate_exposure",
    "covered_clause_ids",
    "format_usd",
    "quantify",
]
