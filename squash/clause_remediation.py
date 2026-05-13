"""squash/clause_remediation.py — Clause-level redline + suggested-fix engine.

Given a :class:`squash.quick_check.QuickCheckResult` (or its dict form),
this module emits an actionable remediation list — one entry per missing
clause — with:

* **clause_id**       — stable ID (e.g. ``"GDPR-LAWFUL-BASIS"``)
* **label**           — human-readable clause name
* **issue**           — one-sentence statement of *what is wrong*
* **original**        — short representative phrase as it would have appeared
* **suggested_fix**   — drafted passing clause text the user can paste in
* **risk_level**      — ``low`` / ``medium`` / ``high`` / ``critical``
* **dollar_low_usd``  — financial exposure lower bound (from financial_risk)
* **dollar_high_usd`` — financial exposure upper bound
* **citation**        — regulation article / TSC control

The catalog covers every clause-id currently emitted by
:mod:`squash.quick_check` (28 entries across GDPR, CCPA, EU AI Act, SOC 2,
and the general privacy baseline). Coverage is verified by the test suite.

The redline view in the demo UI consumes this data as a side-by-side
``original vs suggested_fix`` diff coloured red / green.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from squash.financial_risk import (
    AggregateExposure,
    aggregate_exposure,
    format_usd,
    quantify,
)


# ──────────────────────────────────────────────────────────────────────────────
# Catalogue — one entry per missing-clause-id
# ──────────────────────────────────────────────────────────────────────────────


def _entry(
    *,
    label: str,
    issue: str,
    original: str,
    suggested_fix: str,
    citation: str = "",
) -> dict[str, str]:
    return {
        "label": label,
        "issue": issue,
        "original": original,
        "suggested_fix": suggested_fix,
        "citation": citation,
    }


_REMEDIATION_CATALOG: dict[str, dict[str, str]] = {
    # ── GDPR ──────────────────────────────────────────────────────────────
    "GDPR-LAWFUL-BASIS": _entry(
        label="Lawful basis for processing",
        issue="No lawful basis declared — processing is presumptively unlawful under GDPR Art. 6.",
        original="We collect and process your data.",
        suggested_fix=(
            "We process your personal data on the lawful bases of "
            "(a) your consent (Art. 6(1)(a)), (b) performance of the "
            "contract with you (Art. 6(1)(b)), and (c) our legitimate "
            "interests in providing and securing the service, balanced "
            "against your rights and freedoms (Art. 6(1)(f))."
        ),
        citation="GDPR Art. 6",
    ),
    "GDPR-DATA-SUBJECT-RIGHTS": _entry(
        label="Data subject rights (access / erasure / portability)",
        issue="Required DSAR rights not enumerated — Art. 15-22 obligations missing.",
        original="You may contact us if you have questions.",
        suggested_fix=(
            "You have the right to access (Art. 15), rectify (Art. 16), "
            "erase (Art. 17), restrict (Art. 18) and port (Art. 20) the "
            "personal data we hold about you. You may also object to "
            "processing (Art. 21). Submit a request to privacy@example.com; "
            "we respond within 30 days at no cost."
        ),
        citation="GDPR Art. 15-22",
    ),
    "GDPR-RETENTION": _entry(
        label="Retention period",
        issue="No retention period stated — storage-limitation principle (Art. 5(1)(e)) violated.",
        original="We may keep your data.",
        suggested_fix=(
            "We retain personal data only for as long as necessary for the "
            "purposes set out above: account data for the lifetime of the "
            "account plus 30 days, transaction records for 7 years (legal "
            "obligation), marketing data until you withdraw consent. After "
            "the retention period, data is securely deleted or anonymised."
        ),
        citation="GDPR Art. 5(1)(e) + Art. 13(2)(a)",
    ),
    "GDPR-DPO-CONTACT": _entry(
        label="DPO or controller contact",
        issue="No DPO or controller contact channel — DSAR routing is undefined.",
        original="(no contact provided)",
        suggested_fix=(
            "Data Protection Officer: Acme DPO Ltd, dpo@example.com, "
            "+44 20 0000 0000. Controller: Acme Corp, 1 Example Street, "
            "London EC1A 1AA, United Kingdom."
        ),
        citation="GDPR Art. 37-39",
    ),
    "GDPR-INTL-TRANSFER": _entry(
        label="International transfer disclosure",
        issue="No transfer mechanism disclosed for non-EEA processing.",
        original="We use cloud providers.",
        suggested_fix=(
            "We transfer personal data outside the EEA to processors located "
            "in the United States and Singapore. Transfers are protected by "
            "Standard Contractual Clauses (Module 2, 2021/914) and, where "
            "applicable, EU-US Data Privacy Framework certification. A copy "
            "of the SCCs is available on request."
        ),
        citation="GDPR Chapter V (Art. 44-50)",
    ),
    "GDPR-BREACH-NOTIFICATION": _entry(
        label="Breach notification commitment",
        issue="No notification commitment — Art. 33 72-hour deadline unaddressed.",
        original="(no commitment)",
        suggested_fix=(
            "In the event of a personal data breach likely to result in a "
            "risk to your rights and freedoms, we will notify the competent "
            "supervisory authority within 72 hours of becoming aware, and "
            "will inform affected users without undue delay if the risk is "
            "high."
        ),
        citation="GDPR Art. 33-34",
    ),
    # ── CCPA ──────────────────────────────────────────────────────────────
    "CCPA-RIGHT-TO-KNOW": _entry(
        label="Right to know",
        issue="California 'right to know' not surfaced.",
        original="(omitted)",
        suggested_fix=(
            "California residents have the right to know what categories "
            "and specific pieces of personal information we collected, the "
            "sources, the business or commercial purpose, and the categories "
            "of third parties we shared it with in the preceding 12 months. "
            "Submit a verifiable consumer request to privacy@example.com."
        ),
        citation="CCPA §1798.110 + §1798.115",
    ),
    "CCPA-RIGHT-TO-DELETE": _entry(
        label="Right to delete",
        issue="California 'right to delete' not surfaced.",
        original="(omitted)",
        suggested_fix=(
            "California residents have the right to request deletion of "
            "personal information we have collected, subject to the "
            "exceptions in §1798.105(d). We complete deletion requests "
            "within 45 days at no cost."
        ),
        citation="CCPA §1798.105",
    ),
    "CCPA-OPT-OUT": _entry(
        label="Opt-out of sale / sharing",
        issue="No 'Do Not Sell or Share My Personal Information' link disclosed.",
        original="(omitted)",
        suggested_fix=(
            "California residents may opt out of the sale or sharing of "
            "their personal information at any time. Use the link "
            "[Do Not Sell or Share My Personal Information] in our footer, "
            "or send a signed Global Privacy Control header — we honour both."
        ),
        citation="CCPA §1798.135 + CPRA Reg §7026",
    ),
    "CCPA-NON-DISCRIMINATION": _entry(
        label="Non-discrimination commitment",
        issue="No non-discrimination commitment for exercising CCPA rights.",
        original="(omitted)",
        suggested_fix=(
            "We will not discriminate against you for exercising any CCPA "
            "right. We will not deny goods or services, charge different "
            "prices, or provide a different level of quality based on the "
            "exercise of any privacy right."
        ),
        citation="CCPA §1798.125",
    ),
    "CCPA-CATEGORIES": _entry(
        label="Categories of personal information disclosed",
        issue="Categories of PI collected and shared not enumerated.",
        original="(omitted)",
        suggested_fix=(
            "In the last 12 months we collected the following categories "
            "of personal information: identifiers (name, email, IP), "
            "internet activity (pages visited, clicks), geolocation "
            "(approximate), and inferences drawn from the above. We did "
            "not collect sensitive personal information beyond account "
            "credentials."
        ),
        citation="CCPA §1798.110(c)",
    ),
    # ── EU AI Act ─────────────────────────────────────────────────────────
    "AIA-RISK-CLASS": _entry(
        label="Risk classification statement",
        issue="No EU AI Act risk classification — Annex III high-risk obligations unconfirmed.",
        original="(omitted)",
        suggested_fix=(
            "This system has been assessed against EU AI Act Annex III and "
            "is classified as a high-risk AI system in the area of "
            "employment / education / law enforcement (delete as applicable). "
            "The conformity assessment under Art. 43 has been completed; the "
            "CE marking is recorded in the EU database under registration "
            "number EU-AI-2026-XXXXX."
        ),
        citation="EU AI Act Art. 6 + Annex III",
    ),
    "AIA-HUMAN-OVERSIGHT": _entry(
        label="Human oversight provisions",
        issue="Required human-oversight measures (Art. 14) not described.",
        original="(omitted)",
        suggested_fix=(
            "A trained human operator can review every consequential output "
            "before it acts on the user, can override the system at any "
            "time, and can stop the system via a documented kill-switch. "
            "Operator training is refreshed annually."
        ),
        citation="EU AI Act Art. 14",
    ),
    "AIA-TRANSPARENCY": _entry(
        label="Transparency to end-users",
        issue="Required user-facing transparency (Art. 13) not provided.",
        original="(omitted)",
        suggested_fix=(
            "Users are informed at first contact that they are interacting "
            "with an AI system. The system's purpose, intended population, "
            "known limitations, and accuracy expectations are published in "
            "the product's transparency notice (linked below)."
        ),
        citation="EU AI Act Art. 13 + Art. 52",
    ),
    "AIA-LOGGING": _entry(
        label="Automatic logging",
        issue="Required automatic logging (Art. 12) not described.",
        original="(omitted)",
        suggested_fix=(
            "The system automatically records each inference event, the "
            "input identifier, the output, the model version, and the "
            "human-reviewer ID (if applicable). Logs are retained for the "
            "lifecycle of the system plus 10 years and are tamper-evident "
            "via SLSA L2 provenance."
        ),
        citation="EU AI Act Art. 12",
    ),
    "AIA-ROBUSTNESS": _entry(
        label="Accuracy, robustness, cybersecurity",
        issue="No accuracy / robustness / cybersecurity declaration (Art. 15).",
        original="(omitted)",
        suggested_fix=(
            "Accuracy: validated at 92% (95% CI [91.1, 92.7]) on a held-out "
            "test set; performance is monitored continuously and re-trained "
            "on quarterly cadence. Robustness: tested against 200 adversarial "
            "probes across OWASP LLM Top-10 categories. Cybersecurity: "
            "deployed behind authenticated API gateway with rate-limiting "
            "and anomaly detection."
        ),
        citation="EU AI Act Art. 15",
    ),
    # ── SOC 2 ────────────────────────────────────────────────────────────
    "SOC2-CC1-CONTROL-ENV": _entry(
        label="Control environment (CC1)",
        issue="No documented governance / ethics / accountability structure (CC1).",
        original="(omitted)",
        suggested_fix=(
            "The board has approved a Code of Conduct (annual attestation), "
            "an Information Security Policy (CISO-owned, reviewed annually), "
            "and an accountability matrix (RACI) linking each Trust Services "
            "Criterion to a named control owner."
        ),
        citation="AICPA TSC CC1.1 - CC1.5",
    ),
    "SOC2-CC6-LOGICAL-ACCESS": _entry(
        label="Logical access (CC6)",
        issue="No description of authentication / authorisation / privileged-access controls (CC6).",
        original="(omitted)",
        suggested_fix=(
            "All access requires SSO with hardware-key MFA (FIDO2). "
            "Privileged access is granted just-in-time via a four-eyes "
            "approval workflow and expires within 4 hours. Quarterly user-"
            "access reviews are performed by control owner and signed off "
            "by the CISO."
        ),
        citation="AICPA TSC CC6.1 - CC6.8",
    ),
    "SOC2-CC7-MONITORING": _entry(
        label="System monitoring (CC7)",
        issue="No description of monitoring / detection / log-review controls (CC7).",
        original="(omitted)",
        suggested_fix=(
            "All production systems emit OpenTelemetry traces and metrics "
            "to a centralised SIEM (Datadog / Splunk / Elastic). Detection "
            "rules cover the MITRE ATT&CK enterprise matrix; alerts are "
            "triaged 24/7. Log retention is 13 months — exceeds the 12-month "
            "SOC 2 minimum."
        ),
        citation="AICPA TSC CC7.1 - CC7.3",
    ),
    "SOC2-CC7-INCIDENT-RESPONSE": _entry(
        label="Incident response (CC7.4 / CC7.5)",
        issue="No documented incident response plan.",
        original="(omitted)",
        suggested_fix=(
            "An Incident Response Plan governs detection, containment, "
            "eradication, recovery, and post-incident review. The plan is "
            "tested twice a year via tabletop exercise; results, gaps, and "
            "remediation actions are documented and reviewed by the audit "
            "committee."
        ),
        citation="AICPA TSC CC7.4 + CC7.5",
    ),
    "SOC2-A1-AVAILABILITY": _entry(
        label="Availability commitment (A1)",
        issue="No availability SLA / capacity / DR description.",
        original="(omitted)",
        suggested_fix=(
            "The service targets 99.9% monthly availability, measured at "
            "the public API edge. Capacity is reviewed monthly against a "
            "12-month projection. Disaster-recovery: cross-region async "
            "replication, RPO 5 min, RTO 1 hour, tested quarterly."
        ),
        citation="AICPA TSC A1.1 - A1.3",
    ),
    "SOC2-C1-CONFIDENTIALITY": _entry(
        label="Confidentiality (C1)",
        issue="No description of confidentiality classification / handling.",
        original="(omitted)",
        suggested_fix=(
            "Customer data is classified Confidential by default and "
            "encrypted at rest (AES-256) and in transit (TLS 1.3+). Access "
            "is restricted to a named processing group. Confidential data "
            "is purged from non-production environments within 24 hours of "
            "ingestion."
        ),
        citation="AICPA TSC C1.1 - C1.2",
    ),
    # ── General privacy baseline ──────────────────────────────────────────
    "GEN-DATA-COLLECTION": _entry(
        label="Data collection disclosure",
        issue="No statement of what data is collected.",
        original="(omitted)",
        suggested_fix=(
            "We collect: account data you provide (name, email, password "
            "hash); product usage telemetry (page views, feature clicks); "
            "device metadata (IP address, browser fingerprint, OS); and "
            "support correspondence."
        ),
        citation="FTC Section 5 / state UDAP",
    ),
    "GEN-PURPOSE": _entry(
        label="Purpose of processing",
        issue="No statement of *why* data is collected.",
        original="(omitted)",
        suggested_fix=(
            "We use this data to (a) operate and secure the service, "
            "(b) bill you and respond to support requests, (c) improve the "
            "product through aggregated analytics, and (d) send "
            "transactional and (with your consent) marketing emails."
        ),
        citation="GDPR Art. 5(1)(b) / FTC Section 5",
    ),
    "GEN-THIRD-PARTIES": _entry(
        label="Third-party data sharing",
        issue="Third-party processors / recipients not disclosed.",
        original="(omitted)",
        suggested_fix=(
            "We share data with the following sub-processors: Stripe "
            "(billing), AWS (hosting), SendGrid (transactional email), "
            "Datadog (monitoring). A full sub-processor list is maintained "
            "at example.com/subprocessors and updated within 14 days of "
            "any change."
        ),
        citation="GDPR Art. 28 / CCPA §1798.115",
    ),
    "GEN-CONTACT": _entry(
        label="Privacy contact",
        issue="No privacy contact channel.",
        original="(omitted)",
        suggested_fix=(
            "Privacy inquiries: privacy@example.com. Postal: Acme Corp, "
            "Attn: Privacy, 1 Example Street, San Francisco CA 94105."
        ),
        citation="FTC Section 5",
    ),
    "GEN-COOKIES": _entry(
        label="Cookies and similar technologies",
        issue="No cookie disclosure or consent mechanism.",
        original="(omitted)",
        suggested_fix=(
            "We use strictly necessary cookies to operate the service; "
            "analytics and advertising cookies are loaded only after you "
            "grant consent via our cookie banner. You can withdraw consent "
            "at any time via the Cookie Settings link in our footer."
        ),
        citation="ePrivacy Directive Art. 5(3) + GDPR Art. 7",
    ),
}


# ──────────────────────────────────────────────────────────────────────────────
# Public model
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RemediationEntry:
    """One remediation row — clause text, suggested fix, financial exposure."""

    clause_id: str
    label: str
    issue: str
    original: str
    suggested_fix: str
    risk_level: str
    dollar_low_usd: int
    dollar_high_usd: int
    citation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id,
            "label": self.label,
            "issue": self.issue,
            "original": self.original,
            "suggested_fix": self.suggested_fix,
            "risk_level": self.risk_level,
            "dollar_low_usd": self.dollar_low_usd,
            "dollar_high_usd": self.dollar_high_usd,
            "dollar_display": (
                f"{format_usd(self.dollar_low_usd)}–{format_usd(self.dollar_high_usd)}"
                if self.dollar_high_usd > 0 else ""
            ),
            "citation": self.citation,
        }


@dataclass(frozen=True)
class RemediationReport:
    """Full remediation envelope — entries + aggregate exposure."""

    entries: list[RemediationEntry] = field(default_factory=list)
    aggregate: AggregateExposure = field(
        default_factory=lambda: AggregateExposure(0, 0, 0, {})
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "aggregate": self.aggregate.to_dict(),
            "aggregate_display": (
                f"{format_usd(self.aggregate.low_usd)}–{format_usd(self.aggregate.high_usd)}"
                if self.aggregate.high_usd > 0 else ""
            ),
            "count": len(self.entries),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


def build_remediation(
    missing: Iterable[Mapping[str, Any] | str],
) -> RemediationReport:
    """Build a :class:`RemediationReport` from a list of missing clauses.

    ``missing`` may be:
      * a list of dicts as produced by :class:`QuickCheckResult.to_dict`
        (``[{"id": "GDPR-LAWFUL-BASIS", "label": …, "severity": …, …}, …]``)
      * a list of plain clause-id strings — the catalogue label is used.
    """

    entries: list[RemediationEntry] = []
    ids: list[str] = []
    for item in missing:
        if isinstance(item, str):
            clause_id = item
            override_label = ""
        elif isinstance(item, Mapping):
            clause_id = str(item.get("id") or item.get("clause_id") or "")
            override_label = str(item.get("label") or "")
        else:
            continue
        if not clause_id:
            continue
        catalog = _REMEDIATION_CATALOG.get(clause_id)
        band = quantify(clause_id)
        if catalog is None:
            entry = RemediationEntry(
                clause_id=clause_id,
                label=override_label or clause_id,
                issue="No remediation guidance available for this clause yet.",
                original="(omitted)",
                suggested_fix=(
                    "Add a clause covering this requirement. "
                    "Open an issue on github.com/konjoai/squash if you would like "
                    "guidance shipped in the catalogue."
                ),
                risk_level=(band.risk_level if band else "medium"),
                dollar_low_usd=(band.low_usd if band else 0),
                dollar_high_usd=(band.high_usd if band else 0),
                citation=(band.citation if band else ""),
            )
        else:
            entry = RemediationEntry(
                clause_id=clause_id,
                label=catalog["label"],
                issue=catalog["issue"],
                original=catalog["original"],
                suggested_fix=catalog["suggested_fix"],
                risk_level=(band.risk_level if band else "medium"),
                dollar_low_usd=(band.low_usd if band else 0),
                dollar_high_usd=(band.high_usd if band else 0),
                citation=catalog.get("citation", "") or (band.citation if band else ""),
            )
        entries.append(entry)
        ids.append(clause_id)

    return RemediationReport(entries=entries, aggregate=aggregate_exposure(ids))


def covered_clause_ids() -> list[str]:
    """Return the list of clause-IDs the catalogue covers."""

    return list(_REMEDIATION_CATALOG.keys())


__all__ = [
    "RemediationEntry",
    "RemediationReport",
    "build_remediation",
    "covered_clause_ids",
]
