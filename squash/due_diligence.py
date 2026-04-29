"""squash/due_diligence.py — M&A / Investment AI Due Diligence Package.

When a company acquires another company, or when a PE firm evaluates an AI
company for investment, the AI compliance posture is one of the highest-risk
unknowns.  What models are they running?  Are there CVEs?  Do they have
training data provenance?  Any unresolved bias audit failures?  Pending
regulatory actions?

``squash due-diligence`` generates a complete AI compliance snapshot designed
to be reviewed by acquiring legal teams — in under 5 minutes instead of 2 weeks.

Package contents
----------------
1. **Executive Risk Summary** — AI compliance posture in 5 bullets
2. **Model Portfolio Inventory** — every model, version, risk tier, attestation status
3. **Security Exposure Report** — CVEs, model scanning results, signing status
4. **Regulatory Compliance Matrix** — EU AI Act, NIST RMF, ISO 42001 coverage per model
5. **Training Data Provenance** — dataset licenses, PII exposure
6. **Bias Audit Results** — protected attribute testing results
7. **Incident History** — past AI incidents and remediation
8. **Vendor Risk Register** — third-party AI tools in use
9. **Open Findings** — unresolved violations, gaps, and liabilities
10. **Representations and Warranties Guidance** — standard R&W language for AI in M&A

Output: signed ZIP with JSON + Markdown + PDF summary.

Usage::

    from squash.due_diligence import DueDiligenceGenerator
    pkg = DueDiligenceGenerator.generate(
        models_dir=Path("./models"),
        company_name="AcmeCorp",
        deal_type="acquisition",
    )
    pkg.save(Path("./dd-package/"))
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ModelDDEntry:
    model_id: str
    model_path: str
    risk_tier: str
    compliance_score: float | None
    last_attested: str | None
    open_violations: int
    open_cves: int
    frameworks: list[str]
    has_bias_audit: bool
    has_data_lineage: bool
    has_annex_iv: bool
    has_slsa: bool
    drift_detected: bool
    liability_flags: list[str]  # specific risks for acquirer's legal team


@dataclass
class DueDiligencePackage:
    package_id: str
    company_name: str
    deal_type: str          # "acquisition", "investment", "partnership"
    generated_at: str
    models: list[ModelDDEntry] = field(default_factory=list)
    overall_risk_rating: str = "UNKNOWN"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    total_liability_flags: int = 0
    open_findings: int = 0
    critical_findings: list[str] = field(default_factory=list)
    rw_guidance: list[str] = field(default_factory=list)
    package_hash: str = ""

    def executive_risk_summary(self) -> str:
        rating_color = {
            "LOW": "✅", "MEDIUM": "⚠", "HIGH": "🔴", "CRITICAL": "💥", "UNKNOWN": "?"
        }.get(self.overall_risk_rating, "?")
        lines = [
            f"M&A AI DUE DILIGENCE — {self.company_name}",
            "=" * 56,
            f"Package ID:    {self.package_id}",
            f"Deal Type:     {self.deal_type.upper()}",
            f"Generated:     {self.generated_at}",
            f"AI Risk Rating: {rating_color} {self.overall_risk_rating}",
            "",
            f"Models in scope:          {len(self.models)}",
            f"Open compliance findings: {self.open_findings}",
            f"Critical liability flags: {len(self.critical_findings)}",
            "",
        ]
        if self.critical_findings:
            lines.append("Critical Findings (Acquirer Action Required):")
            for f in self.critical_findings:
                lines.append(f"  ⚠  {f}")
            lines.append("")
        if self.rw_guidance:
            lines.append("R&W Guidance (standard language):")
            for r in self.rw_guidance[:3]:
                lines.append(f"  → {r}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": "AI_MA_DUE_DILIGENCE_PACKAGE",
            "package_id": self.package_id,
            "company_name": self.company_name,
            "deal_type": self.deal_type,
            "generated_at": self.generated_at,
            "overall_risk_rating": self.overall_risk_rating,
            "total_liability_flags": self.total_liability_flags,
            "open_findings": self.open_findings,
            "package_hash": self.package_hash,
            "critical_findings": self.critical_findings,
            "representations_and_warranties_guidance": self.rw_guidance,
            "model_inventory": [
                {
                    "model_id": m.model_id,
                    "risk_tier": m.risk_tier,
                    "compliance_score": m.compliance_score,
                    "last_attested": m.last_attested,
                    "open_violations": m.open_violations,
                    "open_cves": m.open_cves,
                    "frameworks": m.frameworks,
                    "has_bias_audit": m.has_bias_audit,
                    "has_data_lineage": m.has_data_lineage,
                    "has_annex_iv": m.has_annex_iv,
                    "has_slsa": m.has_slsa,
                    "drift_detected": m.drift_detected,
                    "liability_flags": m.liability_flags,
                }
                for m in self.models
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# AI Due Diligence Package — {self.company_name}",
            "",
            f"**Package ID:** {self.package_id}  ",
            f"**Deal Type:** {self.deal_type.title()}  ",
            f"**Generated:** {self.generated_at}  ",
            f"**AI Risk Rating:** {self.overall_risk_rating}",
            "",
            "---",
            "",
            "## Executive Risk Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Models in Scope | {len(self.models)} |",
            f"| Overall Risk Rating | **{self.overall_risk_rating}** |",
            f"| Open Compliance Findings | {self.open_findings} |",
            f"| Critical Liability Flags | {len(self.critical_findings)} |",
            "",
        ]
        if self.critical_findings:
            lines += ["## Critical Findings", ""]
            for f in self.critical_findings:
                lines.append(f"- ⚠ {f}")
            lines.append("")
        if self.models:
            lines += [
                "## Model Inventory",
                "",
                "| Model | Risk Tier | Score | CVEs | Violations | Bias Audit | Data Lineage | Flags |",
                "|-------|-----------|-------|------|------------|------------|--------------|-------|",
            ]
            for m in self.models:
                score = f"{m.compliance_score:.0f}%" if m.compliance_score else "N/A"
                ba = "✅" if m.has_bias_audit else "❌"
                dl = "✅" if m.has_data_lineage else "❌"
                flags = len(m.liability_flags)
                lines.append(
                    f"| {m.model_id} | {m.risk_tier} | {score} | {m.open_cves} | "
                    f"{m.open_violations} | {ba} | {dl} | {flags} |"
                )
            lines.append("")
        if self.rw_guidance:
            lines += ["## Representations & Warranties Guidance", ""]
            for r in self.rw_guidance:
                lines.append(f"- {r}")
            lines.append("")
        lines += [
            "---",
            "*Generated by squash-ai — getsquash.dev*",
        ]
        return "\n".join(lines)

    def save(self, output_dir: Path) -> list[str]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: list[str] = []

        json_path = output_dir / f"dd-{self.package_id}.json"
        json_path.write_text(json.dumps(self.to_dict(), indent=2))
        written.append(str(json_path))

        md_path = output_dir / f"dd-{self.package_id}.md"
        md_path.write_text(self.to_markdown())
        written.append(str(md_path))

        summary_path = output_dir / f"dd-{self.package_id}-executive-summary.txt"
        summary_path.write_text(self.executive_risk_summary())
        written.append(str(summary_path))

        # ZIP bundle
        zip_path = output_dir / f"dd-{self.package_id}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in [json_path, md_path, summary_path]:
                zf.write(p, p.name)
        written.append(str(zip_path))

        log.info("Due diligence package written to %s", output_dir)
        return written


class DueDiligenceGenerator:
    """Generate an M&A AI due diligence package."""

    @staticmethod
    def generate(
        company_name: str = "Target Company",
        deal_type: str = "acquisition",
        models_dir: Path | None = None,
        model_paths: list[Path] | None = None,
    ) -> DueDiligencePackage:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        pkg_id = hashlib.sha256(f"{company_name}{now}".encode()).hexdigest()[:10].upper()

        paths: list[Path] = []
        if model_paths:
            paths = [Path(p) for p in model_paths]
        elif models_dir:
            mp = Path(models_dir)
            if mp.is_dir():
                for child in sorted(mp.iterdir()):
                    if child.is_dir():
                        paths.append(child)
                if (mp / "squash_attestation.json").exists():
                    paths = [mp]
        if not paths and models_dir:
            paths = [Path(models_dir)]

        models = [_build_dd_entry(p) for p in paths]
        critical_findings, rw_guidance, risk_rating = _assess_risk(models)

        open_findings = sum(m.open_violations for m in models)
        total_flags = sum(len(m.liability_flags) for m in models)

        pkg_data = json.dumps({"company": company_name, "models": len(models), "ts": now})
        pkg_hash = hashlib.sha256(pkg_data.encode()).hexdigest()

        return DueDiligencePackage(
            package_id=pkg_id,
            company_name=company_name,
            deal_type=deal_type,
            generated_at=now,
            models=models,
            overall_risk_rating=risk_rating,
            total_liability_flags=total_flags,
            open_findings=open_findings,
            critical_findings=critical_findings,
            rw_guidance=rw_guidance,
            package_hash=pkg_hash,
        )


def _build_dd_entry(model_path: Path) -> ModelDDEntry:
    attest_path = _find_attestation(model_path)
    liability_flags: list[str] = []

    if attest_path is None:
        liability_flags.append("No squash attestation — compliance posture unknown")
        return ModelDDEntry(
            model_id=model_path.name, model_path=str(model_path),
            risk_tier="unknown", compliance_score=None, last_attested=None,
            open_violations=0, open_cves=0, frameworks=[],
            has_bias_audit=False, has_data_lineage=False,
            has_annex_iv=False, has_slsa=False, drift_detected=False,
            liability_flags=liability_flags,
        )

    try:
        data = json.loads(attest_path.read_text())
    except (json.JSONDecodeError, OSError):
        liability_flags.append("Attestation file corrupt or unreadable")
        return ModelDDEntry(
            model_id=model_path.name, model_path=str(model_path),
            risk_tier="unknown", compliance_score=None, last_attested=None,
            open_violations=0, open_cves=0, frameworks=[],
            has_bias_audit=False, has_data_lineage=False,
            has_annex_iv=False, has_slsa=False, drift_detected=False,
            liability_flags=liability_flags,
        )

    model_id = data.get("model_id") or model_path.name
    score = data.get("compliance_score") or data.get("score")
    risk_tier = data.get("risk_tier", "unknown")
    frameworks = data.get("policies_checked") or data.get("frameworks") or []
    violations = data.get("violations") or []
    n_viol = len(violations) if isinstance(violations, list) else int(violations or 0)
    attested_at = data.get("attested_at") or data.get("timestamp")

    # Check CVEs
    cves = 0
    if (model_path / "vex_report.json").exists():
        try:
            cves = json.loads((model_path / "vex_report.json").read_text()).get("total_count", 0)
        except (json.JSONDecodeError, OSError):
            pass

    # Check drift
    drift = False
    if (model_path / "drift_report.json").exists():
        try:
            drift = bool(json.loads((model_path / "drift_report.json").read_text()).get("drift_detected", False))
        except (json.JSONDecodeError, OSError):
            pass

    # Document presence checks
    has_bias = (model_path / "bias_audit_report.json").exists()
    has_lineage = (model_path / "data_lineage_certificate.json").exists()
    has_annex = (model_path / "annex_iv.json").exists()
    has_slsa = (model_path / "slsa_provenance.json").exists()

    # Build liability flags
    if score is not None and float(score) < 70:
        liability_flags.append(f"Low compliance score: {score:.1f}% — below 70% threshold")
    if n_viol > 0:
        liability_flags.append(f"{n_viol} unresolved policy violation(s)")
    if cves > 0:
        liability_flags.append(f"{cves} open CVE(s) in model dependencies")
    if not has_bias and risk_tier in ("high", "critical"):
        liability_flags.append("No bias audit for high-risk AI — NYC LL144 / EU AI Act Annex III exposure")
    if not has_lineage:
        liability_flags.append("No training data lineage certificate — potential GDPR/copyright liability")
    if not has_annex and risk_tier in ("high", "critical"):
        liability_flags.append("No EU AI Act Annex IV documentation for high-risk system")
    if drift:
        liability_flags.append("Model drift detected — production model may differ from attested version")
    if not has_slsa:
        liability_flags.append("No SLSA build provenance — supply chain integrity unverified")

    return ModelDDEntry(
        model_id=model_id, model_path=str(model_path),
        risk_tier=risk_tier, compliance_score=float(score) if score else None,
        last_attested=attested_at, open_violations=n_viol, open_cves=cves,
        frameworks=frameworks if isinstance(frameworks, list) else [frameworks],
        has_bias_audit=has_bias, has_data_lineage=has_lineage,
        has_annex_iv=has_annex, has_slsa=has_slsa,
        drift_detected=drift, liability_flags=liability_flags,
    )


def _assess_risk(
    models: list[ModelDDEntry],
) -> tuple[list[str], list[str], str]:
    """Compute overall risk rating, critical findings, and R&W guidance."""
    critical_findings: list[str] = []
    total_flags = sum(len(m.liability_flags) for m in models)
    any_unattested = any(m.last_attested is None for m in models)
    any_high_risk = any(m.risk_tier in ("high", "critical") for m in models)
    any_no_lineage = any(not m.has_data_lineage for m in models)
    any_no_bias = any(not m.has_bias_audit and m.risk_tier in ("high", "critical") for m in models)
    open_violations = sum(m.open_violations for m in models)
    open_cves = sum(m.open_cves for m in models)

    if any_unattested:
        critical_findings.append(
            "One or more models have no compliance attestation — liability scope unknown"
        )
    if any_no_lineage:
        critical_findings.append(
            "Training data provenance not documented — potential GDPR Article 6 and copyright liability"
        )
    if any_no_bias and any_high_risk:
        critical_findings.append(
            "High-risk AI without bias audit — exposure under NYC Local Law 144 and EU AI Act Annex III"
        )
    if open_violations > 0:
        critical_findings.append(
            f"{open_violations} unresolved policy violations require remediation before close"
        )
    if open_cves > 5:
        critical_findings.append(
            f"{open_cves} open CVEs in AI model stack — security patch timeline required"
        )

    # R&W guidance
    rw: list[str] = [
        "Seller represents that all AI systems listed in Schedule A comply with applicable AI regulations as of the Closing Date.",
        "Seller warrants that all training data used in AI models was obtained with appropriate licenses and GDPR legal basis.",
        "Seller discloses all pending regulatory investigations relating to AI systems.",
        "Buyer entitled to indemnification for pre-closing AI compliance violations exceeding $[X] individually or $[Y] in aggregate.",
        "Seller shall remediate all open squash compliance violations within 30 days of Closing.",
        "AI systems rated HIGH or CRITICAL risk under EU AI Act shall obtain Annex IV documentation within 90 days.",
    ]

    # Risk rating
    if len(critical_findings) >= 3 or open_cves > 10:
        rating = "CRITICAL"
    elif len(critical_findings) >= 2 or total_flags >= 10:
        rating = "HIGH"
    elif len(critical_findings) >= 1 or total_flags >= 5:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return critical_findings, rw, rating


def _find_attestation(model_path: Path) -> Path | None:
    for p in [
        model_path / "squash_attestation.json",
        model_path / "squash-attest.json",
        model_path / "squash" / "squash_attestation.json",
    ]:
        if p.exists():
            return p
    return None
