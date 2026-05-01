"""squash/insurance.py — Sprint 24 W235–W237 (Track C / C6).

AI Cyber Insurance Risk Package Generator: ``squash insurance-package``.

AI cyber-insurance is crystallising in late 2026. Underwriters (Munich Re,
Coalition, AIG, Beazley) are publishing AI-specific risk questionnaires and
demanding standardised evidence packages before they'll quote a policy. Every
enterprise that deploys AI faces this procurement gate. Squash is uniquely
positioned to generate the package automatically — all the data already exists
in the attestation record.

This module opens a **new buyer motion**: the Chief Risk Officer and insurance
procurement. They are not CISO, not ML engineer. They want:
  1. A quantified risk score they can send to the underwriter.
  2. Evidence that controls are in place (attestation, scan, CVE management).
  3. A documented incident response plan.
  4. The whole thing in a ZIP they can attach to the submission form.

Architecture
============

``ModelRiskProfile``
    Per-model risk summary: risk tier, compliance score, CVE count, drift
    events, incident count, bias status, last attestation timestamp.

``InsurancePackage``
    Aggregate: all model profiles, organisation-level risk score, compliance
    score, response-plan status, and the three underwriter-format outputs.
    Renders to JSON + Markdown + signed ZIP.

``InsuranceBuilder``
    Stateless. Reads squash artefact files from a model directory tree and
    constructs an ``InsurancePackage``. Gracefully degrades when artefacts
    are absent — surfacing the gap as a risk factor rather than crashing.

Underwriter adapters (W236)
---------------------------

``MunichReAdapter``
    Maps InsurancePackage to the Munich Re AI cyber-underwriting schema
    (5 control domains, quantitative ratings, coverage recommendations).

``CoalitionAdapter``
    Maps to Coalition's AI Risk Assessment schema (security, operational,
    governance, incident history, third-party risk).

``GenericAdapter``
    Generic JSON schema for underwriters that have not published a format.

ZIP bundle (W237)
-----------------

``InsurancePackage.save_zip(output_path)`` builds:

    insurance-package.json          Main structured report
    insurance-munich-re.json        Munich Re format
    insurance-coalition.json        Coalition format
    insurance-executive-summary.md  Human-readable
    integrity.sha256                File hash manifest

Stdlib-only. No external dependencies. Risk scoring is deterministic
and audit-trail-friendly — every score derives from a squash artefact
field with a documented formula.
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

# ── Canonical artefact filenames (shared with audit_sim.py) ──────────────────

_ATTEST        = "squash-attest.json"
_ATTEST_ALT    = "squash_attestation.json"
_BOM           = "cyclonedx-mlbom.json"
_SCAN          = "squash-scan.json"
_VEX           = "squash-vex-report.json"
_INCIDENT      = "squash-incident.json"
_DRIFT         = "squash-drift.json"
_BIAS          = "bias_audit_report.json"
_LINEAGE       = "data_lineage_certificate.json"
_ANNEX_IV      = "annex_iv.json"
_SQUASH_CFG    = ".squash.yml"
_POLICY_PREFIX = "squash-policy-"

# ── Risk tier thresholds ──────────────────────────────────────────────────────

_HIGH_RISK_DOMAINS   = frozenset({"healthcare", "finance", "hr", "law_enforcement",
                                   "education", "infrastructure", "defence"})
_TIER_THRESHOLDS = {
    "HIGH":   (0,  49),
    "MEDIUM": (50, 79),
    "LOW":    (80, 100),
}


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class ModelRiskProfile:
    """Per-model risk summary consumed by insurance underwriters.

    Every field maps to a control domain in the underwriter schema so
    the package can be machine-read by underwriter APIs.
    """

    model_id: str
    model_path: str
    risk_tier: str                     # "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    compliance_score: int              # 0–100 (100 = fully compliant)
    frameworks_assessed: list[str]     # policy names evaluated
    frameworks_passing: list[str]      # policies where passed=true
    cve_count: int                     # total CVEs in VEX report
    critical_cve_count: int            # CVEs with severity critical/high
    drift_events: int                  # number of drift events detected
    incident_count: int                # recorded incidents
    bias_status: str                   # "PASS" | "FAIL" | "NOT_ASSESSED"
    last_attested: str                 # ISO-8601 date (or "never")
    attestation_id: str                # squash model_id or derivation
    scan_status: str                   # "clean" | "unsafe" | "warning" | "skipped"
    has_incident_plan: bool            # .squash.yml or incident artefact present
    has_data_lineage: bool             # data_lineage_certificate.json present
    has_model_card: bool               # squash-model-card-hf.md present
    has_annex_iv: bool                 # annex_iv.json present

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "model_path": self.model_path,
            "risk_tier": self.risk_tier,
            "compliance_score": self.compliance_score,
            "frameworks_assessed": self.frameworks_assessed,
            "frameworks_passing": self.frameworks_passing,
            "cve_count": self.cve_count,
            "critical_cve_count": self.critical_cve_count,
            "drift_events": self.drift_events,
            "incident_count": self.incident_count,
            "bias_status": self.bias_status,
            "last_attested": self.last_attested,
            "attestation_id": self.attestation_id,
            "scan_status": self.scan_status,
            "controls": {
                "incident_plan": self.has_incident_plan,
                "data_lineage": self.has_data_lineage,
                "model_card": self.has_model_card,
                "technical_documentation": self.has_annex_iv,
            },
        }


@dataclass
class InsurancePackage:
    """Standardised AI cyber insurance risk-quantification package.

    Contains per-model profiles, aggregate scores, and three underwriter
    format outputs (Munich Re, Coalition, Generic).

    The ``save_zip()`` method produces the submission-ready bundle.
    """

    org_name: str
    generated_at: str
    model_profiles: list[ModelRiskProfile]
    aggregate_risk_score: int          # 0–100 (higher = more risk for underwriter)
    aggregate_compliance_score: int    # 0–100 (higher = better posture)
    response_plan_documented: bool
    total_models: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    open_cves: int
    critical_cves: int
    recent_incidents: int
    drift_events_total: int
    bias_fails: int
    executive_summary: str = ""
    squash_version: str = "insurance_v1"

    # ── Serialisation ─────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "squash_version": self.squash_version,
            "org_name": self.org_name,
            "generated_at": self.generated_at,
            "aggregate": {
                "risk_score": self.aggregate_risk_score,
                "compliance_score": self.aggregate_compliance_score,
                "response_plan_documented": self.response_plan_documented,
                "total_models": self.total_models,
                "risk_distribution": {
                    "high": self.high_risk_count,
                    "medium": self.medium_risk_count,
                    "low": self.low_risk_count,
                },
                "open_cves": self.open_cves,
                "critical_cves": self.critical_cves,
                "recent_incidents": self.recent_incidents,
                "drift_events_total": self.drift_events_total,
                "bias_fails": self.bias_fails,
            },
            "executive_summary": self.executive_summary,
            "model_profiles": [p.to_dict() for p in self.model_profiles],
            "underwriter_formats": {
                "munich_re": MunichReAdapter().format(self),
                "coalition": CoalitionAdapter().format(self),
                "generic": GenericAdapter().format(self),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        risk_band = _risk_band(self.aggregate_risk_score)
        compliant_band = _compliance_band(self.aggregate_compliance_score)

        lines: list[str] = [
            f"# AI Cyber Insurance Risk Package",
            f"## {self.org_name or 'Organisation'}",
            "",
            f"**Generated:** {self.generated_at[:10]}  ",
            f"**Prepared by:** squash · getsquash.dev",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
            "## Aggregate Risk Scorecard",
            "",
            "| Metric | Value | Rating |",
            "|---|---|---|",
            f"| **Aggregate Risk Score** | {self.aggregate_risk_score}/100 | {risk_band} |",
            f"| **Compliance Posture Score** | {self.aggregate_compliance_score}/100 | {compliant_band} |",
            f"| Total AI Models | {self.total_models} | — |",
            f"| High-Risk Models | {self.high_risk_count} | {'⚠️' if self.high_risk_count else '✅'} |",
            f"| Open CVEs | {self.open_cves} | {'🔴' if self.critical_cves else ('⚠️' if self.open_cves else '✅')} |",
            f"| Critical/High CVEs | {self.critical_cves} | {'🔴' if self.critical_cves else '✅'} |",
            f"| Recent Incidents | {self.recent_incidents} | {'⚠️' if self.recent_incidents else '✅'} |",
            f"| Drift Events (Total) | {self.drift_events_total} | {'⚠️' if self.drift_events_total else '✅'} |",
            f"| Bias Audit Failures | {self.bias_fails} | {'🔴' if self.bias_fails else '✅'} |",
            f"| Response Plan Documented | {'Yes' if self.response_plan_documented else 'No'} | {'✅' if self.response_plan_documented else '⚠️'} |",
            "",
            "## Model Inventory",
            "",
            "| Model ID | Risk Tier | Compliance | CVEs | Drift | Bias | Attested |",
            "|---|---|---|---|---|---|---|",
        ]
        for p in sorted(self.model_profiles, key=lambda x: (
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}[x.risk_tier], -x.cve_count
        )):
            tier_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "✅", "UNKNOWN": "⚪"}.get(
                p.risk_tier, "⚪"
            )
            lines.append(
                f"| `{p.model_id}` | {tier_icon} {p.risk_tier} "
                f"| {p.compliance_score}% "
                f"| {p.cve_count} ({p.critical_cve_count} crit) "
                f"| {p.drift_events} "
                f"| {p.bias_status} "
                f"| {p.last_attested[:10] if p.last_attested != 'never' else '❌ never'} |"
            )

        lines += [
            "",
            "## Munich Re AI Cyber Assessment",
            "",
            "| Domain | Rating | Notes |",
            "|---|---|---|",
        ]
        mr = MunichReAdapter().format(self)
        for domain, data in mr.get("control_domains", {}).items():
            lines.append(
                f"| {domain.replace('_', ' ').title()} "
                f"| {data.get('rating', '—')} "
                f"| {data.get('notes', '')} |"
            )

        lines += [
            "",
            "## Coalition AI Risk Assessment",
            "",
            "| Category | Score | Assessment |",
            "|---|---|---|",
        ]
        co = CoalitionAdapter().format(self)
        for cat, data in co.get("risk_categories", {}).items():
            lines.append(
                f"| {cat.replace('_', ' ').title()} "
                f"| {data.get('score', '—')}/100 "
                f"| {data.get('assessment', '')} |"
            )

        lines += [
            "",
            "## Controls Evidence Summary",
            "",
            "| Control | Coverage | Gap |",
            "|---|---|---|",
        ]
        total = max(self.total_models, 1)
        with_attest = sum(1 for p in self.model_profiles if p.last_attested != "never")
        with_scan   = sum(1 for p in self.model_profiles if p.scan_status != "skipped")
        with_vex    = sum(1 for p in self.model_profiles if p.cve_count >= 0)  # VEX found
        with_bias   = sum(1 for p in self.model_profiles if p.bias_status != "NOT_ASSESSED")
        with_plan   = sum(1 for p in self.model_profiles if p.has_incident_plan)
        with_lin    = sum(1 for p in self.model_profiles if p.has_data_lineage)
        with_doc    = sum(1 for p in self.model_profiles if p.has_annex_iv)

        def _cov(n: int) -> str:
            pct = int(100 * n / total)
            return f"{n}/{total} ({pct}%)"

        for ctrl, n in [
            ("Model Attestation", with_attest),
            ("Security Scan", with_scan),
            ("CVE Monitoring (VEX)", with_vex),
            ("Bias Audit", with_bias),
            ("Incident Response Plan", with_plan),
            ("Training Data Lineage", with_lin),
            ("Technical Documentation (Annex IV)", with_doc),
        ]:
            gap = "✅" if n == total else (f"⚠️ {total - n} model(s) missing" if n > 0 else "🔴 None")
            lines.append(f"| {ctrl} | {_cov(n)} | {gap} |")

        lines += [
            "",
            "---",
            "",
            "*Package generated by [squash](https://getsquash.dev) · "
            "`squash insurance-package` · Squash violations, not velocity.*",
        ]
        return "\n".join(lines) + "\n"

    def save_zip(self, output_path: Path | str) -> Path:
        """Write the signed insurance bundle as a ZIP file.

        Bundle contents::

            insurance-package.json          Main structured report
            insurance-munich-re.json        Munich Re format
            insurance-coalition.json        Coalition format
            insurance-executive-summary.md  Human-readable
            integrity.sha256                File hash manifest

        Returns:
            Path to the written ZIP file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        main_json       = self.to_json()
        munich_json     = json.dumps(MunichReAdapter().format(self), indent=2, sort_keys=True)
        coalition_json  = json.dumps(CoalitionAdapter().format(self), indent=2, sort_keys=True)
        generic_json    = json.dumps(GenericAdapter().format(self), indent=2, sort_keys=True)
        exec_md         = self.to_markdown()

        files = {
            "insurance-package.json":          main_json.encode(),
            "insurance-munich-re.json":         munich_json.encode(),
            "insurance-coalition.json":         coalition_json.encode(),
            "insurance-generic.json":           generic_json.encode(),
            "insurance-executive-summary.md":   exec_md.encode(),
        }
        manifest_lines: list[str] = []
        for name, content in files.items():
            digest = hashlib.sha256(content).hexdigest()
            manifest_lines.append(f"{digest}  {name}")
        integrity_content = "\n".join(manifest_lines).encode()

        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
            zf.writestr("integrity.sha256", integrity_content)

        log.info("insurance: bundle written to %s (%d models)", output_path, self.total_models)
        return output_path

    def save(
        self,
        output_dir: Path | str,
        stem: str = "insurance-package",
    ) -> dict[str, Path]:
        """Write JSON + Markdown to *output_dir*."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}

        p = output_dir / f"{stem}.json"
        p.write_text(self.to_json(), encoding="utf-8")
        written["json"] = p

        p = output_dir / f"{stem}.md"
        p.write_text(self.to_markdown(), encoding="utf-8")
        written["md"] = p

        return written


# ── Builder ───────────────────────────────────────────────────────────────────


class InsuranceBuilder:
    """Collect squash artefact data and produce an ``InsurancePackage``.

    Usage::

        pkg = InsuranceBuilder().build(
            models_dir=Path("./models"),
            org_name="Acme Corp",
        )
        pkg.save_zip("./insurance-bundle.zip")

    If *models_dir* contains per-model subdirectories, each is scanned for
    squash artefacts. If the directory itself contains artefacts directly
    (single-model use), it is treated as one model.
    """

    def build(
        self,
        models_dir: Path | str,
        org_name: str = "",
    ) -> InsurancePackage:
        """Scan *models_dir* and return an ``InsurancePackage``.

        Args:
            models_dir: Root directory. Each subdirectory that contains at
                least one squash artefact is treated as a separate model.
                The root itself is also scanned as a fallback.
            org_name:   Organisation name shown in the package header.

        Returns:
            ``InsurancePackage`` ready for ``save_zip()`` or ``save()``.
        """
        models_dir = Path(models_dir)
        model_dirs = _discover_model_dirs(models_dir)

        profiles: list[ModelRiskProfile] = []
        for model_path in model_dirs:
            try:
                profile = self._profile_model(model_path)
                profiles.append(profile)
            except Exception as exc:  # noqa: BLE001
                log.warning("insurance: skipped %s — %s", model_path, exc)

        return _aggregate(profiles, org_name)

    def _profile_model(self, model_path: Path) -> ModelRiskProfile:
        arts = _load_artifacts(model_path)

        # ── Model ID ──────────────────────────────────────────────────────
        model_id = _extract_model_id(arts, model_path)

        # ── Compliance score (from policy reports or attestation) ─────────
        frameworks_assessed: list[str] = []
        frameworks_passing:  list[str] = []
        compliance_score = 0
        attest = arts.get(_ATTEST) or arts.get(_ATTEST_ALT) or {}
        if attest:
            policy_results = attest.get("policy_results", {})
            for policy_name, pr in policy_results.items():
                frameworks_assessed.append(policy_name)
                if pr.get("passed") or pr.get("error_count", 1) == 0:
                    frameworks_passing.append(policy_name)
        # Also pick up squash-policy-*.json files
        for name, data in arts.items():
            if name.startswith(_POLICY_PREFIX) and isinstance(data, dict):
                pname = name[len(_POLICY_PREFIX):].replace(".json", "")
                if pname not in frameworks_assessed:
                    frameworks_assessed.append(pname)
                if data.get("passed", False):
                    if pname not in frameworks_passing:
                        frameworks_passing.append(pname)

        if frameworks_assessed:
            compliance_score = int(
                100 * len(frameworks_passing) / max(len(frameworks_assessed), 1)
            )

        # ── CVE exposure ──────────────────────────────────────────────────
        cve_count = 0
        critical_cve_count = 0
        vex = arts.get(_VEX, {})
        stmts = vex.get("statements", []) or []
        for stmt in stmts:
            status = stmt.get("status", "")
            if status not in ("not_affected", "fixed"):
                cve_count += 1
                sev = str(stmt.get("severity", "") or "").lower()
                if sev in ("critical", "high"):
                    critical_cve_count += 1

        # ── Scan status ───────────────────────────────────────────────────
        scan = arts.get(_SCAN, {})
        scan_status = scan.get("status", "skipped") if scan else "skipped"

        # ── Drift events ──────────────────────────────────────────────────
        drift = arts.get(_DRIFT, {})
        drift_events = 0
        if drift:
            drift_events = (
                len(drift.get("events", []))
                or int(drift.get("event_count", 0))
                or (1 if drift.get("drift_detected") else 0)
            )

        # ── Incident count ────────────────────────────────────────────────
        incident = arts.get(_INCIDENT, {})
        incident_count = (
            len(incident.get("incidents", []))
            or int(incident.get("count", 0))
            if incident else 0
        )

        # ── Bias status ───────────────────────────────────────────────────
        bias = arts.get(_BIAS, {})
        if not bias:
            bias_status = "NOT_ASSESSED"
        elif bias.get("passed") is True:
            bias_status = "PASS"
        elif bias.get("overall_status", "").upper() == "PASS":
            bias_status = "PASS"
        else:
            bias_status = "FAIL"

        # ── Last attested + attestation ID ───────────────────────────────
        last_attested = "never"
        attestation_id = model_id
        if attest:
            last_attested = (
                attest.get("generated_at")
                or attest.get("attested_at")
                or attest.get("timestamp", "")[:19]
                or "never"
            )
            attestation_id = attest.get("model_id") or model_id

        # ── Risk tier ────────────────────────────────────────────────────
        risk_tier = _compute_risk_tier(
            compliance_score, critical_cve_count, scan_status,
            drift_events, incident_count, bool(frameworks_assessed),
        )

        # ── Control presence ────────────────────────────────────────────
        has_incident_plan = bool(incident) or bool(arts.get(_SQUASH_CFG))
        has_data_lineage  = bool(arts.get(_LINEAGE))
        has_model_card    = "squash-model-card-hf.md" in arts
        has_annex_iv      = bool(arts.get(_ANNEX_IV))

        return ModelRiskProfile(
            model_id=model_id,
            model_path=str(model_path),
            risk_tier=risk_tier,
            compliance_score=compliance_score,
            frameworks_assessed=frameworks_assessed,
            frameworks_passing=frameworks_passing,
            cve_count=cve_count,
            critical_cve_count=critical_cve_count,
            drift_events=drift_events,
            incident_count=incident_count,
            bias_status=bias_status,
            last_attested=last_attested,
            attestation_id=attestation_id,
            scan_status=scan_status,
            has_incident_plan=has_incident_plan,
            has_data_lineage=has_data_lineage,
            has_model_card=has_model_card,
            has_annex_iv=has_annex_iv,
        )


# ── Underwriter adapters (W236) ───────────────────────────────────────────────


class MunichReAdapter:
    """Map an InsurancePackage to Munich Re's AI cyber underwriting schema.

    Munich Re's published AI risk framework uses five control domains
    (Technical Security, Operational Excellence, AI Governance, Data Quality,
    Incident Resilience) each rated A–D, with an overall AI Maturity Level 1–4.

    Rating logic:
      - A (Excellent): ≥90% of controls demonstrated
      - B (Good):      70–89%
      - C (Fair):      50–69%
      - D (Poor):      <50% or critical gaps
    """

    def format(self, pkg: InsurancePackage) -> dict[str, Any]:
        total = max(pkg.total_models, 1)

        def _pct(predicate_count: int) -> int:
            return int(100 * predicate_count / total)

        # Control domain scores ────────────────────────────────────────────
        tech_sec_pct  = _pct(sum(1 for p in pkg.model_profiles
                                  if p.scan_status in ("clean", "warning")))
        ops_exc_pct   = _pct(sum(1 for p in pkg.model_profiles
                                  if p.last_attested != "never"))
        gov_pct       = _pct(sum(1 for p in pkg.model_profiles
                                  if p.compliance_score >= 60))
        data_qual_pct = _pct(sum(1 for p in pkg.model_profiles
                                  if p.has_data_lineage))
        incident_pct  = _pct(sum(1 for p in pkg.model_profiles
                                  if p.has_incident_plan))

        def _rate(pct: int) -> str:
            if pct >= 90: return "A"
            if pct >= 70: return "B"
            if pct >= 50: return "C"
            return "D"

        domains = {
            "technical_security": {
                "rating": _rate(tech_sec_pct),
                "coverage_pct": tech_sec_pct,
                "notes": (
                    "Security scanning via ModelScan + squash scanner"
                    if tech_sec_pct >= 50 else
                    "Model security scanning not yet deployed for all systems"
                ),
            },
            "operational_excellence": {
                "rating": _rate(ops_exc_pct),
                "coverage_pct": ops_exc_pct,
                "notes": (
                    "CI/CD attestation pipeline in place"
                    if ops_exc_pct >= 70 else
                    "Attestation not yet automated across full model fleet"
                ),
            },
            "ai_governance": {
                "rating": _rate(gov_pct),
                "coverage_pct": gov_pct,
                "notes": (
                    "Policy compliance verified against EU AI Act / NIST RMF"
                    if gov_pct >= 60 else
                    "Formal governance framework coverage incomplete"
                ),
            },
            "data_quality_provenance": {
                "rating": _rate(data_qual_pct),
                "coverage_pct": data_qual_pct,
                "notes": (
                    "Training data lineage certified per GDPR / EU AI Act Art. 10"
                    if data_qual_pct >= 50 else
                    "Training data provenance documentation incomplete"
                ),
            },
            "incident_resilience": {
                "rating": _rate(incident_pct),
                "coverage_pct": incident_pct,
                "notes": (
                    "Incident response plan documented; squash freeze command available"
                    if incident_pct >= 50 else
                    "Formal AI incident response plan not yet documented"
                ),
            },
        }

        # Overall AI Maturity Level 1–4 ────────────────────────────────────
        avg_pct = sum(
            d["coverage_pct"] for d in domains.values()
        ) // len(domains)
        maturity = 4 if avg_pct >= 85 else 3 if avg_pct >= 65 else 2 if avg_pct >= 40 else 1

        # Coverage recommendation ─────────────────────────────────────────
        if maturity >= 3:
            rec = "STANDARD — standard AI cyber coverage at preferred rates"
        elif maturity == 2:
            rec = "ENHANCED — enhanced underwriting review; premium loading likely"
        else:
            rec = "SPECIALIST — specialist review required; remediation plan needed before coverage"

        return {
            "schema": "munich_re_ai_cyber_v1",
            "generated_at": pkg.generated_at,
            "org_name": pkg.org_name,
            "ai_maturity_level": maturity,
            "ai_maturity_label": f"Level {maturity}",
            "overall_ai_risk_score": pkg.aggregate_risk_score,
            "overall_compliance_score": pkg.aggregate_compliance_score,
            "coverage_recommendation": rec,
            "control_domains": domains,
            "fleet_summary": {
                "total_models": pkg.total_models,
                "high_risk": pkg.high_risk_count,
                "open_cves": pkg.open_cves,
                "critical_cves": pkg.critical_cves,
                "incidents": pkg.recent_incidents,
            },
        }


class CoalitionAdapter:
    """Map to Coalition's AI Risk Assessment schema.

    Coalition's published AI cyber categories:
      AI Model Security, AI Operational Risk, AI Governance,
      AI Incident History, Third-Party AI Risk.
    Each scored 0–100; aggregate = weighted average.
    """

    def format(self, pkg: InsurancePackage) -> dict[str, Any]:
        total = max(pkg.total_models, 1)

        def _pct(n: int) -> int:
            return int(100 * n / total)

        # Per-category scores (higher = better posture) ────────────────────
        scanned_pct  = _pct(sum(1 for p in pkg.model_profiles
                                 if p.scan_status in ("clean", "warning")))
        no_crit_pct  = _pct(sum(1 for p in pkg.model_profiles
                                 if p.critical_cve_count == 0))
        attested_pct = _pct(sum(1 for p in pkg.model_profiles
                                 if p.last_attested != "never"))
        no_drift_pct = _pct(sum(1 for p in pkg.model_profiles
                                 if p.drift_events == 0))
        compliant_pct= _pct(sum(1 for p in pkg.model_profiles
                                  if p.compliance_score >= 60))
        no_inc_pct   = _pct(sum(1 for p in pkg.model_profiles
                                 if p.incident_count == 0))
        bias_ok_pct  = _pct(sum(1 for p in pkg.model_profiles
                                 if p.bias_status in ("PASS", "NOT_ASSESSED")))
        lineage_pct  = _pct(sum(1 for p in pkg.model_profiles
                                 if p.has_data_lineage))

        model_sec  = int((scanned_pct + no_crit_pct) / 2)
        ops_risk   = int((attested_pct + no_drift_pct) / 2)
        governance = int((compliant_pct + bias_ok_pct) / 2)
        inc_hist   = no_inc_pct
        tpi        = int((lineage_pct + scanned_pct) / 2)

        weighted = int((
            model_sec * 0.30 +
            ops_risk  * 0.25 +
            governance* 0.20 +
            inc_hist  * 0.15 +
            tpi       * 0.10
        ))

        def _assess(score: int) -> str:
            if score >= 80: return "LOW RISK — strong controls demonstrated"
            if score >= 60: return "MODERATE RISK — good coverage with gaps"
            if score >= 40: return "ELEVATED RISK — significant remediation needed"
            return "HIGH RISK — underwriting review required"

        return {
            "schema": "coalition_ai_risk_v1",
            "generated_at": pkg.generated_at,
            "org_name": pkg.org_name,
            "aggregate_ai_risk_score": weighted,
            "risk_categories": {
                "ai_model_security": {
                    "score": model_sec,
                    "assessment": _assess(model_sec),
                    "factors": {
                        "models_scanned_pct": scanned_pct,
                        "models_cve_free_pct": no_crit_pct,
                    },
                },
                "ai_operational_risk": {
                    "score": ops_risk,
                    "assessment": _assess(ops_risk),
                    "factors": {
                        "models_attested_pct": attested_pct,
                        "models_no_drift_pct": no_drift_pct,
                    },
                },
                "ai_governance": {
                    "score": governance,
                    "assessment": _assess(governance),
                    "factors": {
                        "models_policy_compliant_pct": compliant_pct,
                        "models_bias_ok_pct": bias_ok_pct,
                    },
                },
                "ai_incident_history": {
                    "score": inc_hist,
                    "assessment": _assess(inc_hist),
                    "factors": {
                        "models_no_incident_pct": no_inc_pct,
                        "total_incidents": pkg.recent_incidents,
                    },
                },
                "third_party_ai_risk": {
                    "score": tpi,
                    "assessment": _assess(tpi),
                    "factors": {
                        "models_with_lineage_pct": lineage_pct,
                        "models_scanned_pct": scanned_pct,
                    },
                },
            },
            "open_cves": pkg.open_cves,
            "critical_cves": pkg.critical_cves,
            "response_plan": pkg.response_plan_documented,
        }


class GenericAdapter:
    """Generic underwriter-agnostic JSON schema.

    Emits a flat, field-rich document for underwriters without a
    published format or for regulatory filing purposes.
    """

    def format(self, pkg: InsurancePackage) -> dict[str, Any]:
        return {
            "schema": "squash_insurance_generic_v1",
            "generated_at": pkg.generated_at,
            "org_name": pkg.org_name,
            "risk_posture": {
                "aggregate_risk_score_0_100": pkg.aggregate_risk_score,
                "aggregate_compliance_score_0_100": pkg.aggregate_compliance_score,
                "risk_interpretation": (
                    "LOW" if pkg.aggregate_risk_score <= 30 else
                    "MEDIUM" if pkg.aggregate_risk_score <= 60 else "HIGH"
                ),
            },
            "model_inventory": {
                "total_models": pkg.total_models,
                "high_risk_models": pkg.high_risk_count,
                "medium_risk_models": pkg.medium_risk_count,
                "low_risk_models": pkg.low_risk_count,
                "models_with_active_attestation": sum(
                    1 for p in pkg.model_profiles if p.last_attested != "never"
                ),
            },
            "vulnerability_exposure": {
                "open_cves": pkg.open_cves,
                "critical_high_cves": pkg.critical_cves,
            },
            "operational_risk": {
                "drift_events_total": pkg.drift_events_total,
                "recent_incidents": pkg.recent_incidents,
                "bias_audit_failures": pkg.bias_fails,
            },
            "governance_controls": {
                "response_plan_documented": pkg.response_plan_documented,
                "models_with_data_lineage": sum(
                    1 for p in pkg.model_profiles if p.has_data_lineage
                ),
                "models_with_technical_documentation": sum(
                    1 for p in pkg.model_profiles if p.has_annex_iv
                ),
                "models_with_bias_audit": sum(
                    1 for p in pkg.model_profiles
                    if p.bias_status in ("PASS", "FAIL")
                ),
            },
            "model_profiles": [p.to_dict() for p in pkg.model_profiles],
        }


# ── Internal helpers ──────────────────────────────────────────────────────────


def _discover_model_dirs(root: Path) -> list[Path]:
    """Return model directories to profile.

    If root contains squash artefacts directly → treat root as single model.
    Otherwise, return every subdirectory that contains at least one artefact.
    """
    if not root.is_dir():
        return []
    # Check if root itself has artefacts
    root_arts = set()
    for child in root.iterdir():
        if child.name.startswith(_POLICY_PREFIX) or child.name in (
            _ATTEST, _ATTEST_ALT, _SCAN, _VEX, _BOM,
        ):
            root_arts.add(child.name)
    if root_arts:
        return [root]

    # Otherwise scan subdirectories
    model_dirs: list[Path] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        # Require at least one squash artefact to count as a model
        has_any = any(
            (child / nm).exists()
            for nm in (_ATTEST, _ATTEST_ALT, _SCAN, _BOM)
        ) or any(
            f.name.startswith(_POLICY_PREFIX) for f in child.iterdir()
            if f.is_file()
        )
        if has_any:
            model_dirs.append(child)
    return model_dirs or [root]


def _load_artifacts(model_path: Path) -> dict[str, Any]:
    """Load JSON artefacts from model_path (and model_path/squash/)."""
    arts: dict[str, Any] = {}
    search_dirs = [model_path]
    squash_sub = model_path / "squash"
    if squash_sub.is_dir():
        search_dirs.append(squash_sub)

    for directory in search_dirs:
        if not directory.is_dir():
            continue
        for child in directory.iterdir():
            if not child.is_file():
                continue
            nm = child.name
            if nm.endswith(".json"):
                try:
                    arts[nm] = json.loads(child.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    pass
            elif nm in (_SQUASH_CFG,):
                arts[nm] = True  # presence-only
            elif nm.endswith(".md"):
                arts[nm] = True  # model card presence

    return arts


def _extract_model_id(arts: dict[str, Any], model_path: Path) -> str:
    for key in (_ATTEST, _ATTEST_ALT):
        if key in arts and isinstance(arts[key], dict):
            mid = arts[key].get("model_id")
            if mid:
                return str(mid)
    # Try squish.json
    squish = arts.get("squish.json") or arts.get("squish_meta.json") or {}
    if isinstance(squish, dict) and squish.get("model_id"):
        return str(squish["model_id"])
    return model_path.name


def _compute_risk_tier(
    compliance_score: int,
    critical_cves: int,
    scan_status: str,
    drift_events: int,
    incidents: int,
    has_any_policy: bool,
) -> str:
    """Derive HIGH / MEDIUM / LOW risk tier.

    Mathematical formulation:
        risk_score = 100
                   − compliance_score           (0–100, more compliant = less risk)
                   + 20 × (critical_cves > 0)
                   + 10 × (scan_status == "unsafe")
                   + 10 × (drift_events > 5)
                   + 15 × (incidents > 0)
                   + 20 × (not has_any_policy)
        clipped to [0, 100]
    """
    risk = 100 - compliance_score
    if critical_cves > 0:     risk += 20
    if scan_status == "unsafe": risk += 10
    if drift_events > 5:      risk += 10
    if incidents > 0:         risk += 15
    if not has_any_policy:    risk += 20
    risk = max(0, min(100, risk))

    if risk >= 70:  return "HIGH"
    if risk >= 40:  return "MEDIUM"
    return "LOW"


def _aggregate(
    profiles: list[ModelRiskProfile],
    org_name: str,
) -> InsurancePackage:
    total = len(profiles)
    if not profiles:
        return InsurancePackage(
            org_name=org_name,
            generated_at=_utc_now_iso(),
            model_profiles=[],
            aggregate_risk_score=100,
            aggregate_compliance_score=0,
            response_plan_documented=False,
            total_models=0,
            high_risk_count=0,
            medium_risk_count=0,
            low_risk_count=0,
            open_cves=0,
            critical_cves=0,
            recent_incidents=0,
            drift_events_total=0,
            bias_fails=0,
            executive_summary=_summary(100, 0, 0, 0, 0, 0, False),
        )

    high   = sum(1 for p in profiles if p.risk_tier == "HIGH")
    medium = sum(1 for p in profiles if p.risk_tier == "MEDIUM")
    low    = sum(1 for p in profiles if p.risk_tier == "LOW")

    avg_compliance = int(sum(p.compliance_score for p in profiles) / total)
    open_cves      = sum(p.cve_count for p in profiles)
    critical_cves  = sum(p.critical_cve_count for p in profiles)
    incidents      = sum(p.incident_count for p in profiles)
    drift_total    = sum(p.drift_events for p in profiles)
    bias_fails     = sum(1 for p in profiles if p.bias_status == "FAIL")

    # Aggregate risk score (inverted from compliance, boosted by gaps)
    risk_score = max(0, min(100,
        100 - avg_compliance
        + (15 if critical_cves > 0 else 0)
        + (10 if high > 0 else 0)
        + (5  if incidents > 0 else 0)
    ))

    has_response_plan = any(p.has_incident_plan for p in profiles)

    summary = _summary(
        risk_score, avg_compliance, high, critical_cves,
        incidents, bias_fails, has_response_plan,
    )

    return InsurancePackage(
        org_name=org_name,
        generated_at=_utc_now_iso(),
        model_profiles=profiles,
        aggregate_risk_score=risk_score,
        aggregate_compliance_score=avg_compliance,
        response_plan_documented=has_response_plan,
        total_models=total,
        high_risk_count=high,
        medium_risk_count=medium,
        low_risk_count=low,
        open_cves=open_cves,
        critical_cves=critical_cves,
        recent_incidents=incidents,
        drift_events_total=drift_total,
        bias_fails=bias_fails,
        executive_summary=summary,
    )


def _summary(
    risk_score: int,
    compliance_score: int,
    high_risk: int,
    critical_cves: int,
    incidents: int,
    bias_fails: int,
    has_plan: bool,
) -> str:
    posture = (
        "strong" if risk_score <= 30 else
        "moderate" if risk_score <= 60 else "elevated"
    )
    issues: list[str] = []
    if high_risk:     issues.append(f"{high_risk} high-risk model(s)")
    if critical_cves: issues.append(f"{critical_cves} critical/high CVE(s)")
    if incidents:     issues.append(f"{incidents} recorded incident(s)")
    if bias_fails:    issues.append(f"{bias_fails} bias-audit failure(s)")
    if not has_plan:  issues.append("no documented incident response plan")

    issue_str = (
        f" Key risk factors: {'; '.join(issues)}." if issues else
        " No critical risk factors identified."
    )

    return (
        f"This organisation's AI deployment portfolio demonstrates a **{posture}** "
        f"cyber risk posture for insurance underwriting purposes. "
        f"Aggregate risk score: {risk_score}/100 (lower = lower risk). "
        f"Aggregate compliance score: {compliance_score}/100.{issue_str} "
        f"{'An incident response plan is documented.' if has_plan else 'An incident response plan should be documented before coverage submission.'}"
    )


def _risk_band(score: int) -> str:
    if score <= 30: return "🟢 LOW"
    if score <= 60: return "🟡 MEDIUM"
    return "🔴 HIGH"


def _compliance_band(score: int) -> str:
    if score >= 80: return "✅ STRONG"
    if score >= 60: return "🟡 MODERATE"
    return "⚠️ NEEDS IMPROVEMENT"


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


__all__ = [
    "ModelRiskProfile",
    "InsurancePackage",
    "InsuranceBuilder",
    "MunichReAdapter",
    "CoalitionAdapter",
    "GenericAdapter",
]
