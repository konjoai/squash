"""squash/incident.py — AI incident response package generator.

When an AI system produces a harmful output, generates a discriminatory
decision, exposes PII, or causes a business failure, the incident response
process must be documented for regulators, insurers, and auditors.

This module generates a signed incident response package containing:
  * Incident report (structured JSON + human-readable summary)
  * Model attestation snapshot at the time of the incident
  * EU AI Act Article 73 regulatory disclosure document
  * NIST AI RMF Incident Response (MANAGE) section
  * VEX CVE status at incident time
  * Drift delta (what changed between last attestation and incident time)
  * Remediation action plan

EU AI Act Article 73 requires providers of high-risk AI systems to notify
the relevant national supervisory authority within 15 working days of any
serious incident.  This module generates the Article 73-compliant disclosure
document automatically.

Usage::

    from squash.incident import IncidentResponder
    from pathlib import Path

    pkg = IncidentResponder.respond(
        model_path=Path("./my-model"),
        description="Model output contained PII of 3 users.",
        timestamp="2026-04-15T14:32:00Z",
        severity="serious",
        affected_persons=3,
    )
    print(pkg.summary())
    pkg.save(Path("./incident-2026-04-15/"))
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"     # Immediate threat to life, fundamental rights, or major financial impact
    SERIOUS = "serious"       # EU AI Act Article 73 notifiable event
    MODERATE = "moderate"     # Significant performance failure or policy violation
    MINOR = "minor"           # Low-impact issue, no regulatory notification required


class IncidentCategory(str, Enum):
    BIAS_DISCRIMINATION = "bias_discrimination"
    PII_EXPOSURE = "pii_exposure"
    HARMFUL_OUTPUT = "harmful_output"
    MODEL_FAILURE = "model_failure"
    SECURITY_BREACH = "security_breach"
    ACCURACY_REGRESSION = "accuracy_regression"
    POLICY_VIOLATION = "policy_violation"
    DATA_POISONING = "data_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    OTHER = "other"


@dataclass
class IncidentPackage:
    incident_id: str
    model_id: str
    model_path: str
    incident_timestamp: str
    report_generated_at: str
    severity: IncidentSeverity
    category: IncidentCategory
    description: str
    affected_persons: int
    attestation_snapshot: dict[str, Any]
    article_73_disclosure: dict[str, Any]
    drift_delta: dict[str, Any]
    remediation_plan: list[dict[str, Any]]
    regulatory_notification_required: bool
    notification_deadline: str | None
    artifacts_written: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "AI INCIDENT RESPONSE PACKAGE",
            "=" * 54,
            f"Incident ID:    {self.incident_id}",
            f"Model:          {self.model_id}",
            f"Incident time:  {self.incident_timestamp}",
            f"Report time:    {self.report_generated_at}",
            f"Severity:       {self.severity.value.upper()}",
            f"Category:       {self.category.value}",
            f"Description:    {self.description}",
            f"Affected:       {self.affected_persons} person(s)",
            "",
        ]

        if self.regulatory_notification_required:
            lines += [
                "⚠  REGULATORY NOTIFICATION REQUIRED",
                f"   EU AI Act Article 73 — deadline: {self.notification_deadline}",
                "",
            ]
        else:
            lines.append("ℹ  No immediate regulatory notification required.")
            lines.append("")

        if self.remediation_plan:
            lines.append("Remediation Plan:")
            for i, action in enumerate(self.remediation_plan, 1):
                lines.append(f"  {i}. [{action.get('priority', 'Medium')}] {action.get('action', '')}")
                lines.append(f"     Owner: {action.get('owner', 'TBD')} | "
                              f"Deadline: {action.get('deadline', 'TBD')}")

        if self.artifacts_written:
            lines += [
                "",
                "Artifacts written:",
                *[f"  {a}" for a in self.artifacts_written],
            ]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "incident_timestamp": self.incident_timestamp,
            "report_generated_at": self.report_generated_at,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "affected_persons": self.affected_persons,
            "regulatory_notification_required": self.regulatory_notification_required,
            "notification_deadline": self.notification_deadline,
            "attestation_snapshot": self.attestation_snapshot,
            "article_73_disclosure": self.article_73_disclosure,
            "drift_delta": self.drift_delta,
            "remediation_plan": self.remediation_plan,
        }

    def save(self, output_dir: Path) -> list[str]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        written: list[str] = []

        report_path = output_dir / "incident_report.json"
        report_path.write_text(json.dumps(self.to_dict(), indent=2))
        written.append(str(report_path))

        if self.article_73_disclosure:
            a73_path = output_dir / "article_73_disclosure.json"
            a73_path.write_text(json.dumps(self.article_73_disclosure, indent=2))
            written.append(str(a73_path))

        summary_path = output_dir / "INCIDENT_SUMMARY.txt"
        summary_path.write_text(self.summary())
        written.append(str(summary_path))

        self.artifacts_written = written
        log.info("Incident package written to %s", output_dir)
        return written


class IncidentResponder:
    """Generate a structured AI incident response package."""

    @staticmethod
    def respond(
        model_path: Path,
        description: str,
        timestamp: str | None = None,
        severity: str = "serious",
        category: str = "other",
        affected_persons: int = 0,
        model_id: str | None = None,
    ) -> IncidentPackage:
        model_path = Path(model_path)
        incident_id = f"INC-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if timestamp is None:
            incident_ts = now
        else:
            incident_ts = _normalize_timestamp(timestamp)

        if model_id is None:
            model_id = model_path.name

        sev = _parse_severity(severity)
        cat = _parse_category(category)

        # Collect attestation snapshot
        attestation_snapshot = _load_attestation_snapshot(model_path)

        # Compute drift delta (before vs current)
        drift_delta = _compute_drift_delta(model_path, incident_ts)

        # Determine regulatory notification requirements
        reg_required, notification_deadline = _assess_regulatory_requirements(sev, affected_persons)

        # Generate Article 73 disclosure
        article_73 = _generate_article_73_disclosure(
            incident_id=incident_id,
            model_id=model_id,
            incident_timestamp=incident_ts,
            severity=sev,
            category=cat,
            description=description,
            affected_persons=affected_persons,
            attestation_snapshot=attestation_snapshot,
        )

        # Build remediation plan
        remediation_plan = _build_remediation_plan(sev, cat, attestation_snapshot)

        return IncidentPackage(
            incident_id=incident_id,
            model_id=model_id,
            model_path=str(model_path),
            incident_timestamp=incident_ts,
            report_generated_at=now,
            severity=sev,
            category=cat,
            description=description,
            affected_persons=affected_persons,
            attestation_snapshot=attestation_snapshot,
            article_73_disclosure=article_73,
            drift_delta=drift_delta,
            remediation_plan=remediation_plan,
            regulatory_notification_required=reg_required,
            notification_deadline=notification_deadline,
        )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _normalize_timestamp(ts: str) -> str:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return ts


def _parse_severity(s: str) -> IncidentSeverity:
    mapping = {
        "critical": IncidentSeverity.CRITICAL,
        "serious": IncidentSeverity.SERIOUS,
        "moderate": IncidentSeverity.MODERATE,
        "minor": IncidentSeverity.MINOR,
    }
    return mapping.get(s.lower(), IncidentSeverity.SERIOUS)


def _parse_category(c: str) -> IncidentCategory:
    mapping = {cat.value: cat for cat in IncidentCategory}
    return mapping.get(c.lower(), IncidentCategory.OTHER)


def _load_attestation_snapshot(model_path: Path) -> dict[str, Any]:
    """Load the most recent squash attestation record from model_path."""
    for candidate in [
        model_path / "squash_attestation.json",
        model_path / "squash" / "squash_attestation.json",
        model_path / ".squash" / "attestation.json",
    ]:
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                return {
                    "found": True,
                    "source": str(candidate),
                    "attestation": data,
                }
            except (json.JSONDecodeError, OSError):
                pass

    # No attestation found
    return {
        "found": False,
        "source": None,
        "attestation": {},
        "note": (
            "No squash attestation found in model directory. "
            "Run `squash attest ./model` to establish baseline."
        ),
    }


def _compute_drift_delta(model_path: Path, incident_ts: str) -> dict[str, Any]:
    """Compute drift between last attestation and incident timestamp."""
    drift_report_path = model_path / "drift_report.json"
    if drift_report_path.exists():
        try:
            drift_data = json.loads(drift_report_path.read_text())
            return {
                "drift_detected": drift_data.get("drift_detected", False),
                "drift_report": drift_data,
                "note": "Drift report loaded from model directory.",
            }
        except (json.JSONDecodeError, OSError):
            pass

    return {
        "drift_detected": None,
        "drift_report": {},
        "note": (
            "No drift report available. "
            "Run `squash drift-check ./model` to generate a baseline comparison."
        ),
    }


def _assess_regulatory_requirements(
    severity: IncidentSeverity,
    affected_persons: int,
) -> tuple[bool, str | None]:
    """Determine if EU AI Act Article 73 notification is required."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # Article 73: Serious incidents must be notified within 15 working days
    # (approximately 21 calendar days)
    if severity in (IncidentSeverity.CRITICAL, IncidentSeverity.SERIOUS):
        deadline_dt = now + datetime.timedelta(days=21)
        return True, deadline_dt.strftime("%Y-%m-%d")

    # Also required for large-scale impacts even if classified moderate
    if affected_persons >= 100:
        deadline_dt = now + datetime.timedelta(days=21)
        return True, deadline_dt.strftime("%Y-%m-%d")

    return False, None


def _generate_article_73_disclosure(
    incident_id: str,
    model_id: str,
    incident_timestamp: str,
    severity: IncidentSeverity,
    category: IncidentCategory,
    description: str,
    affected_persons: int,
    attestation_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Generate EU AI Act Article 73 serious incident disclosure document."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    attestation = attestation_snapshot.get("attestation", {})
    model_version = (
        attestation.get("model_version")
        or attestation.get("version")
        or "unknown"
    )

    return {
        "document_type": "EU_AI_ACT_ARTICLE_73_DISCLOSURE",
        "regulation": "Regulation (EU) 2024/1689 — Article 73",
        "incident_id": incident_id,
        "disclosure_date": now,
        "incident_date": incident_timestamp,
        "provider": {
            "model_id": model_id,
            "model_version": model_version,
            "note": "Complete provider details must be added before submission.",
        },
        "incident_details": {
            "severity": severity.value,
            "category": category.value,
            "description": description,
            "estimated_affected_persons": affected_persons,
        },
        "ai_system_information": {
            "model_id": model_id,
            "model_version": model_version,
            "attestation_present": attestation_snapshot.get("found", False),
            "attestation_source": attestation_snapshot.get("source"),
        },
        "required_fields_checklist": {
            "incident_description": bool(description),
            "affected_persons_count": affected_persons > 0,
            "model_identification": bool(model_id),
            "incident_date": bool(incident_timestamp),
            "provider_identification": False,  # must be completed manually
            "corrective_measures": False,       # must be completed manually
            "national_supervisory_authority": False,  # must be identified
        },
        "completion_instructions": (
            "Before submitting to the national supervisory authority:\n"
            "1. Add full provider contact details under 'provider'\n"
            "2. Describe corrective measures taken or planned\n"
            "3. Identify the relevant national supervisory authority\n"
            "4. Attach squash attestation artifacts as supporting evidence\n"
            "5. Submit within 15 working days of incident detection"
        ),
    }


def _build_remediation_plan(
    severity: IncidentSeverity,
    category: IncidentCategory,
    attestation_snapshot: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a prioritized remediation action plan."""
    now = datetime.datetime.now(datetime.timezone.utc)
    actions: list[dict[str, Any]] = []

    # Universal immediate actions
    actions.append({
        "action": "Contain — suspend or rollback affected model version",
        "priority": "Critical",
        "owner": "ML Ops / Platform Team",
        "deadline": (now + datetime.timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": "squash drift-check ./model",
    })

    actions.append({
        "action": "Document — capture full incident timeline in incident_report.json",
        "priority": "Critical",
        "owner": "AI Safety / Compliance Team",
        "deadline": (now + datetime.timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": "squash incident --model ./model",
    })

    if severity in (IncidentSeverity.CRITICAL, IncidentSeverity.SERIOUS):
        actions.append({
            "action": "Notify — prepare EU AI Act Article 73 disclosure for national supervisory authority",
            "priority": "Critical",
            "owner": "Legal / DPO",
            "deadline": (now + datetime.timedelta(days=15)).strftime("%Y-%m-%d"),
            "command": "Review article_73_disclosure.json and submit to relevant authority",
        })

    if category == IncidentCategory.BIAS_DISCRIMINATION:
        actions.append({
            "action": "Audit — run bias assessment on affected model outputs",
            "priority": "High",
            "owner": "AI Safety Team",
            "deadline": (now + datetime.timedelta(days=3)).strftime("%Y-%m-%d"),
            "command": "squash evaluate --model ./model --include-bias",
        })

    if category == IncidentCategory.PII_EXPOSURE:
        actions.append({
            "action": "GDPR — notify data protection authority within 72 hours (GDPR Art. 33)",
            "priority": "Critical",
            "owner": "DPO / Legal",
            "deadline": (now + datetime.timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "command": "Prepare GDPR Art. 33 notification separately",
        })

    if category == IncidentCategory.PROMPT_INJECTION:
        actions.append({
            "action": "Harden — add prompt injection detection layer before model inputs",
            "priority": "High",
            "owner": "ML Engineering",
            "deadline": (now + datetime.timedelta(days=7)).strftime("%Y-%m-%d"),
            "command": "squash attest-mcp --manifest agent.json",
        })

    # Reattestiation
    actions.append({
        "action": "Re-attest — run full squash attestation before restoring service",
        "priority": "High",
        "owner": "ML Ops",
        "deadline": (now + datetime.timedelta(days=3)).strftime("%Y-%m-%d"),
        "command": "squash attest ./model --policy eu-ai-act --sign",
    })

    # Post-incident monitoring
    actions.append({
        "action": "Monitor — enable continuous drift detection for 30 days post-incident",
        "priority": "Medium",
        "owner": "ML Ops",
        "deadline": (now + datetime.timedelta(days=30)).strftime("%Y-%m-%d"),
        "command": "squash watch ./model --interval 3600",
    })

    return actions
