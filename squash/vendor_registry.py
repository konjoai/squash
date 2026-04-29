"""squash/vendor_registry.py — AI Vendor Risk Register.

The average enterprise runs 66 GenAI apps; 65% operate without IT approval.
Shadow AI added $670K to the average breach cost in 2025.  Procurement teams
track AI vendors in spreadsheets and email chains.  This module replaces that
with a structured, queryable vendor risk register.

Two-sided marketplace foundation
---------------------------------
* **Vendor side** — vendors export a signed Trust Package (squash/trust_package.py)
  as their attestation artifact, replacing the 40-page Word questionnaire.
* **Buyer side** — buyers register each AI vendor, generate a tailored
  due-diligence questionnaire, import and verify vendor Trust Packages,
  and maintain continuous monitoring status.

Features
--------
* SQLite-backed persistent registry (``~/.squash/vendor_registry.db``)
* Risk tiering: CRITICAL / HIGH / MEDIUM / LOW based on data access + use-case
* Auto-generated due-diligence questionnaire per risk tier
* Trust Package import + integrity verification
* Exposure surface scoring

Usage::

    from squash.vendor_registry import VendorRegistry, VendorRiskTier
    reg = VendorRegistry()
    vid = reg.add_vendor("OpenAI", "https://openai.com", risk_tier="high",
                         use_case="Customer support chatbot", data_access="PII")
    q = reg.generate_questionnaire(vid)
    print(q.to_text())
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / ".squash" / "vendor_registry.db"

# ── Enums ─────────────────────────────────────────────────────────────────────

class VendorRiskTier(str, Enum):
    CRITICAL = "critical"   # High-risk AI + PII/financial data
    HIGH = "high"           # High-risk AI or significant data access
    MEDIUM = "medium"       # Limited-risk AI, internal use
    LOW = "low"             # Minimal-risk AI, no sensitive data


class VendorStatus(str, Enum):
    ACTIVE = "active"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    SUSPENDED = "suspended"
    OFFBOARDED = "offboarded"


class AssessmentStatus(str, Enum):
    NOT_STARTED = "not_started"
    QUESTIONNAIRE_SENT = "questionnaire_sent"
    TRUST_PACKAGE_RECEIVED = "trust_package_received"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    FAILED = "failed"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class VendorRecord:
    vendor_id: str
    name: str
    website: str
    risk_tier: VendorRiskTier
    status: VendorStatus
    assessment_status: AssessmentStatus
    use_case: str
    data_access: str          # "PII", "financial", "none", etc.
    added_at: str
    last_assessed: str | None
    trust_package_path: str | None
    trust_package_score: float | None
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "name": self.name,
            "website": self.website,
            "risk_tier": self.risk_tier.value,
            "status": self.status.value,
            "assessment_status": self.assessment_status.value,
            "use_case": self.use_case,
            "data_access": self.data_access,
            "added_at": self.added_at,
            "last_assessed": self.last_assessed,
            "trust_package_path": self.trust_package_path,
            "trust_package_score": self.trust_package_score,
            "notes": self.notes,
        }


@dataclass
class QuestionnaireItem:
    question_id: str
    category: str
    question: str
    required: bool
    applicable_tiers: list[str]  # ["critical", "high", "medium", "low"]


@dataclass
class VendorQuestionnaire:
    vendor_id: str
    vendor_name: str
    risk_tier: str
    generated_at: str
    items: list[QuestionnaireItem] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [
            f"AI VENDOR DUE DILIGENCE QUESTIONNAIRE",
            "=" * 56,
            f"Vendor:     {self.vendor_name}",
            f"Risk Tier:  {self.risk_tier.upper()}",
            f"Generated:  {self.generated_at}",
            f"Questions:  {len(self.items)}",
            "",
        ]
        current_cat = ""
        for i, item in enumerate(self.items, 1):
            if item.category != current_cat:
                current_cat = item.category
                lines.append(f"\n{current_cat.upper()}")
                lines.append("-" * 40)
            req = "* " if item.required else "  "
            lines.append(f"{req}{i:2d}. {item.question}")
        lines.append("\n* Required field")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "risk_tier": self.risk_tier,
            "generated_at": self.generated_at,
            "items": [
                {"question_id": i.question_id, "category": i.category,
                 "question": i.question, "required": i.required}
                for i in self.items
            ],
        }

    def save(self, path: Path) -> None:
        path = Path(path)
        if path.suffix == ".json":
            path.write_text(json.dumps(self.to_dict(), indent=2))
        else:
            path.write_text(self.to_text())


# ── Question bank ─────────────────────────────────────────────────────────────

_QUESTION_BANK: list[QuestionnaireItem] = [
    # Model Governance
    QuestionnaireItem("MG-1", "Model Governance", "What foundation models or base models does your AI system use?", True, ["critical","high","medium","low"]),
    QuestionnaireItem("MG-2", "Model Governance", "Provide your EU AI Act risk tier classification (Unacceptable/High/Limited/Minimal).", True, ["critical","high","medium"]),
    QuestionnaireItem("MG-3", "Model Governance", "Do you maintain a CycloneDX ML-BOM or SPDX SBOM for deployed models?", True, ["critical","high"]),
    QuestionnaireItem("MG-4", "Model Governance", "What is your model update/version management policy?", True, ["critical","high","medium"]),
    QuestionnaireItem("MG-5", "Model Governance", "How do you detect and respond to model drift in production?", False, ["critical","high"]),
    QuestionnaireItem("MG-6", "Model Governance", "Do you hold an ISO/IEC 42001 certification or readiness assessment?", False, ["critical","high","medium"]),
    # Training Data
    QuestionnaireItem("TD-1", "Training Data", "Describe the datasets used to train your AI system.", True, ["critical","high","medium"]),
    QuestionnaireItem("TD-2", "Training Data", "Confirm all training datasets are licensed for commercial use.", True, ["critical","high","medium"]),
    QuestionnaireItem("TD-3", "Training Data", "Were any personal data (PII) included in training data? If so, what legal basis under GDPR?", True, ["critical","high"]),
    QuestionnaireItem("TD-4", "Training Data", "Do you have a documented data provenance certificate (training data lineage)?", False, ["critical","high"]),
    QuestionnaireItem("TD-5", "Training Data", "How do you handle data subject access requests (GDPR Art. 15) for training data?", True, ["critical","high"]),
    # Security
    QuestionnaireItem("SEC-1", "Security", "Do you conduct regular security scanning of model artifacts (e.g., pickle scan, ModelScan)?", True, ["critical","high","medium"]),
    QuestionnaireItem("SEC-2", "Security", "Provide your CVE exposure status and patching SLA.", True, ["critical","high"]),
    QuestionnaireItem("SEC-3", "Security", "Do you sign model artifacts with Sigstore or equivalent cryptographic signing?", False, ["critical","high"]),
    QuestionnaireItem("SEC-4", "Security", "What is your SLSA build provenance level?", False, ["critical","high"]),
    QuestionnaireItem("SEC-5", "Security", "How do you protect against prompt injection attacks?", True, ["critical","high"]),
    QuestionnaireItem("SEC-6", "Security", "Do you have a published VEX (Vulnerability Exploitability eXchange) feed?", False, ["critical","high"]),
    # Bias & Fairness
    QuestionnaireItem("BF-1", "Bias & Fairness", "Have you conducted a bias audit against protected attributes (age, gender, race)?", True, ["critical","high"]),
    QuestionnaireItem("BF-2", "Bias & Fairness", "Which bias metrics do you report (demographic parity, equalized odds, disparate impact)?", True, ["critical","high"]),
    QuestionnaireItem("BF-3", "Bias & Fairness", "For employment/credit/medical AI: do you comply with NYC Local Law 144 or equivalent?", True, ["critical","high"]),
    QuestionnaireItem("BF-4", "Bias & Fairness", "Provide your most recent bias audit report or summary.", False, ["critical","high"]),
    # Data Handling
    QuestionnaireItem("DH-1", "Data Handling", "What user data does the AI system collect and process?", True, ["critical","high","medium","low"]),
    QuestionnaireItem("DH-2", "Data Handling", "Where is data processed and stored (EU/US/other)?", True, ["critical","high","medium"]),
    QuestionnaireItem("DH-3", "Data Handling", "Is customer/user data used to train or fine-tune models?", True, ["critical","high","medium"]),
    QuestionnaireItem("DH-4", "Data Handling", "What is your data retention policy for AI system inputs/outputs?", True, ["critical","high","medium"]),
    QuestionnaireItem("DH-5", "Data Handling", "Provide your DPA (Data Processing Agreement) template.", True, ["critical","high"]),
    # Explainability & Transparency
    QuestionnaireItem("ET-1", "Explainability", "Does your AI system provide explanations for its decisions?", False, ["critical","high","medium"]),
    QuestionnaireItem("ET-2", "Explainability", "Do you publish a model card for deployed models?", False, ["critical","high","medium"]),
    QuestionnaireItem("ET-3", "Explainability", "Is AI involvement disclosed to end users?", True, ["critical","high","medium","low"]),
    # Human Oversight
    QuestionnaireItem("HO-1", "Human Oversight", "What human oversight mechanisms are in place for AI decisions?", True, ["critical","high"]),
    QuestionnaireItem("HO-2", "Human Oversight", "Can users contest or request human review of AI decisions?", True, ["critical","high"]),
    # Incident Response
    QuestionnaireItem("IR-1", "Incident Response", "Do you have an AI incident response plan?", True, ["critical","high","medium"]),
    QuestionnaireItem("IR-2", "Incident Response", "What is your SLA for reporting serious AI incidents (EU AI Act Art. 73)?", True, ["critical","high"]),
    QuestionnaireItem("IR-3", "Incident Response", "Describe your most recent AI incident and remediation steps.", False, ["critical","high"]),
    # Attestation
    QuestionnaireItem("AT-1", "Attestation", "Can you provide a squash Trust Package or equivalent signed attestation bundle?", False, ["critical","high","medium"]),
    QuestionnaireItem("AT-2", "Attestation", "What is your EU AI Act Annex IV documentation status?", True, ["critical","high"]),
]


def _questions_for_tier(tier: VendorRiskTier) -> list[QuestionnaireItem]:
    return [q for q in _QUESTION_BANK if tier.value in q.applicable_tiers]


# ── Registry ──────────────────────────────────────────────────────────────────

class VendorRegistry:
    """SQLite-backed AI vendor risk register."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS vendors (
                vendor_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                website TEXT,
                risk_tier TEXT NOT NULL,
                status TEXT NOT NULL,
                assessment_status TEXT NOT NULL,
                use_case TEXT,
                data_access TEXT,
                added_at TEXT NOT NULL,
                last_assessed TEXT,
                trust_package_path TEXT,
                trust_package_score REAL,
                notes TEXT
            )
        """)
        self._conn.commit()

    def add_vendor(
        self,
        name: str,
        website: str = "",
        risk_tier: str = "medium",
        use_case: str = "",
        data_access: str = "none",
        notes: str = "",
    ) -> str:
        vendor_id = str(uuid.uuid4())[:12].replace("-", "")
        tier = VendorRiskTier(risk_tier.lower())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO vendors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (vendor_id, name, website, tier.value, VendorStatus.PENDING_REVIEW.value,
             AssessmentStatus.NOT_STARTED.value, use_case, data_access, now,
             None, None, None, notes),
        )
        self._conn.commit()
        log.info("Vendor added: %s (%s) tier=%s", name, vendor_id, tier.value)
        return vendor_id

    def get_vendor(self, vendor_id: str) -> VendorRecord | None:
        row = self._conn.execute(
            "SELECT * FROM vendors WHERE vendor_id=?", (vendor_id,)
        ).fetchone()
        return _row_to_vendor(row) if row else None

    def list_vendors(self, status: str | None = None, tier: str | None = None) -> list[VendorRecord]:
        sql = "SELECT * FROM vendors"
        params: list[str] = []
        filters: list[str] = []
        if status:
            filters.append("status=?")
            params.append(status)
        if tier:
            filters.append("risk_tier=?")
            params.append(tier)
        if filters:
            sql += " WHERE " + " AND ".join(filters)
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_vendor(r) for r in rows]

    def update_assessment_status(self, vendor_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE vendors SET assessment_status=?, last_assessed=? WHERE vendor_id=?",
            (status, datetime.datetime.now(datetime.timezone.utc).isoformat(), vendor_id),
        )
        self._conn.commit()

    def import_trust_package(self, vendor_id: str, package_path: Path) -> dict[str, Any]:
        """Import and verify a vendor's Trust Package."""
        from squash.trust_package import TrustPackageVerifier
        result = TrustPackageVerifier.verify(package_path)
        cs = result.compliance_summary
        score = cs.get("eu_ai_act_score") or 0.0
        self._conn.execute(
            "UPDATE vendors SET trust_package_path=?, trust_package_score=?, "
            "assessment_status=?, last_assessed=? WHERE vendor_id=?",
            (str(package_path), score,
             AssessmentStatus.TRUST_PACKAGE_RECEIVED.value if result.passed
             else AssessmentStatus.UNDER_REVIEW.value,
             datetime.datetime.now(datetime.timezone.utc).isoformat(),
             vendor_id),
        )
        self._conn.commit()
        return {"passed": result.passed, "score": score, "errors": result.integrity_errors}

    def generate_questionnaire(self, vendor_id: str) -> VendorQuestionnaire:
        vendor = self.get_vendor(vendor_id)
        if vendor is None:
            raise ValueError(f"Vendor not found: {vendor_id}")
        items = _questions_for_tier(vendor.risk_tier)
        return VendorQuestionnaire(
            vendor_id=vendor_id,
            vendor_name=vendor.name,
            risk_tier=vendor.risk_tier.value,
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            items=items,
        )

    def remove_vendor(self, vendor_id: str) -> bool:
        rows = self._conn.execute(
            "DELETE FROM vendors WHERE vendor_id=?", (vendor_id,)
        ).rowcount
        self._conn.commit()
        return rows > 0

    def risk_summary(self) -> dict[str, Any]:
        vendors = self.list_vendors()
        by_tier: dict[str, int] = {t.value: 0 for t in VendorRiskTier}
        by_status: dict[str, int] = {s.value: 0 for s in AssessmentStatus}
        for v in vendors:
            by_tier[v.risk_tier.value] += 1
            by_status[v.assessment_status.value] += 1
        unreviewed = sum(1 for v in vendors if v.assessment_status == AssessmentStatus.NOT_STARTED)
        return {
            "total_vendors": len(vendors),
            "by_risk_tier": by_tier,
            "by_assessment_status": by_status,
            "unreviewed": unreviewed,
            "high_or_critical_unreviewed": sum(
                1 for v in vendors
                if v.risk_tier in (VendorRiskTier.CRITICAL, VendorRiskTier.HIGH)
                and v.assessment_status == AssessmentStatus.NOT_STARTED
            ),
        }

    def export(self) -> list[dict[str, Any]]:
        return [v.to_dict() for v in self.list_vendors()]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "VendorRegistry":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _row_to_vendor(row: tuple) -> VendorRecord:
    return VendorRecord(
        vendor_id=row[0], name=row[1], website=row[2],
        risk_tier=VendorRiskTier(row[3]), status=VendorStatus(row[4]),
        assessment_status=AssessmentStatus(row[5]),
        use_case=row[6] or "", data_access=row[7] or "",
        added_at=row[8], last_assessed=row[9],
        trust_package_path=row[10], trust_package_score=row[11],
        notes=row[12] or "",
    )
