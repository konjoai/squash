"""squash/asset_registry.py — AI Asset Registry.

The first question any regulator, auditor, or board member asks:
"What AI systems do you have deployed?"

The answer today is a shrug followed by two weeks of Slack messages.

This module provides a continuously updated, machine-readable inventory of
every AI model the organization owns — auto-populated by squash CI/CD
integrations and queryable by compliance, security, and engineering teams.

Features
--------
* SQLite-backed persistent registry (``~/.squash/asset_registry.db``)
* Auto-registration from squash attestation artifacts
* Ownership, deployment status, risk tier, compliance score, last-attested date
* Stale asset detection (unattested assets older than N days)
* Shadow AI detection integration (from squash/shadow_ai CLI)
* JSON + Markdown export for board reports

Usage::

    from squash.asset_registry import AssetRegistry
    reg = AssetRegistry()
    aid = reg.register(
        model_id="gpt4-finetuned-v2",
        model_path="/prod/models/gpt4-finetuned-v2",
        owner="ml-platform-team@company.com",
        environment="production",
    )
    reg.sync_from_attestation(Path("/prod/models/gpt4-finetuned-v2"))
    print(reg.summary())
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

_DEFAULT_DB = Path.home() / ".squash" / "asset_registry.db"

_STALE_DAYS_DEFAULT = 30   # Assets unattested for longer than this are flagged


class AssetEnvironment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    RESEARCH = "research"
    RETIRED = "retired"


class AssetRiskTier(str, Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


@dataclass
class AssetRecord:
    asset_id: str
    model_id: str
    model_path: str
    model_version: str
    owner: str
    team: str
    environment: AssetEnvironment
    risk_tier: AssetRiskTier
    frameworks: list[str]          # e.g. ["eu-ai-act", "nist-ai-rmf"]
    compliance_score: float | None
    last_attested: str | None
    deployment_date: str | None
    registered_at: str
    is_shadow_ai: bool
    open_violations: int
    open_cves: int
    drift_detected: bool
    attestation_path: str | None
    notes: str

    @property
    def is_stale(self, stale_days: int = _STALE_DAYS_DEFAULT) -> bool:
        if self.last_attested is None:
            return True
        try:
            last = datetime.datetime.fromisoformat(self.last_attested.rstrip("Z"))
            age = (datetime.datetime.now() - last).days
            return age > stale_days
        except (ValueError, TypeError):
            return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "model_version": self.model_version,
            "owner": self.owner,
            "team": self.team,
            "environment": self.environment.value,
            "risk_tier": self.risk_tier.value,
            "frameworks": self.frameworks,
            "compliance_score": self.compliance_score,
            "last_attested": self.last_attested,
            "deployment_date": self.deployment_date,
            "registered_at": self.registered_at,
            "is_shadow_ai": self.is_shadow_ai,
            "open_violations": self.open_violations,
            "open_cves": self.open_cves,
            "drift_detected": self.drift_detected,
            "attestation_path": self.attestation_path,
            "notes": self.notes,
        }


@dataclass
class RegistrySummary:
    total_assets: int
    by_environment: dict[str, int]
    by_risk_tier: dict[str, int]
    compliant: int           # compliance_score >= 70
    non_compliant: int
    unattested: int
    stale: int               # attested >30 days ago
    shadow_ai_count: int
    total_violations: int
    total_cves: int
    drift_count: int

    def to_text(self) -> str:
        lines = [
            "AI ASSET REGISTRY SUMMARY",
            "=" * 46,
            f"Total Assets:     {self.total_assets}",
            f"  Production:     {self.by_environment.get('production', 0)}",
            f"  Staging:        {self.by_environment.get('staging', 0)}",
            f"  Development:    {self.by_environment.get('development', 0)}",
            "",
            f"Risk Tiers:       High: {self.by_risk_tier.get('high', 0)} · "
            f"Limited: {self.by_risk_tier.get('limited', 0)} · "
            f"Minimal: {self.by_risk_tier.get('minimal', 0)} · "
            f"Unknown: {self.by_risk_tier.get('unknown', 0)}",
            "",
            f"Compliance:       {self.compliant} passing · {self.non_compliant} failing",
            f"Unattested:       {self.unattested}",
            f"Stale (>30d):     {self.stale}",
            f"Shadow AI:        {self.shadow_ai_count}",
            f"Open Violations:  {self.total_violations}",
            f"Open CVEs:        {self.total_cves}",
            f"Drift Detected:   {self.drift_count}",
        ]
        return "\n".join(lines)


class AssetRegistry:
    """SQLite-backed AI model asset registry."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                model_id TEXT NOT NULL,
                model_path TEXT,
                model_version TEXT,
                owner TEXT,
                team TEXT,
                environment TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                frameworks TEXT,
                compliance_score REAL,
                last_attested TEXT,
                deployment_date TEXT,
                registered_at TEXT NOT NULL,
                is_shadow_ai INTEGER NOT NULL DEFAULT 0,
                open_violations INTEGER NOT NULL DEFAULT 0,
                open_cves INTEGER NOT NULL DEFAULT 0,
                drift_detected INTEGER NOT NULL DEFAULT 0,
                attestation_path TEXT,
                notes TEXT
            )
        """)
        self._conn.commit()

    def register(
        self,
        model_id: str,
        model_path: str = "",
        model_version: str = "unknown",
        owner: str = "",
        team: str = "",
        environment: str = "development",
        risk_tier: str = "unknown",
        notes: str = "",
        is_shadow_ai: bool = False,
    ) -> str:
        # Upsert by model_id + environment
        existing = self._conn.execute(
            "SELECT asset_id FROM assets WHERE model_id=? AND environment=?",
            (model_id, environment),
        ).fetchone()
        if existing:
            return existing[0]

        asset_id = str(uuid.uuid4())[:12].replace("-", "")
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (asset_id, model_id, model_path, model_version, owner, team,
             environment, risk_tier, "[]", None, None, None, now,
             int(is_shadow_ai), 0, 0, 0, None, notes),
        )
        self._conn.commit()
        return asset_id

    def sync_from_attestation(self, model_path: Path) -> str | None:
        """Read squash attestation artifacts from model_path and register/update the asset."""
        model_path = Path(model_path)
        attest_path = _find_attestation(model_path)
        if attest_path is None:
            return None

        try:
            data = json.loads(attest_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

        model_id = (
            data.get("model_id") or data.get("model_name") or model_path.name
        )
        version = data.get("model_version") or data.get("version") or "unknown"
        env = data.get("environment") or "development"
        risk_tier = data.get("risk_tier") or "unknown"
        score = data.get("compliance_score") or data.get("score")
        frameworks = data.get("policies_checked") or data.get("frameworks") or []
        violations = data.get("violations") or []
        attested_at = data.get("attested_at") or data.get("timestamp")

        # Register or get existing
        existing = self._conn.execute(
            "SELECT asset_id FROM assets WHERE model_id=? AND environment=?",
            (model_id, env),
        ).fetchone()

        if existing:
            asset_id = existing[0]
            self._conn.execute(
                "UPDATE assets SET model_version=?, risk_tier=?, frameworks=?, "
                "compliance_score=?, last_attested=?, open_violations=?, "
                "attestation_path=? WHERE asset_id=?",
                (version, risk_tier, json.dumps(frameworks), score,
                 attested_at, len(violations) if isinstance(violations, list) else 0,
                 str(attest_path), asset_id),
            )
        else:
            asset_id = self.register(
                model_id=model_id, model_path=str(model_path),
                model_version=version, environment=env, risk_tier=risk_tier,
            )
            self._conn.execute(
                "UPDATE assets SET frameworks=?, compliance_score=?, last_attested=?, "
                "open_violations=?, attestation_path=? WHERE asset_id=?",
                (json.dumps(frameworks), score, attested_at,
                 len(violations) if isinstance(violations, list) else 0,
                 str(attest_path), asset_id),
            )

        # Check drift
        drift_path = model_path / "drift_report.json"
        if drift_path.exists():
            try:
                drift = json.loads(drift_path.read_text())
                self._conn.execute(
                    "UPDATE assets SET drift_detected=? WHERE asset_id=?",
                    (int(drift.get("drift_detected", False)), asset_id),
                )
            except (json.JSONDecodeError, OSError):
                pass

        # Check CVEs
        vex_path = model_path / "vex_report.json"
        if vex_path.exists():
            try:
                vex = json.loads(vex_path.read_text())
                self._conn.execute(
                    "UPDATE assets SET open_cves=? WHERE asset_id=?",
                    (vex.get("total_count", 0) or vex.get("cve_count", 0), asset_id),
                )
            except (json.JSONDecodeError, OSError):
                pass

        self._conn.commit()
        return asset_id

    def get_asset(self, asset_id: str) -> AssetRecord | None:
        row = self._conn.execute(
            "SELECT * FROM assets WHERE asset_id=?", (asset_id,)
        ).fetchone()
        return _row_to_asset(row) if row else None

    def find_by_model_id(self, model_id: str) -> list[AssetRecord]:
        rows = self._conn.execute(
            "SELECT * FROM assets WHERE model_id=?", (model_id,)
        ).fetchall()
        return [_row_to_asset(r) for r in rows]

    def list_assets(
        self,
        environment: str | None = None,
        risk_tier: str | None = None,
        shadow_only: bool = False,
    ) -> list[AssetRecord]:
        sql = "SELECT * FROM assets"
        params: list[Any] = []
        filters: list[str] = []
        if environment:
            filters.append("environment=?")
            params.append(environment)
        if risk_tier:
            filters.append("risk_tier=?")
            params.append(risk_tier)
        if shadow_only:
            filters.append("is_shadow_ai=1")
        if filters:
            sql += " WHERE " + " AND ".join(filters)
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_asset(r) for r in rows]

    def flag_shadow_ai(self, asset_id: str) -> None:
        self._conn.execute(
            "UPDATE assets SET is_shadow_ai=1 WHERE asset_id=?", (asset_id,)
        )
        self._conn.commit()

    def remove_asset(self, asset_id: str) -> bool:
        rows = self._conn.execute(
            "DELETE FROM assets WHERE asset_id=?", (asset_id,)
        ).rowcount
        self._conn.commit()
        return rows > 0

    def summary(self) -> RegistrySummary:
        assets = self.list_assets()
        now = datetime.datetime.now()

        by_env: dict[str, int] = {}
        by_tier: dict[str, int] = {}
        compliant = non_compliant = unattested = stale = shadow = violations = cves = drift = 0

        for a in assets:
            by_env[a.environment.value] = by_env.get(a.environment.value, 0) + 1
            by_tier[a.risk_tier.value] = by_tier.get(a.risk_tier.value, 0) + 1
            if a.last_attested is None:
                unattested += 1
            else:
                try:
                    last = datetime.datetime.fromisoformat(a.last_attested.rstrip("Z"))
                    if (now - last).days > _STALE_DAYS_DEFAULT:
                        stale += 1
                except (ValueError, TypeError):
                    stale += 1
            if a.compliance_score is None:
                non_compliant += 1
            elif a.compliance_score >= 70:
                compliant += 1
            else:
                non_compliant += 1
            if a.is_shadow_ai:
                shadow += 1
            violations += a.open_violations
            cves += a.open_cves
            if a.drift_detected:
                drift += 1

        return RegistrySummary(
            total_assets=len(assets),
            by_environment=by_env,
            by_risk_tier=by_tier,
            compliant=compliant,
            non_compliant=non_compliant,
            unattested=unattested,
            stale=stale,
            shadow_ai_count=shadow,
            total_violations=violations,
            total_cves=cves,
            drift_count=drift,
        )

    def export(self, format: str = "json") -> str:
        assets = self.list_assets()
        if format == "json":
            return json.dumps([a.to_dict() for a in assets], indent=2)
        # Markdown table
        lines = [
            "| Model ID | Environment | Risk Tier | Score | Last Attested | Violations | CVEs |",
            "|----------|-------------|-----------|-------|---------------|------------|------|",
        ]
        for a in assets:
            score = f"{a.compliance_score:.0f}%" if a.compliance_score is not None else "N/A"
            lines.append(
                f"| {a.model_id} | {a.environment.value} | {a.risk_tier.value} | "
                f"{score} | {a.last_attested or 'Never'} | {a.open_violations} | {a.open_cves} |"
            )
        return "\n".join(lines)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AssetRegistry":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _find_attestation(model_path: Path) -> Path | None:
    for candidate in [
        model_path / "squash_attestation.json",
        model_path / "squash-attest.json",
        model_path / "squash" / "squash_attestation.json",
    ]:
        if candidate.exists():
            return candidate
    return None


def _row_to_asset(row: tuple) -> AssetRecord:
    return AssetRecord(
        asset_id=row[0], model_id=row[1], model_path=row[2] or "",
        model_version=row[3] or "unknown", owner=row[4] or "", team=row[5] or "",
        environment=AssetEnvironment(row[6]), risk_tier=AssetRiskTier(row[7]),
        frameworks=json.loads(row[8]) if row[8] else [],
        compliance_score=row[9], last_attested=row[10], deployment_date=row[11],
        registered_at=row[12], is_shadow_ai=bool(row[13]),
        open_violations=row[14] or 0, open_cves=row[15] or 0,
        drift_detected=bool(row[16]), attestation_path=row[17], notes=row[18] or "",
    )
