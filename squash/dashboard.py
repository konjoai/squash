"""squash/dashboard.py — CISO / Executive AI Compliance Dashboard.

Executives don't read attestation JSON.  They need a single screen with five
numbers: total models, percentage compliant, active violations, open CVEs,
and days to next regulatory deadline.

This module renders a terminal dashboard (no mandatory external dependencies —
uses ``rich`` when installed, falls back to plain ANSI/ASCII).

Five key metrics
----------------
1. Models in portfolio (total / passing / failing / unattested)
2. Overall compliance score (% + trend arrow)
3. Active policy violations (total / critical)
4. Open CVEs (total / critical)
5. Days to next regulatory deadline

Below: a risk heat-map table of the model portfolio sorted by compliance score.

Usage::

    from squash.dashboard import Dashboard
    from pathlib import Path

    d = Dashboard.build(models_dir=Path("./models"))
    print(d.render_text())         # always works
    d.render_rich()                # uses rich if installed
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ModelRow:
    model_id: str
    environment: str
    compliance_score: float | None
    risk_tier: str
    open_violations: int
    open_cves: int
    last_attested: str | None
    drift_detected: bool

    @property
    def status_icon(self) -> str:
        if self.compliance_score is None:
            return "?"
        if self.compliance_score >= 80 and self.open_violations == 0:
            return "✅"
        if self.compliance_score >= 60:
            return "⚠"
        return "❌"

    @property
    def risk_color(self) -> str:
        # ANSI escape codes for terminal colour
        if self.compliance_score is None:
            return "\033[33m"  # yellow
        if self.compliance_score >= 80 and self.open_violations == 0:
            return "\033[32m"  # green
        if self.compliance_score >= 60:
            return "\033[33m"  # yellow
        return "\033[31m"  # red


@dataclass
class Dashboard:
    generated_at: str
    total_models: int
    models_passing: int
    models_failing: int
    models_unattested: int
    overall_score: float | None
    total_violations: int
    critical_violations: int
    total_cves: int
    critical_cves: int
    eu_days_remaining: int
    next_deadline_label: str
    model_rows: list[ModelRow] = field(default_factory=list)
    portfolio_trend: str = "stable"

    @classmethod
    def build(
        cls,
        models_dir: Path | None = None,
        model_paths: list[Path] | None = None,
    ) -> "Dashboard":
        now = datetime.datetime.now(datetime.timezone.utc)
        eu_days = max(0, (datetime.date(2026, 8, 2) - now.date()).days)
        col_days = max(0, (datetime.date(2026, 6, 1) - now.date()).days)
        if col_days < eu_days and col_days > 0:
            next_label, next_days = "Colorado AI Act", col_days
        elif eu_days > 0:
            next_label, next_days = "EU AI Act enforcement", eu_days
        else:
            next_label, next_days = "ISO 42001 recommended", 245

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
        if not paths and models_dir and model_paths:
            paths = [Path(models_dir)]

        rows: list[ModelRow] = [_build_row(p) for p in paths]

        scores = [r.compliance_score for r in rows if r.compliance_score is not None]
        overall = sum(scores) / max(len(scores), 1) if scores else None
        passing = sum(1 for r in rows if (r.compliance_score or 0) >= 70 and r.open_violations == 0)
        failing = sum(1 for r in rows if r.compliance_score is not None and r.compliance_score < 70)
        unattested = sum(1 for r in rows if r.compliance_score is None)
        violations = sum(r.open_violations for r in rows)
        cves = sum(r.open_cves for r in rows)
        crit_viol = sum(1 for r in rows if r.open_violations >= 3)
        crit_cves = sum(1 for r in rows if r.open_cves >= 3)

        if overall is not None and overall >= 80 and violations == 0:
            trend = "improving"
        elif violations > 3 or (overall is not None and overall < 50):
            trend = "degrading"
        else:
            trend = "stable"

        # Sort by compliance score ascending (worst first)
        rows.sort(key=lambda r: (r.compliance_score or -1))

        return cls(
            generated_at=now.isoformat(),
            total_models=len(rows),
            models_passing=passing,
            models_failing=failing,
            models_unattested=unattested,
            overall_score=round(overall, 1) if overall is not None else None,
            total_violations=violations,
            critical_violations=crit_viol,
            total_cves=cves,
            critical_cves=crit_cves,
            eu_days_remaining=eu_days,
            next_deadline_label=next_label,
            model_rows=rows,
            portfolio_trend=trend,
        )

    def render_text(self, color: bool = True) -> str:
        RESET = "\033[0m" if color else ""
        BOLD = "\033[1m" if color else ""
        GREEN = "\033[32m" if color else ""
        YELLOW = "\033[33m" if color else ""
        RED = "\033[31m" if color else ""
        CYAN = "\033[36m" if color else ""

        trend_sym = {"improving": "↑", "degrading": "↓", "stable": "→"}.get(self.portfolio_trend, "?")
        score_str = f"{self.overall_score:.1f}%" if self.overall_score is not None else "N/A"
        score_color = GREEN if (self.overall_score or 0) >= 80 else YELLOW if (self.overall_score or 0) >= 60 else RED

        lines = [
            f"{BOLD}{'─' * 62}{RESET}",
            f"{BOLD}  SQUASH AI COMPLIANCE DASHBOARD{RESET}  {self.generated_at[:19]}",
            f"{'─' * 62}",
            "",
            f"  {BOLD}Portfolio Score:{RESET}  {score_color}{score_str}{RESET}  {trend_sym}  "
            f"({self.models_passing} pass · {self.models_failing} fail · {self.models_unattested} unattested)",
            f"  {BOLD}Violations:{RESET}      {RED if self.total_violations else GREEN}"
            f"{self.total_violations}{RESET}  ({self.critical_violations} critical)",
            f"  {BOLD}Open CVEs:{RESET}       {RED if self.total_cves else GREEN}"
            f"{self.total_cves}{RESET}  ({self.critical_cves} critical)",
            f"  {BOLD}Next deadline:{RESET}   {YELLOW}{self.next_deadline_label}{RESET} "
            f"— {self.eu_days_remaining} days",
            "",
            f"{'─' * 62}",
            f"  {'MODEL':<28} {'SCORE':>7}  {'ENV':<12} {'VIOL':>5}  {'CVE':>4}  {'DRIFT':>5}",
            f"{'─' * 62}",
        ]

        for r in self.model_rows:
            sc = f"{r.compliance_score:.0f}%" if r.compliance_score is not None else "N/A"
            drift = "YES" if r.drift_detected else "-"
            col = r.risk_color if color else ""
            lines.append(
                f"  {col}{r.status_icon} {r.model_id:<26}{RESET}"
                f" {sc:>7}  {r.environment:<12} {r.open_violations:>5}  {r.open_cves:>4}  {drift:>5}"
            )

        lines += [f"{'─' * 62}", ""]
        return "\n".join(lines)

    def render_rich(self) -> None:
        """Render with rich library if available; fall back to render_text."""
        try:
            from rich.console import Console  # type: ignore[import]
            from rich.table import Table
            from rich.text import Text
            console = Console()
            console.print(self.render_text(color=False))
        except ImportError:
            print(self.render_text())

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_score": self.overall_score,
            "portfolio_trend": self.portfolio_trend,
            "models": {
                "total": self.total_models,
                "passing": self.models_passing,
                "failing": self.models_failing,
                "unattested": self.models_unattested,
            },
            "violations": {
                "total": self.total_violations,
                "critical": self.critical_violations,
            },
            "cves": {
                "total": self.total_cves,
                "critical": self.critical_cves,
            },
            "next_deadline": {
                "label": self.next_deadline_label,
                "days_remaining": self.eu_days_remaining,
            },
            "model_portfolio": [
                {
                    "model_id": r.model_id,
                    "environment": r.environment,
                    "compliance_score": r.compliance_score,
                    "risk_tier": r.risk_tier,
                    "open_violations": r.open_violations,
                    "open_cves": r.open_cves,
                    "last_attested": r.last_attested,
                    "drift_detected": r.drift_detected,
                    "status": r.status_icon,
                }
                for r in self.model_rows
            ],
        }


def _build_row(model_path: Path) -> ModelRow:
    attest_path = _find_attestation(model_path)
    if attest_path is None:
        return ModelRow(
            model_id=model_path.name, environment="unknown",
            compliance_score=None, risk_tier="unknown",
            open_violations=0, open_cves=0,
            last_attested=None, drift_detected=False,
        )
    try:
        data = json.loads(attest_path.read_text())
    except (json.JSONDecodeError, OSError):
        return ModelRow(
            model_id=model_path.name, environment="unknown",
            compliance_score=None, risk_tier="unknown",
            open_violations=0, open_cves=0,
            last_attested=None, drift_detected=False,
        )

    violations = data.get("violations") or []
    n_viol = len(violations) if isinstance(violations, list) else int(violations or 0)

    cves = 0
    vex_path = model_path / "vex_report.json"
    if vex_path.exists():
        try:
            vex = json.loads(vex_path.read_text())
            cves = vex.get("total_count", 0) or vex.get("cve_count", 0)
        except (json.JSONDecodeError, OSError):
            pass

    drift = False
    drift_path = model_path / "drift_report.json"
    if drift_path.exists():
        try:
            drift = bool(json.loads(drift_path.read_text()).get("drift_detected", False))
        except (json.JSONDecodeError, OSError):
            pass

    return ModelRow(
        model_id=data.get("model_id") or model_path.name,
        environment=data.get("environment", "unknown"),
        compliance_score=data.get("compliance_score") or data.get("score"),
        risk_tier=data.get("risk_tier", "unknown"),
        open_violations=n_viol,
        open_cves=cves,
        last_attested=data.get("attested_at") or data.get("timestamp"),
        drift_detected=drift,
    )


def _find_attestation(model_path: Path) -> Path | None:
    for p in [
        model_path / "squash_attestation.json",
        model_path / "squash-attest.json",
        model_path / "squash" / "squash_attestation.json",
    ]:
        if p.exists():
            return p
    return None
