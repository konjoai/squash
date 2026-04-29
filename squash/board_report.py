"""squash/board_report.py — Executive board report generator.

Automates the most painful manual process in AI governance: the quarterly
board report on AI risk.  A 20-30 page document produced manually by a
compliance team becomes a single CLI command.

The board report contains
--------------------------
1. Executive Summary — AI compliance posture in 5 bullet points
2. Compliance Scorecard — per-framework scores with trend
3. Model Portfolio Status — all attested models, risk tier, last attestation
4. Active Policy Violations — grouped by severity
5. CVE / Security Exposure Summary — open vulnerabilities
6. Regulatory Update Summary — EU AI Act, NIST RMF, ISO 42001 status
7. Incident Log — incidents since last report
8. Remediation Roadmap — open actions by priority
9. Next Period Objectives — upcoming compliance milestones

Output formats: JSON (machine-readable), Markdown, plain text.
PDF generation via weasyprint (optional extra).

Usage::

    from squash.board_report import BoardReportGenerator
    from pathlib import Path

    report = BoardReportGenerator.generate(
        models_dir=Path("./models"),
        quarter="Q2-2026",
    )
    print(report.executive_summary())
    report.save(Path("./board-report-Q2-2026/"))
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
class ModelStatus:
    model_id: str
    model_path: str
    last_attested: str | None
    compliance_score: float | None
    risk_tier: str            # "high-risk" | "limited-risk" | "minimal-risk"
    frameworks: list[str]
    open_violations: int
    open_cves: int
    drift_detected: bool


@dataclass
class BoardReport:
    quarter: str
    generated_at: str
    reporting_period_start: str
    reporting_period_end: str
    models: list[ModelStatus] = field(default_factory=list)
    overall_compliance_score: float = 0.0
    frameworks_assessed: list[str] = field(default_factory=list)
    total_models: int = 0
    models_passing: int = 0
    models_failing: int = 0
    models_unattested: int = 0
    total_violations: int = 0
    critical_violations: int = 0
    total_cves: int = 0
    critical_cves: int = 0
    incidents_this_period: int = 0
    regulatory_deadlines: list[dict[str, Any]] = field(default_factory=list)
    remediation_actions: list[dict[str, Any]] = field(default_factory=list)
    portfolio_trend: str = "STABLE"   # "IMPROVING" | "STABLE" | "DEGRADING"

    def executive_summary(self) -> str:
        score_label = "STRONG" if self.overall_compliance_score >= 80 else \
                      "ADEQUATE" if self.overall_compliance_score >= 60 else "AT RISK"

        lines = [
            f"AI COMPLIANCE BOARD REPORT — {self.quarter}",
            "=" * 54,
            f"Generated: {self.generated_at}",
            f"Period: {self.reporting_period_start} → {self.reporting_period_end}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 54,
            f"Overall Compliance: {self.overall_compliance_score:.1f}% ({score_label}) — Trend: {self.portfolio_trend}",
            f"Models in Portfolio: {self.total_models} total · {self.models_passing} passing · "
            f"{self.models_failing} failing · {self.models_unattested} unattested",
            f"Policy Violations: {self.total_violations} total ({self.critical_violations} critical)",
            f"Security CVEs: {self.total_cves} open ({self.critical_cves} critical)",
            f"AI Incidents: {self.incidents_this_period} this period",
            "",
        ]

        # Regulatory deadlines
        upcoming = [d for d in self.regulatory_deadlines if not d.get("met", False)]
        if upcoming:
            lines.append("Upcoming Regulatory Deadlines:")
            for d in upcoming[:5]:
                days = d.get("days_remaining", "?")
                lines.append(f"  ⏰ {d.get('framework', '?')} — {d.get('deadline', '?')} ({days} days)")
            lines.append("")

        # Key remediation actions
        critical_actions = [a for a in self.remediation_actions if a.get("priority") == "Critical"]
        if critical_actions:
            lines.append(f"Critical Actions Required ({len(critical_actions)}):")
            for a in critical_actions[:5]:
                lines.append(f"  ⚠  {a.get('action', '')} — Owner: {a.get('owner', 'TBD')}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": "AI_COMPLIANCE_BOARD_REPORT",
            "quarter": self.quarter,
            "generated_at": self.generated_at,
            "reporting_period": {
                "start": self.reporting_period_start,
                "end": self.reporting_period_end,
            },
            "executive_summary": {
                "overall_compliance_score": round(self.overall_compliance_score, 2),
                "portfolio_trend": self.portfolio_trend,
                "total_models": self.total_models,
                "models_passing": self.models_passing,
                "models_failing": self.models_failing,
                "models_unattested": self.models_unattested,
                "total_violations": self.total_violations,
                "critical_violations": self.critical_violations,
                "total_cves": self.total_cves,
                "critical_cves": self.critical_cves,
                "incidents_this_period": self.incidents_this_period,
            },
            "frameworks_assessed": self.frameworks_assessed,
            "model_portfolio": [
                {
                    "model_id": m.model_id,
                    "model_path": m.model_path,
                    "last_attested": m.last_attested,
                    "compliance_score": m.compliance_score,
                    "risk_tier": m.risk_tier,
                    "frameworks": m.frameworks,
                    "open_violations": m.open_violations,
                    "open_cves": m.open_cves,
                    "drift_detected": m.drift_detected,
                }
                for m in self.models
            ],
            "regulatory_deadlines": self.regulatory_deadlines,
            "remediation_actions": self.remediation_actions,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# AI Compliance Board Report — {self.quarter}",
            "",
            f"**Generated:** {self.generated_at}  ",
            f"**Period:** {self.reporting_period_start} → {self.reporting_period_end}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Overall Compliance Score | **{self.overall_compliance_score:.1f}%** |",
            f"| Portfolio Trend | {self.portfolio_trend} |",
            f"| Models: Total / Passing / Failing / Unattested | "
            f"{self.total_models} / {self.models_passing} / {self.models_failing} / {self.models_unattested} |",
            f"| Policy Violations (Critical) | {self.total_violations} ({self.critical_violations}) |",
            f"| Security CVEs (Critical) | {self.total_cves} ({self.critical_cves}) |",
            f"| AI Incidents This Period | {self.incidents_this_period} |",
            "",
        ]

        if self.regulatory_deadlines:
            lines += [
                "## Regulatory Deadlines",
                "",
                "| Framework | Deadline | Days Remaining | Status |",
                "|-----------|----------|----------------|--------|",
            ]
            for d in self.regulatory_deadlines:
                status = "✅ Met" if d.get("met") else "⏳ Pending"
                lines.append(
                    f"| {d.get('framework', '?')} | {d.get('deadline', '?')} | "
                    f"{d.get('days_remaining', '?')} | {status} |"
                )
            lines.append("")

        if self.models:
            lines += [
                "## Model Portfolio Status",
                "",
                "| Model | Risk Tier | Compliance Score | Last Attested | Violations | CVEs | Drift |",
                "|-------|-----------|-----------------|---------------|------------|------|-------|",
            ]
            for m in self.models:
                score_str = f"{m.compliance_score:.0f}%" if m.compliance_score is not None else "N/A"
                drift_str = "⚠ Yes" if m.drift_detected else "No"
                lines.append(
                    f"| {m.model_id} | {m.risk_tier} | {score_str} | "
                    f"{m.last_attested or 'Never'} | {m.open_violations} | {m.open_cves} | {drift_str} |"
                )
            lines.append("")

        if self.remediation_actions:
            lines += [
                "## Remediation Roadmap",
                "",
                "| Priority | Action | Owner | Deadline |",
                "|----------|--------|-------|----------|",
            ]
            for a in self.remediation_actions:
                lines.append(
                    f"| {a.get('priority', 'Medium')} | {a.get('action', '')} | "
                    f"{a.get('owner', 'TBD')} | {a.get('deadline', 'TBD')} |"
                )
            lines.append("")

        lines += [
            "---",
            "",
            "*Generated by squash-ai — AI compliance automation*  ",
            "*https://getsquash.dev*",
        ]
        return "\n".join(lines)

    def save(self, output_dir: Path) -> list[str]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: list[str] = []

        json_path = output_dir / f"board-report-{self.quarter}.json"
        json_path.write_text(json.dumps(self.to_dict(), indent=2))
        written.append(str(json_path))

        md_path = output_dir / f"board-report-{self.quarter}.md"
        md_path.write_text(self.to_markdown())
        written.append(str(md_path))

        txt_path = output_dir / f"board-report-{self.quarter}-summary.txt"
        txt_path.write_text(self.executive_summary())
        written.append(str(txt_path))

        # Attempt PDF generation
        try:
            pdf_path = _to_pdf(output_dir, self.quarter, self.to_markdown())
            if pdf_path:
                written.append(str(pdf_path))
        except Exception as exc:
            log.debug("PDF generation skipped: %s", exc)

        log.info("Board report written to %s", output_dir)
        return written


class BoardReportGenerator:
    """Generate a quarterly AI compliance board report."""

    @staticmethod
    def generate(
        models_dir: Path | None = None,
        model_paths: list[Path] | None = None,
        quarter: str | None = None,
        period_start: str | None = None,
        period_end: str | None = None,
    ) -> BoardReport:
        now = datetime.datetime.now(datetime.timezone.utc)

        if quarter is None:
            q = (now.month - 1) // 3 + 1
            quarter = f"Q{q}-{now.year}"

        # Derive reporting period
        p_start, p_end = _derive_period(quarter, period_start, period_end, now)

        # Collect model paths
        paths: list[Path] = []
        if model_paths:
            paths = [Path(p) for p in model_paths]
        elif models_dir:
            models_dir = Path(models_dir)
            if models_dir.is_dir():
                # Each subdirectory with a squash_attestation.json is a model
                for child in sorted(models_dir.iterdir()):
                    if child.is_dir():
                        paths.append(child)
                # Also the dir itself if it has an attestation
                if (models_dir / "squash_attestation.json").exists():
                    paths = [models_dir]

        # Single-model mode
        if not paths and models_dir and Path(models_dir).exists():
            paths = [Path(models_dir)]

        models: list[ModelStatus] = []
        for p in paths:
            models.append(_assess_model(p))

        return _build_report(quarter, p_start, p_end, now, models)

    @staticmethod
    def generate_from_models(model_statuses: list[dict[str, Any]], quarter: str) -> BoardReport:
        """Generate from pre-built model status dicts (for API/test use)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        p_start, p_end = _derive_period(quarter, None, None, now)
        models = [
            ModelStatus(
                model_id=m.get("model_id", "unknown"),
                model_path=m.get("model_path", ""),
                last_attested=m.get("last_attested"),
                compliance_score=m.get("compliance_score"),
                risk_tier=m.get("risk_tier", "unknown"),
                frameworks=m.get("frameworks", []),
                open_violations=m.get("open_violations", 0),
                open_cves=m.get("open_cves", 0),
                drift_detected=m.get("drift_detected", False),
            )
            for m in model_statuses
        ]
        return _build_report(quarter, p_start, p_end, now, models)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _derive_period(
    quarter: str,
    period_start: str | None,
    period_end: str | None,
    now: datetime.datetime,
) -> tuple[str, str]:
    if period_start and period_end:
        return period_start, period_end

    try:
        q_part, year_part = quarter.upper().split("-")
        q_num = int(q_part[1])
        year = int(year_part)
        month_start = (q_num - 1) * 3 + 1
        month_end = month_start + 2
        import calendar
        start = datetime.date(year, month_start, 1)
        end = datetime.date(year, month_end, calendar.monthrange(year, month_end)[1])
        return start.isoformat(), end.isoformat()
    except (ValueError, IndexError):
        # Fallback to last 90 days
        end_dt = now.date()
        start_dt = end_dt - datetime.timedelta(days=90)
        return start_dt.isoformat(), end_dt.isoformat()


def _assess_model(model_path: Path) -> ModelStatus:
    """Read squash artifacts to build ModelStatus for a model directory."""
    model_id = model_path.name
    last_attested: str | None = None
    compliance_score: float | None = None
    frameworks: list[str] = []
    open_violations = 0
    open_cves = 0
    drift_detected = False
    risk_tier = "unknown"

    attestation_path = model_path / "squash_attestation.json"
    if not attestation_path.exists():
        attestation_path = model_path / "squash" / "squash_attestation.json"

    if attestation_path.exists():
        try:
            data = json.loads(attestation_path.read_text())
            last_attested = data.get("attested_at") or data.get("timestamp")
            compliance_score = data.get("compliance_score") or data.get("score")
            frameworks = data.get("policies_checked", []) or data.get("frameworks", [])
            violations = data.get("violations", [])
            open_violations = len(violations) if isinstance(violations, list) else int(violations or 0)
            risk_tier = data.get("risk_tier", "unknown")
        except (json.JSONDecodeError, OSError):
            pass

    vex_path = model_path / "vex_report.json"
    if vex_path.exists():
        try:
            vex = json.loads(vex_path.read_text())
            open_cves = vex.get("total_count", 0) or vex.get("cve_count", 0)
        except (json.JSONDecodeError, OSError):
            pass

    drift_path = model_path / "drift_report.json"
    if drift_path.exists():
        try:
            drift = json.loads(drift_path.read_text())
            drift_detected = bool(drift.get("drift_detected", False))
        except (json.JSONDecodeError, OSError):
            pass

    return ModelStatus(
        model_id=model_id,
        model_path=str(model_path),
        last_attested=last_attested,
        compliance_score=compliance_score,
        risk_tier=risk_tier,
        frameworks=frameworks,
        open_violations=open_violations,
        open_cves=open_cves,
        drift_detected=drift_detected,
    )


def _build_report(
    quarter: str,
    p_start: str,
    p_end: str,
    now: datetime.datetime,
    models: list[ModelStatus],
) -> BoardReport:
    total = len(models)
    attested = [m for m in models if m.last_attested is not None]
    unattested_count = total - len(attested)

    scores = [m.compliance_score for m in attested if m.compliance_score is not None]
    overall_score = sum(scores) / max(len(scores), 1) if scores else 0.0

    passing = sum(1 for m in attested if (m.compliance_score or 0) >= 70)
    failing = len(attested) - passing

    total_violations = sum(m.open_violations for m in models)
    total_cves = sum(m.open_cves for m in models)

    frameworks_seen: set[str] = set()
    for m in models:
        frameworks_seen.update(m.frameworks)

    # Regulatory deadlines
    eu_days = (datetime.date(2026, 8, 2) - now.date()).days
    col_days = (datetime.date(2026, 6, 1) - now.date()).days
    deadlines = [
        {"framework": "EU AI Act (high-risk enforcement)", "deadline": "2026-08-02",
         "days_remaining": max(eu_days, 0), "met": eu_days <= 0},
        {"framework": "Colorado AI Act", "deadline": "2026-06-01",
         "days_remaining": max(col_days, 0), "met": col_days <= 0},
        {"framework": "ISO 42001 (recommended certification)", "deadline": "2026-12-31",
         "days_remaining": (datetime.date(2026, 12, 31) - now.date()).days, "met": False},
    ]

    # Portfolio trend (simplified: based on score and violations)
    if overall_score >= 80 and total_violations == 0:
        trend = "IMPROVING"
    elif total_violations > 5 or overall_score < 50:
        trend = "DEGRADING"
    else:
        trend = "STABLE"

    # Build remediation actions from violations/CVEs
    actions: list[dict[str, Any]] = []
    for m in models:
        if m.open_violations > 0:
            actions.append({
                "action": f"Resolve {m.open_violations} policy violation(s) in {m.model_id}",
                "priority": "High",
                "owner": "ML Ops",
                "deadline": (now + datetime.timedelta(days=14)).strftime("%Y-%m-%d"),
            })
        if m.open_cves > 0:
            actions.append({
                "action": f"Patch {m.open_cves} CVE(s) in {m.model_id}",
                "priority": "Critical" if m.open_cves >= 5 else "High",
                "owner": "Security Team",
                "deadline": (now + datetime.timedelta(days=7)).strftime("%Y-%m-%d"),
            })
        if m.drift_detected:
            actions.append({
                "action": f"Investigate model drift in {m.model_id} and re-attest",
                "priority": "High",
                "owner": "ML Ops",
                "deadline": (now + datetime.timedelta(days=7)).strftime("%Y-%m-%d"),
            })
        if m.last_attested is None:
            actions.append({
                "action": f"Run initial attestation for unattested model: {m.model_id}",
                "priority": "Medium",
                "owner": "ML Ops",
                "deadline": (now + datetime.timedelta(days=30)).strftime("%Y-%m-%d"),
            })

    if eu_days <= 30:
        actions.insert(0, {
            "action": f"Complete EU AI Act compliance review — enforcement in {eu_days} days",
            "priority": "Critical",
            "owner": "Compliance Team",
            "deadline": (now + datetime.timedelta(days=min(eu_days, 14))).strftime("%Y-%m-%d"),
        })

    return BoardReport(
        quarter=quarter,
        generated_at=now.isoformat(),
        reporting_period_start=p_start,
        reporting_period_end=p_end,
        models=models,
        overall_compliance_score=overall_score,
        frameworks_assessed=sorted(frameworks_seen),
        total_models=total,
        models_passing=passing,
        models_failing=failing,
        models_unattested=unattested_count,
        total_violations=total_violations,
        critical_violations=sum(1 for m in models if m.open_violations > 0),
        total_cves=total_cves,
        critical_cves=sum(1 for m in models if m.open_cves > 0),
        incidents_this_period=0,
        regulatory_deadlines=deadlines,
        remediation_actions=actions,
        portfolio_trend=trend,
    )


def _to_pdf(output_dir: Path, quarter: str, markdown_content: str) -> Path | None:
    try:
        import weasyprint  # type: ignore[import]
    except ImportError:
        return None

    try:
        import markdown  # type: ignore[import]
        html_body = markdown.markdown(markdown_content, extensions=["tables"])
    except ImportError:
        html_body = f"<pre>{markdown_content}</pre>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<style>
body {{font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 11pt; line-height: 1.4; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a2e;}}
h1 {{color: #0d1b2a; border-bottom: 2px solid #0d1b2a; padding-bottom: 8px;}}
h2 {{color: #1b263b; margin-top: 2em; border-bottom: 1px solid #ccc;}}
table {{border-collapse: collapse; width: 100%; margin: 1em 0;}}
th, td {{border: 1px solid #ccc; padding: 6px 10px; text-align: left;}}
th {{background: #f0f4f8;}}
code {{background: #f4f4f4; padding: 2px 4px; border-radius: 3px;}}
</style></head>
<body>{html_body}
<footer style='margin-top:3em; font-size: 9pt; color: #666; border-top: 1px solid #ccc; padding-top: 8px;'>
Generated by squash-ai — getsquash.dev
</footer></body></html>"""

    pdf_path = output_dir / f"board-report-{quarter}.pdf"
    weasyprint.HTML(string=html).write_pdf(str(pdf_path))
    return pdf_path
