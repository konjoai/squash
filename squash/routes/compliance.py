"""squash/routes/compliance.py — FastAPI router for multi-framework scanning.

Mounted under the prefix ``/api/compliance`` by :mod:`squash.api`. The
clause-clustering route is mounted under ``/api/analysis``.

Routes
------
* ``POST /api/compliance/scan``  — body
  ``{clauses, frameworks?, min_confidence?, record?}``.
  Returns a full :class:`squash.compliance.ComplianceReport` as JSON and
  (by default) persists a row to the analysis-history SQLite store so
  ``GET /api/trends/risk`` can chart it later.
* ``POST /api/analysis/cluster`` — body ``{clauses, k?}``.
  Returns a :class:`squash.analysis.ClusterResult`.
"""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from squash.analysis import ClauseClustering
from squash.compliance import ComplianceFramework, ComplianceScanner
from squash.routes import trends as _trends


# ──────────────────────────────────────────────────────────────────────────────
# Compliance router
# ──────────────────────────────────────────────────────────────────────────────

compliance_router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class _ScanRequest(BaseModel):
    clauses: list[str] = Field(..., min_length=1, max_length=5000)
    frameworks: list[str] | None = None
    min_confidence: float = Field(0.5, ge=0.0, le=1.0)
    record: bool = True
    doc_label: str = ""


@compliance_router.post("/scan")
async def compliance_scan(req: _ScanRequest) -> dict[str, Any]:
    """Score clauses against SOC2 / HIPAA / PCI-DSS (or any subset)."""
    try:
        parsed_fws = (
            [ComplianceFramework.parse(f) for f in req.frameworks]
            if req.frameworks
            else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scanner = ComplianceScanner()
    try:
        report = scanner.scan(
            req.clauses,
            parsed_fws,
            min_confidence=req.min_confidence,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    body = report.to_dict()

    if req.record:
        doc_hash = _doc_hash(req.clauses)
        # Per-framework rows so trend filtering by framework works.
        risk_score = report.overall_coverage_pct()
        high_risk_count = sum(
            1 for fr in report.framework_results.values()
            if fr.coverage_pct < 50.0
        )
        for fw, fr in report.framework_results.items():
            _trends.record_analysis(
                doc_hash=doc_hash,
                risk_score=fr.coverage_pct,
                framework=fw.value,
                clause_count=len(req.clauses),
                high_risk_count=len(fr.gaps),
                overall_risk=report.overall_risk,
                doc_label=req.doc_label,
            )
        # also one aggregate row keyed under '*' so 'all frameworks' queries work
        if report.framework_results:
            _trends.record_analysis(
                doc_hash=doc_hash,
                risk_score=risk_score,
                framework="*",
                clause_count=len(req.clauses),
                high_risk_count=high_risk_count,
                overall_risk=report.overall_risk,
                doc_label=req.doc_label,
            )
        body["recorded"] = True
        body["doc_hash"] = doc_hash
    else:
        body["recorded"] = False

    # Fire any matching saved-search alerts. Imported locally so the
    # router module stays cheap to import when alerts aren't in use.
    try:
        from squash.routes.alerts import evaluate_after_scan
        deliveries = evaluate_after_scan(report)
    except Exception:  # noqa: BLE001 — alerts never block scans
        deliveries = []
    body["alerts_fired"] = deliveries

    return body


def _doc_hash(clauses: list[str]) -> str:
    h = hashlib.sha256()
    for c in clauses:
        h.update(c.strip().encode("utf-8", "replace"))
        h.update(b"\n")
    return h.hexdigest()[:16]


# ──────────────────────────────────────────────────────────────────────────────
# Analysis router
# ──────────────────────────────────────────────────────────────────────────────

analysis_router = APIRouter(prefix="/api/analysis", tags=["analysis"])


class _ClusterRequest(BaseModel):
    clauses: list[str] = Field(..., min_length=1, max_length=5000)
    k: int = Field(5, ge=1, le=64)
    seed: int = Field(42)


@analysis_router.post("/cluster")
async def analysis_cluster(req: _ClusterRequest) -> dict[str, Any]:
    """Group similar clauses by TF-IDF cosine similarity (k-means++)."""
    engine = ClauseClustering(seed=req.seed)
    try:
        result = engine.cluster(req.clauses, k=req.k)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result.to_dict()


__all__ = ["compliance_router", "analysis_router"]
