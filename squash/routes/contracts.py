"""squash/routes/contracts.py — FastAPI router for contract primitives.

Mounted onto :data:`squash.api.app` by :mod:`squash.api`.

* ``POST /api/extract/obligations`` — body ``{text?, clauses?}``.
  Returns the list of structured :class:`Obligation` records.
* ``POST /api/contracts/diff``       — body
  ``{old, new, match_threshold?, modified_threshold?}``. Both ``old`` and
  ``new`` accept either a single string (whole contract) or a list of
  clause strings. Returns the full :class:`ContractDiff` envelope.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator

from squash.contracts import (
    ContractDiffer,
    ObligationExtractor,
)


contracts_router = APIRouter(prefix="/api", tags=["contracts"])


# ──────────────────────────────────────────────────────────────────────────────
# Obligation extraction
# ──────────────────────────────────────────────────────────────────────────────


class _ObligationsRequest(BaseModel):
    text: str = ""
    clauses: list[str] | None = None

    @model_validator(mode="after")
    def _at_least_one(self):
        if not self.text and not self.clauses:
            raise ValueError("either text or clauses is required")
        return self


@contracts_router.post("/extract/obligations")
async def extract_obligations(req: _ObligationsRequest) -> dict[str, Any]:
    extractor = ObligationExtractor()
    try:
        if req.clauses:
            obligations = extractor.extract_from_clauses(req.clauses)
        else:
            obligations = extractor.extract_from_text(req.text)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    binding = [o for o in obligations if o.is_binding]
    return {
        "count":           len(obligations),
        "binding_count":   len(binding),
        "obligations":     [o.to_dict() for o in obligations],
        "parties":         sorted({o.party for o in obligations if o.party}),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Contract diff
# ──────────────────────────────────────────────────────────────────────────────


class _DiffRequest(BaseModel):
    old: list[str] | str
    new: list[str] | str
    match_threshold: float = Field(0.95, gt=0.0, le=1.0)
    modified_threshold: float = Field(0.45, gt=0.0, le=1.0)
    auto_scan_frameworks: list[str] | None = None

    @model_validator(mode="after")
    def _thresholds_ordered(self):
        if self.modified_threshold >= self.match_threshold:
            raise ValueError(
                "modified_threshold must be strictly less than match_threshold",
            )
        return self


def _to_clauses(value: list[str] | str) -> list[str]:
    if isinstance(value, list):
        return [c for c in value if isinstance(c, str)]
    if not value or not value.strip():
        return []
    # Naïve sentence-split for whole-contract input; the differ tolerates
    # noisy clause boundaries so this is good enough for the first cut.
    import re
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(\"])|\n{2,}", value.strip())
    return [p.strip() for p in parts if p and p.strip()]


@contracts_router.post("/contracts/diff")
async def diff_contracts(req: _DiffRequest) -> dict[str, Any]:
    old_clauses = _to_clauses(req.old)
    new_clauses = _to_clauses(req.new)
    if not old_clauses and not new_clauses:
        raise HTTPException(
            status_code=422,
            detail="both old and new are empty after clause extraction",
        )
    try:
        diff = ContractDiffer(
            match_threshold=req.match_threshold,
            modified_threshold=req.modified_threshold,
        ).diff(old_clauses, new_clauses)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Optional risk delta: scan both sides through the multi-framework
    # scanner using the requested framework subset (or all by default).
    if req.auto_scan_frameworks is not None or True:
        try:
            from squash.compliance import (
                ComplianceFramework, ComplianceScanner,
            )
            fws = (
                [ComplianceFramework.parse(f) for f in req.auto_scan_frameworks]
                if req.auto_scan_frameworks else None
            )
            scanner = ComplianceScanner()
            old_report = scanner.scan(old_clauses, fws) if old_clauses else None
            new_report = scanner.scan(new_clauses, fws) if new_clauses else None
            diff.with_risk_delta(old_report, new_report)
        except ValueError as exc:
            # bad framework name — surface as 400 instead of silently swallowing
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception:  # noqa: BLE001
            # never let the optional enrichment block the core diff
            diff.risk_delta = None

    return diff.to_dict()


__all__ = ["contracts_router"]
