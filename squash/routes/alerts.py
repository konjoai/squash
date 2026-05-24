"""squash/routes/alerts.py — Saved-search alert CRUD + auto-evaluate hook.

* ``POST   /api/alerts``        — create a rule
* ``GET    /api/alerts``        — list active rules
* ``GET    /api/alerts/{id}``   — fetch one rule
* ``DELETE /api/alerts/{id}``   — soft-delete (sets active=0)
* ``POST   /api/alerts/{id}/test`` — fire a synthetic delivery so the
  configured webhook can be wired up before any real scan triggers it.

In addition, :func:`evaluate_after_scan` is a tiny helper that the
compliance route calls after a scan lands; it walks every active rule
and POSTs to its configured webhook for any firing.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

from squash.alerts import (
    AlertDeliveryResult,
    AlertRule,
    RISK_RANKS,
    default_store,
    dispatch,
    AlertFiring,
)

alerts_router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class _CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    notify_webhook: str = Field(..., min_length=8, max_length=2048)
    framework: str = "*"
    min_overall_risk: str = "high"
    max_coverage_pct: float | None = Field(None, ge=0.0, le=100.0)
    webhook_secret: str = Field("", max_length=256)

    @field_validator("min_overall_risk")
    @classmethod
    def _validate_risk(cls, v: str) -> str:
        if v.lower() not in RISK_RANKS:
            raise ValueError(
                f"min_overall_risk must be one of {sorted(RISK_RANKS)}",
            )
        return v.lower()


@alerts_router.post("")
async def create_rule(req: _CreateRuleRequest) -> dict[str, Any]:
    store = default_store()
    try:
        rule = store.create(
            name=req.name,
            notify_webhook=req.notify_webhook,
            framework=req.framework,
            min_overall_risk=req.min_overall_risk,
            max_coverage_pct=req.max_coverage_pct,
            webhook_secret=req.webhook_secret,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return rule.to_dict()


@alerts_router.get("")
async def list_rules(active_only: bool = True) -> dict[str, Any]:
    store = default_store()
    rules = store.list(active_only=active_only)
    return {"count": len(rules), "rules": [r.to_dict() for r in rules]}


@alerts_router.get("/{rule_id}")
async def get_rule(rule_id: str) -> dict[str, Any]:
    rule = default_store().get(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule.to_dict()


@alerts_router.delete("/{rule_id}")
async def delete_rule(rule_id: str) -> dict[str, Any]:
    deleted = default_store().delete(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"deleted": True, "id": rule_id}


@alerts_router.post("/{rule_id}/test")
async def test_rule(rule_id: str) -> dict[str, Any]:
    rule = default_store().get(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    # Fire a synthetic delivery so callers can confirm their webhook is reachable.
    firing = AlertFiring(
        rule=rule,
        report_overall_risk="high",
        report_overall_coverage_pct=42.0,
        framework=rule.framework if rule.framework != "*" else "SOC2",
        framework_coverage_pct=42.0,
        framework_gap_count=3,
    )
    result = dispatch(firing)
    return {"firing": firing.to_dict(), "delivery": result.to_dict()}


# ──────────────────────────────────────────────────────────────────────────────
# Hook used by /api/compliance/scan after recording the trend rows.
# ──────────────────────────────────────────────────────────────────────────────


def evaluate_after_scan(report: Any) -> list[dict[str, Any]]:
    """Walk every active rule, fire any matches, POST their payloads.

    Returns a list of delivery-result dicts so the scan endpoint can
    surface ``alerts_fired`` in its response body. Best-effort: any
    exception (including DB unavailability) is swallowed because alert
    fan-out must never block a scan.
    """
    try:
        results: list[AlertDeliveryResult] = (
            default_store().evaluate_and_dispatch(report)
        )
    except Exception:  # noqa: BLE001
        return []
    return [r.to_dict() for r in results]


__all__ = ["alerts_router", "evaluate_after_scan"]
