"""squash/routes/trends.py — Risk-exposure trend persistence + endpoint.

Append-only SQLite store at ``~/.squash/analysis_history.db`` (override
with ``SQUASH_ANALYSIS_HISTORY_PATH``).  Each compliance scan writes one
row per framework plus one aggregate row keyed under the framework
``"*"``.

Routes (mounted by :mod:`squash.api`)
-------------------------------------
* ``GET  /api/trends/risk?days=30&framework=SOC2`` — daily aggregates over
  the last *N* days plus a trend direction (``improving`` /
  ``stable`` / ``degrading``) and a period summary.
* ``POST /api/analyses`` — explicit recorder used by external integrations
  and by tests.  ``POST /api/compliance/scan`` records implicitly.
"""

from __future__ import annotations

import datetime
import logging
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

_DEFAULT_PATH = Path(
    os.environ.get("SQUASH_ANALYSIS_HISTORY_PATH")
    or str(Path.home() / ".squash" / "analysis_history.db")
)
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_active_path: Path | None = None


_SCHEMA = """\
CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    doc_hash        TEXT NOT NULL,
    risk_score      REAL NOT NULL,
    framework       TEXT NOT NULL,
    clause_count    INTEGER NOT NULL,
    high_risk_count INTEGER NOT NULL,
    overall_risk    TEXT NOT NULL DEFAULT 'unknown',
    doc_label       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_analyses_ts        ON analyses(timestamp);
CREATE INDEX IF NOT EXISTS idx_analyses_framework ON analyses(framework);
CREATE INDEX IF NOT EXISTS idx_analyses_doc_hash  ON analyses(doc_hash);
"""


def _get_conn() -> sqlite3.Connection:
    global _conn, _active_path
    with _lock:
        target = Path(
            os.environ.get("SQUASH_ANALYSIS_HISTORY_PATH")
            or str(_DEFAULT_PATH)
        )
        if _conn is None or _active_path != target:
            target.parent.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(str(target), check_same_thread=False)
            _conn.executescript(_SCHEMA)
            _conn.commit()
            _active_path = target
        return _conn


def reset_store_for_tests(path: str | os.PathLike[str] | None = None) -> None:
    """Test helper — close any open connection and optionally pin a new path."""
    global _conn, _active_path
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
        _conn = None
        _active_path = None
        if path is not None:
            os.environ["SQUASH_ANALYSIS_HISTORY_PATH"] = str(path)


def record_analysis(
    *,
    doc_hash: str,
    risk_score: float,
    framework: str,
    clause_count: int,
    high_risk_count: int,
    overall_risk: str = "unknown",
    doc_label: str = "",
    timestamp: str | None = None,
) -> str:
    """Insert one analysis row. Returns the generated row ID."""
    ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
    row_id = uuid.uuid4().hex
    conn = _get_conn()
    with _lock:
        conn.execute(
            "INSERT INTO analyses "
            "(id, timestamp, doc_hash, risk_score, framework, clause_count, "
            "high_risk_count, overall_risk, doc_label) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                row_id, ts, doc_hash, float(risk_score), framework,
                int(clause_count), int(high_risk_count),
                overall_risk, doc_label,
            ),
        )
        conn.commit()
    return row_id


# ──────────────────────────────────────────────────────────────────────────────
# Router
# ──────────────────────────────────────────────────────────────────────────────


trends_router = APIRouter(prefix="/api", tags=["trends"])


class _AnalysisRecordRequest(BaseModel):
    doc_hash: str = Field(..., min_length=4, max_length=128)
    risk_score: float = Field(..., ge=0.0, le=100.0)
    framework: str = Field(..., min_length=1, max_length=64)
    clause_count: int = Field(..., ge=0, le=100000)
    high_risk_count: int = Field(..., ge=0, le=100000)
    overall_risk: str = Field("unknown", min_length=1, max_length=32)
    doc_label: str = Field("", max_length=128)
    timestamp: str = ""


@trends_router.post("/analyses")
async def post_analysis(req: _AnalysisRecordRequest) -> dict[str, Any]:
    """Stub recorder — explicit insert path used by external integrations."""
    row_id = record_analysis(
        doc_hash=req.doc_hash,
        risk_score=req.risk_score,
        framework=req.framework,
        clause_count=req.clause_count,
        high_risk_count=req.high_risk_count,
        overall_risk=req.overall_risk,
        doc_label=req.doc_label,
        timestamp=req.timestamp or None,
    )
    return {"id": row_id, "recorded": True}


@trends_router.get("/trends/risk")
async def get_risk_trend(
    days: int = 30,
    framework: str | None = None,
) -> dict[str, Any]:
    """Return daily-aggregated risk trend over the last *days* days."""
    if days < 1 or days > 365:
        raise HTTPException(
            status_code=400, detail="days must be in 1..365",
        )

    conn = _get_conn()
    now = datetime.datetime.now(datetime.timezone.utc)
    # "last N days" is inclusive of today, so we want N buckets total:
    # today-(N-1), today-(N-2), …, today.
    since = now - datetime.timedelta(days=max(days - 1, 0))
    since_iso = since.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    fw_clause = ""
    params: list[Any] = [since_iso]
    if framework:
        fw_clause = " AND framework = ?"
        params.append(framework)

    with _lock:
        rows = conn.execute(
            "SELECT timestamp, risk_score, high_risk_count, clause_count, doc_hash "
            f"FROM analyses WHERE timestamp >= ?{fw_clause} ORDER BY timestamp ASC",
            params,
        ).fetchall()

    # Bucket by UTC date
    buckets: dict[str, dict[str, Any]] = {}
    for ts, risk_score, high_risk_count, clause_count, doc_hash in rows:
        day = ts[:10]
        b = buckets.setdefault(day, {
            "date": day,
            "_risk_sum": 0.0,
            "doc_count": 0,
            "_high_risk_doc_count": 0,
            "_unique_docs": set(),
        })
        b["_risk_sum"] += float(risk_score)
        b["doc_count"] += 1
        b["_unique_docs"].add(doc_hash)
        if int(high_risk_count) >= 3:
            b["_high_risk_doc_count"] += 1

    data_points: list[dict[str, Any]] = []
    # Fill every day in the window — inclusive of both endpoints — so the
    # client can chart gaps as zero and today's scans are always visible.
    span_days = (now.date() - since.date()).days + 1
    for d_offset in range(span_days):
        d = (since.date() + datetime.timedelta(days=d_offset)).isoformat()
        if d in buckets:
            b = buckets[d]
            avg = b["_risk_sum"] / b["doc_count"]
            high_pct = (
                (b["_high_risk_doc_count"] / b["doc_count"]) * 100.0
                if b["doc_count"] else 0.0
            )
            data_points.append({
                "date": d,
                "avg_risk_score": round(avg, 2),
                "doc_count": b["doc_count"],
                "unique_docs": len(b["_unique_docs"]),
                "high_risk_pct": round(high_pct, 2),
            })
        else:
            data_points.append({
                "date": d,
                "avg_risk_score": 0.0,
                "doc_count": 0,
                "unique_docs": 0,
                "high_risk_pct": 0.0,
            })

    direction = _trend_direction(data_points)
    period_summary = _period_summary(data_points)

    return {
        "days": days,
        "framework": framework or "*",
        "data_points": data_points,
        "trend_direction": direction,
        "period_summary": period_summary,
    }


def _trend_direction(points: list[dict[str, Any]]) -> str:
    """Compare first-half mean risk vs second-half mean risk.

    A *rising* risk score under our scoring convention (risk_score = coverage_pct)
    means coverage is going up, which is *improving* compliance.  Inverse for
    falling.  The threshold is 5 percentage points to ignore noise.
    """
    populated = [p for p in points if p["doc_count"] > 0]
    if len(populated) < 4:
        return "stable"
    mid = len(populated) // 2
    first_half = sum(p["avg_risk_score"] for p in populated[:mid]) / max(1, mid)
    second_half = sum(p["avg_risk_score"] for p in populated[mid:]) / max(1, len(populated) - mid)
    delta = second_half - first_half
    if delta > 5.0:
        return "improving"
    if delta < -5.0:
        return "degrading"
    return "stable"


def _period_summary(points: list[dict[str, Any]]) -> dict[str, Any]:
    populated = [p for p in points if p["doc_count"] > 0]
    if not populated:
        return {
            "total_scans": 0,
            "unique_docs": 0,
            "avg_risk_score": 0.0,
            "min_risk_score": 0.0,
            "max_risk_score": 0.0,
            "high_risk_days": 0,
        }
    total_scans = sum(p["doc_count"] for p in populated)
    risks = [p["avg_risk_score"] for p in populated]
    high_days = sum(1 for p in populated if p["high_risk_pct"] >= 50.0)
    unique_docs = sum(p.get("unique_docs", 0) for p in populated)
    return {
        "total_scans": total_scans,
        "unique_docs": unique_docs,
        "avg_risk_score": round(sum(risks) / len(risks), 2),
        "min_risk_score": round(min(risks), 2),
        "max_risk_score": round(max(risks), 2),
        "high_risk_days": high_days,
    }


__all__ = ["trends_router", "record_analysis", "reset_store_for_tests"]
