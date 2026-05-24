"""squash/alerts/rules.py — Saved-search alert rules with webhook fan-out.

A rule is a tiny declarative predicate over a compliance scan report:

    {
        "name": "HIPAA high-risk",
        "framework": "HIPAA",      # or "*" to match any
        "min_overall_risk": "high",  # one of low/medium/high/critical
        "max_coverage_pct": 60.0,    # optional ceiling on coverage
        "notify_webhook": "https://hooks.acme.example/squash"
    }

When :func:`evaluate` is called with a fresh report it returns one
:class:`AlertFiring` per matched rule. The :class:`AlertStore` then
POSTs each firing's payload to the rule's ``notify_webhook`` (HMAC-SHA256
signed) and records the dispatch outcome.

Pure stdlib. SQLite-backed. Webhook delivery uses ``urllib.request``.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

log = logging.getLogger(__name__)

__all__ = [
    "AlertDeliveryResult",
    "AlertFiring",
    "AlertRule",
    "AlertStore",
    "RISK_RANKS",
    "default_store",
    "evaluate",
    "reset_store_for_tests",
]


# Higher == worse. A rule's ``min_overall_risk`` fires when the report's
# overall_risk has rank >= this value.
RISK_RANKS: dict[str, int] = {
    "low": 0, "medium": 1, "high": 2, "critical": 3,
}

_DEFAULT_PATH = Path(
    os.environ.get("SQUASH_ALERT_STORE_PATH")
    or str(Path.home() / ".squash" / "alert_rules.db")
)

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS alert_rules (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    framework          TEXT NOT NULL DEFAULT '*',
    min_overall_risk   TEXT NOT NULL DEFAULT 'high',
    max_coverage_pct   REAL,
    notify_webhook     TEXT NOT NULL,
    webhook_secret     TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    last_fired_at      TEXT,
    fire_count         INTEGER NOT NULL DEFAULT 0,
    active             INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_alerts_active    ON alert_rules(active);
CREATE INDEX IF NOT EXISTS idx_alerts_framework ON alert_rules(framework);
"""


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class AlertRule:
    id: str = ""
    name: str = ""
    framework: str = "*"
    min_overall_risk: str = "high"
    max_coverage_pct: float | None = None
    notify_webhook: str = ""
    webhook_secret: str = ""
    created_at: str = ""
    last_fired_at: str = ""
    fire_count: int = 0
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "framework": self.framework,
            "min_overall_risk": self.min_overall_risk,
            "max_coverage_pct": self.max_coverage_pct,
            "notify_webhook": self.notify_webhook,
            # webhook_secret intentionally redacted from public dict
            "created_at": self.created_at,
            "last_fired_at": self.last_fired_at,
            "fire_count": self.fire_count,
            "active": self.active,
        }


@dataclass
class AlertFiring:
    rule: AlertRule
    report_overall_risk: str
    report_overall_coverage_pct: float
    framework: str
    framework_coverage_pct: float
    framework_gap_count: int
    fired_at: str = field(default_factory=lambda:
                          datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "framework": self.framework,
            "report_overall_risk": self.report_overall_risk,
            "report_overall_coverage_pct": self.report_overall_coverage_pct,
            "framework_coverage_pct": self.framework_coverage_pct,
            "framework_gap_count": self.framework_gap_count,
            "fired_at": self.fired_at,
        }


@dataclass
class AlertDeliveryResult:
    rule_id: str
    webhook: str
    success: bool
    status_code: int | None = None
    duration_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "webhook": self.webhook,
            "success": self.success,
            "status_code": self.status_code,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────────────


def evaluate(rule: AlertRule, report: Any) -> list[AlertFiring]:
    """Decide whether *rule* fires on *report*. Returns 0 or more firings."""
    if not rule.active:
        return []
    try:
        overall_risk = str(getattr(report, "overall_risk", "") or "unknown").lower()
        overall_cov = float(report.overall_coverage_pct())
    except Exception:
        return []

    threshold = RISK_RANKS.get(rule.min_overall_risk.lower(), 99)
    overall_rank = RISK_RANKS.get(overall_risk, -1)
    if overall_rank < threshold:
        return []

    fws = getattr(report, "framework_results", {}) or {}
    candidates: list[tuple[str, Any]] = []
    if rule.framework == "*":
        for fw, fr in fws.items():
            candidates.append((_fw_key(fw), fr))
    else:
        for fw, fr in fws.items():
            if _fw_key(fw) == rule.framework:
                candidates.append((_fw_key(fw), fr))

    out: list[AlertFiring] = []
    for fw_key, fr in candidates:
        cov = float(getattr(fr, "coverage_pct", 0.0))
        if rule.max_coverage_pct is not None and cov > float(rule.max_coverage_pct):
            continue
        gaps = list(getattr(fr, "gaps", []) or [])
        out.append(AlertFiring(
            rule=rule,
            report_overall_risk=overall_risk,
            report_overall_coverage_pct=overall_cov,
            framework=fw_key,
            framework_coverage_pct=cov,
            framework_gap_count=len(gaps),
        ))
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Webhook dispatch
# ──────────────────────────────────────────────────────────────────────────────


def _sign(payload: bytes, secret: str) -> str:
    if not secret:
        return ""
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def dispatch(
    firing: AlertFiring,
    *,
    http_call: Callable[..., tuple[int, str]] | None = None,
    timeout_s: float = 10.0,
) -> AlertDeliveryResult:
    """POST the firing payload to ``firing.rule.notify_webhook``."""
    rule = firing.rule
    payload = json.dumps(firing.to_dict(), sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "squash-alerts/1.0",
        "X-Squash-Event": "compliance.alert",
        "X-Squash-Rule-Id": rule.id,
    }
    sig = _sign(payload, rule.webhook_secret)
    if sig:
        headers["X-Squash-Signature"] = sig

    t0 = time.monotonic()
    if http_call is not None:
        try:
            status, body = http_call(
                rule.notify_webhook, payload=payload, headers=headers,
                timeout_s=timeout_s,
            )
            dur = (time.monotonic() - t0) * 1000
            return AlertDeliveryResult(
                rule_id=rule.id, webhook=rule.notify_webhook,
                success=200 <= status < 300, status_code=status,
                duration_ms=dur, error=("" if 200 <= status < 300
                                        else f"HTTP {status} body={body[:120]!r}"),
            )
        except Exception as exc:  # pragma: no cover — test path uses http_call
            return AlertDeliveryResult(
                rule_id=rule.id, webhook=rule.notify_webhook,
                success=False, duration_ms=(time.monotonic() - t0) * 1000,
                error=f"{type(exc).__name__}: {exc}",
            )

    req = urllib.request.Request(
        rule.notify_webhook, data=payload, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            dur = (time.monotonic() - t0) * 1000
            return AlertDeliveryResult(
                rule_id=rule.id, webhook=rule.notify_webhook,
                success=200 <= resp.status < 300,
                status_code=resp.status, duration_ms=dur,
            )
    except urllib.error.HTTPError as exc:
        return AlertDeliveryResult(
            rule_id=rule.id, webhook=rule.notify_webhook,
            success=False, status_code=exc.code,
            duration_ms=(time.monotonic() - t0) * 1000, error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        return AlertDeliveryResult(
            rule_id=rule.id, webhook=rule.notify_webhook,
            success=False, duration_ms=(time.monotonic() - t0) * 1000,
            error=f"{type(exc).__name__}: {exc}",
        )


# ──────────────────────────────────────────────────────────────────────────────
# AlertStore — SQLite CRUD + evaluate-and-fan-out
# ──────────────────────────────────────────────────────────────────────────────


class AlertStore:
    """Thread-safe SQLite-backed alert rule store."""

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        target = Path(db_path) if db_path else Path(
            os.environ.get("SQUASH_ALERT_STORE_PATH") or str(_DEFAULT_PATH)
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        self._path = target
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(target), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── public api ─────────────────────────────────────────────────────────

    def create(
        self,
        *,
        name: str,
        notify_webhook: str,
        framework: str = "*",
        min_overall_risk: str = "high",
        max_coverage_pct: float | None = None,
        webhook_secret: str = "",
    ) -> AlertRule:
        if not name or not notify_webhook:
            raise ValueError("name and notify_webhook are required")
        risk_key = min_overall_risk.lower()
        if risk_key not in RISK_RANKS:
            raise ValueError(
                f"min_overall_risk must be one of {sorted(RISK_RANKS)}",
            )
        rid = uuid.uuid4().hex
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rule = AlertRule(
            id=rid, name=name, framework=framework,
            min_overall_risk=risk_key,
            max_coverage_pct=max_coverage_pct,
            notify_webhook=notify_webhook,
            webhook_secret=webhook_secret,
            created_at=now,
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO alert_rules (id, name, framework, min_overall_risk, "
                "max_coverage_pct, notify_webhook, webhook_secret, created_at, "
                "active) VALUES (?,?,?,?,?,?,?,?,1)",
                (
                    rid, name, framework, risk_key, max_coverage_pct,
                    notify_webhook, webhook_secret, now,
                ),
            )
            self._conn.commit()
        return rule

    def list(self, *, active_only: bool = True) -> list[AlertRule]:
        q = (
            "SELECT id, name, framework, min_overall_risk, max_coverage_pct, "
            "notify_webhook, webhook_secret, created_at, last_fired_at, "
            "fire_count, active FROM alert_rules"
        )
        params: tuple[Any, ...] = ()
        if active_only:
            q += " WHERE active=1"
        q += " ORDER BY created_at DESC"
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [_row_to_rule(r) for r in rows]

    def get(self, rule_id: str) -> AlertRule | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, name, framework, min_overall_risk, max_coverage_pct, "
                "notify_webhook, webhook_secret, created_at, last_fired_at, "
                "fire_count, active FROM alert_rules WHERE id=?",
                (rule_id,),
            ).fetchone()
        return _row_to_rule(row) if row else None

    def delete(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alert_rules SET active=0 WHERE id=?", (rule_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def evaluate_and_dispatch(
        self,
        report: Any,
        *,
        http_call: Callable[..., tuple[int, str]] | None = None,
    ) -> list[AlertDeliveryResult]:
        """Run every active rule against the report and POST any firings."""
        results: list[AlertDeliveryResult] = []
        for rule in self.list(active_only=True):
            firings = evaluate(rule, report)
            if not firings:
                continue
            for firing in firings:
                res = dispatch(firing, http_call=http_call)
                results.append(res)
            # Record the fact that it fired, regardless of delivery outcome.
            self._touch(rule.id)
        return results

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    # ── internal ───────────────────────────────────────────────────────────

    def _touch(self, rule_id: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE alert_rules SET last_fired_at=?, fire_count=fire_count+1 "
                "WHERE id=?",
                (now, rule_id),
            )
            self._conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────


_singleton: AlertStore | None = None
_singleton_lock = threading.Lock()


def default_store() -> AlertStore:
    """Lazy process-wide singleton over the configured DB path."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AlertStore()
        return _singleton


def reset_store_for_tests(path: str | os.PathLike[str] | None = None) -> None:
    """Test helper — close the singleton and optionally pin a new DB path."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
            _singleton = None
        if path is not None:
            os.environ["SQUASH_ALERT_STORE_PATH"] = str(path)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _row_to_rule(row: tuple[Any, ...]) -> AlertRule:
    return AlertRule(
        id=row[0], name=row[1], framework=row[2],
        min_overall_risk=row[3], max_coverage_pct=row[4],
        notify_webhook=row[5], webhook_secret=row[6],
        created_at=row[7], last_fired_at=row[8] or "",
        fire_count=int(row[9]), active=bool(row[10]),
    )


def _fw_key(fw: Any) -> str:
    v = getattr(fw, "value", None)
    return str(v) if v is not None else str(fw)
