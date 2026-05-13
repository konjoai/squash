"""squash/scan_history.py — Append-only audit trail for quick-check scans.

Every time the public ``POST /quick-check`` endpoint runs, the record
lands here:

* `timestamp`   — ISO8601 UTC
* `input_hash`  — SHA-256 of the trimmed input text (first 16 hex chars exposed)
* `framework`   — the clause library used
* `verdict`     — pass / warn / fail
* `score`       — 0-100
* `share_hash`  — if the caller asked for a share permalink, mirror it here
* `text_length` — character count, for transparency

The store is **append-only**. There is no public ``delete()``; rows can
only be evicted by the bounded-capacity FIFO sweep (default 100 000 rows).
The on-disk format is SQLite so the data survives process restarts and
remains queryable with standard tools; access is locked for thread
safety. The endpoint exposes a paginated read view and a sparkline
helper for the demo's "recent scans" panel.

Public API
----------
* :class:`ScanHistory` — `record()`, `list()`, `pass_rate_sparkline()`, `stats()`.
* :func:`global_history` — lazy, process-wide singleton (overridable for tests).
"""

from __future__ import annotations

import datetime
import hashlib
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


_DEFAULT_PATH = Path(os.environ.get("SQUASH_SCAN_HISTORY_PATH") or
                     str(Path.home() / ".squash" / "scan_history.db"))
_DEFAULT_CAPACITY = 100_000


@dataclass(frozen=True)
class ScanRecord:
    timestamp: str
    input_hash: str           # 16-hex prefix of SHA-256(trimmed_text)
    framework: str
    verdict: str
    score: int
    share_hash: str = ""
    text_length: int = 0
    sub_scores: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "input_hash": self.input_hash,
            "framework": self.framework,
            "verdict": self.verdict,
            "score": self.score,
            "share_hash": self.share_hash,
            "text_length": self.text_length,
            "sub_scores": dict(self.sub_scores),
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    input_hash  TEXT NOT NULL,
    framework   TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    share_hash  TEXT DEFAULT '',
    text_length INTEGER DEFAULT 0,
    sub_scores  TEXT DEFAULT ''           -- JSON dict
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_share ON scans(share_hash);
"""


class ScanHistory:
    """Thread-safe, append-only scan ledger backed by SQLite."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        capacity: int = _DEFAULT_CAPACITY,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._path = (
            ":memory:" if path == ":memory:"
            else str(Path(path).expanduser()) if path is not None
            else str(_DEFAULT_PATH)
        )
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False — we guard with our own lock.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    # ── recording ──────────────────────────────────────────────────────────

    def record(
        self,
        *,
        text: str,
        framework: str,
        verdict: str,
        score: int,
        share_hash: str = "",
        sub_scores: dict[str, int] | None = None,
        timestamp: str | None = None,
    ) -> ScanRecord:
        """Append a scan to the ledger and return the canonical record."""

        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if not isinstance(framework, str) or not framework:
            raise ValueError("framework must be a non-empty string")
        if verdict not in {"pass", "warn", "fail"}:
            raise ValueError(f"unknown verdict: {verdict!r}")
        if not (0 <= int(score) <= 100):
            raise ValueError("score must be in 0..100")

        trimmed = text.strip()
        digest = hashlib.sha256(trimmed.encode("utf-8")).hexdigest()[:16]
        ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        )
        sub_scores = dict(sub_scores or {})
        import json
        sub_json = json.dumps(sub_scores, sort_keys=True, separators=(",", ":"))

        record = ScanRecord(
            timestamp=ts,
            input_hash=digest,
            framework=framework,
            verdict=verdict,
            score=int(score),
            share_hash=share_hash,
            text_length=len(trimmed),
            sub_scores=sub_scores,
        )

        with self._lock:
            self._conn.execute(
                "INSERT INTO scans (timestamp, input_hash, framework, verdict, "
                "score, share_hash, text_length, sub_scores) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, digest, framework, verdict, int(score),
                 share_hash, len(trimmed), sub_json),
            )
            # FIFO eviction once over capacity (cheap because of the
            # AUTOINCREMENT id and the timestamp index).
            cur = self._conn.execute("SELECT COUNT(*) FROM scans")
            total = cur.fetchone()[0]
            if total > self._capacity:
                excess = total - self._capacity
                self._conn.execute(
                    "DELETE FROM scans WHERE id IN ("
                    "  SELECT id FROM scans ORDER BY id ASC LIMIT ?"
                    ")",
                    (excess,),
                )
            self._conn.commit()
        return record

    # ── reading ───────────────────────────────────────────────────────────

    def list(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        framework: str | None = None,
        verdict: str | None = None,
    ) -> list[ScanRecord]:
        """Return the most recent records, newest first."""

        if limit < 1:
            raise ValueError("limit must be >= 1")
        if limit > 500:
            limit = 500
        if offset < 0:
            raise ValueError("offset must be >= 0")

        where: list[str] = []
        params: list[Any] = []
        if framework:
            where.append("framework = ?")
            params.append(framework)
        if verdict:
            if verdict not in {"pass", "warn", "fail"}:
                raise ValueError(f"unknown verdict filter: {verdict!r}")
            where.append("verdict = ?")
            params.append(verdict)
        sql = "SELECT timestamp, input_hash, framework, verdict, score, " \
              "share_hash, text_length, sub_scores FROM scans"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_record(r) for r in rows]

    def count(
        self,
        *,
        framework: str | None = None,
        verdict: str | None = None,
    ) -> int:
        where: list[str] = []
        params: list[Any] = []
        if framework:
            where.append("framework = ?"); params.append(framework)
        if verdict:
            where.append("verdict = ?"); params.append(verdict)
        sql = "SELECT COUNT(*) FROM scans"
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self._lock:
            return int(self._conn.execute(sql, params).fetchone()[0])

    # ── derived metrics ────────────────────────────────────────────────────

    def pass_rate_sparkline(
        self,
        *,
        points: int = 24,
        bucket_seconds: int = 3600,
        framework: str | None = None,
    ) -> list[float]:
        """Return a list of length *points* with the pass rate per bucket.

        Buckets are equal-width and aligned to *now*: index `-1` is the
        most recent bucket. Each entry is a float in `[0.0, 1.0]` — `0.0`
        for an empty bucket. The demo UI renders this as a polyline.
        """

        if points < 1:
            raise ValueError("points must be >= 1")
        if bucket_seconds < 1:
            raise ValueError("bucket_seconds must be >= 1")
        now = datetime.datetime.now(datetime.timezone.utc)
        boundaries: list[datetime.datetime] = [
            now - datetime.timedelta(seconds=bucket_seconds * (points - i))
            for i in range(points + 1)
        ]
        buckets: list[tuple[int, int]] = [(0, 0)] * points

        where = ["timestamp >= ?"]
        params: list[Any] = [boundaries[0].isoformat(timespec="seconds")]
        if framework:
            where.append("framework = ?")
            params.append(framework)
        sql = (
            "SELECT timestamp, verdict FROM scans WHERE "
            + " AND ".join(where)
            + " ORDER BY timestamp ASC"
        )
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        for ts_str, verdict in rows:
            try:
                ts = datetime.datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue
            # find bucket index — linear search since `points` is small (~24)
            idx = -1
            for i in range(points):
                if boundaries[i] <= ts < boundaries[i + 1]:
                    idx = i
                    break
            if idx < 0:
                continue
            passed, total = buckets[idx]
            buckets[idx] = (passed + (1 if verdict == "pass" else 0), total + 1)

        return [
            round(p / t, 4) if t else 0.0
            for (p, t) in buckets
        ]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = int(self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
            by_verdict = {
                row[0]: int(row[1])
                for row in self._conn.execute(
                    "SELECT verdict, COUNT(*) FROM scans GROUP BY verdict"
                ).fetchall()
            }
            avg = self._conn.execute(
                "SELECT AVG(score) FROM scans"
            ).fetchone()[0]
        return {
            "total": total,
            "by_verdict": by_verdict,
            "avg_score": round(float(avg), 2) if avg is not None else 0.0,
            "capacity": self._capacity,
        }

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_record(row: Iterable[Any]) -> ScanRecord:
        import json
        ts, ih, fw, v, sc, sh, tl, sub = row
        try:
            parsed = json.loads(sub) if sub else {}
            if not isinstance(parsed, dict):
                parsed = {}
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        return ScanRecord(
            timestamp=str(ts), input_hash=str(ih),
            framework=str(fw), verdict=str(v), score=int(sc),
            share_hash=str(sh or ""), text_length=int(tl or 0),
            sub_scores=parsed,
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton (lazy + overridable for tests)
# ──────────────────────────────────────────────────────────────────────────────

_SINGLETON: ScanHistory | None = None
_SINGLETON_LOCK = threading.Lock()


def global_history() -> ScanHistory:
    """Process-wide :class:`ScanHistory` (lazy-initialised)."""

    global _SINGLETON
    if _SINGLETON is not None:
        return _SINGLETON
    with _SINGLETON_LOCK:
        if _SINGLETON is None:
            _SINGLETON = ScanHistory()
    return _SINGLETON


def reset_global_history(history: ScanHistory | None = None) -> None:
    """Replace the singleton — used in tests."""

    global _SINGLETON
    with _SINGLETON_LOCK:
        if _SINGLETON is not None and _SINGLETON is not history:
            try:
                _SINGLETON.close()
            except Exception:  # noqa: BLE001
                pass
        _SINGLETON = history


__all__ = [
    "ScanHistory",
    "ScanRecord",
    "global_history",
    "reset_global_history",
]
