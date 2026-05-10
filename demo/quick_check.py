"""demo/quick_check.py — Lightweight policy compliance heuristic.

Used by the demo's `/quick-check` endpoint and shareable `/r/{hash}` permalinks.
Pure-Python, stdlib-only — no external dependencies, no network calls.

The check is a keyword-anchored heuristic that scores a free-text policy
against five compliance dimensions:

- ``gdpr``      — EU GDPR alignment markers (lawful basis, DSR, breach notice)
- ``ccpa``      — CCPA / CPRA markers (Do Not Sell, opt-out, categories)
- ``soc2``      — SOC 2 Trust Services Criteria markers (encryption, MFA, audit)
- ``ai_use``    — AI-specific safety markers (transparency, prohibited uses)
- ``retention`` — Data minimisation / retention markers

Each dimension contributes a sub-score in [0, 1]. The overall score is the
weighted mean. The verdict is derived from the score.

This is intentionally not the full ``squash.policy`` engine — it operates on
free-form prose, not structured SBOM JSON. It exists so the demo lets a user
paste any policy and get a verdict in seconds.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Dimension:
    key: str
    label: str
    weight: float
    must_have: tuple[str, ...]
    nice_to_have: tuple[str, ...] = ()


_DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        key="gdpr",
        label="GDPR",
        weight=0.25,
        must_have=(
            r"lawful\s+basis|article\s*6|legitimate\s+interest|consent",
            r"data\s+subject|right\s+to\s+(access|erasure|rectif|port|object)|dpo|data\s+protection\s+officer",
            r"breach\s+notif|72\s*hours|supervisory\s+authority",
        ),
        nice_to_have=(
            r"article\s*30|record\s+of\s+processing",
            r"standard\s+contractual\s+clauses|adequacy\s+decision",
            r"pseudonym|minimi[sz]ation",
        ),
    ),
    Dimension(
        key="ccpa",
        label="CCPA",
        weight=0.20,
        must_have=(
            r"california|ccpa|cpra",
            r"do\s+not\s+sell|opt[-\s]?out|right\s+to\s+(know|delete|correct)",
            r"categories\s+of\s+personal\s+information|sensitive\s+personal",
        ),
        nice_to_have=(
            r"authori[sz]ed\s+agent",
            r"non[-\s]?discriminat",
            r"cross[-\s]?context\s+behavioural",
        ),
    ),
    Dimension(
        key="soc2",
        label="SOC 2",
        weight=0.20,
        must_have=(
            r"encrypt(ion|ed).*(rest|transit)|aes[-\s]?256|tls\s*1\.[23]",
            r"access\s+control|rbac|role[-\s]?based|mfa|multi[-\s]?factor",
            r"audit|monitor|incident\s+response|sla",
        ),
        nice_to_have=(
            r"sso|single\s+sign[-\s]?on|hardware\s+key",
            r"soc\s*2|trust\s+services\s+criteria|cc6|cc7",
            r"disaster\s+recovery|business\s+continuity",
        ),
    ),
    Dimension(
        key="ai_use",
        label="AI safety",
        weight=0.20,
        must_have=(
            r"prohibited\s+use|acceptable\s+use|misuse",
            r"transparency|disclos|ai[-\s]?generated|c2pa",
            r"human\s+oversight|meaningful\s+human|risk\s+management",
        ),
        nice_to_have=(
            r"eu\s+ai\s+act|annex\s+iii|high[-\s]?risk",
            r"bias|fairness|discriminat",
            r"red[-\s]?team|adversarial",
        ),
    ),
    Dimension(
        key="retention",
        label="Retention",
        weight=0.15,
        must_have=(
            r"retention|retain(ed)?\s+for|delete\s+after|purge",
            r"\d+\s*(day|month|year)s?",
        ),
        nice_to_have=(
            r"minimi[sz]ation|only\s+what.*necessary|strictly\s+necessary",
            r"review(ed)?\s+annually|reviewed\s+quarterly",
        ),
    ),
)


# Phrases that always reduce the score — vague hedges and red flags.
_RED_FLAGS: tuple[tuple[str, str, float], ...] = (
    (r"may\s+share.*(any|appropriate|reason)", "broad sharing carve-out", 0.08),
    (r"may\s+update.*without\s+notice", "silent policy updates", 0.08),
    (r"as\s+long\s+as\s+(we|it)\s+(feel|deem|think)", "indefinite retention", 0.08),
    (r"reasonable\s+steps", "vague security language", 0.04),
    (r"cannot\s+guarantee", "explicit no-guarantee", 0.04),
    (r"continued\s+use.*constitutes\s+(your\s+)?acceptance", "forced opt-in", 0.05),
)


@dataclass
class DimensionScore:
    key: str
    label: str
    score: float
    must_hits: int
    must_total: int
    nice_hits: int


@dataclass
class QuickCheckResult:
    verdict: str  # "pass" | "warn" | "fail"
    score: int  # 0..100
    summary: str
    dimensions: list[DimensionScore]
    red_flags: list[str]
    word_count: int
    elapsed_ms: float
    sha256: str
    snippet: str
    timestamp: str
    framework_badges: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "summary": self.summary,
            "dimensions": [d.__dict__ for d in self.dimensions],
            "red_flags": self.red_flags,
            "word_count": self.word_count,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "sha256": self.sha256,
            "snippet": self.snippet,
            "timestamp": self.timestamp,
            "framework_badges": self.framework_badges,
        }


def _count_hits(patterns: tuple[str, ...], text: str) -> int:
    """Return how many of `patterns` match anywhere in `text` (case-insensitive)."""
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))


def quick_check_policy(text: str) -> QuickCheckResult:
    """Score a free-text policy against the five built-in dimensions.

    Returns a :class:`QuickCheckResult` with a 0–100 score, a categorical
    verdict (``pass`` / ``warn`` / ``fail``), per-dimension scores, and a
    deterministic SHA-256 digest of the input that can be used as a permalink.

    The function is pure: same input → identical output (the timestamp and
    elapsed_ms are filled at call time, but the signed score and digest are
    deterministic on the policy text alone).
    """
    if not isinstance(text, str):
        raise TypeError("policy text must be a string")

    t0 = time.perf_counter()
    cleaned = text.strip()
    if not cleaned:
        return QuickCheckResult(
            verdict="fail",
            score=0,
            summary="Empty policy — nothing to evaluate.",
            dimensions=[
                DimensionScore(d.key, d.label, 0.0, 0, len(d.must_have), 0)
                for d in _DIMENSIONS
            ],
            red_flags=[],
            word_count=0,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
            sha256=hashlib.sha256(b"").hexdigest(),
            snippet="",
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            framework_badges={d.label: False for d in _DIMENSIONS},
        )

    word_count = len(cleaned.split())
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    snippet = cleaned[:280] + ("…" if len(cleaned) > 280 else "")

    dim_scores: list[DimensionScore] = []
    weighted_total = 0.0
    badges: dict[str, bool] = {}
    for d in _DIMENSIONS:
        must_hits = _count_hits(d.must_have, cleaned)
        nice_hits = _count_hits(d.nice_to_have, cleaned) if d.nice_to_have else 0
        must_score = must_hits / max(1, len(d.must_have))
        bonus = (nice_hits / max(1, len(d.nice_to_have))) * 0.25 if d.nice_to_have else 0.0
        score = min(1.0, must_score + bonus)
        dim_scores.append(DimensionScore(d.key, d.label, round(score, 3), must_hits, len(d.must_have), nice_hits))
        weighted_total += score * d.weight
        badges[d.label] = must_score >= 0.66

    red_flag_labels: list[str] = []
    penalty = 0.0
    for pattern, label, weight in _RED_FLAGS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            red_flag_labels.append(label)
            penalty += weight

    raw = max(0.0, min(1.0, weighted_total - penalty))
    score_int = int(round(raw * 100))

    if score_int >= 60:
        verdict = "pass"
    elif score_int >= 30:
        verdict = "warn"
    else:
        verdict = "fail"

    covered = [d.label for d in dim_scores if d.must_hits >= max(1, d.must_total // 2)]
    missing = [d.label for d in dim_scores if d.must_hits == 0]
    if verdict == "pass":
        summary = "Solid coverage across " + ", ".join(covered) + "."
    elif verdict == "warn":
        if missing:
            summary = "Partial coverage — gaps in " + ", ".join(missing) + "."
        else:
            summary = "Coverage thin in places — review per-dimension scores."
    else:
        if not covered:
            summary = "Vague or boilerplate — no dimension has meaningful coverage."
        else:
            summary = "Weak overall — only " + ", ".join(covered) + " has any signal."

    if red_flag_labels:
        summary += " Red flags: " + ", ".join(red_flag_labels) + "."

    elapsed = (time.perf_counter() - t0) * 1000
    return QuickCheckResult(
        verdict=verdict,
        score=score_int,
        summary=summary,
        dimensions=dim_scores,
        red_flags=red_flag_labels,
        word_count=word_count,
        elapsed_ms=elapsed,
        sha256=digest,
        snippet=snippet,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        framework_badges=badges,
    )
