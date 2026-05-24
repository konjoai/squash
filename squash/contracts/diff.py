"""squash/contracts/diff.py — Contract redline / structural diff.

Compares two contract versions (as clause lists) and returns a structured
diff: which clauses were added, which were removed, which were modified
(with a similarity score), and — when the caller passes both sides
through the multi-framework scanner — how the aggregate risk shifted.

Why this exists
---------------
Manual contract negotiation today still pastes two Word files into a
table column-by-column. This module collapses that into one function
call and gives downstream UIs the structured payload they need to render
a tracked-changes view in milliseconds.

Algorithm
---------
1. Compute TF-IDF vectors for every clause on each side using the
   shared helpers from :mod:`squash.analysis.clustering`.
2. Greedy bipartite match: walk old clauses, find the most similar
   unused new clause. If similarity ≥ ``match_threshold`` (default 0.95)
   it's *unchanged*; in ``[modified_threshold, match_threshold)`` it's
   *modified*; below ``modified_threshold`` (default 0.45) the clauses
   are too different to consider a match — the old clause is *removed*
   and the new one stays in the pool as a candidate *added*.
3. Anything left over after the pass is added (new side) or removed
   (old side).

Risk delta
----------
:meth:`ContractDiff.with_risk_delta` accepts two
:class:`squash.compliance.ComplianceReport` instances and computes
``new.overall_coverage_pct() - old.overall_coverage_pct()``. A positive
delta means the new version is *more compliant* (covers more
requirements); the per-framework deltas are also recorded.

Pure stdlib. No external NLP dependency.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from squash.analysis.clustering import _STOPWORDS, _cosine, _l2_normalize


# Diff-specific tokenizer: keeps digits (deadlines, dollar amounts, percentages)
# because numeric edits are the most common contract change. The clustering
# tokenizer intentionally drops them so cluster centroids don't surface "30"
# as a topic term.
_DIFF_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-'][a-z0-9]+)*|\$?\d+(?:[.,]\d+)?%?")


def _diff_tokenize(text: str) -> list[str]:
    if not text:
        return []
    return [
        t for t in _DIFF_TOKEN_RE.findall(text.lower())
        if len(t) >= 1 and t not in _STOPWORDS
    ]

__all__ = [
    "ChangeKind",
    "ClauseChange",
    "ContractDiff",
    "ContractDiffer",
    "diff_contracts",
]


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────


class ChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class ClauseChange:
    kind: ChangeKind
    old_index: int | None = None      # None for ADDED
    new_index: int | None = None      # None for REMOVED
    old_text: str = ""
    new_text: str = ""
    similarity: float = 0.0           # 1.0 for UNCHANGED, 0.0 for ADDED/REMOVED
    diff_terms_added: list[str] = field(default_factory=list)
    diff_terms_removed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "old_index": self.old_index,
            "new_index": self.new_index,
            "old_text": self.old_text,
            "new_text": self.new_text,
            "similarity": round(self.similarity, 4),
            "diff_terms_added": list(self.diff_terms_added),
            "diff_terms_removed": list(self.diff_terms_removed),
        }


@dataclass
class ContractDiff:
    added: list[ClauseChange] = field(default_factory=list)
    removed: list[ClauseChange] = field(default_factory=list)
    modified: list[ClauseChange] = field(default_factory=list)
    unchanged: list[ClauseChange] = field(default_factory=list)
    old_clause_count: int = 0
    new_clause_count: int = 0
    risk_delta: dict[str, Any] | None = None     # populated by with_risk_delta

    @property
    def all_changes(self) -> list[ClauseChange]:
        return self.added + self.removed + self.modified + self.unchanged

    def summary(self) -> dict[str, int]:
        return {
            "old_clause_count": self.old_clause_count,
            "new_clause_count": self.new_clause_count,
            "added":     len(self.added),
            "removed":   len(self.removed),
            "modified":  len(self.modified),
            "unchanged": len(self.unchanged),
        }

    def with_risk_delta(
        self,
        old_report: Any | None,
        new_report: Any | None,
    ) -> "ContractDiff":
        """Attach an overall + per-framework risk delta computed from two
        :class:`squash.compliance.ComplianceReport` instances.

        The reports are duck-typed so callers don't need to import the
        compliance module to use the differ — only that each report exposes
        ``overall_coverage_pct() -> float`` and a ``framework_results`` map
        whose values expose ``.coverage_pct`` and (optionally)
        ``.framework.value``.
        """
        if old_report is None or new_report is None:
            self.risk_delta = None
            return self

        try:
            old_overall = float(old_report.overall_coverage_pct())
            new_overall = float(new_report.overall_coverage_pct())
        except Exception:
            self.risk_delta = None
            return self

        per_framework: dict[str, dict[str, float]] = {}
        old_fws = getattr(old_report, "framework_results", {}) or {}
        new_fws = getattr(new_report, "framework_results", {}) or {}
        for fw in set(_keys(old_fws)) | set(_keys(new_fws)):
            old_cov = _coverage(old_fws.get(fw))
            new_cov = _coverage(new_fws.get(fw))
            per_framework[str(_fw_key(fw))] = {
                "old_coverage_pct": round(old_cov, 2),
                "new_coverage_pct": round(new_cov, 2),
                "delta_pct":        round(new_cov - old_cov, 2),
            }

        self.risk_delta = {
            "old_overall_coverage_pct": round(old_overall, 2),
            "new_overall_coverage_pct": round(new_overall, 2),
            "delta_pct": round(new_overall - old_overall, 2),
            "direction": _direction(new_overall - old_overall),
            "per_framework": per_framework,
        }
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "added":     [c.to_dict() for c in self.added],
            "removed":   [c.to_dict() for c in self.removed],
            "modified":  [c.to_dict() for c in self.modified],
            "unchanged": [c.to_dict() for c in self.unchanged],
            "risk_delta": self.risk_delta,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Differ
# ──────────────────────────────────────────────────────────────────────────────


class ContractDiffer:
    """Compare two contract versions clause-by-clause."""

    def __init__(
        self,
        *,
        match_threshold: float = 0.95,
        modified_threshold: float = 0.45,
    ) -> None:
        if not 0.0 < modified_threshold < match_threshold <= 1.0:
            raise ValueError(
                "thresholds must satisfy 0 < modified_threshold < "
                "match_threshold <= 1"
            )
        self._match = match_threshold
        self._modified = modified_threshold

    def diff(self, old: list[str], new: list[str]) -> ContractDiff:
        if not isinstance(old, list) or any(not isinstance(c, str) for c in old):
            raise TypeError("old must be list[str]")
        if not isinstance(new, list) or any(not isinstance(c, str) for c in new):
            raise TypeError("new must be list[str]")

        old_clean = [c.strip() for c in old if c and c.strip()]
        new_clean = [c.strip() for c in new if c and c.strip()]
        old_vectors, old_tokens = self._vectorise(old_clean)
        new_vectors, new_tokens = self._vectorise(new_clean)

        report = ContractDiff(
            old_clause_count=len(old_clean),
            new_clause_count=len(new_clean),
        )

        used_new: set[int] = set()
        # Build a similarity matrix lazily as we walk old clauses.
        for oi, ov in enumerate(old_vectors):
            best_j, best_sim = -1, -1.0
            for nj, nv in enumerate(new_vectors):
                if nj in used_new:
                    continue
                sim = _cosine(ov, nv)
                if sim > best_sim:
                    best_sim, best_j = sim, nj

            if best_j == -1 or best_sim < self._modified:
                # No salvageable match — this clause was removed wholesale.
                report.removed.append(ClauseChange(
                    kind=ChangeKind.REMOVED,
                    old_index=oi, old_text=old_clean[oi],
                    similarity=0.0,
                    diff_terms_removed=sorted(set(old_tokens[oi]))[:8],
                ))
            elif best_sim >= self._match:
                used_new.add(best_j)
                report.unchanged.append(ClauseChange(
                    kind=ChangeKind.UNCHANGED,
                    old_index=oi, new_index=best_j,
                    old_text=old_clean[oi], new_text=new_clean[best_j],
                    similarity=best_sim,
                ))
            else:
                used_new.add(best_j)
                old_set = set(old_tokens[oi])
                new_set = set(new_tokens[best_j])
                report.modified.append(ClauseChange(
                    kind=ChangeKind.MODIFIED,
                    old_index=oi, new_index=best_j,
                    old_text=old_clean[oi], new_text=new_clean[best_j],
                    similarity=best_sim,
                    diff_terms_added=sorted(new_set - old_set)[:8],
                    diff_terms_removed=sorted(old_set - new_set)[:8],
                ))

        for nj, nclause in enumerate(new_clean):
            if nj in used_new:
                continue
            report.added.append(ClauseChange(
                kind=ChangeKind.ADDED,
                new_index=nj, new_text=nclause,
                similarity=0.0,
                diff_terms_added=sorted(set(new_tokens[nj]))[:8],
            ))

        return report

    # ── helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _vectorise(
        clauses: list[str],
    ) -> tuple[list[dict[str, float]], list[list[str]]]:
        tokens_per = [_diff_tokenize(c) for c in clauses]
        df: Counter[str] = Counter()
        for toks in tokens_per:
            for t in set(toks):
                df[t] += 1
        N = len(clauses)
        out: list[dict[str, float]] = []
        for toks in tokens_per:
            tf = Counter(toks)
            vec: dict[str, float] = {}
            for term, count in tf.items():
                idf = math.log((N + 1) / (df[term] + 1)) + 1.0
                vec[term] = float(count) * idf
            out.append(_l2_normalize(vec))
        return out, tokens_per


def diff_contracts(
    old: list[str], new: list[str],
    *, match_threshold: float = 0.95, modified_threshold: float = 0.45,
) -> ContractDiff:
    return ContractDiffer(
        match_threshold=match_threshold,
        modified_threshold=modified_threshold,
    ).diff(old, new)


# ──────────────────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────────────────


def _keys(d: Any) -> Iterable[Any]:
    if hasattr(d, "keys"):
        try:
            return list(d.keys())
        except Exception:
            return []
    return []


def _coverage(framework_result: Any) -> float:
    if framework_result is None:
        return 0.0
    try:
        return float(getattr(framework_result, "coverage_pct", 0.0))
    except Exception:
        return 0.0


def _fw_key(fw: Any) -> str:
    v = getattr(fw, "value", None)
    if v is not None:
        return str(v)
    return str(fw)


def _direction(delta_pct: float) -> str:
    if delta_pct > 5.0:
        return "improving"
    if delta_pct < -5.0:
        return "degrading"
    return "stable"
