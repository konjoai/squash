"""squash/quick_check.py — One-click compliance heuristic for pasted policy text.

Sprint 28 (W246–W248) — Demo polish + viral features.

This module powers the ``POST /quick-check`` endpoint and the ``/r/{hash}``
shareable-permalink feature. It is intentionally separate from the attest /
policy pipeline:

    * ``squash.policy`` evaluates a *machine-generated SBOM* against a rule list.
    * ``squash.quick_check`` evaluates *human-readable policy text* (privacy
      policy, ToS, GDPR DPA, CCPA notice, cookie banner) against a keyword
      heuristic so demo visitors get a pass/warn/fail badge in <2 seconds.

The heuristic is deliberately conservative — it scores **clause coverage**,
not legal compliance. It is the on-ramp that turns a pasted document into an
inviting "go run squash attest" call to action.

Public surface
--------------

* :class:`QuickCheckResult` — pass/warn/fail verdict, score, missing clauses.
* :func:`run_quick_check` — pure function: text → :class:`QuickCheckResult`.
* :class:`ResultStore` — hash-keyed share store; in-memory by default, JSON
  file persistence when ``path=`` is provided.

Determinism contract
--------------------

The same input ``(text, framework)`` MUST produce a byte-identical result
dict (modulo the share hash, which is itself derived from the canonical
result). This keeps the demo reproducible and the viral permalinks stable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

__all__ = [
    "AVAILABLE_FRAMEWORKS",
    "POLICY_TYPES",
    "QuickCheckResult",
    "ResultStore",
    "StatsTracker",
    "detect_policy_type",
    "get_global_stats",
    "run_quick_check",
    "score_all_frameworks",
]


# ── Heuristic clause definitions ─────────────────────────────────────────────
# Each clause is matched by *any* of its regex alternatives (case-insensitive).
# Severity drives scoring: error = -25 pts, warning = -10 pts. Score floors at 0.
#
# These are intentionally broad — false negatives (a clause IS present but we
# missed it) are acceptable; false positives (we claim a clause is missing
# when it is not) are not, because they erode trust in the demo. When in
# doubt, keep patterns generous.

_CLAUSE_LIBRARY: dict[str, list[dict[str, Any]]] = {
    "gdpr": [
        {
            "id": "GDPR-LAWFUL-BASIS",
            "label": "Lawful basis for processing",
            "severity": "error",
            "patterns": [r"lawful basis", r"legitimate interest", r"article\s*6", r"legal basis"],
            "rationale": "GDPR Art. 6 — every processing activity needs a stated lawful basis.",
        },
        {
            "id": "GDPR-DATA-SUBJECT-RIGHTS",
            "label": "Data subject rights (access / erasure / portability)",
            "severity": "error",
            "patterns": [
                r"right (to|of) access",
                r"right (to|of) erasure",
                r"right to be forgotten",
                r"data portability",
                r"data subject rights?",
            ],
            "rationale": "GDPR Arts. 15–22 — controllers must inform subjects of their rights.",
        },
        {
            "id": "GDPR-RETENTION",
            "label": "Retention period",
            "severity": "error",
            "patterns": [
                r"retention period",
                r"retain(ed)? for",
                r"data retention",
                r"\bretention\b",
                r"how long we (keep|store|retain)",
            ],
            "rationale": "GDPR Art. 13(2)(a) — retention period or criteria must be disclosed.",
        },
        {
            "id": "GDPR-DPO-CONTACT",
            "label": "DPO or controller contact",
            "severity": "warning",
            "patterns": [r"data protection officer", r"\bdpo\b", r"data controller", r"contact\s+us\s+at"],
            "rationale": "GDPR Art. 13(1)(b) — controller / DPO contact must be reachable.",
        },
        {
            "id": "GDPR-INTL-TRANSFER",
            "label": "International transfer disclosure",
            "severity": "warning",
            "patterns": [r"international transfer", r"third country", r"standard contractual clauses", r"\bsccs?\b", r"adequacy decision"],
            "rationale": "GDPR Art. 13(1)(f) — non-EEA transfers and safeguards must be named.",
        },
        {
            "id": "GDPR-BREACH-NOTIFICATION",
            "label": "Breach notification commitment",
            "severity": "warning",
            "patterns": [r"breach notification", r"data breach", r"notify.{0,40}supervisory authority", r"72\s*hours?"],
            "rationale": "GDPR Art. 33 — 72-hour breach notification must be addressed.",
        },
    ],
    "ccpa": [
        {
            "id": "CCPA-RIGHT-TO-KNOW",
            "label": "Right to know",
            "severity": "error",
            "patterns": [r"right to know", r"categories of personal information", r"information we collect"],
            "rationale": "CCPA §1798.110 — consumers may request what data is collected.",
        },
        {
            "id": "CCPA-RIGHT-TO-DELETE",
            "label": "Right to delete",
            "severity": "error",
            "patterns": [r"right to delete", r"deletion request", r"delete your personal information"],
            "rationale": "CCPA §1798.105 — consumers may request deletion of their data.",
        },
        {
            "id": "CCPA-OPT-OUT",
            "label": "Opt-out of sale / sharing",
            "severity": "error",
            "patterns": [r"opt[-\s]?out", r"do not sell", r"do not share", r"sale of personal information"],
            "rationale": "CCPA §1798.120 — consumers may opt out of sale or sharing.",
        },
        {
            "id": "CCPA-NON-DISCRIMINATION",
            "label": "Non-discrimination commitment",
            "severity": "warning",
            "patterns": [r"non[-\s]?discriminat", r"we will not discriminate", r"equal service"],
            "rationale": "CCPA §1798.125 — exercising rights must not trigger penalties.",
        },
        {
            "id": "CCPA-CATEGORIES",
            "label": "Categories of personal information disclosed",
            "severity": "warning",
            "patterns": [r"categories of (personal|sensitive) information", r"identifiers", r"commercial information", r"biometric information"],
            "rationale": "CCPA §1798.130 — categories of PI collected and disclosed.",
        },
    ],
    "eu-ai-act": [
        {
            "id": "AIA-RISK-CLASS",
            "label": "Risk classification statement",
            "severity": "error",
            "patterns": [r"high[-\s]?risk", r"limited[-\s]?risk", r"minimal[-\s]?risk", r"unacceptable[-\s]?risk", r"risk classification"],
            "rationale": "EU AI Act Art. 6–7 — system must be classified into a risk tier.",
        },
        {
            "id": "AIA-HUMAN-OVERSIGHT",
            "label": "Human oversight provisions",
            "severity": "error",
            "patterns": [r"human oversight", r"human in the loop", r"human review", r"manual review"],
            "rationale": "EU AI Act Art. 14 — high-risk AI requires effective human oversight.",
        },
        {
            "id": "AIA-TRANSPARENCY",
            "label": "Transparency / disclosure",
            "severity": "error",
            "patterns": [r"transparenc(y|ies)", r"disclos(ed?|ure)", r"users? are informed", r"notify users"],
            "rationale": "EU AI Act Art. 13 — users must know they are interacting with AI.",
        },
        {
            "id": "AIA-LOGGING",
            "label": "Automatic logging / audit trail",
            "severity": "warning",
            "patterns": [r"automatic.{0,12}log", r"audit (trail|log)", r"event log"],
            "rationale": "EU AI Act Art. 12 — automatic event logging is required.",
        },
        {
            "id": "AIA-ROBUSTNESS",
            "label": "Accuracy / robustness / security",
            "severity": "warning",
            "patterns": [r"accuracy", r"robust(ness)?", r"cybersecurity", r"resilience"],
            "rationale": "EU AI Act Art. 15 — accuracy, robustness, and security obligations.",
        },
    ],
    "soc2": [
        {
            "id": "SOC2-CC1-CONTROL-ENV",
            "label": "Control environment / governance commitment",
            "severity": "error",
            "patterns": [
                r"control environment",
                r"information security (program|policy|policies)",
                r"security (program|governance|committee)",
                r"code of conduct",
            ],
            "rationale": "SOC 2 CC1 — entity demonstrates a commitment to integrity and ethics.",
        },
        {
            "id": "SOC2-CC6-LOGICAL-ACCESS",
            "label": "Logical access controls",
            "severity": "error",
            "patterns": [
                r"access control",
                r"role[-\s]?based access",
                r"least privilege",
                r"multi[-\s]?factor authentication",
                r"\bmfa\b",
                r"authentication",
            ],
            "rationale": "SOC 2 CC6.1/CC6.2 — logical and physical access controls.",
        },
        {
            "id": "SOC2-CC7-MONITORING",
            "label": "System monitoring / anomaly detection",
            "severity": "error",
            "patterns": [
                r"continuous monitoring",
                r"system monitoring",
                r"anomaly detection",
                r"intrusion detection",
                r"\bsiem\b",
                r"log (review|monitoring|aggregation)",
            ],
            "rationale": "SOC 2 CC7.1/CC7.2 — detection and response to security events.",
        },
        {
            "id": "SOC2-CC7-INCIDENT-RESPONSE",
            "label": "Incident response plan",
            "severity": "error",
            "patterns": [
                r"incident response",
                r"security incident",
                r"breach response",
                r"escalation procedure",
            ],
            "rationale": "SOC 2 CC7.3/CC7.4 — documented incident response procedures.",
        },
        {
            "id": "SOC2-A1-AVAILABILITY",
            "label": "Availability / disaster recovery",
            "severity": "warning",
            "patterns": [
                r"disaster recovery",
                r"business continuity",
                r"backup (and|&) (restore|recovery)",
                r"\brto\b",
                r"\brpo\b",
                r"availability",
            ],
            "rationale": "SOC 2 Availability — disaster recovery and continuity commitments.",
        },
        {
            "id": "SOC2-C1-CONFIDENTIALITY",
            "label": "Confidentiality / encryption",
            "severity": "warning",
            "patterns": [
                r"encryption (in transit|at rest)",
                r"\baes[-\s]?256\b",
                r"\btls\b",
                r"key management",
                r"data classification",
                r"confidential",
            ],
            "rationale": "SOC 2 Confidentiality — encryption and key management commitments.",
        },
    ],
    "general": [
        {
            "id": "GEN-DATA-COLLECTION",
            "label": "Data collection disclosure",
            "severity": "error",
            "patterns": [r"(personal|user) (data|information)", r"information (we|that) collect", r"data (we|that) collect"],
            "rationale": "Privacy baseline — what is collected must be stated.",
        },
        {
            "id": "GEN-PURPOSE",
            "label": "Purpose of processing",
            "severity": "error",
            "patterns": [r"purpose of (processing|use)", r"how we use", r"why we collect", r"use your (data|information)"],
            "rationale": "Privacy baseline — why the data is processed must be stated.",
        },
        {
            "id": "GEN-THIRD-PARTIES",
            "label": "Third-party sharing",
            "severity": "warning",
            "patterns": [r"third part(y|ies)", r"share.{0,30}(with|to)", r"service provider"],
            "rationale": "Privacy baseline — disclose recipients of personal data.",
        },
        {
            "id": "GEN-CONTACT",
            "label": "Contact channel",
            "severity": "warning",
            "patterns": [r"contact (us|me)", r"email.{0,20}@", r"address.{0,40}\d", r"privacy@"],
            "rationale": "Privacy baseline — users need a way to reach you.",
        },
        {
            "id": "GEN-COOKIES",
            "label": "Cookies / tracking technologies",
            "severity": "warning",
            "patterns": [r"\bcookies?\b", r"tracking technolog", r"local storage", r"web beacon"],
            "rationale": "Privacy baseline — cookies and similar trackers must be disclosed.",
        },
    ],
}

AVAILABLE_FRAMEWORKS: frozenset[str] = frozenset(_CLAUSE_LIBRARY.keys())

_SEVERITY_PENALTY: dict[str, int] = {"error": 25, "warning": 10}

# Hard cap on text length to keep the endpoint sub-2s and protect memory.
# 200 KB of text is ~30 pages — far longer than any realistic policy snippet.
_MAX_TEXT_BYTES = 200 * 1024

# Compiled regex cache: (framework, clause_id) → list[re.Pattern]
_PATTERN_CACHE: dict[tuple[str, str], list[re.Pattern[str]]] = {}
_CACHE_LOCK = threading.Lock()


def _compiled_patterns(framework: str, clause: dict[str, Any]) -> list[re.Pattern[str]]:
    """Return compiled regex objects for *clause*, cached across calls.

    The cache is keyed on ``(framework, clause_id)`` so the same clause used
    in multiple frameworks (none today, but a near-future likelihood) compiles
    once per framework.
    """
    key = (framework, clause["id"])
    cached = _PATTERN_CACHE.get(key)
    if cached is not None:
        return cached
    with _CACHE_LOCK:
        cached = _PATTERN_CACHE.get(key)
        if cached is not None:
            return cached
        compiled = [re.compile(p, re.IGNORECASE) for p in clause["patterns"]]
        _PATTERN_CACHE[key] = compiled
        return compiled


# ── Result dataclass ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class QuickCheckResult:
    """Outcome of a single ``run_quick_check`` invocation.

    Attributes
    ----------
    framework:
        Framework heuristic applied (gdpr / ccpa / eu-ai-act / general).
    score:
        Integer 0–100. 100 = all clauses present.
    verdict:
        One of ``"pass"`` (>= 80), ``"warn"`` (50–79), ``"fail"`` (< 50).
    matched:
        Clause IDs present in the text.
    missing:
        Clause records (id / label / severity / rationale) absent from the text.
    summary:
        One-line human-readable summary suitable for a badge or chat reply.
    text_length:
        Character count of the input (post-trim) — surfaced for transparency.
    """

    framework: str
    score: int
    verdict: str
    matched: list[str] = field(default_factory=list)
    missing: list[dict[str, str]] = field(default_factory=list)
    summary: str = ""
    text_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict — used for response and storage."""
        return {
            "framework": self.framework,
            "score": self.score,
            "verdict": self.verdict,
            "matched": list(self.matched),
            "missing": [dict(m) for m in self.missing],
            "summary": self.summary,
            "text_length": self.text_length,
        }


def _verdict_for(score: int) -> str:
    if score >= 80:
        return "pass"
    if score >= 50:
        return "warn"
    return "fail"


def _summarise(framework: str, score: int, verdict: str, missing_count: int) -> str:
    label = {"pass": "PASS", "warn": "PARTIAL", "fail": "FAIL"}[verdict]
    if missing_count == 0:
        return f"{label} — {framework} clause coverage {score}/100, no gaps detected"
    plural = "clause" if missing_count == 1 else "clauses"
    return f"{label} — {framework} clause coverage {score}/100, {missing_count} {plural} missing"


def run_quick_check(text: str, framework: str = "general") -> QuickCheckResult:
    """Score *text* against the *framework* clause heuristic.

    Parameters
    ----------
    text:
        The raw policy / ToS / contract snippet to scan.
    framework:
        Which clause library to apply. Defaults to ``"general"`` privacy
        baseline. ``"auto"`` picks the highest-scoring framework — useful
        when the visitor doesn't know what they pasted.

    Returns
    -------
    QuickCheckResult
        Score, verdict, matched/missing clause lists, one-line summary.

    Raises
    ------
    ValueError
        If *framework* is not recognised, or if *text* exceeds the
        ``_MAX_TEXT_BYTES`` safety cap, or is empty after trimming.
    """
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    trimmed = text.strip()
    if not trimmed:
        raise ValueError("text is empty")
    if len(trimmed.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise ValueError(f"text exceeds {_MAX_TEXT_BYTES // 1024} KB cap")

    if framework == "auto":
        # Run every framework, pick the highest score; ties broken by name order.
        candidates = sorted(_CLAUSE_LIBRARY.keys())
        best = max(
            (run_quick_check(trimmed, fw) for fw in candidates),
            key=lambda r: (r.score, -candidates.index(r.framework)),
        )
        return best

    if framework not in _CLAUSE_LIBRARY:
        raise ValueError(
            f"unknown framework {framework!r}; choose from {sorted(AVAILABLE_FRAMEWORKS)} or 'auto'"
        )

    clauses = _CLAUSE_LIBRARY[framework]
    matched: list[str] = []
    missing: list[dict[str, str]] = []
    deductions = 0
    for clause in clauses:
        patterns = _compiled_patterns(framework, clause)
        if any(p.search(trimmed) for p in patterns):
            matched.append(clause["id"])
        else:
            missing.append({
                "id": clause["id"],
                "label": clause["label"],
                "severity": clause["severity"],
                "rationale": clause["rationale"],
            })
            deductions += _SEVERITY_PENALTY.get(clause["severity"], 5)

    score = max(0, 100 - deductions)
    verdict = _verdict_for(score)
    summary = _summarise(framework, score, verdict, len(missing))
    return QuickCheckResult(
        framework=framework,
        score=score,
        verdict=verdict,
        matched=matched,
        missing=missing,
        summary=summary,
        text_length=len(trimmed),
    )


# ── Result store ─────────────────────────────────────────────────────────────


def make_share_hash(payload: dict[str, Any]) -> str:
    """Derive an 8-byte hex permalink hash from the canonical result payload.

    Hash collision risk at 8 bytes (16 hex chars) is ≈ 1 in 1.8e19 — fine
    for a viral demo where the worst case is a stale entry being overwritten
    on overwrite-attempt (which we explicitly reject; see :meth:`ResultStore.put`).
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


_HASH_RE = re.compile(r"^[0-9a-f]{16}$")


def is_valid_share_hash(value: str) -> bool:
    """Return True if *value* is a 16-char lowercase hex share hash."""
    return bool(_HASH_RE.fullmatch(value))


class ResultStore:
    """Hash-keyed store for shareable :class:`QuickCheckResult` payloads.

    In-memory by default. When ``path`` is provided, the store mirrors writes
    to a JSON file on disk (``{"hashes": {<hash>: <payload>}}``). The on-disk
    file is rewritten atomically via temp-file + ``os.replace`` so a crashed
    write cannot corrupt prior entries.

    The store is bounded — once ``capacity`` is reached, the oldest entry is
    evicted. This keeps a public, unauthenticated share endpoint from being
    weaponised as an unbounded data sink.
    """

    DEFAULT_CAPACITY = 10_000

    def __init__(self, path: Path | str | None = None, capacity: int | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.capacity = capacity if capacity is not None else self.DEFAULT_CAPACITY
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        # Insertion order matters for FIFO eviction — Python 3.7+ dict is ordered.
        self._records: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        if self.path is not None:
            self._load_from_disk()

    # ── persistence ──────────────────────────────────────────────────────

    def _load_from_disk(self) -> None:
        assert self.path is not None
        if not self.path.exists():
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("ResultStore: could not load %s (%s); starting fresh", self.path, exc)
            return
        hashes = data.get("hashes")
        if not isinstance(hashes, dict):
            log.warning("ResultStore: %s has no 'hashes' map; starting fresh", self.path)
            return
        # Trust but cap — drop overflow if file was edited externally past our cap.
        for share_hash, payload in list(hashes.items())[: self.capacity]:
            if is_valid_share_hash(share_hash) and isinstance(payload, dict):
                self._records[share_hash] = payload

    def _flush_to_disk(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        body = json.dumps({"hashes": self._records}, sort_keys=True, separators=(",", ":"))
        tmp.write_text(body, encoding="utf-8")
        # Atomic replace — readers either see the old file or the new file.
        tmp.replace(self.path)

    # ── public API ───────────────────────────────────────────────────────

    def put(self, payload: dict[str, Any]) -> str:
        """Store *payload* and return its share hash. Idempotent on identical input.

        Identical payloads produce the same hash — re-storing is a no-op (the
        existing entry is kept, no eviction). Different payloads with the
        same hash (collision) are rejected with ValueError; this should never
        happen at 16-hex precision but the guard makes the contract explicit.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        share_hash = make_share_hash(payload)
        with self._lock:
            existing = self._records.get(share_hash)
            if existing is not None:
                if existing != payload:
                    raise ValueError(f"hash collision on {share_hash}")
                return share_hash
            if len(self._records) >= self.capacity:
                # FIFO eviction — pop the oldest entry.
                oldest = next(iter(self._records))
                self._records.pop(oldest, None)
            self._records[share_hash] = payload
            self._flush_to_disk()
        return share_hash

    def get(self, share_hash: str) -> dict[str, Any] | None:
        """Return the stored payload for *share_hash* or ``None`` if absent."""
        if not is_valid_share_hash(share_hash):
            return None
        with self._lock:
            payload = self._records.get(share_hash)
            return dict(payload) if payload is not None else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __contains__(self, share_hash: object) -> bool:
        if not isinstance(share_hash, str):
            return False
        with self._lock:
            return share_hash in self._records


# ── Sprint 30: policy-type detection + trending stats ────────────────────────


# Display order matches what /trending should return; also defines the
# allowlist for policy_type values stored in the share payload.
POLICY_TYPES: tuple[str, ...] = (
    "privacy_policy",
    "terms_of_service",
    "gdpr_dpa",
    "ccpa_notice",
    "cookie_policy",
    "ai_system_card",
    "soc2_report",
    "other",
)

# Each entry is a list of weighted (regex, weight) signals. The detector
# computes a score per type and returns the argmax (or "other" if no signal
# fires). Patterns are anchored on policy-document conventions, not legal
# correctness — false positives that misclassify are recoverable; missing
# the document type entirely surfaces as "other" in trending.
_POLICY_TYPE_SIGNALS: dict[str, list[tuple[str, int]]] = {
    "privacy_policy": [
        # Title weight is intentionally heavier than peer doc-type titles —
        # a privacy policy that *mentions* a DPA must still classify as
        # privacy_policy, never as gdpr_dpa.
        (r"\bprivacy policy\b", 5),
        (r"personal information we collect", 2),
        (r"data subject rights?", 2),
        (r"data protection officer", 1),
    ],
    "terms_of_service": [
        (r"\bterms of (service|use)\b", 3),
        (r"acceptable use", 2),
        (r"limitation of liability", 2),
        (r"governing law", 1),
        (r"warranty disclaimer", 1),
    ],
    "gdpr_dpa": [
        (r"data processing agreement", 3),
        (r"\bdpa\b", 1),
        (r"article ?28", 2),
        (r"\bsub[-\s]?processor", 2),
        (r"standard contractual clauses", 2),
        (r"\bcontroller\b.{0,40}\bprocessor\b", 2),
    ],
    "ccpa_notice": [
        (r"\bccpa\b", 3),
        (r"\bcpra\b", 2),
        (r"california (consumer|resident)", 2),
        (r"do not sell", 2),
        (r"right to (know|delete|opt[-\s]?out)", 1),
    ],
    "cookie_policy": [
        (r"\bcookie (policy|notice|banner)\b", 3),
        (r"\bcookies?\b.{0,40}\b(strictly necessary|functional|analytic|advertising)", 2),
        (r"cookie (preferences|consent|settings)", 2),
        (r"local storage", 1),
        (r"web beacon", 1),
    ],
    "ai_system_card": [
        (r"\bmodel card\b", 3),
        (r"\bsystem card\b", 3),
        (r"intended use", 2),
        (r"out[-\s]?of[-\s]?scope", 2),
        (r"\b(eu )?ai act\b", 2),
        (r"high[-\s]?risk", 1),
        (r"human oversight", 1),
    ],
    "soc2_report": [
        (r"\bsoc ?2\b", 3),
        (r"trust services criteria", 2),
        (r"\baicpa\b", 2),
        (r"\bcc6\.\d", 1),
        (r"control objectives?", 1),
    ],
}

_POLICY_TYPE_PATTERN_CACHE: dict[str, list[tuple[re.Pattern[str], int]]] = {}
_POLICY_TYPE_LOCK = threading.Lock()


def _compiled_policy_type_signals(policy_type: str) -> list[tuple[re.Pattern[str], int]]:
    cached = _POLICY_TYPE_PATTERN_CACHE.get(policy_type)
    if cached is not None:
        return cached
    with _POLICY_TYPE_LOCK:
        cached = _POLICY_TYPE_PATTERN_CACHE.get(policy_type)
        if cached is not None:
            return cached
        compiled = [
            (re.compile(p, re.IGNORECASE), w)
            for p, w in _POLICY_TYPE_SIGNALS[policy_type]
        ]
        _POLICY_TYPE_PATTERN_CACHE[policy_type] = compiled
        return compiled


def detect_policy_type(text: str) -> str:
    """Classify *text* into one of :data:`POLICY_TYPES`.

    Returns the highest-scoring type, or ``"other"`` if no signal fires.
    Ties are broken in favour of the more specific document class
    (``ccpa_notice`` > ``privacy_policy`` etc.) — see ``_TIE_PRIORITY``.

    Heuristic only — false positives are recoverable; the caller should
    treat the result as advisory metadata, not a legal classification.
    """
    if not isinstance(text, str) or not text.strip():
        return "other"
    scores: dict[str, int] = {}
    for ptype in _POLICY_TYPE_SIGNALS:
        signals = _compiled_policy_type_signals(ptype)
        scores[ptype] = sum(w for pattern, w in signals if pattern.search(text))
    best_score = max(scores.values())
    if best_score == 0:
        return "other"
    # Tie-break: prefer narrowly-recognisable B2B documents over the
    # generic "privacy policy" catch-all (later in this tuple = higher prio).
    # Rationale: a privacy-policy file that *mentions* a DPA is still a
    # privacy policy; a DPA file does not contain a "privacy policy" title.
    # Putting privacy_policy near the top means it loses ties to
    # cookie_policy / ccpa_notice / gdpr_dpa / soc2_report when those
    # specific markers also fire — but wins versus terms_of_service.
    tie_order = (
        "terms_of_service", "ai_system_card",
        "privacy_policy",
        "cookie_policy", "ccpa_notice", "soc2_report", "gdpr_dpa",
    )
    winners = [t for t, s in scores.items() if s == best_score]
    for ptype in reversed(tie_order):
        if ptype in winners:
            return ptype
    return winners[0]


def score_all_frameworks(
    text: str,
    frameworks: tuple[str, ...] = ("gdpr", "ccpa", "soc2"),
) -> dict[str, QuickCheckResult]:
    """Score *text* against each named framework — used by the SVG card.

    Skips any framework not in :data:`AVAILABLE_FRAMEWORKS`; raises
    ``ValueError`` if *text* is empty or oversized (delegated to
    :pyfunc:`run_quick_check`).
    """
    out: dict[str, QuickCheckResult] = {}
    for fw in frameworks:
        if fw not in AVAILABLE_FRAMEWORKS:
            continue
        out[fw] = run_quick_check(text, framework=fw)
    return out


# ── Trending stats tracker ───────────────────────────────────────────────────


@dataclass
class _Bucket:
    """Per-policy-type aggregate counters for the trending feed."""

    count: int = 0
    pass_count: int = 0
    warn_count: int = 0
    fail_count: int = 0

    def record(self, verdict: str) -> None:
        self.count += 1
        if verdict == "pass":
            self.pass_count += 1
        elif verdict == "warn":
            self.warn_count += 1
        elif verdict == "fail":
            self.fail_count += 1

    def to_dict(self) -> dict[str, Any]:
        rate = (self.pass_count / self.count) if self.count else 0.0
        return {
            "count": self.count,
            "pass": self.pass_count,
            "warn": self.warn_count,
            "fail": self.fail_count,
            "pass_rate": round(rate, 4),
        }


class StatsTracker:
    """Thread-safe in-memory aggregate counter for the ``/trending`` endpoint.

    One bucket per :data:`POLICY_TYPES` entry. Each ``/quick-check`` call
    records ``(policy_type, verdict)`` so trending always reflects what the
    public has been pasting into the demo.

    The store is intentionally process-local — for a multi-replica deploy
    the API server fronts a single instance per pod, and trending is
    "approximate / per-pod" by design. A future Sprint can back this with
    Redis if precision matters; today, viral momentum is the goal.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {pt: _Bucket() for pt in POLICY_TYPES}
        self._total: int = 0
        self._lock = threading.Lock()

    def record(self, policy_type: str, verdict: str) -> None:
        """Record one check. Unknown *policy_type* falls back to ``"other"``."""
        if policy_type not in self._buckets:
            policy_type = "other"
        if verdict not in {"pass", "warn", "fail"}:
            return
        with self._lock:
            self._buckets[policy_type].record(verdict)
            self._total += 1

    def trending(self, top: int = 5) -> dict[str, Any]:
        """Return the top *top* policy types by check count, plus totals.

        Always returns a complete payload (``{"total", "top": [...]}``) even
        when the tracker is empty — keeps the demo UI's render path simple.
        """
        if top <= 0:
            top = 5
        with self._lock:
            ranked = sorted(
                self._buckets.items(),
                key=lambda kv: (-kv[1].count, kv[0]),
            )
            top_list = [
                {"policy_type": pt, **bucket.to_dict()}
                for pt, bucket in ranked[:top]
                if bucket.count > 0
            ]
            return {"total": self._total, "top": top_list}

    def reset(self) -> None:
        """Wipe all counters — used by tests."""
        with self._lock:
            for bucket in self._buckets.values():
                bucket.count = 0
                bucket.pass_count = 0
                bucket.warn_count = 0
                bucket.fail_count = 0
            self._total = 0


_GLOBAL_STATS = StatsTracker()


def get_global_stats() -> StatsTracker:
    """Return the process-wide :class:`StatsTracker` used by the API."""
    return _GLOBAL_STATS
