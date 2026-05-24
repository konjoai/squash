"""squash/contracts/obligations.py — Obligation extraction.

Parses contract text for explicit commitments — phrases like
"Party A shall …", "Vendor must …", "Client agrees to …" — and returns
them as structured :class:`Obligation` records with party, modal,
predicate text, optional deadline, and optional precondition.

Why this exists
---------------
Every downstream contract-analysis feature (diff, summary, alert rules,
playbook validation) needs to reason about *who promised what*. Today
that's eyeball work on every clause. This module collapses the primitive
into one deterministic, regex-driven pass that runs in <50 ms on
typical contracts.

Public surface (re-exported from :mod:`squash.contracts`)
---------------------------------------------------------
:class:`Obligation` · :class:`ObligationExtractor` ·
:func:`extract_obligations`.

Pure stdlib. No external NLP dependency, no LLM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

__all__ = [
    "MODAL_WEIGHTS",
    "Obligation",
    "ObligationExtractor",
    "extract_obligations",
]


# ──────────────────────────────────────────────────────────────────────────────
# Modal vocabulary — drives the strength score
# ──────────────────────────────────────────────────────────────────────────────


MODAL_WEIGHTS: dict[str, float] = {
    # binding
    "shall":        1.00,
    "must":         1.00,
    "will":         0.80,
    "is required":  0.95,
    "are required": 0.95,
    "agrees to":    0.92,
    "agree to":     0.92,
    "undertakes":   0.90,
    "undertake":    0.90,
    "covenants":    0.90,
    # weaker / discretionary
    "may":          0.40,
    "should":       0.50,
    "is entitled":  0.35,
}


# Party patterns — keep generous so we catch both proper nouns ("ACME Corp")
# and role nouns ("the Vendor", "Client", "either party").
_PARTY_PATTERNS: tuple[str, ...] = (
    # "The Customer", "The Vendor", etc — role-noun reference
    r"(?:[Tt]he\s+)?(?:Customer|Client|Vendor|Provider|Supplier|"
    r"Licensee|Licensor|Lessee|Lessor|Buyer|Seller|Contractor|"
    r"Subscriber|Subcontractor|Disclosing\s+Party|Receiving\s+Party|"
    r"Indemnitor|Indemnitee|Service\s+Provider|"
    r"Party\s+[A-Z](?:\w+)?|Parties|Either\s+Party|Each\s+Party|"
    r"Both\s+Parties)",
    # ALL-CAPS party labels (common in contracts: "COMPANY shall ...")
    r"(?:[A-Z]{3,}(?:\s+[A-Z]{2,})*)",
    # capitalised proper-noun phrases up to 4 tokens
    r"(?:[A-Z][a-z][\w&'-]*(?:\s+(?:Inc\.|LLC|Ltd\.|Corp\.|Corporation|"
    r"Group|Holdings|Company|Co\.|GmbH|S\.A\.|Limited|"
    r"[A-Z][a-z][\w&'-]*))*)",
)


_PARTY_RE = re.compile(
    r"\b(?P<party>" + "|".join(_PARTY_PATTERNS) + r")\b"
)


# Modal pattern — ordered longest-first so "is required to" wins over "is".
_MODAL_TOKENS = sorted(MODAL_WEIGHTS.keys(), key=len, reverse=True)
_MODAL_RE = re.compile(
    r"(?P<modal>" + "|".join(re.escape(t) for t in _MODAL_TOKENS) + r")\b"
    r"(?:\s+to\b)?",
    re.IGNORECASE,
)


# Sentence splitter — keep generous; legal text uses ; freely.
_SENT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"])|(?<=;)\s+(?=[A-Za-z])")


# Deadline / condition patterns
_DEADLINE_PATTERNS: tuple[tuple[str, str], ...] = (
    # numeric: "within thirty (30) days"
    (r"\bwithin\s+(?:[a-z]+(?:[-\s][a-z]+)*\s+)?\(?\s*\d+\s*\)?\s*"
     r"(?:business\s+|calendar\s+)?(?:day|week|month|year|hour)s?",
     "within {match}"),
    (r"\bno\s+later\s+than\s+\(?\s*\d+\s*\)?\s*"
     r"(?:business\s+|calendar\s+)?(?:day|week|month|year)s?",
     "no later than {match}"),
    # explicit calendar date: "by December 31, 2026", "on or before 12/31/2026"
    (r"\bby\s+(?:January|February|March|April|May|June|July|August|"
     r"September|October|November|December)\s+\d{1,2}(?:,?\s+\d{4})?",
     "by {match}"),
    (r"\b(?:on\s+or\s+before|by)\s+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
     "by {match}"),
    (r"\bby\s+the\s+(?:end\s+of\s+)?(?:next|each|every|"
     r"following|first|last|fiscal)\s+(?:day|week|month|quarter|year|"
     r"calendar\s+month)",
     "by {match}"),
    (r"\bprior\s+to\s+(?:the\s+)?(?:effective\s+date|expiration|"
     r"termination|closing|delivery|renewal)\b",
     "prior to {match}"),
    # recurrent: "annually", "monthly", "quarterly"
    (r"\b(?:annually|monthly|quarterly|weekly|daily|semi-annually|"
     r"bi-annually|on a (?:monthly|annual|quarterly) basis)\b",
     "{match}"),
)


_CONDITION_PATTERNS: tuple[str, ...] = (
    # "upon written notice", "upon request"
    r"\bupon\s+(?:written\s+)?(?:notice|request|completion|"
    r"delivery|receipt|payment)\b[^.;]*",
    # "in the event of ..."
    r"\bin\s+the\s+event\s+(?:of|that)\s+[^.;]*",
    # "if [clause] then [clause]" — capture the conditional
    r"\bif\s+[^,.;]*",
    # "provided that ..." / "subject to ..."
    r"\b(?:provided\s+that|subject\s+to)\s+[^.;]*",
    # "before ...", "after ..."
    r"\b(?:before|after|until|once)\s+[^,.;]{4,}",
)


# Sentences not actually obligations (recitals, definitions, headings…)
_NON_OBLIGATION_PREFIXES: tuple[str, ...] = (
    "whereas", "now therefore", "this agreement",
    "for purposes of", "as used herein",
)

# Single-token "parties" that are really English connectors at sentence start.
# Multi-token role labels like "Either Party" or "Service Provider" are safe;
# only block when the WHOLE party match is one of these tokens.
_BAD_SINGLE_TOKEN_PARTIES: frozenset[str] = frozenset({
    "If", "When", "Where", "Upon", "As", "Provided", "Notwithstanding",
    "Subject", "At", "On", "In", "For", "To", "While", "This", "That",
    "These", "Those", "All", "Each", "Both", "However", "Furthermore",
    "Moreover", "Whether", "Although", "Because", "Since", "Under",
    "During", "Before", "After", "Until", "Once", "Per",
})


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Obligation:
    party: str
    obligation: str
    modal: str
    strength: float                        # 0..1 — derived from modal
    deadline: str = ""
    condition: str = ""
    source_clause: str = ""
    source_index: int = 0
    span_start: int = 0
    span_end: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "party": self.party,
            "obligation": self.obligation,
            "modal": self.modal,
            "strength": round(self.strength, 3),
            "deadline": self.deadline,
            "condition": self.condition,
            "source_clause": self.source_clause,
            "source_index": self.source_index,
            "span_start": self.span_start,
            "span_end": self.span_end,
        }

    @property
    def is_binding(self) -> bool:
        return self.strength >= 0.75


# ──────────────────────────────────────────────────────────────────────────────
# Extractor
# ──────────────────────────────────────────────────────────────────────────────


class ObligationExtractor:
    """Pull explicit obligations from contract text.

    The extractor walks each *clause* (caller-provided) or splits a full
    contract into sentences, then for every sentence:

    1. Skips known non-obligation prefixes (recitals, definitions).
    2. Finds the leading party reference (proper noun / role label).
    3. Locates the modal verb that gates the commitment.
    4. Extracts everything after the modal as the obligation predicate.
    5. Heuristically pulls out any deadline / precondition substring.

    Each match becomes one :class:`Obligation` record. Empty matches
    (party found but no modal, or vice versa) are dropped silently.
    """

    def __init__(self, modal_weights: dict[str, float] | None = None) -> None:
        self._weights = dict(modal_weights or MODAL_WEIGHTS)

    # ── public api ─────────────────────────────────────────────────────────

    def extract_from_text(self, text: str) -> list[Obligation]:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        return self.extract_from_clauses(self._split_sentences(text))

    def extract_from_clauses(self, clauses: Iterable[str]) -> list[Obligation]:
        out: list[Obligation] = []
        for idx, clause in enumerate(clauses):
            if not isinstance(clause, str):
                raise TypeError("each clause must be str")
            for ob in self._extract_one(clause, idx):
                out.append(ob)
        return out

    # ── internal ───────────────────────────────────────────────────────────

    def _extract_one(self, clause: str, source_index: int) -> list[Obligation]:
        c = clause.strip()
        if not c:
            return []
        low = c.lower()
        for prefix in _NON_OBLIGATION_PREFIXES:
            if low.startswith(prefix):
                return []

        out: list[Obligation] = []
        # Walk every party-modal pair, in document order, on each sentence.
        for sent in self._split_sentences(c):
            sent = sent.strip()
            if not sent:
                continue
            party_match = self._best_party(sent)
            if party_match is None:
                continue
            after_party = sent[party_match.end():]
            # The modal we accept must come within ~80 chars of the party so
            # we don't link far-apart references.
            modal_match = _MODAL_RE.search(after_party[:120])
            if modal_match is None:
                continue
            modal_text = modal_match.group("modal").lower()
            strength = self._weights.get(modal_text, 0.5)
            predicate = after_party[modal_match.end():].strip(" ,;:.")
            if not predicate:
                continue
            # Take the whole predicate as the obligation body. Don't split on
            # bare periods — decimals ("99.9%"), abbreviations ("U.S.", "Inc.")
            # and parenthetical numerals ("(30)") all contain dots without
            # ending the clause. The sentence splitter has already broken on
            # real sentence boundaries upstream.
            obligation_text = predicate.rstrip(" ,;:.")
            deadline = self._extract_deadline(obligation_text)
            condition = self._extract_condition(sent)

            out.append(Obligation(
                party=_normalize_party(party_match.group("party")),
                obligation=obligation_text,
                modal=modal_text,
                strength=strength,
                deadline=deadline,
                condition=condition,
                source_clause=clause.strip(),
                source_index=source_index,
                span_start=party_match.start(),
                span_end=party_match.end() + modal_match.end(),
            ))
        return out

    @staticmethod
    def _best_party(sent: str) -> "re.Match[str] | None":
        """Pick the first party reference that isn't an English connector.

        ``_PARTY_RE.search`` greedily grabs the leftmost match, which on a
        sentence like *"If a breach occurs, Vendor shall …"* lands on
        ``"If"`` instead of ``"Vendor"``. Filter such single-token matches
        out via :data:`_BAD_SINGLE_TOKEN_PARTIES` and walk forward.
        """
        for m in _PARTY_RE.finditer(sent):
            raw = m.group("party").strip()
            if " " in raw:
                # multi-token role labels are always accepted
                return m
            if raw not in _BAD_SINGLE_TOKEN_PARTIES:
                return m
        return None

    @staticmethod
    def _split_sentences(text: str) -> list[str]:
        if not text:
            return []
        text = text.replace("\n", " ").strip()
        parts = _SENT_RE.split(text)
        return [p.strip() for p in parts if p and p.strip()]

    @staticmethod
    def _extract_deadline(text: str) -> str:
        for pat, fmt in _DEADLINE_PATTERNS:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                inner = m.group(0).strip()
                # Avoid double-prefixing ("by by ...")
                if fmt == "{match}":
                    return inner
                lead = fmt.split("{")[0].strip().lower()
                if inner.lower().startswith(lead):
                    return inner
                return fmt.format(match=inner)
        return ""

    @staticmethod
    def _extract_condition(text: str) -> str:
        for pat in _CONDITION_PATTERNS:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(0).strip(" ,.;:")
        return ""


def extract_obligations(text_or_clauses: str | Iterable[str]) -> list[Obligation]:
    """Convenience wrapper — accept either a contract string or clause list."""
    extractor = ObligationExtractor()
    if isinstance(text_or_clauses, str):
        return extractor.extract_from_text(text_or_clauses)
    return extractor.extract_from_clauses(list(text_or_clauses))


# ──────────────────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────────────────


def _normalize_party(raw: str) -> str:
    s = raw.strip()
    s = re.sub(r"^[Tt]he\s+", "", s)
    return s
