"""squash/model_card_validator.py — HuggingFace model-card schema validator.

Validates a generated `squash-model-card-hf.md` against the HuggingFace
model card schema requirements before publication. Produces a structured
``ModelCardValidationReport`` that callers (CLI / push flow / CI gates)
can branch on.

The HF model card schema is defined informally across:
  - https://huggingface.co/docs/hub/model-cards
  - https://huggingface.co/docs/hub/model-card-annotated
  - The ``modelcard`` Python library schema

This validator implements the practical subset enforced at upload time
plus the additional Annex IV / bias / lineage richness squash promises.

Usage::

    from squash.model_card_validator import ModelCardValidator
    report = ModelCardValidator().validate(Path("squash-model-card-hf.md"))
    if not report.is_valid:
        print(report.summary())

stdlib-only — no PyYAML dep; minimal frontmatter parser handles the
shapes ``ModelCard.render()`` emits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Schema constants ─────────────────────────────────────────────────────────

# Required HF model card YAML frontmatter fields. Soft-required: HF accepts
# uploads without these but flags them in the UI and reduces discoverability.
REQUIRED_FRONTMATTER_FIELDS: frozenset[str] = frozenset({"license", "language", "tags"})

RECOMMENDED_FRONTMATTER_FIELDS: frozenset[str] = frozenset(
    {"pipeline_tag", "model_id", "model-index"}
)

# Sections HF reviewers and squash compliance both expect to see.
REQUIRED_SECTIONS: tuple[str, ...] = (
    "Intended Use",
    "Limitations",
)

RECOMMENDED_SECTIONS: tuple[str, ...] = (
    "Training Data",
    "Evaluation",
    "Ethical Considerations",
    "How to Use",
)

# Common SPDX licence identifiers HF recognises. Not exhaustive — used as a
# warning surface, not a hard reject.
KNOWN_LICENSES: frozenset[str] = frozenset({
    "apache-2.0", "mit", "bsd-2-clause", "bsd-3-clause", "cc-by-4.0",
    "cc-by-sa-4.0", "cc-by-nc-4.0", "cc-by-nc-sa-4.0", "cc0-1.0",
    "gpl-2.0", "gpl-3.0", "lgpl-2.1", "lgpl-3.0", "agpl-3.0", "mpl-2.0",
    "openrail", "bigscience-openrail-m", "bigscience-bloom-rail-1.0",
    "creativeml-openrail-m", "llama2", "llama3", "llama3.1", "llama3.2",
    "gemma", "other", "unknown", "unlicense",
})

# Recognised HF pipeline_tag values (subset). Extra entries are tolerated.
KNOWN_PIPELINE_TAGS: frozenset[str] = frozenset({
    "text-generation", "text2text-generation", "text-classification",
    "token-classification", "fill-mask", "translation", "summarization",
    "question-answering", "feature-extraction", "sentence-similarity",
    "image-classification", "image-to-text", "text-to-image",
    "automatic-speech-recognition", "audio-classification",
    "zero-shot-classification", "conversational",
})


# ── Result classes ───────────────────────────────────────────────────────────


@dataclass
class ValidationFinding:
    """A single validation issue surfaced by the validator.

    severity is one of ``"error"`` (blocks upload), ``"warning"``
    (HF accepts but flags), or ``"info"`` (squash hint, not HF-blocking).
    """

    severity: str
    field: str
    message: str

    def render(self) -> str:
        sigil = {"error": "✗", "warning": "⚠", "info": "ℹ"}.get(self.severity, "·")
        return f"{sigil} [{self.severity}] {self.field}: {self.message}"


@dataclass
class ModelCardValidationReport:
    """Structured outcome of validating a model card."""

    card_path: Path
    findings: list[ValidationFinding] = field(default_factory=list)
    frontmatter: dict[str, Any] = field(default_factory=dict)
    section_titles: list[str] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationFinding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[ValidationFinding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def infos(self) -> list[ValidationFinding]:
        return [f for f in self.findings if f.severity == "info"]

    @property
    def is_valid(self) -> bool:
        """True iff there are no error-severity findings."""
        return len(self.errors) == 0

    def summary(self) -> str:
        status = "✅ VALID" if self.is_valid else "❌ INVALID"
        return (
            f"{status} — {self.card_path.name} | "
            f"errors={len(self.errors)} warnings={len(self.warnings)} "
            f"infos={len(self.infos)}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "card_path": str(self.card_path),
            "is_valid": self.is_valid,
            "errors": [f.__dict__ for f in self.errors],
            "warnings": [f.__dict__ for f in self.warnings],
            "infos": [f.__dict__ for f in self.infos],
            "frontmatter": self.frontmatter,
            "section_titles": self.section_titles,
        }


# ── Frontmatter / section parser ─────────────────────────────────────────────


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_SECTION_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)


def _parse_frontmatter(text: str) -> dict[str, Any]:
    """Minimal YAML-frontmatter parser scoped to the shapes ModelCard emits.

    Handles: scalar (str/int/bool), list of scalars (``- item``), dict
    (single-level), quoted strings. Does *not* attempt full YAML.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}

    body = m.group(1)
    out: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[Any] | None = None
    current_dict: dict[str, Any] | None = None

    for raw_line in body.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        # Top-level "key: value" or "key:" (block follows)
        top = re.match(r"^([A-Za-z_][\w\-]*):\s*(.*)$", line)
        if top and not raw_line.startswith(("  ", "\t")):
            current_key = top.group(1)
            value_part = top.group(2)
            if value_part == "":
                # Block follows — could be list or dict
                current_list = []
                current_dict = {}
                out[current_key] = current_list  # tentative; finalised on next line
                continue
            out[current_key] = _coerce_scalar(value_part)
            current_list = None
            current_dict = None
            continue

        # Indented list item: "  - item" or "  - key: value"
        list_item = re.match(r"^\s+-\s+(.*)$", line)
        if list_item and current_key is not None:
            item_body = list_item.group(1)
            kv = re.match(r"^([A-Za-z_][\w\-]*):\s*(.*)$", item_body)
            if kv:
                # List of dicts
                if not isinstance(out.get(current_key), list):
                    out[current_key] = []
                d = {kv.group(1): _coerce_scalar(kv.group(2))}
                out[current_key].append(d)
            else:
                if not isinstance(out.get(current_key), list):
                    out[current_key] = []
                out[current_key].append(_coerce_scalar(item_body))
            continue

        # Indented "  key: value" — dict body
        dict_kv = re.match(r"^\s+([A-Za-z_][\w\-]*):\s*(.*)$", line)
        if dict_kv and current_key is not None:
            existing = out.get(current_key)
            if isinstance(existing, list) and existing and isinstance(existing[-1], dict):
                # Continuation of a list-of-dicts entry
                existing[-1][dict_kv.group(1)] = _coerce_scalar(dict_kv.group(2))
            else:
                if not isinstance(existing, dict):
                    out[current_key] = {}
                out[current_key][dict_kv.group(1)] = _coerce_scalar(dict_kv.group(2))
            continue

    return out


def _coerce_scalar(raw: str) -> Any:
    s = raw.strip()
    if not s:
        return ""
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1]
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1]
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        pass
    return s


def _extract_section_titles(text: str) -> list[str]:
    """Return all level-2 section titles in document order."""
    return [m.strip() for m in _SECTION_RE.findall(text)]


# ── Validator ────────────────────────────────────────────────────────────────


class ModelCardValidator:
    """Validate a HuggingFace model card markdown file against the squash schema.

    Usage::

        report = ModelCardValidator().validate(Path("squash-model-card-hf.md"))
        if not report.is_valid:
            for f in report.errors:
                print(f.render())
    """

    def validate(self, card_path: Path | str) -> ModelCardValidationReport:
        card_path = Path(card_path)
        report = ModelCardValidationReport(card_path=card_path)

        if not card_path.exists():
            report.findings.append(ValidationFinding(
                severity="error", field="card_path",
                message=f"Model card file not found: {card_path}",
            ))
            return report

        text = card_path.read_text(encoding="utf-8")
        if not text.strip():
            report.findings.append(ValidationFinding(
                severity="error", field="card_path",
                message="Model card file is empty",
            ))
            return report

        report.frontmatter = _parse_frontmatter(text)
        report.section_titles = _extract_section_titles(text)

        self._check_frontmatter(report)
        self._check_sections(report)
        self._check_content(text, report)
        return report

    # ── Frontmatter checks ────────────────────────────────────────────────

    def _check_frontmatter(self, report: ModelCardValidationReport) -> None:
        fm = report.frontmatter
        if not fm:
            report.findings.append(ValidationFinding(
                severity="error", field="frontmatter",
                message="No YAML frontmatter found — HF model cards require a frontmatter block",
            ))
            return

        for required in REQUIRED_FRONTMATTER_FIELDS:
            if required not in fm or fm[required] in (None, "", []):
                report.findings.append(ValidationFinding(
                    severity="error", field=f"frontmatter.{required}",
                    message=f"Required frontmatter field '{required}' is missing or empty",
                ))

        for recommended in RECOMMENDED_FRONTMATTER_FIELDS:
            if recommended not in fm:
                report.findings.append(ValidationFinding(
                    severity="warning", field=f"frontmatter.{recommended}",
                    message=f"Recommended frontmatter field '{recommended}' is missing",
                ))

        # Licence sanity check
        lic = fm.get("license")
        if isinstance(lic, str) and lic and lic.lower() not in KNOWN_LICENSES:
            report.findings.append(ValidationFinding(
                severity="warning", field="frontmatter.license",
                message=f"License '{lic}' is not a recognised SPDX identifier; "
                        "HF will accept but may not display correctly",
            ))

        # Pipeline tag sanity check
        ptag = fm.get("pipeline_tag")
        if isinstance(ptag, str) and ptag and ptag not in KNOWN_PIPELINE_TAGS:
            report.findings.append(ValidationFinding(
                severity="info", field="frontmatter.pipeline_tag",
                message=f"pipeline_tag '{ptag}' is not in the well-known set",
            ))

        # Language must be a list
        lang = fm.get("language")
        if lang is not None and not isinstance(lang, list):
            report.findings.append(ValidationFinding(
                severity="warning", field="frontmatter.language",
                message="'language' should be a list of BCP-47 codes",
            ))

        # Tags must be a list
        tags = fm.get("tags")
        if tags is not None and not isinstance(tags, list):
            report.findings.append(ValidationFinding(
                severity="warning", field="frontmatter.tags",
                message="'tags' should be a list of strings",
            ))

    # ── Section checks ────────────────────────────────────────────────────

    def _check_sections(self, report: ModelCardValidationReport) -> None:
        titles = set(report.section_titles)
        for required in REQUIRED_SECTIONS:
            if required not in titles:
                report.findings.append(ValidationFinding(
                    severity="error", field=f"section.{required}",
                    message=f"Required section '{required}' is missing",
                ))
        for recommended in RECOMMENDED_SECTIONS:
            if recommended not in titles:
                report.findings.append(ValidationFinding(
                    severity="info", field=f"section.{recommended}",
                    message=f"Recommended section '{recommended}' is missing — "
                            "consider running `squash annex-iv` and `squash bias-audit` "
                            "before regenerating the card to auto-populate it",
                ))

    # ── Content checks ────────────────────────────────────────────────────

    def _check_content(self, text: str, report: ModelCardValidationReport) -> None:
        # Body length: HF rejects effectively-empty cards.
        body = _FRONTMATTER_RE.sub("", text, count=1).strip()
        if len(body) < 200:
            report.findings.append(ValidationFinding(
                severity="warning", field="body",
                message=f"Card body is very short ({len(body)} chars); "
                        "HF reviewers expect substantive documentation",
            ))


__all__ = [
    "ModelCardValidator",
    "ModelCardValidationReport",
    "ValidationFinding",
    "REQUIRED_FRONTMATTER_FIELDS",
    "RECOMMENDED_FRONTMATTER_FIELDS",
    "REQUIRED_SECTIONS",
    "RECOMMENDED_SECTIONS",
    "KNOWN_LICENSES",
    "KNOWN_PIPELINE_TAGS",
]
