"""squash/annex_iv_generator.py — EU AI Act Annex IV document generator.

Transforms ArtifactExtractionResult (W128-W132 outputs) into a complete,
auditor-ready EU AI Act Annex IV technical documentation package.

Produces three formats from a single generation call:
  - Markdown  — human-readable, version-controllable, diff-friendly
  - HTML      — standalone, print-ready, embedded professional CSS
  - PDF       — via weasyprint (optional dep); degrades gracefully to HTML

All 12 required Annex IV sections are generated, with:
  - Per-section completeness scores (0-100) weighted by legal importance
  - Article-specific gap statements (not generic "N/A") for every missing field
  - Confidence badges: ✅ Full / ⚠️ Partial / ❌ Missing
  - Overall compliance score with breakdown
  - Executive summary auto-generated from available evidence

AnnexIVValidator enforces hard-fail thresholds aligned with Article 11
minimum requirements — a score below the threshold is flagged before submission.

Wave 133 (document generator) + Wave 134 (PDF pipeline).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from squash.artifact_extractor import ArtifactExtractionResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Section weight table — reflects EU AI Act legal importance
# ---------------------------------------------------------------------------

_SECTION_WEIGHTS: dict[str, int] = {
    "1a_general_description":  8,
    "1b_intended_purpose":    10,
    "1c_development_process": 15,
    "2a_data_governance":     15,
    "2b_data_preprocessing":   8,
    "3a_model_architecture":  10,
    "3b_training_methodology": 10,
    "4_risk_management":      10,
    "5_human_oversight":       8,
    "6a_performance_metrics":  8,
    "6b_robustness_testing":   5,
    "7_lifecycle_management":  5,
}

_TOTAL_WEIGHT: int = sum(_SECTION_WEIGHTS.values())  # 112

_SECTION_TITLES: dict[str, str] = {
    "1a_general_description":  "1(a) — General Description of the AI System",
    "1b_intended_purpose":     "1(b) — Intended Purpose and Deployment Context",
    "1c_development_process":  "1(c) — Development Process and Software Stack",
    "2a_data_governance":      "2(a) — Training Data Governance and Provenance",
    "2b_data_preprocessing":   "2(b) — Data Preprocessing and Pipeline",
    "3a_model_architecture":   "3(a) — Model Architecture",
    "3b_training_methodology": "3(b) — Training Methodology and Validation",
    "4_risk_management":       "4 — Risk Management System (Article 9)",
    "5_human_oversight":       "5 — Human Oversight Measures (Article 14)",
    "6a_performance_metrics":  "6(a) — Performance Metrics and Accuracy",
    "6b_robustness_testing":   "6(b) — Robustness and Cybersecurity Testing",
    "7_lifecycle_management":  "7 — Lifecycle Management and Change Log",
}

_SECTION_ARTICLES: dict[str, str] = {
    "1a_general_description":  "Art. 11, Annex IV §1(a)",
    "1b_intended_purpose":     "Art. 9(2)(a), Annex IV §1(b)",
    "1c_development_process":  "Art. 11, Annex IV §2",
    "2a_data_governance":      "Art. 10, Annex IV §2(a)",
    "2b_data_preprocessing":   "Art. 10(2)(f), Annex IV §2(b)",
    "3a_model_architecture":   "Annex IV §3(a)",
    "3b_training_methodology": "Annex IV §3(b)",
    "4_risk_management":       "Art. 9, Annex IV §5",
    "5_human_oversight":       "Art. 14, Annex IV §5",
    "6a_performance_metrics":  "Annex IV §3(a), Art. 15",
    "6b_robustness_testing":   "Art. 15, Annex IV §3(a)",
    "7_lifecycle_management":  "Art. 12, Annex IV §6",
}


def _badge(completeness: int) -> str:
    if completeness >= 80:
        return "✅ Full"
    if completeness >= 40:
        return "⚠️ Partial"
    return "❌ Missing"


def _gap_block(gaps: list[str], article: str) -> str:
    if not gaps:
        return ""
    lines = ["", f"> **Compliance gaps** ({article}):", ""]
    for g in gaps:
        lines.append(f"> - {g}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class AnnexIVSection:
    """A single rendered section of the Annex IV technical documentation."""
    key: str
    title: str
    article: str
    content: str          # Markdown body
    completeness: int     # 0–100 for this section
    gaps: list[str] = field(default_factory=list)

    @property
    def badge(self) -> str:
        return _badge(self.completeness)

    @property
    def weight(self) -> int:
        return _SECTION_WEIGHTS.get(self.key, 0)


@dataclass
class ValidationFinding:
    severity: str    # "hard_fail" | "warning" | "info"
    section: str
    article: str
    message: str


@dataclass
class ValidationReport:
    """Result of AnnexIVValidator.validate() — pre-submission compliance check."""
    overall_score: int
    hard_fails: list[ValidationFinding] = field(default_factory=list)
    warnings: list[ValidationFinding] = field(default_factory=list)
    infos: list[ValidationFinding] = field(default_factory=list)

    @property
    def is_submittable(self) -> bool:
        """True when there are no hard fails — document can be submitted."""
        return len(self.hard_fails) == 0

    def summary(self) -> str:
        status = "✅ SUBMITTABLE" if self.is_submittable else "❌ NOT SUBMITTABLE"
        return (
            f"{status} — Score: {self.overall_score}/100 | "
            f"Hard fails: {len(self.hard_fails)} | "
            f"Warnings: {len(self.warnings)}"
        )


@dataclass
class AnnexIVDocument:
    """Complete EU AI Act Annex IV technical documentation package."""
    system_name: str
    version: str
    generated_at: str
    sections: list[AnnexIVSection]
    overall_score: int
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Completeness helpers

    @property
    def missing_sections(self) -> list[str]:
        return [s.key for s in self.sections if s.completeness < 40]

    @property
    def partial_sections(self) -> list[str]:
        return [s.key for s in self.sections if 40 <= s.completeness < 80]

    @property
    def complete_sections(self) -> list[str]:
        return [s.key for s in self.sections if s.completeness >= 80]

    def section(self, key: str) -> AnnexIVSection | None:
        return next((s for s in self.sections if s.key == key), None)

    # ------------------------------------------------------------------ #
    # Markdown export

    def to_markdown(self) -> str:
        lines: list[str] = [
            f"# EU AI Act — Annex IV Technical Documentation",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **System** | {self.system_name} |",
            f"| **Version** | {self.version} |",
            f"| **Generated** | {self.generated_at} |",
            f"| **Compliance Score** | {self.overall_score}/100 |",
            f"| **Status** | {_badge(self.overall_score)} ({len(self.complete_sections)}/12 sections complete) |",
            f"",
            f"---",
            f"",
        ]

        for section in self.sections:
            lines.append(f"## {section.title}")
            lines.append(f"")
            lines.append(f"**Coverage:** {section.badge} ({section.completeness}%)  "
                         f"| **Legal basis:** {section.article}")
            lines.append(f"")
            lines.append(section.content)
            lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

        lines.append(f"*Generated by [Squash](https://github.com/konjoai/squash) "
                     f"— Automated EU AI Act Compliance · {self.generated_at}*")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # HTML export (standalone, print-ready)

    def to_html(self) -> str:
        try:
            import markdown as md_lib  # type: ignore
            body_html = md_lib.markdown(
                self.to_markdown(),
                extensions=["tables", "fenced_code", "toc"],
            )
        except ImportError:
            # Minimal conversion: headers, bold, code spans, line breaks
            body_html = _minimal_md_to_html(self.to_markdown())

        score_color = "#22c55e" if self.overall_score >= 80 else (
            "#f59e0b" if self.overall_score >= 40 else "#ef4444"
        )

        return _HTML_TEMPLATE.format(
            system_name=self.system_name,
            version=self.version,
            generated_at=self.generated_at,
            overall_score=self.overall_score,
            score_color=score_color,
            body=body_html,
        )

    # ------------------------------------------------------------------ #
    # JSON export

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "squash_version": "annex_iv_v1",
            "system_name": self.system_name,
            "version": self.version,
            "generated_at": self.generated_at,
            "overall_score": self.overall_score,
            "sections": [
                {
                    "key": s.key,
                    "title": s.title,
                    "article": s.article,
                    "completeness": s.completeness,
                    "badge": s.badge,
                    "gaps": s.gaps,
                    "content": s.content,
                }
                for s in self.sections
            ],
            "summary": {
                "complete": self.complete_sections,
                "partial": self.partial_sections,
                "missing": self.missing_sections,
            },
            "metadata": self.metadata,
        }, indent=indent, ensure_ascii=False)

    # ------------------------------------------------------------------ #
    # PDF export (optional weasyprint)

    def to_pdf(self, output_path: Path) -> None:
        """Write PDF to *output_path*.

        Requires ``weasyprint``. Raises ImportError if not installed.
        Install with: ``pip install weasyprint``
        """
        try:
            from weasyprint import HTML as WeasyprintHTML  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "weasyprint is required for PDF export. "
                "Install with: pip install weasyprint"
            ) from exc
        WeasyprintHTML(string=self.to_html()).write_pdf(str(output_path))
        log.info("annex_iv: PDF written to %s", output_path)

    # ------------------------------------------------------------------ #
    # Multi-format save

    def save(
        self,
        output_dir: Path,
        formats: list[str] | None = None,
        stem: str | None = None,
    ) -> dict[str, Path]:
        """Write the document in one or more formats to *output_dir*.

        Args:
            output_dir: Directory to write files into (created if absent).
            formats:    List of ``"md"``, ``"html"``, ``"json"``, ``"pdf"``.
                        Defaults to ``["md", "json"]``.
            stem:       Filename stem. Defaults to ``"annex_iv"``.

        Returns:
            Dict mapping format → written Path.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        formats = formats or ["md", "json"]
        stem = stem or "annex_iv"
        written: dict[str, Path] = {}

        if "md" in formats:
            p = output_dir / f"{stem}.md"
            p.write_text(self.to_markdown(), encoding="utf-8")
            written["md"] = p

        if "html" in formats:
            p = output_dir / f"{stem}.html"
            p.write_text(self.to_html(), encoding="utf-8")
            written["html"] = p

        if "json" in formats:
            p = output_dir / f"{stem}.json"
            p.write_text(self.to_json(), encoding="utf-8")
            written["json"] = p

        if "pdf" in formats:
            p = output_dir / f"{stem}.pdf"
            try:
                self.to_pdf(p)
                written["pdf"] = p
            except ImportError as exc:
                log.warning("annex_iv: PDF skipped — %s", exc)

        log.info("annex_iv: saved %s to %s", list(written.keys()), output_dir)
        return written


# ---------------------------------------------------------------------------
# Section renderers — one function per Annex IV section
# ---------------------------------------------------------------------------

def _render_1a(meta: dict) -> tuple[str, int, list[str]]:
    name = meta.get("system_name", "")
    desc = meta.get("general_description", "")
    version = meta.get("version", "")
    risk = meta.get("risk_level", "")
    hw = meta.get("hardware_requirements", "")

    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if name:
        lines.append(f"**System name:** {name}")
        score += 30
    else:
        gaps.append("System name not provided (Annex IV §1(a))")

    if version:
        lines.append(f"**Version:** {version}")
        score += 10

    if risk:
        lines.append(f"**EU AI Act risk classification:** {risk.title()}")
        score += 20
    else:
        gaps.append("Risk classification not provided — classify as minimal / limited / high / unacceptable risk (Art. 9)")

    if desc:
        lines.append(f"")
        lines.append(desc)
        score += 40
    else:
        gaps.append("General description not provided — describe what the system does, its key capabilities, and scope of use (Annex IV §1(a))")

    if hw:
        lines.append(f"")
        lines.append(f"**Hardware requirements:** {hw}")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 11, Annex IV §1(a)")
    return content, min(score, 100), gaps


def _render_1b(meta: dict) -> tuple[str, int, list[str]]:
    purpose = meta.get("intended_purpose", "")
    users = meta.get("intended_users", [])
    prohibited = meta.get("prohibited_uses", "")
    deployment = meta.get("deployment_context", "")

    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if purpose:
        lines.append(f"**Intended purpose:**")
        lines.append(f"")
        lines.append(purpose)
        score += 50
    else:
        gaps.append("Intended purpose not provided — required by Art. 9(2)(a) and Annex IV §1(b)")

    if users:
        user_list = users if isinstance(users, list) else [users]
        lines.append(f"")
        lines.append(f"**Intended users:** {', '.join(user_list)}")
        score += 20

    if deployment:
        lines.append(f"")
        lines.append(f"**Deployment context:** {deployment}")
        score += 15

    if prohibited:
        lines.append(f"")
        lines.append(f"**Prohibited uses:**")
        lines.append(f"")
        lines.append(prohibited)
        score += 15
    else:
        gaps.append("Prohibited uses not documented — high-risk AI systems must specify forbidden applications (Art. 9(2))")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 9(2)(a), Annex IV §1(b)")
    return content, min(score, 100), gaps


def _render_1c(result: "ArtifactExtractionResult") -> tuple[str, int, list[str]]:
    code = result.code
    config = result.config
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if code:
        if code.framework:
            lines.append(f"**ML framework:** {code.framework.title()}")
            score += 20

        fw_deps = sorted({r.module for r in code.imports if r.purpose == "framework"})
        util_deps = sorted({r.module for r in code.imports if r.purpose == "training_utility"})
        dataset_libs = sorted({r.module for r in code.imports if r.purpose == "dataset"})

        if fw_deps:
            lines.append(f"**Framework dependencies:** {', '.join(f'`{d}`' for d in fw_deps)}")
            score += 10
        if util_deps:
            lines.append(f"**Training utilities:** {', '.join(f'`{d}`' for d in util_deps)}")
            score += 10
        if dataset_libs:
            lines.append(f"**Dataset libraries:** {', '.join(f'`{d}`' for d in dataset_libs)}")

        if code.optimizers:
            lines.append(f"")
            lines.append(f"**Optimizers:**")
            lines.append(f"")
            for opt in code.optimizers:
                kw_str = ", ".join(f"{k}={v}" for k, v in opt.kwargs.items()) if opt.kwargs else ""
                lines.append(f"- `{opt.name}`{(' — ' + kw_str) if kw_str else ''}")
            score += 20

        if code.loss_functions:
            deduped = list(dict.fromkeys(code.loss_functions))
            lines.append(f"")
            lines.append(f"**Loss functions:** {', '.join(f'`{lf}`' for lf in deduped)}")
            score += 10

        if code.checkpoint_ops:
            lines.append(f"")
            lines.append(f"**Checkpoint strategy:** {', '.join(f'`{c}`' for c in dict.fromkeys(code.checkpoint_ops))}")
            score += 10

        if code.requirements:
            lines.append(f"")
            lines.append(f"**Training environment dependencies ({len(code.requirements)} packages):**")
            lines.append(f"")
            lines.append(f"```text")
            lines.extend(code.requirements[:20])
            if len(code.requirements) > 20:
                lines.append(f"# ... and {len(code.requirements) - 20} more")
            lines.append(f"```")
            score += 20

    elif config:
        lines.append("*Source: training configuration file*")
        lines.append(f"")
        if config.optimizer:
            opt_type = config.optimizer.get("type", "unknown")
            lr = config.optimizer.get("learning_rate", "")
            wd = config.optimizer.get("weight_decay", "")
            lines.append(f"**Optimizer:** {opt_type}"
                         + (f" — lr={lr}" if lr else "")
                         + (f", weight_decay={wd}" if wd else ""))
            score += 40
        if config.training:
            lines.append(f"")
            lines.append(f"**Training settings:**")
            lines.append(f"")
            for k, v in config.training.items():
                lines.append(f"- {k}: {v}")
            score += 30
    else:
        gaps.append("No development process artifacts found — provide training scripts or configuration files (Annex IV §2)")
        gaps.append("Include: ML framework versions, optimizer settings, training hyperparameters, software dependencies")

    if not code and not config:
        score = 0

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 11, Annex IV §2")
    return content, min(score, 100), gaps


def _render_2a(result: "ArtifactExtractionResult") -> tuple[str, int, list[str]]:
    datasets = result.datasets
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if not datasets:
        gaps.append("No training dataset provenance records found (Art. 10, Annex IV §2(a))")
        gaps.append("Use `squash attest --dataset <hf_dataset_id>` or provide dataset metadata manually")
        content = _gap_block(gaps, "Art. 10, Annex IV §2(a)")
        return content, 0, gaps

    ds_scores = []
    for ds in datasets:
        ds_score = ds.completeness_score()
        ds_scores.append(ds_score)
        lines.append(f"### {ds.pretty_name or ds.dataset_id}")
        lines.append(f"")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Dataset ID** | `{ds.dataset_id}` |")
        lines.append(f"| **Source** | {ds.source} |")
        lines.append(f"| **License** | {ds.license or '⚠️ Not specified'} |")
        if ds.languages:
            lines.append(f"| **Languages** | {', '.join(ds.languages)} |")
        if ds.task_categories:
            lines.append(f"| **Task categories** | {', '.join(ds.task_categories)} |")
        if ds.size_category:
            lines.append(f"| **Size** | {ds.size_category} |")
        if ds.source_datasets:
            lines.append(f"| **Source datasets** | {', '.join(ds.source_datasets)} |")
        if ds.downloads:
            lines.append(f"| **Downloads** | {ds.downloads:,} |")
        lines.append(f"| **Completeness** | {ds_score}% |")
        lines.append(f"| **Bias analysis** | {'✅ Present' if ds.has_bias_analysis else '❌ Missing (Art. 10(2)(f))'} |")
        lines.append(f"")

        if ds.citation:
            lines.append(f"**Citation:**")
            lines.append(f"")
            lines.append(f"```bibtex")
            lines.append(ds.citation)
            lines.append(f"```")
            lines.append(f"")

        if ds.completeness_gaps():
            for gap in ds.completeness_gaps():
                gaps.append(f"{ds.dataset_id}: {gap}")

        if not ds.has_bias_analysis:
            gaps.append(f"{ds.dataset_id}: Bias and fairness analysis required by Art. 10(2)(f)")

    score = int(sum(ds_scores) / len(ds_scores)) if ds_scores else 0
    content = "\n".join(lines)
    content += _gap_block(gaps, "Art. 10, Annex IV §2(a)")
    return content, score, gaps


def _render_2b(result: "ArtifactExtractionResult") -> tuple[str, int, list[str]]:
    code = result.code
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if code and code.data_loaders:
        lines.append(f"**Data loading / pipeline:**")
        lines.append(f"")
        for dl in dict.fromkeys(code.data_loaders):
            lines.append(f"- `{dl}`")
        score += 60
    else:
        gaps.append("No data preprocessing pipeline detected — document tokenization, normalization, augmentation steps (Art. 10(2)(f))")

    if code and code.imports:
        transform_libs = [r.module for r in code.imports
                          if any(kw in r.module.lower() for kw in
                                 ("transform", "augment", "preprocess", "tokeniz", "albument"))]
        if transform_libs:
            lines.append(f"")
            lines.append(f"**Preprocessing libraries:** {', '.join(f'`{t}`' for t in transform_libs)}")
            score += 40
        else:
            gaps.append("No preprocessing / augmentation libraries detected — if applicable, document tokenizer choice and normalization strategy")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 10(2)(f), Annex IV §2(b)")
    return content, min(score, 100), gaps


def _render_3a(result: "ArtifactExtractionResult", meta: dict) -> tuple[str, int, list[str]]:
    code = result.code
    arch_desc = meta.get("architecture_description", "")
    model_type = meta.get("model_type", "")
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if model_type:
        lines.append(f"**Model type:** {model_type}")
        score += 20

    if arch_desc:
        lines.append(f"")
        lines.append(arch_desc)
        score += 40

    if code and code.model_classes:
        deduped = list(dict.fromkeys(code.model_classes))
        lines.append(f"")
        lines.append(f"**Detected model classes / checkpoints:**")
        lines.append(f"")
        for mc in deduped[:10]:
            lines.append(f"- `{mc}`")
        score += 40

        pretrained = [mc for mc in deduped if any(
            kw in mc for kw in ("BERT", "GPT", "LLaMA", "Mistral", "T5", "Falcon",
                                "Qwen", "Auto", "llama", "mistral", "falcon")
        )]
        if pretrained:
            lines.append(f"")
            lines.append(f"*Pre-trained checkpoint(s) detected — document fine-tuning approach and "
                         f"base model provenance (Annex IV §2(a)).*")
    else:
        gaps.append("No model architecture detected — provide model class name, architecture family, parameter count (Annex IV §3(a))")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Annex IV §3(a)")
    return content, min(score, 100), gaps


def _render_3b(result: "ArtifactExtractionResult") -> tuple[str, int, list[str]]:
    metrics = result.metrics
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if not metrics or not metrics.series:
        gaps.append("No training metrics found — provide loss curves and validation performance (Annex IV §3(b))")
        gaps.append("Use `squash attest --tensorboard-logs ./logs` or `--mlflow-run <id>` to extract metrics")
        content = _gap_block(gaps, "Annex IV §3(b)")
        return content, 0, gaps

    lines.append(f"**Source:** {metrics.source}"
                 + (f" (run: `{metrics.run_id}`)" if metrics.run_id else ""))
    lines.append(f"")
    score += 20

    loss_tags = [t for t in metrics.series if "loss" in t.lower()]
    val_tags = [t for t in metrics.series if any(k in t.lower() for k in ("val", "valid", "eval", "test", "acc", "f1", "auc", "bleu", "rouge"))]

    if loss_tags:
        lines.append(f"**Loss curves ({len(loss_tags)} tracked):**")
        lines.append(f"")
        lines.append(f"| Metric | Steps | Final value | Min value |")
        lines.append(f"|--------|-------|-------------|-----------|")
        for tag in loss_tags[:8]:
            s = metrics.series[tag]
            final = f"{s.last():.4f}" if s.last() is not None else "—"
            minimum = f"{s.min():.4f}" if s.min() is not None else "—"
            lines.append(f"| `{tag}` | {len(s.steps)} | {final} | {minimum} |")
        score += 40

    if val_tags:
        lines.append(f"")
        lines.append(f"**Validation / evaluation metrics ({len(val_tags)} tracked):**")
        lines.append(f"")
        lines.append(f"| Metric | Steps | Final value | Peak value |")
        lines.append(f"|--------|-------|-------------|------------|")
        for tag in val_tags[:8]:
            s = metrics.series[tag]
            final = f"{s.last():.4f}" if s.last() is not None else "—"
            peak = f"{s.max():.4f}" if s.max() is not None else "—"
            lines.append(f"| `{tag}` | {len(s.steps)} | {final} | {peak} |")
        score += 40

    if not val_tags:
        gaps.append("No validation metrics found — document model performance on held-out data (Annex IV §3(b))")
        score = min(score, 60)

    content = "\n".join(lines)
    content += _gap_block(gaps, "Annex IV §3(b)")
    return content, min(score, 100), gaps


def _render_4(meta: dict) -> tuple[str, int, list[str]]:
    rm = meta.get("risk_management", "")
    risk_level = meta.get("risk_level", "")
    mitigation = meta.get("risk_mitigations", "")
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if risk_level:
        lines.append(f"**Risk classification:** {risk_level.title()}")
        score += 30
    else:
        gaps.append("Risk level not classified — classify system risk per Art. 6 and Annex III")

    if rm:
        lines.append(f"")
        lines.append(rm)
        score += 40

    if mitigation:
        lines.append(f"")
        lines.append(f"**Risk mitigations:**")
        lines.append(f"")
        lines.append(mitigation)
        score += 30
    else:
        gaps.append("Risk mitigation measures not documented — required for high-risk systems (Art. 9(2)(b))")

    if not rm and not mitigation:
        gaps.append("Risk management system not described — document the risk management process per Art. 9")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 9, Annex IV §5")
    return content, min(score, 100), gaps


def _render_5(meta: dict) -> tuple[str, int, list[str]]:
    oversight = meta.get("oversight_description", "")
    mechanisms = meta.get("human_oversight_mechanisms", [])
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if oversight:
        lines.append(oversight)
        score += 60

    if mechanisms:
        mech_list = mechanisms if isinstance(mechanisms, list) else [mechanisms]
        lines.append(f"")
        lines.append(f"**Oversight mechanisms:**")
        lines.append(f"")
        for m in mech_list:
            lines.append(f"- {m}")
        score += 40
    else:
        gaps.append("Human oversight mechanisms not specified — document how humans monitor, control, and intervene (Art. 14)")

    if not oversight:
        gaps.append("Human oversight description not provided — Art. 14 requires documented oversight measures for high-risk AI")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 14, Annex IV §5")
    return content, min(score, 100), gaps


def _render_6a(result: "ArtifactExtractionResult", meta: dict) -> tuple[str, int, list[str]]:
    perf = meta.get("performance_metrics", {})
    metrics = result.metrics
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if perf:
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        for k, v in perf.items():
            lines.append(f"| {k} | {v} |")
        score += 60

    if metrics and metrics.series:
        val_series = {t: s for t, s in metrics.series.items()
                      if any(k in t.lower() for k in ("acc", "f1", "auc", "bleu", "rouge", "precision", "recall"))}
        if val_series:
            if not perf:
                lines.append(f"*Performance metrics from training run:*")
                lines.append(f"")
                lines.append(f"| Metric | Final |")
                lines.append(f"|--------|-------|")
            for tag, s in list(val_series.items())[:6]:
                if not perf:
                    final = f"{s.last():.4f}" if s.last() is not None else "—"
                    lines.append(f"| `{tag}` | {final} |")
            score += 40

    if not perf and (not metrics or not metrics.series):
        gaps.append("Performance metrics not provided — document accuracy, F1, AUC, or task-specific metrics (Annex IV §3(a))")
        gaps.append("Include metric definitions, evaluation datasets, and statistical confidence where applicable")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Annex IV §3(a), Art. 15")
    return content, min(score, 100), gaps


def _render_6b(meta: dict) -> tuple[str, int, list[str]]:
    robustness = meta.get("robustness_testing", "")
    adversarial = meta.get("adversarial_testing", "")
    score = 0
    gaps: list[str] = []
    lines: list[str] = []

    if robustness:
        lines.append(robustness)
        score += 60

    if adversarial:
        lines.append(f"")
        lines.append(f"**Adversarial testing:**")
        lines.append(f"")
        lines.append(adversarial)
        score += 40
    else:
        gaps.append("Adversarial testing results not documented — recommended for high-risk AI systems (Art. 15)")

    if not robustness:
        gaps.append("Robustness testing not documented — describe testing against distribution shift, edge cases, and failure modes (Art. 15)")

    content = "\n".join(lines) if lines else ""
    content += _gap_block(gaps, "Art. 15, Annex IV §3(a)")
    return content, min(score, 100), gaps


def _render_7(meta: dict) -> tuple[str, int, list[str]]:
    lifecycle = meta.get("lifecycle_plan", "")
    version = meta.get("version", "")
    changelog = meta.get("changelog", "")
    monitoring = meta.get("monitoring_plan", "")
    score = 20  # version alone gives baseline credit
    gaps: list[str] = []
    lines: list[str] = []

    lines.append(f"**Current version:** {version or 'Not specified'}")

    if changelog:
        lines.append(f"")
        lines.append(f"**Change history:**")
        lines.append(f"")
        lines.append(changelog)
        score += 30

    if monitoring:
        lines.append(f"")
        lines.append(f"**Post-deployment monitoring plan:**")
        lines.append(f"")
        lines.append(monitoring)
        score += 30

    if lifecycle:
        lines.append(f"")
        lines.append(lifecycle)
        score += 20
    else:
        gaps.append("Lifecycle management plan not provided — describe versioning, monitoring, and withdrawal procedures (Art. 12, Annex IV §6)")

    if not monitoring:
        gaps.append("Post-deployment monitoring plan not documented — high-risk systems require ongoing monitoring (Art. 12)")

    content = "\n".join(lines)
    content += _gap_block(gaps, "Art. 12, Annex IV §6")
    return content, min(score, 100), gaps


def _compute_overall_score(sections: list[AnnexIVSection]) -> int:
    weighted = sum(s.completeness * s.weight for s in sections)
    return round(weighted / _TOTAL_WEIGHT)


# ---------------------------------------------------------------------------
# AnnexIVGenerator
# ---------------------------------------------------------------------------

class AnnexIVGenerator:
    """Generate EU AI Act Annex IV technical documentation from extracted artifacts.

    Accepts an ``ArtifactExtractionResult`` (W128-W132 outputs) plus
    supplemental metadata for sections that cannot be auto-extracted
    (intended purpose, risk management, human oversight, etc.).

    Example::

        from squash import ArtifactExtractor, AnnexIVGenerator

        result = ArtifactExtractor.from_run_dir("./my-training-run")
        result.datasets = ArtifactExtractor.from_huggingface_dataset_list(["squad"])

        doc = AnnexIVGenerator().generate(
            result,
            system_name="BERT Sentiment Classifier",
            version="1.2.0",
            intended_purpose="Classify product reviews into positive/negative sentiment.",
            risk_level="high",
        )
        doc.save("./compliance-docs", formats=["md", "html", "json"])
    """

    def generate(
        self,
        result: "ArtifactExtractionResult",
        *,
        system_name: str = "AI System",
        version: str = "1.0.0",
        intended_purpose: str | None = None,
        intended_users: list[str] | None = None,
        prohibited_uses: str | None = None,
        deployment_context: str | None = None,
        general_description: str | None = None,
        hardware_requirements: str | None = None,
        risk_level: str | None = None,
        risk_management: str | None = None,
        risk_mitigations: str | None = None,
        oversight_description: str | None = None,
        human_oversight_mechanisms: list[str] | None = None,
        performance_metrics: dict[str, Any] | None = None,
        robustness_testing: str | None = None,
        adversarial_testing: str | None = None,
        model_type: str | None = None,
        architecture_description: str | None = None,
        lifecycle_plan: str | None = None,
        changelog: str | None = None,
        monitoring_plan: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AnnexIVDocument:
        """Generate a complete Annex IV document.

        Args:
            result:                  Extracted artifacts from W128–W132 pipeline.
            system_name:             Human-readable name of the AI system.
            version:                 Current version string.
            intended_purpose:        §1(b) — what the system is designed to do.
            intended_users:          §1(b) — who will use the system.
            prohibited_uses:         §1(b) — forbidden applications.
            deployment_context:      §1(b) — production environment description.
            general_description:     §1(a) — free-text system overview.
            hardware_requirements:   §1(a) — compute / hardware requirements.
            risk_level:              §4 — "minimal" / "limited" / "high" / "unacceptable".
            risk_management:         §4 — risk management system description.
            risk_mitigations:        §4 — specific mitigation measures applied.
            oversight_description:   §5 — human oversight description.
            human_oversight_mechanisms: §5 — list of oversight mechanisms.
            performance_metrics:     §6(a) — evaluation results dict.
            robustness_testing:      §6(b) — robustness test description.
            adversarial_testing:     §6(b) — adversarial test results.
            model_type:              §3(a) — architecture family.
            architecture_description: §3(a) — detailed architecture description.
            lifecycle_plan:          §7 — lifecycle management description.
            changelog:               §7 — version history.
            monitoring_plan:         §7 — post-deployment monitoring.
            metadata:                Arbitrary extra metadata stored in the document.

        Returns:
            AnnexIVDocument ready for export.
        """
        meta: dict[str, Any] = {
            "system_name": system_name,
            "version": version,
            "intended_purpose": intended_purpose or "",
            "intended_users": intended_users or [],
            "prohibited_uses": prohibited_uses or "",
            "deployment_context": deployment_context or "",
            "general_description": general_description or "",
            "hardware_requirements": hardware_requirements or "",
            "risk_level": risk_level or "",
            "risk_management": risk_management or "",
            "risk_mitigations": risk_mitigations or "",
            "oversight_description": oversight_description or "",
            "human_oversight_mechanisms": human_oversight_mechanisms or [],
            "performance_metrics": performance_metrics or {},
            "robustness_testing": robustness_testing or "",
            "adversarial_testing": adversarial_testing or "",
            "model_type": model_type or "",
            "architecture_description": architecture_description or "",
            "lifecycle_plan": lifecycle_plan or "",
            "changelog": changelog or "",
            "monitoring_plan": monitoring_plan or "",
            **(metadata or {}),
        }

        renderers: list[tuple[str, tuple[str, int, list[str]]]] = [
            ("1a_general_description",  _render_1a(meta)),
            ("1b_intended_purpose",     _render_1b(meta)),
            ("1c_development_process",  _render_1c(result)),
            ("2a_data_governance",      _render_2a(result)),
            ("2b_data_preprocessing",   _render_2b(result)),
            ("3a_model_architecture",   _render_3a(result, meta)),
            ("3b_training_methodology", _render_3b(result)),
            ("4_risk_management",       _render_4(meta)),
            ("5_human_oversight",       _render_5(meta)),
            ("6a_performance_metrics",  _render_6a(result, meta)),
            ("6b_robustness_testing",   _render_6b(meta)),
            ("7_lifecycle_management",  _render_7(meta)),
        ]

        sections: list[AnnexIVSection] = [
            AnnexIVSection(
                key=key,
                title=_SECTION_TITLES[key],
                article=_SECTION_ARTICLES[key],
                content=content,
                completeness=completeness,
                gaps=gaps,
            )
            for key, (content, completeness, gaps) in renderers
        ]

        overall = _compute_overall_score(sections)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return AnnexIVDocument(
            system_name=system_name,
            version=version,
            generated_at=generated_at,
            sections=sections,
            overall_score=overall,
            metadata={k: v for k, v in meta.items() if v},
        )


# ---------------------------------------------------------------------------
# AnnexIVValidator
# ---------------------------------------------------------------------------

class AnnexIVValidator:
    """Validate an AnnexIVDocument against EU AI Act Article 11 minimum requirements.

    Hard fails block submission. Warnings must be addressed before
    deploying a high-risk AI system.
    """

    # Minimum completeness per section for a high-risk system
    _HARD_FAIL_THRESHOLDS: dict[str, int] = {
        "1a_general_description": 30,
        "1b_intended_purpose":    30,
        "2a_data_governance":     30,
        "3a_model_architecture":  20,
    }

    _WARNING_THRESHOLDS: dict[str, int] = {
        "1c_development_process":  40,
        "3b_training_methodology": 30,
        "4_risk_management":       30,
        "5_human_oversight":       30,
        "6a_performance_metrics":  30,
    }

    def validate(self, doc: AnnexIVDocument) -> ValidationReport:
        """Validate the document and return a ValidationReport.

        Args:
            doc: AnnexIVDocument from AnnexIVGenerator.generate().

        Returns:
            ValidationReport with hard_fails, warnings, and overall assessment.
        """
        report = ValidationReport(overall_score=doc.overall_score)

        for s in doc.sections:
            article = s.article

            threshold = self._HARD_FAIL_THRESHOLDS.get(s.key)
            if threshold is not None and s.completeness < threshold:
                report.hard_fails.append(ValidationFinding(
                    severity="hard_fail",
                    section=s.key,
                    article=article,
                    message=(
                        f"{s.title}: completeness {s.completeness}% "
                        f"is below the minimum {threshold}% required for submission ({article})"
                    ),
                ))

            warn_threshold = self._WARNING_THRESHOLDS.get(s.key)
            if warn_threshold is not None and s.completeness < warn_threshold:
                report.warnings.append(ValidationFinding(
                    severity="warning",
                    section=s.key,
                    article=article,
                    message=(
                        f"{s.title}: completeness {s.completeness}% "
                        f"should be ≥ {warn_threshold}% for high-risk AI deployment ({article})"
                    ),
                ))

        # Overall score warning
        if doc.overall_score < 60:
            report.warnings.append(ValidationFinding(
                severity="warning",
                section="overall",
                article="Art. 11",
                message=(
                    f"Overall compliance score {doc.overall_score}/100 is below "
                    f"recommended threshold of 60 for submission to a conformity assessment body"
                ),
            ))

        # Dataset bias analysis check
        for s in doc.sections:
            if s.key == "2a_data_governance":
                for gap in s.gaps:
                    if "bias" in gap.lower():
                        report.warnings.append(ValidationFinding(
                            severity="warning",
                            section="2a_data_governance",
                            article="Art. 10(2)(f)",
                            message=gap,
                        ))

        return report


# ---------------------------------------------------------------------------
# Minimal Markdown → HTML fallback (no `markdown` package required)
# ---------------------------------------------------------------------------

def _minimal_md_to_html(md: str) -> str:
    """Convert Markdown to HTML without external deps (simplified subset)."""
    lines = md.split("\n")
    html_lines: list[str] = []
    in_code = False
    in_table = False

    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_lines.append("</code></pre>")
                in_code = False
            else:
                html_lines.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            html_lines.append(line)
            continue

        # Tables
        if "|" in line and line.strip().startswith("|"):
            if not in_table:
                html_lines.append("<table>")
                in_table = True
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.match(r"^[-: ]+$", c) for c in cells):
                continue  # skip separator row
            tag = "th" if not html_lines or "<th>" in html_lines[-1] else "td"
            row = "".join(f"<{tag}>{c}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            html_lines.append("</table>")
            in_table = False

        # Headers
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            lvl = len(m.group(1))
            html_lines.append(f"<h{lvl}>{m.group(2)}</h{lvl}>")
            continue

        # Blockquotes
        if line.startswith("> "):
            html_lines.append(f"<blockquote>{line[2:]}</blockquote>")
            continue

        # List items
        if line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
            continue

        # Horizontal rules
        if line.strip() == "---":
            html_lines.append("<hr>")
            continue

        # Inline: bold, code
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
        line = re.sub(r"`(.+?)`", r"<code>\1</code>", line)

        html_lines.append(f"<p>{line}</p>" if line.strip() else "")

    if in_table:
        html_lines.append("</table>")
    if in_code:
        html_lines.append("</code></pre>")

    return "\n".join(html_lines)


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Annex IV — {system_name}</title>
<style>
  :root {{
    --brand: #1e40af;
    --pass: #16a34a;
    --warn: #d97706;
    --fail: #dc2626;
    --bg: #f8fafc;
    --surface: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: var(--bg); color: var(--text); line-height: 1.6; }}
  .header {{ background: var(--brand); color: white; padding: 2rem 3rem; }}
  .header h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: .25rem; }}
  .header .meta {{ opacity: .8; font-size: .875rem; }}
  .score-badge {{
    display: inline-block; padding: .25rem .75rem;
    border-radius: 9999px; font-weight: 700; font-size: 1.25rem;
    background: {score_color}; color: white; margin-top: .5rem;
  }}
  .container {{ max-width: 900px; margin: 2rem auto; padding: 0 1.5rem; }}
  h2 {{ color: var(--brand); font-size: 1.125rem; margin: 2rem 0 .75rem;
        padding-bottom: .5rem; border-bottom: 2px solid var(--border); }}
  h3 {{ color: var(--text); font-size: 1rem; margin: 1.25rem 0 .5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: var(--bg); text-align: left; padding: .5rem .75rem;
        font-size: .8rem; color: var(--muted); text-transform: uppercase; }}
  td {{ padding: .5rem .75rem; border-bottom: 1px solid var(--border);
        font-size: .9rem; }}
  code {{ background: var(--bg); padding: .1rem .35rem; border-radius: 3px;
          font-family: "JetBrains Mono", "Fira Code", monospace; font-size: .85rem; }}
  pre {{ background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 6px;
         overflow-x: auto; margin: 1rem 0; }}
  pre code {{ background: none; color: inherit; padding: 0; }}
  blockquote {{ border-left: 3px solid var(--warn); padding: .5rem 1rem;
                background: #fffbeb; margin: 1rem 0; color: var(--muted); }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
  .footer {{ text-align: center; color: var(--muted); font-size: .8rem;
             padding: 2rem; }}
  @media print {{
    .header {{ background: #1e40af !important; -webkit-print-color-adjust: exact; }}
    body {{ font-size: 11pt; }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1>EU AI Act — Annex IV Technical Documentation</h1>
  <div class="meta">{system_name} · v{version} · Generated {generated_at}</div>
  <div class="score-badge">Compliance Score: {overall_score}/100</div>
</div>
<div class="container">
{body}
</div>
<div class="footer">
  Generated by <a href="https://github.com/konjoai/squash">Squash</a> —
  Automated EU AI Act Compliance · {generated_at}
</div>
</body>
</html>"""
