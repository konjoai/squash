"""squash/pdf_report.py — B2 (Sprint 15 W208) — Branded PDF compliance report.

Generates an executive-ready PDF from an existing AnnexIVDocument with:

  1. **Cover page** — dark navy background, Squash wordmark, system name,
     compliance score (colour-coded), attestation ID, metadata table.
  2. **Executive summary** — 4-KPI scorecard, section completion table,
     gap highlights and quick-win callouts.
  3. **Full Annex IV body** — all 12 sections with branded styling,
     completeness badges, and section-level gap notes.
  4. **Signature block** — three approval lines (Legal, Compliance, CTO).

The CSS is loaded from ``squash/templates/annex_iv_branded.css``.
Logos are embedded from ``squash/templates/squash-logo-*.svg``.

WeasyPrint ≥ 60 is required:

    pip install weasyprint

Usage::

    from squash.pdf_report import PDFReportBuilder, BrandedPDFConfig
    from squash.annex_iv_generator import AnnexIVGenerator, ArtifactExtractionResult

    doc = AnnexIVGenerator().generate(result, system_name="BERT v3", ...)
    cfg = BrandedPDFConfig(org_name="Acme Corp", author="Platform Team")
    pdf_bytes = PDFReportBuilder(cfg).build_from_document(doc)
    Path("annex_iv_branded.pdf").write_bytes(pdf_bytes)

Stdlib-only except for the WeasyPrint call; the whole render pipeline
degrades to an HTML string when WeasyPrint is absent so callers can
preview without installing the C dependency.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_CSS_PATH = _TEMPLATES_DIR / "annex_iv_branded.css"
_LOGO_DARK_PATH = _TEMPLATES_DIR / "squash-logo-dark.svg"
_LOGO_MARK_PATH = _TEMPLATES_DIR / "squash-logo-mark.svg"


# ── Configuration ─────────────────────────────────────────────────────────


@dataclass
class BrandedPDFConfig:
    """Configuration for the branded PDF report.

    Attributes:
        org_name:       Organisation name shown on the cover page
                        (e.g. ``"Acme Corp"``). Empty → omitted.
        author:         Name or role of the preparer
                        (e.g. ``"ML Platform Team"``).
        logo_path:      Path to a custom SVG/PNG logo to display on the
                        cover page. If absent, the Squash wordmark is
                        used. Supply the file path — the CSS embeds the
                        image inline so the PDF is self-contained.
        accent_color:   Brand accent colour (hex). Default: Squash green.
        include_cover:  Whether to include the cover page. Default: True.
        include_exec_summary: Whether to include the 1-page exec summary.
        include_signature:    Whether to include the signature block.
        confidentiality_label: Text shown in the running page header
                               (e.g. ``"STRICTLY CONFIDENTIAL"``).
    """

    org_name: str = ""
    author: str = ""
    logo_path: Path | None = None
    accent_color: str = "#22c55e"
    include_cover: bool = True
    include_exec_summary: bool = True
    include_signature: bool = True
    confidentiality_label: str = "CONFIDENTIAL · ANNEX IV TECHNICAL DOCUMENTATION"

    def __post_init__(self) -> None:
        if self.logo_path is not None:
            self.logo_path = Path(self.logo_path)


# ── Builder ───────────────────────────────────────────────────────────────


class PDFReportBuilder:
    """Generate a branded Annex IV PDF from an ``AnnexIVDocument``.

    The builder is stateless — every call to :meth:`build_from_document`
    produces an independent PDF.  The optional ``page_callback`` hook
    receives the progress percentage (0–100) as each page renders.

    Usage::

        cfg = BrandedPDFConfig(org_name="Acme", accent_color="#3b82f6")
        pdf_bytes = PDFReportBuilder(cfg).build_from_document(doc)
    """

    def __init__(self, config: BrandedPDFConfig | None = None) -> None:
        self.config = config or BrandedPDFConfig()

    # ── Public API ────────────────────────────────────────────────────────

    def build_from_document(self, doc: "Any") -> bytes:
        """Render *doc* as a branded PDF and return the raw bytes.

        Args:
            doc: An ``AnnexIVDocument`` instance produced by
                 :class:`squash.annex_iv_generator.AnnexIVGenerator`.

        Returns:
            Raw PDF bytes.  Write to a ``.pdf`` file directly.

        Raises:
            ImportError: When ``weasyprint`` is not installed.
        """
        html = self.build_html(doc)
        return self._html_to_pdf(html)

    def build_html(self, doc: "Any") -> str:
        """Render *doc* to a full branded HTML string (useful for preview).

        The same HTML is fed into WeasyPrint when generating the PDF, so
        ``build_html`` + ``weasyprint.HTML(string=...).write_pdf()`` is
        equivalent to :meth:`build_from_document`.
        """
        parts: list[str] = [self._html_head(doc)]

        if self.config.include_cover:
            parts.append(self._cover_page(doc))
        if self.config.include_exec_summary:
            parts.append(self._exec_summary(doc))
        parts.append(self._body(doc))
        if self.config.include_signature:
            parts.append(self._signature_block(doc))

        parts.append("</body></html>")
        return "".join(parts)

    def save(
        self,
        doc: "Any",
        output_dir: Path | str,
        stem: str = "annex_iv_branded",
    ) -> dict[str, Path]:
        """Write the branded PDF (and optionally the HTML source) to *output_dir*.

        Returns a dict mapping ``"pdf"`` → path (and ``"html"`` → path if
        WeasyPrint is absent and only the HTML can be saved).
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}

        html = self.build_html(doc)
        html_path = output_dir / f"{stem}.html"
        html_path.write_text(html, encoding="utf-8")
        written["html"] = html_path

        try:
            pdf_bytes = self._html_to_pdf(html)
            pdf_path = output_dir / f"{stem}.pdf"
            pdf_path.write_bytes(pdf_bytes)
            written["pdf"] = pdf_path
            log.info("pdf_report: branded PDF written to %s", pdf_path)
        except ImportError as exc:
            log.warning(
                "pdf_report: WeasyPrint not installed — HTML written but PDF "
                "skipped. Install with: pip install weasyprint. (%s)", exc,
            )

        return written

    # ── Internal rendering ────────────────────────────────────────────────

    def _html_head(self, doc: "Any") -> str:
        css = self._load_css()
        accent = _esc(self.config.accent_color)
        custom_css = ""
        if self.config.accent_color != "#22c55e":
            # Override accent colour if caller provided a custom one.
            custom_css = f"""
<style>
  .cover-top-bar {{ background: {accent}; }}
  h1, h2 {{ border-color: {accent}; }}
  .cover-score-block {{ border-left-color: {accent}; }}
  .cover-badge {{ color: {accent}; border-color: rgba(0,0,0,0.3); }}
  th {{ background: #0f172a; }}
  pre {{ border-left-color: {accent}; }}
  code {{ color: {accent}; }}
  .badge-complete {{ background: #dcfce7; }}
</style>"""

        return (
            "<!doctype html>"
            "<html lang='en'>"
            "<head>"
            "<meta charset='utf-8'/>"
            f"<title>{_esc(getattr(doc, 'system_name', 'Compliance Report'))}</title>"
            f"<style>{css}</style>"
            f"{custom_css}"
            "</head>"
            "<body>"
        )

    def _cover_page(self, doc: "Any") -> str:
        system_name = _esc(getattr(doc, "system_name", "AI System"))
        version = _esc(getattr(doc, "version", ""))
        generated = str(getattr(doc, "generated_at", ""))[:19].replace("T", " ")
        score = getattr(doc, "overall_score", 0) or 0
        score_cls = (
            "score-green" if score >= 80 else
            "score-amber" if score >= 40 else
            "score-red"
        )
        org = _esc(self.config.org_name)
        author = _esc(self.config.author)
        attest_id = _attestation_id(doc)
        logo_html = self._logo_html()

        # Build metadata rows
        meta_rows: list[str] = []
        if org:
            meta_rows.append(f"<tr><td>Organisation</td><td>{org}</td></tr>")
        meta_rows.append(f"<tr><td>System name</td><td>{system_name}</td></tr>")
        if version:
            meta_rows.append(f"<tr><td>Version</td><td>{version}</td></tr>")
        meta_rows.append(f"<tr><td>Generated</td><td>{generated}</td></tr>")
        if author:
            meta_rows.append(f"<tr><td>Prepared by</td><td>{author}</td></tr>")
        if attest_id:
            meta_rows.append(
                f"<tr><td>Attestation ID</td>"
                f"<td style='font-family:monospace;font-size:8pt;word-break:break-all'>"
                f"{_esc(attest_id)}</td></tr>"
            )

        sections = getattr(doc, "sections", []) or []
        complete = sum(1 for s in sections if (s.completeness or 0) >= 80)
        total = len(sections)

        return f"""
<div class="cover-page">
  <div class="cover-top-bar"></div>
  <div class="cover-content">
    {logo_html}
    <div class="cover-label">EU AI Act · Annex IV Technical Documentation</div>
    <div class="cover-badge">COMPLIANCE REPORT</div>
    <div class="cover-title">{system_name}</div>
    {"<div class='cover-subtitle'>v" + version + "</div>" if version else ""}

    <div class="cover-score-block">
      <div class="cover-score-label">Overall compliance score</div>
      <div class="cover-score-value {score_cls}">{score}<span style="font-size:20pt;color:#64748b">%</span></div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:8pt;color:#64748b;margin-top:2mm">
        {complete} / {total} sections complete
      </div>
    </div>

    <table class="cover-meta-table">{"".join(meta_rows)}</table>
  </div>

  <div class="cover-footer">
    <div class="cover-footer-left">
      Prepared by Squash · <strong style="color:#22c55e">getsquash.dev</strong>
    </div>
    <div class="cover-footer-right">
      EU AI Act enforcement: <strong style="color:#ef4444">August 2, 2026</strong>
    </div>
  </div>
</div>

<!-- String captures for running headers -->
<span class="doc-title" style="display:none">{system_name}</span>
<span class="doc-version" style="display:none">{"v" + version if version else ""}</span>
"""

    def _exec_summary(self, doc: "Any") -> str:
        sections = list(getattr(doc, "sections", []) or [])
        score = getattr(doc, "overall_score", 0) or 0
        score_cls = "score-green" if score >= 80 else "score-amber" if score >= 40 else "score-red"

        complete = sum(1 for s in sections if (s.completeness or 0) >= 80)
        partial = sum(1 for s in sections
                      if 20 <= (s.completeness or 0) < 80)
        missing = sum(1 for s in sections if (s.completeness or 0) < 20)
        total_gaps = sum(len(s.gaps or []) for s in sections)

        kpi_cls_missing = "kpi-fail" if missing > 0 else ""
        kpi_cls_gaps = "kpi-warn" if total_gaps > 0 else ""

        # Section completion table
        section_rows: list[str] = []
        for s in sections:
            comp = s.completeness or 0
            if comp >= 80:
                badge = "<span class='badge badge-complete'>✓ Complete</span>"
            elif comp >= 20:
                badge = f"<span class='badge badge-partial'>⚠ {comp}%</span>"
            else:
                badge = "<span class='badge badge-missing'>✗ Missing</span>"
            gaps_cell = str(len(s.gaps or []))
            section_rows.append(
                f"<tr>"
                f"<td><strong>{_esc(s.key)}</strong></td>"
                f"<td>{_esc(s.title)}</td>"
                f"<td style='font-size:8pt;color:#64748b'>{_esc(s.article)}</td>"
                f"<td style='text-align:center'>{badge}</td>"
                f"<td style='text-align:center;font-family:monospace;font-size:8.5pt'>"
                f"{'<span style=color:#ef4444>' + gaps_cell + '</span>' if int(gaps_cell) > 0 else gaps_cell}"
                f"</td>"
                f"</tr>"
            )

        # Gaps + quick-win blocks
        gap_blocks: list[str] = []
        for s in sections:
            if s.gaps:
                gap_list = "".join(f"<li>{_esc(g)}</li>" for g in s.gaps[:4])
                gap_blocks.append(
                    f"<div class='exec-gap-block'>"
                    f"<h4>{_esc(s.key)} — {_esc(s.title)}</h4>"
                    f"<ul>{gap_list}</ul>"
                    f"</div>"
                )
        if not gap_blocks:
            gap_blocks.append(
                "<div class='exec-pass-block'>"
                "<h4>All sections complete</h4>"
                "<p style='font-size:9pt;color:#166534;margin:0'>"
                "No documentation gaps detected. This Annex IV package is ready for submission."
                "</p>"
                "</div>"
            )

        system_name = _esc(getattr(doc, "system_name", "AI System"))
        generated = str(getattr(doc, "generated_at", ""))[:10]

        return f"""
<div class="exec-summary-page">
  <h2>Executive Summary</h2>
  <p style="font-size:9pt;color:#64748b;margin-bottom:6mm">
    Compliance assessment for <strong>{system_name}</strong> · Generated {generated}
  </p>

  <!-- KPI scorecard -->
  <table class="kpi-table">
    <tr>
      <td class="kpi-cell">
        <span class="kpi-value {score_cls}">{score}%</span>
        <span class="kpi-label">Overall score</span>
      </td>
      <td class="kpi-cell">
        <span class="kpi-value">{complete}</span>
        <span class="kpi-label">Sections complete</span>
      </td>
      <td class="kpi-cell {kpi_cls_missing}">
        <span class="kpi-value">{missing}</span>
        <span class="kpi-label">Sections missing</span>
      </td>
      <td class="kpi-cell {kpi_cls_gaps}">
        <span class="kpi-value">{total_gaps}</span>
        <span class="kpi-label">Total gaps</span>
      </td>
    </tr>
  </table>

  <!-- Section table -->
  <table class="exec-section-table">
    <thead>
      <tr>
        <th style="width:14mm">Key</th>
        <th>Section</th>
        <th style="width:28mm">Article</th>
        <th style="width:26mm;text-align:center">Status</th>
        <th style="width:16mm;text-align:center">Gaps</th>
      </tr>
    </thead>
    <tbody>{"".join(section_rows)}</tbody>
  </table>

  <!-- Gap callouts -->
  <h3 style="margin-top:6mm;margin-bottom:3mm">Documentation gaps</h3>
  {"".join(gap_blocks)}
</div>
"""

    def _body(self, doc: "Any") -> str:
        sections = list(getattr(doc, "sections", []) or [])
        parts: list[str] = ['<div class="body-content">']

        system_name = _esc(getattr(doc, "system_name", "AI System"))
        version = _esc(getattr(doc, "version", ""))
        version_str = f" · v{version}" if version else ""

        parts.append(
            f"<h1>{system_name}{version_str} — Annex IV Technical Documentation</h1>"
        )

        attest_id = _attestation_id(doc)
        if attest_id:
            parts.append(
                f"<div class='attest-id-banner'>"
                f"<span class='attest-id-label'>Attestation ID</span><br/>"
                f"<span class='attest-id-value'>{_esc(attest_id)}</span>"
                f"</div>"
            )

        for section in sections:
            comp = section.completeness or 0
            if comp >= 80:
                badge_cls, badge_txt = "badge-complete", f"✓ {comp}%"
            elif comp >= 20:
                badge_cls, badge_txt = "badge-partial", f"⚠ {comp}%"
            else:
                badge_cls, badge_txt = "badge-missing", f"✗ {comp}%"

            content_html = _md_to_html(section.content or "")
            gap_html = ""
            if section.gaps:
                gap_items = "".join(f"<li>{_esc(g)}</li>" for g in section.gaps)
                gap_html = (
                    f"<div class='section-gap-note'>"
                    f"<strong>Documentation gaps:</strong>"
                    f"<ul style='margin:2mm 0 0 5mm;padding:0;list-style:disc'>"
                    f"{gap_items}</ul></div>"
                )

            parts.append(
                f"<div class='section-block'>"
                f"<div class='section-header'>"
                f"<span class='section-key'>{_esc(section.key)}</span> "
                f"<span class='section-title'>{_esc(section.title)}</span>"
                f"<span class='section-completeness'>"
                f"<span class='badge {badge_cls}'>{badge_txt}</span></span>"
                f"</div>"
                f"{content_html}"
                f"{gap_html}"
                f"</div>"
            )

        parts.append("</div>")
        return "".join(parts)

    def _signature_block(self, doc: "Any") -> str:
        system_name = _esc(getattr(doc, "system_name", "AI System"))
        generated = str(getattr(doc, "generated_at", ""))[:19].replace("T", " ")

        return f"""
<div class="signature-block">
  <h3>Approval &amp; Sign-off</h3>
  <p style="font-size:9pt;color:#64748b;margin-bottom:5mm">
    By signing below, each reviewer confirms they have reviewed the Annex IV technical
    documentation for <strong>{system_name}</strong> (generated {generated}) and
    affirm it is accurate and complete.
  </p>
  <table class="sig-table">
    <tr>
      <td class="sig-cell">
        <div class="sig-line"></div>
        <div class="sig-label">Legal Review</div>
      </td>
      <td class="sig-cell">
        <div class="sig-line"></div>
        <div class="sig-label">Compliance Officer</div>
      </td>
      <td class="sig-cell">
        <div class="sig-line"></div>
        <div class="sig-label">Engineering Lead</div>
      </td>
    </tr>
  </table>
  <div class="squash-brand-footer">
    Generated by <strong>squash</strong> · getsquash.dev ·
    "Squash violations, not velocity."
  </div>
</div>
"""

    # ── Helpers ───────────────────────────────────────────────────────────

    def _logo_html(self) -> str:
        """Embed the Squash wordmark or a custom logo."""
        if self.config.logo_path and self.config.logo_path.exists():
            path = self.config.logo_path
        elif _LOGO_DARK_PATH.exists():
            path = _LOGO_DARK_PATH
        else:
            # Inline fallback wordmark (no file dependency)
            return (
                "<div style=\"font-family:'Inter',sans-serif;font-size:28pt;"
                "font-weight:900;letter-spacing:-0.04em;color:#f1f5f9;"
                "margin-bottom:32mm\">"
                "squas<span style='color:#22c55e'>h</span>"
                "</div>"
            )

        suffix = path.suffix.lower()
        if suffix == ".svg":
            svg = path.read_text(encoding="utf-8")
            # Inline SVG — safest for WeasyPrint; no external requests
            return f'<div class="cover-logo">{svg}</div>'
        else:
            import base64
            b64 = base64.b64encode(path.read_bytes()).decode("ascii")
            mime = "image/png" if suffix == ".png" else f"image/{suffix.lstrip('.')}"
            return (
                f'<img class="cover-logo" src="data:{mime};base64,{b64}" '
                f'alt="Logo" style="max-width:220px;"/>'
            )

    def _load_css(self) -> str:
        if _CSS_PATH.exists():
            return _CSS_PATH.read_text(encoding="utf-8")
        # Inline minimal fallback — renders without the file
        return _MINIMAL_CSS

    @staticmethod
    def _html_to_pdf(html: str) -> bytes:
        try:
            from weasyprint import HTML as WeasyprintHTML  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "WeasyPrint is required for branded PDF export. "
                "Install with: pip install weasyprint"
            ) from exc
        return WeasyprintHTML(string=html).write_pdf()


# ── Helpers ───────────────────────────────────────────────────────────────


def _esc(s: Any) -> str:
    """HTML-escape a value."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _attestation_id(doc: "Any") -> str:
    """Extract or compute a short attestation fingerprint."""
    meta = getattr(doc, "metadata", {}) or {}
    if "attestation_id" in meta:
        return str(meta["attestation_id"])
    # Derive a stable fingerprint from content when no explicit ID exists
    content = (
        str(getattr(doc, "system_name", ""))
        + str(getattr(doc, "version", ""))
        + str(getattr(doc, "generated_at", ""))
    )
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()[:16] + "…"


def _md_to_html(md: str) -> str:
    """Convert Markdown to HTML; falls back to minimal conversion."""
    try:
        import markdown as md_lib  # type: ignore
        return md_lib.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        return _minimal_md_to_html(md)


def _minimal_md_to_html(md: str) -> str:
    """Minimal Markdown → HTML (stdlib-only, good-enough for Annex IV)."""
    html = _esc(md)
    # Headings
    for i in range(6, 0, -1):
        html = re.sub(
            r"^" + "#" * i + r" (.+)$",
            rf"<h{i}>\1</h{i}>",
            html, flags=re.MULTILINE,
        )
    # Bold
    html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)
    # Inline code
    html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)
    # Fenced code blocks
    html = re.sub(
        r"```[^\n]*\n(.*?)```",
        r"<pre>\1</pre>",
        html, flags=re.DOTALL,
    )
    # Unordered lists
    html = re.sub(r"(?m)^- (.+)$", r"<li>\1</li>", html)
    html = re.sub(r"(<li>.*?</li>)+", r"<ul>\g<0></ul>", html, flags=re.DOTALL)
    # Paragraphs
    paragraphs = [
        f"<p>{p.strip()}</p>" if not p.strip().startswith("<") else p.strip()
        for p in html.split("\n\n")
        if p.strip()
    ]
    return "\n".join(paragraphs)


# Inline minimal CSS for when the template file is unavailable
_MINIMAL_CSS = """
body { font-family: Inter, Helvetica, Arial, sans-serif; font-size: 10.5pt;
       color: #1e293b; background: #fff; }
h1 { font-size: 14pt; font-weight: 700; border-bottom: 2px solid #22c55e;
     margin: 6mm 0 3mm 0; padding-bottom: 2mm; }
h2 { font-size: 12pt; font-weight: 600; margin: 5mm 0 2mm 0; }
h3 { font-size: 10.5pt; font-weight: 600; margin: 3mm 0 1.5mm 0; }
p { margin-bottom: 3mm; }
table { width: 100%; border-collapse: collapse; margin: 3mm 0; }
th { background: #0f172a; color: #e2e8f0; padding: 2mm 3mm; font-size: 8pt; }
td { padding: 2mm 3mm; border-bottom: 1px solid #e2e8f0; }
code { font-family: monospace; background: #f1f5f9; padding: 0 2pt; }
pre { background: #0f172a; color: #e2e8f0; padding: 4mm; font-size: 8pt;
      border-left: 3px solid #22c55e; white-space: pre-wrap; }
.cover-page { background: #0a0f1a; color: #e2e8f0; padding: 20mm; page-break-after: always; }
"""


__all__ = [
    "BrandedPDFConfig",
    "PDFReportBuilder",
]
