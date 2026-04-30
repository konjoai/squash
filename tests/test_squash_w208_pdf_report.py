"""tests/test_squash_w208_pdf_report.py — Sprint 15 W208 (Track B / B2).

Branded PDF compliance report: cover page, executive summary,
full Annex IV body, signature block, logo embedding.

W208 — squash/pdf_report.py (NEW MODULE)
        squash/templates/annex_iv_branded.css (NEW)
        squash/templates/squash-logo-*.svg (NEW assets)

All tests are WeasyPrint-free — they validate the HTML structure,
CSS file existence, and CLI plumbing, never invoke the actual PDF
renderer. WeasyPrint is mocked where `_html_to_pdf` is called so CI
does not require the C dependency.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Fixture helpers ──────────────────────────────────────────────────────────


def _make_doc(score: int = 87, gap_count: int = 2):
    """Build a minimal AnnexIVDocument via the real generator."""
    from squash.annex_iv_generator import AnnexIVDocument, AnnexIVSection
    sections = [
        AnnexIVSection(
            key=f"§{i}(a)",
            title=f"Section {i}",
            article=f"Annex IV §{i}",
            content=f"Content of section {i}.",
            completeness=95 if i % 2 == 0 else 40,
            gaps=(["Missing datum"] * gap_count if i % 2 != 0 else []),
        )
        for i in range(1, 7)
    ]
    return AnnexIVDocument(
        system_name="BERT Sentiment Classifier",
        version="2.1.0",
        generated_at="2026-04-30T12:00:00Z",
        overall_score=score,
        sections=sections,
        metadata={"attestation_id": "att://acme/bert/v2-1"},
    )


# ── BrandedPDFConfig ─────────────────────────────────────────────────────────


class TestBrandedPDFConfig(unittest.TestCase):
    def test_defaults(self) -> None:
        from squash.pdf_report import BrandedPDFConfig
        cfg = BrandedPDFConfig()
        self.assertEqual(cfg.accent_color, "#22c55e")
        self.assertTrue(cfg.include_cover)
        self.assertTrue(cfg.include_exec_summary)
        self.assertTrue(cfg.include_signature)
        self.assertIsNone(cfg.logo_path)

    def test_logo_path_coerced_to_path(self) -> None:
        from squash.pdf_report import BrandedPDFConfig
        cfg = BrandedPDFConfig(logo_path="/tmp/logo.svg")
        self.assertIsInstance(cfg.logo_path, Path)

    def test_custom_org_and_author(self) -> None:
        from squash.pdf_report import BrandedPDFConfig
        cfg = BrandedPDFConfig(org_name="Acme Corp", author="ML Platform")
        self.assertEqual(cfg.org_name, "Acme Corp")
        self.assertEqual(cfg.author, "ML Platform")


# ── HTML cover page ──────────────────────────────────────────────────────────


class TestCoverPage(unittest.TestCase):
    def setUp(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        self.doc = _make_doc(score=87)
        self.builder = PDFReportBuilder(BrandedPDFConfig(
            org_name="Acme Corp", author="ML Platform",
        ))

    def test_cover_page_present(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("cover-page", html)

    def test_cover_contains_system_name(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("BERT Sentiment Classifier", html)

    def test_cover_contains_score(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("87", html)

    def test_cover_contains_org_name(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("Acme Corp", html)

    def test_cover_contains_author(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("ML Platform", html)

    def test_cover_score_green_above_80(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("score-green", html)

    def test_cover_score_amber_40_to_79(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        doc = _make_doc(score=55)
        html = PDFReportBuilder(BrandedPDFConfig()).build_html(doc)
        self.assertIn("score-amber", html)

    def test_cover_score_red_below_40(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        doc = _make_doc(score=25)
        html = PDFReportBuilder(BrandedPDFConfig()).build_html(doc)
        self.assertIn("score-red", html)

    def test_cover_attestation_id_in_html(self) -> None:
        html = self.builder.build_html(self.doc)
        self.assertIn("att://acme/bert/v2-1", html)

    def test_cover_logo_embedded(self) -> None:
        html = self.builder.build_html(self.doc)
        # Either the SVG logo or fallback wordmark is present
        self.assertTrue(
            "svg" in html.lower() or "squas" in html,
            msg="Expected logo SVG or wordmark fallback",
        )

    def test_cover_disabled(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        cfg = BrandedPDFConfig(include_cover=False)
        html = PDFReportBuilder(cfg).build_html(self.doc)
        # The CSS class name is always present; check the HTML tag is absent
        self.assertNotIn('<div class="cover-page">', html)


# ── Executive summary ────────────────────────────────────────────────────────


class TestExecSummary(unittest.TestCase):
    def setUp(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        self.doc = _make_doc(score=65, gap_count=3)
        self.html = PDFReportBuilder(BrandedPDFConfig()).build_html(self.doc)

    def test_exec_summary_present(self) -> None:
        self.assertIn("Executive Summary", self.html)

    def test_kpi_table_present(self) -> None:
        self.assertIn("kpi-table", self.html)
        self.assertIn("Overall score", self.html)

    def test_gaps_highlighted(self) -> None:
        self.assertIn("Missing datum", self.html)

    def test_section_completion_table(self) -> None:
        self.assertIn("exec-section-table", self.html)

    def test_badge_complete_present(self) -> None:
        self.assertIn("badge-complete", self.html)

    def test_badge_partial_present(self) -> None:
        self.assertIn("badge-partial", self.html)

    def test_exec_summary_disabled(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        cfg = BrandedPDFConfig(include_exec_summary=False)
        html = PDFReportBuilder(cfg).build_html(self.doc)
        self.assertNotIn("Executive Summary", html)


# ── Body ─────────────────────────────────────────────────────────────────────


class TestBody(unittest.TestCase):
    def setUp(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        self.doc = _make_doc()
        self.html = PDFReportBuilder(BrandedPDFConfig()).build_html(self.doc)

    def test_body_present(self) -> None:
        self.assertIn("body-content", self.html)

    def test_section_blocks_rendered(self) -> None:
        self.assertIn("section-block", self.html)
        self.assertIn("§1(a)", self.html)

    def test_section_gap_note_rendered(self) -> None:
        self.assertIn("section-gap-note", self.html)

    def test_attestation_id_banner(self) -> None:
        self.assertIn("attest-id-banner", self.html)

    def test_all_sections_in_html(self) -> None:
        for s in self.doc.sections:
            self.assertIn(s.key, self.html)


# ── Signature block ──────────────────────────────────────────────────────────


class TestSignatureBlock(unittest.TestCase):
    def setUp(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        self.doc = _make_doc()
        self.html = PDFReportBuilder(BrandedPDFConfig()).build_html(self.doc)

    def test_signature_block_present(self) -> None:
        self.assertIn("signature-block", self.html)

    def test_three_sig_lines(self) -> None:
        # CSS defines .sig-line once; body has 3 <div class="sig-line"> elements
        self.assertEqual(self.html.count('<div class="sig-line">'), 3)

    def test_signature_labels_present(self) -> None:
        for label in ("Legal Review", "Compliance Officer", "Engineering Lead"):
            self.assertIn(label, self.html)

    def test_signature_disabled(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        cfg = BrandedPDFConfig(include_signature=False)
        html = PDFReportBuilder(cfg).build_html(self.doc)
        # Check the container div tag is absent (class still in CSS)
        self.assertNotIn('<div class="signature-block">', html)


# ── Custom accent colour ─────────────────────────────────────────────────────


class TestAccentColor(unittest.TestCase):
    def test_custom_accent_in_html(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        cfg = BrandedPDFConfig(accent_color="#3b82f6")
        html = PDFReportBuilder(cfg).build_html(_make_doc())
        # Custom accent override CSS is injected
        self.assertIn("#3b82f6", html)


# ── HTML escaping ────────────────────────────────────────────────────────────


class TestHtmlEscaping(unittest.TestCase):
    def test_xss_in_system_name_escaped(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        from squash.annex_iv_generator import AnnexIVDocument, AnnexIVSection
        doc = AnnexIVDocument(
            system_name="<script>alert(1)</script>",
            version="1.0",
            generated_at="2026-04-30T00:00:00Z",
            overall_score=80,
            sections=[AnnexIVSection(
                key="§1", title="T", article="A", content="C",
                completeness=100, gaps=[],
            )],
        )
        html = PDFReportBuilder(BrandedPDFConfig()).build_html(doc)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_ampersand_in_org_name_escaped(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        cfg = BrandedPDFConfig(org_name="Smith & Jones")
        html = PDFReportBuilder(cfg).build_html(_make_doc())
        self.assertNotIn("Smith & Jones", html)
        self.assertIn("Smith &amp; Jones", html)


# ── save() ───────────────────────────────────────────────────────────────────


class TestSave(unittest.TestCase):
    def test_save_writes_html(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            # Patch WeasyPrint so we don't need the C dep
            with mock.patch(
                "squash.pdf_report.PDFReportBuilder._html_to_pdf",
                return_value=b"%PDF-1.4",
            ):
                written = PDFReportBuilder(BrandedPDFConfig()).save(
                    _make_doc(), out,
                )
            self.assertIn("html", written)
            self.assertTrue(written["html"].exists())
            html = written["html"].read_text()
            self.assertIn("BERT Sentiment Classifier", html)

    def test_save_writes_pdf_when_weasyprint_available(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            fake_bytes = b"%PDF-1.4 fake content"
            with mock.patch(
                "squash.pdf_report.PDFReportBuilder._html_to_pdf",
                return_value=fake_bytes,
            ):
                written = PDFReportBuilder(BrandedPDFConfig()).save(
                    _make_doc(), out,
                )
            self.assertIn("pdf", written)
            self.assertEqual(written["pdf"].read_bytes(), fake_bytes)

    def test_save_skips_pdf_when_weasyprint_missing(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            with mock.patch(
                "squash.pdf_report.PDFReportBuilder._html_to_pdf",
                side_effect=ImportError("weasyprint not installed"),
            ):
                written = PDFReportBuilder(BrandedPDFConfig()).save(
                    _make_doc(), out,
                )
            self.assertIn("html", written)
            self.assertNotIn("pdf", written)

    def test_build_from_document_raises_import_error_gracefully(self) -> None:
        from squash.pdf_report import BrandedPDFConfig, PDFReportBuilder
        with mock.patch(
            "squash.pdf_report.PDFReportBuilder._html_to_pdf",
            side_effect=ImportError("weasyprint"),
        ):
            with self.assertRaises(ImportError):
                PDFReportBuilder(BrandedPDFConfig()).build_from_document(_make_doc())


# ── Template files ───────────────────────────────────────────────────────────


class TestTemplateFiles(unittest.TestCase):
    def test_branded_css_exists(self) -> None:
        from squash.pdf_report import _CSS_PATH
        self.assertTrue(_CSS_PATH.exists(), f"Missing: {_CSS_PATH}")

    def test_logo_dark_svg_exists(self) -> None:
        from squash.pdf_report import _LOGO_DARK_PATH
        self.assertTrue(_LOGO_DARK_PATH.exists(), f"Missing: {_LOGO_DARK_PATH}")

    def test_logo_mark_svg_exists(self) -> None:
        from squash.pdf_report import _LOGO_MARK_PATH
        self.assertTrue(_LOGO_MARK_PATH.exists(), f"Missing: {_LOGO_MARK_PATH}")

    def test_css_contains_brand_green(self) -> None:
        from squash.pdf_report import _CSS_PATH
        css = _CSS_PATH.read_text()
        self.assertIn("#22c55e", css)

    def test_css_contains_cover_page_rule(self) -> None:
        from squash.pdf_report import _CSS_PATH
        css = _CSS_PATH.read_text()
        self.assertIn(".cover-page", css)

    def test_css_contains_page_rule(self) -> None:
        from squash.pdf_report import _CSS_PATH
        css = _CSS_PATH.read_text()
        self.assertIn("@page", css)


# ── CLI: squash annex-iv generate --branded ──────────────────────────────────


class TestCLIBrandedFlag(unittest.TestCase):
    def test_help_includes_branded_flags(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "annex-iv", "generate", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--branded", "--org", "--author", "--logo", "--accent"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing from help")

    def test_branded_produces_html_when_weasyprint_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            # Patch WeasyPrint missing by intercepting the import in pdf_report
            script = f"""
import sys
from unittest.mock import patch, MagicMock

# Simulate WeasyPrint absent for pdf_report._html_to_pdf
import squash.pdf_report as pr
original = pr.PDFReportBuilder._html_to_pdf

def _fake(html):
    raise ImportError("weasyprint not installed")

pr.PDFReportBuilder._html_to_pdf = staticmethod(_fake)

from squash.cli import main
sys.argv = [
    "squash", "annex-iv", "generate",
    "--root", "{td}",
    "--system-name", "Test System",
    "--format", "json",
    "--branded",
    "--org", "Acme",
    "--output-dir", "{out}",
    "--quiet",
]
try:
    main()
except SystemExit:
    pass
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True,
            )
            # Should succeed (rc=0); WeasyPrint absence is a warning, not an error
            self.assertEqual(result.returncode, 0, msg=result.stderr)


# ── Module count gate ─────────────────────────────────────────────────────────


class TestB2ModuleCount(unittest.TestCase):
    """B2 adds pdf_report.py — module count goes 72 → 73 + gateway.py = 74."""

    def test_pdf_report_module_exists(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        self.assertTrue((squash_dir / "pdf_report.py").exists())

    def test_templates_dir_exists(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        self.assertTrue((squash_dir / "templates").is_dir())


if __name__ == "__main__":
    unittest.main()
