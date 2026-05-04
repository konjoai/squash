"""squash/demo_report.py — Konjo Edition demo report generator.

Produces a self-contained, zero-dependency HTML executive summary after
``squash demo`` runs.  All CSS and JS are inlined; the file opens in any
browser with no network access required.

Design language: matches demo/index.html exactly — dark Konjo aesthetic,
#b794ff primary accent, animated compliance bar, expandable findings.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Colour tokens (mirror demo/index.html :root) ──────────────────────────────
_BG = "#0a0c12"
_BG_E = "#11141d"
_BG_E2 = "#161a26"
_LINE = "#232838"
_LINE_S = "#2f3548"
_INK = "#e7eaf3"
_INK_DIM = "#98a0b3"
_INK_FAINT = "#5a6378"
_ACCENT = "#b794ff"
_ACCENT2 = "#8c5dff"
_CYAN = "#5dd9ff"
_GREEN = "#6df0c2"
_WARN = "#f7b955"
_BAD = "#ff6b8a"


def _sev_color(severity: str, passed: bool) -> str:
    if passed:
        return _GREEN
    return _BAD if severity == "error" else _WARN


def _sev_label(severity: str, passed: bool) -> str:
    if passed:
        return "PASS"
    return "FAIL" if severity == "error" else "WARN"


def _sev_icon(severity: str, passed: bool) -> str:
    if passed:
        return "✓"
    return "✗" if severity == "error" else "⚠"


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _score_color(score: int) -> str:
    if score >= 80:
        return _GREEN
    if score >= 60:
        return _WARN
    return _BAD


def _score_label(score: int) -> str:
    if score >= 90:
        return "EXCELLENT"
    if score >= 80:
        return "GOOD"
    if score >= 60:
        return "NEEDS WORK"
    return "HIGH RISK"


def _finding_row(finding: Any, idx: int) -> str:
    sev = getattr(finding, "severity", "error")
    passed = getattr(finding, "passed", False)
    fid = html.escape(getattr(finding, "rule_id", getattr(finding, "id", f"F-{idx}")))
    rationale = html.escape(getattr(finding, "rationale", ""))
    remediation = html.escape(getattr(finding, "remediation", ""))
    field = html.escape(getattr(finding, "field", ""))
    color = _sev_color(sev, passed)
    label = _sev_label(sev, passed)
    icon = _sev_icon(sev, passed)

    return f"""
<div class="finding {'finding-pass' if passed else 'finding-fail'}" onclick="this.classList.toggle('open')">
  <div class="finding-header">
    <span class="finding-icon" style="color:{color}">{icon}</span>
    <span class="finding-id">{fid}</span>
    <span class="finding-field">{field}</span>
    <span class="finding-badge" style="background:{color}22;color:{color};border-color:{color}55">{label}</span>
    <span class="finding-chevron">›</span>
  </div>
  <div class="finding-body">
    <p class="finding-rationale">{rationale}</p>
    {f'<p class="finding-fix"><strong>Fix:</strong> {remediation}</p>' if remediation and not passed else ''}
  </div>
</div>"""


def _artifact_row(name: str, size: int) -> str:
    ext = Path(name).suffix.lstrip(".")
    ext_colors = {
        "json": _CYAN,
        "spdx": _ACCENT,
        "safetensors": _GREEN,
        "pdf": _BAD,
        "html": _WARN,
    }
    color = ext_colors.get(ext, _INK_DIM)
    return f"""
    <div class="artifact-row">
      <span class="artifact-ext" style="color:{color}">{ext.upper() or "FILE"}</span>
      <span class="artifact-name">{html.escape(name)}</span>
      <span class="artifact-size">{_fmt_bytes(size)}</span>
    </div>"""


def generate(
    *,
    model_id: str,
    policy: str,
    passed: bool,
    score: int,
    findings: list[Any],
    artifacts: list[tuple[str, int]],
    elapsed_ms: float,
    output_dir: Path,
    squash_version: str = "3.0.0",
    timestamp: str | None = None,
) -> Path:
    """Write squash-demo-report.html to *output_dir* and return its path."""

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sc = _score_color(score)
    sl = _score_label(score)
    policy_label = policy.upper().replace("-", " ")

    errors = [f for f in findings if not f.passed and getattr(f, "severity", "") == "error"]
    warns = [f for f in findings if not f.passed and getattr(f, "severity", "") == "warning"]
    passes = [f for f in findings if f.passed]

    finding_rows = "".join(_finding_row(f, i) for i, f in enumerate(findings))
    artifact_rows = "".join(_artifact_row(n, s) for n, s in artifacts)

    verdict_color = _GREEN if passed else _BAD
    verdict_text = "COMPLIANT" if passed else "NON-COMPLIANT"
    verdict_icon = "✓" if passed else "✗"

    html_out = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Squash — {html.escape(model_id)} Compliance Report</title>
<style>
:root{{
  --bg:{_BG};--bg-e:{_BG_E};--bg-e2:{_BG_E2};
  --line:{_LINE};--line-s:{_LINE_S};
  --ink:{_INK};--ink-dim:{_INK_DIM};--ink-faint:{_INK_FAINT};
  --accent:{_ACCENT};--accent2:{_ACCENT2};
  --cyan:{_CYAN};--green:{_GREEN};--warn:{_WARN};--bad:{_BAD};
  --grad:linear-gradient(135deg,{_ACCENT} 0%,{_CYAN} 50%,{_GREEN} 100%);
  --r:12px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
html,body{{background:var(--bg);color:var(--ink);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;
  letter-spacing:-0.005em;overflow-x:hidden}}
a{{color:var(--cyan);text-decoration:none}}
code,pre,.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}}

/* ── Layout ── */
.wrap{{max-width:900px;margin:0 auto;padding:0 24px 80px}}

/* ── Header ── */
header{{
  padding:48px 0 40px;
  border-bottom:1px solid var(--line);
  margin-bottom:40px;
}}
.logo{{
  display:inline-flex;align-items:center;gap:10px;
  font-size:13px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
  color:var(--ink-dim);margin-bottom:20px;
}}
.logo-dot{{
  width:10px;height:10px;border-radius:50%;
  background:var(--grad);
  box-shadow:0 0 12px {_ACCENT}88;
}}
h1{{
  font-size:clamp(24px,4vw,38px);font-weight:700;letter-spacing:-0.03em;
  background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;line-height:1.15;margin-bottom:10px;
}}
.header-sub{{color:var(--ink-dim);font-size:14px;display:flex;gap:24px;flex-wrap:wrap}}
.header-meta{{display:flex;align-items:center;gap:6px}}
.header-meta .label{{color:var(--ink-faint)}}

/* ── Score ── */
.score-block{{
  background:var(--bg-e);border:1px solid var(--line-s);border-radius:var(--r);
  padding:28px 32px;margin-bottom:24px;
  display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center;
}}
.score-left h2{{font-size:14px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  color:var(--ink-dim);margin-bottom:12px}}
.score-bar-wrap{{background:var(--bg-e2);border-radius:100px;height:10px;overflow:hidden;margin-bottom:10px}}
.score-bar{{height:100%;border-radius:100px;
  background:var(--grad);
  width:0;transition:width 1.2s cubic-bezier(.22,1,.36,1)}}
.score-stats{{display:flex;gap:20px;font-size:13px;color:var(--ink-dim)}}
.score-stat span{{font-weight:600}}
.score-right{{text-align:right}}
.score-number{{font-size:52px;font-weight:800;letter-spacing:-0.04em;color:{sc};line-height:1}}
.score-denom{{font-size:20px;font-weight:400;color:var(--ink-faint)}}
.score-label{{font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:{sc};margin-top:4px}}

/* ── Verdict pill ── */
.verdict{{
  display:inline-flex;align-items:center;gap:8px;
  padding:8px 18px;border-radius:100px;font-weight:700;font-size:14px;
  background:{verdict_color}18;color:{verdict_color};border:1px solid {verdict_color}44;
  margin-bottom:32px;
}}

/* ── Section titles ── */
.section-title{{
  font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink-faint);margin:32px 0 14px;
  display:flex;align-items:center;gap:10px;
}}
.section-title::after{{content:'';flex:1;height:1px;background:var(--line)}}

/* ── Findings ── */
.finding{{
  background:var(--bg-e);border:1px solid var(--line);border-radius:var(--r);
  margin-bottom:8px;cursor:pointer;overflow:hidden;
  transition:border-color .15s;
}}
.finding:hover{{border-color:var(--line-s)}}
.finding-pass{{border-left:3px solid {_GREEN}44}}
.finding-fail{{border-left:3px solid}}
.finding-header{{
  display:flex;align-items:center;gap:10px;padding:13px 16px;
}}
.finding-icon{{font-size:15px;width:18px;flex-shrink:0;text-align:center}}
.finding-id{{font-family:ui-monospace,monospace;font-size:12px;font-weight:700;
  color:var(--ink-dim);flex-shrink:0}}
.finding-field{{font-size:12px;color:var(--ink-faint);flex:1;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:monospace}}
.finding-badge{{
  font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
  padding:3px 8px;border-radius:100px;border:1px solid;flex-shrink:0;
}}
.finding-chevron{{color:var(--ink-faint);transition:transform .2s;margin-left:4px;font-size:18px}}
.finding.open .finding-chevron{{transform:rotate(90deg)}}
.finding-body{{max-height:0;overflow:hidden;transition:max-height .25s ease}}
.finding.open .finding-body{{max-height:200px}}
.finding-rationale{{padding:0 16px 10px 44px;font-size:13px;color:var(--ink-dim)}}
.finding-fix{{padding:0 16px 14px 44px;font-size:13px;color:var(--ink-dim)}}
.finding-fix strong{{color:var(--warn)}}
code{{background:var(--bg-e2);padding:1px 5px;border-radius:4px;font-size:12px}}

/* ── Artifacts ── */
.artifact-grid{{
  background:var(--bg-e);border:1px solid var(--line);border-radius:var(--r);
  overflow:hidden;
}}
.artifact-row{{
  display:flex;align-items:center;gap:12px;padding:11px 16px;
  border-bottom:1px solid var(--line);font-size:13px;
}}
.artifact-row:last-child{{border-bottom:none}}
.artifact-ext{{font-size:10px;font-weight:700;letter-spacing:.06em;
  width:44px;flex-shrink:0}}
.artifact-name{{flex:1;font-family:ui-monospace,monospace;color:var(--ink-dim)}}
.artifact-size{{color:var(--ink-faint);font-size:12px;flex-shrink:0}}

/* ── Next steps ── */
.steps{{
  background:var(--bg-e);border:1px solid var(--line-s);border-radius:var(--r);
  padding:24px 28px;
}}
.step{{display:flex;gap:14px;padding:10px 0;border-bottom:1px solid var(--line)}}
.step:last-child{{border-bottom:none;padding-bottom:0}}
.step-num{{
  width:26px;height:26px;border-radius:50%;flex-shrink:0;
  background:var(--accent)18;color:var(--accent);
  font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;
  margin-top:2px;
}}
.step-text{{font-size:14px}}
.step-cmd{{
  display:inline-block;margin-top:5px;
  background:var(--bg-e2);border:1px solid var(--line-s);border-radius:6px;
  padding:4px 10px;font-family:ui-monospace,monospace;font-size:12px;color:var(--cyan);
}}

/* ── Footer ── */
footer{{
  margin-top:48px;padding-top:24px;border-top:1px solid var(--line);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;
  font-size:12px;color:var(--ink-faint);
}}
.footer-brand{{display:flex;align-items:center;gap:8px;font-weight:600;color:var(--ink-dim)}}
.footer-links{{display:flex;gap:20px}}
.footer-links a{{color:var(--ink-faint);transition:color .15s}}
.footer-links a:hover{{color:var(--cyan)}}

/* ── Responsive ── */
@media(max-width:600px){{
  .score-block{{grid-template-columns:1fr}}
  .score-right{{text-align:left}}
}}
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="logo">
    <div class="logo-dot"></div>
    SQUASH · Konjo Edition
  </div>
  <h1>EU AI Act Compliance Report</h1>
  <div class="header-sub">
    <div class="header-meta"><span class="label">Model</span>&nbsp;<strong>{html.escape(model_id)}</strong></div>
    <div class="header-meta"><span class="label">Policy</span>&nbsp;<strong>{html.escape(policy_label)}</strong></div>
    <div class="header-meta"><span class="label">Generated</span>&nbsp;{html.escape(timestamp)}</div>
    <div class="header-meta"><span class="label">squash-ai</span>&nbsp;v{html.escape(squash_version)}</div>
    <div class="header-meta"><span class="label">Runtime</span>&nbsp;{elapsed_ms:.0f} ms</div>
  </div>
</header>

<div class="verdict">{verdict_icon} {verdict_text}</div>

<div class="score-block">
  <div class="score-left">
    <h2>{html.escape(policy_label)} Compliance Score</h2>
    <div class="score-bar-wrap">
      <div class="score-bar" id="bar" style="width:{score}%"></div>
    </div>
    <div class="score-stats">
      <div><span>{len(passes)}</span> passed</div>
      <div><span style="color:{_BAD}">{len(errors)}</span> violations</div>
      <div><span style="color:{_WARN}">{len(warns)}</span> warnings</div>
    </div>
  </div>
  <div class="score-right">
    <div class="score-number">{score}<span class="score-denom">/100</span></div>
    <div class="score-label">{sl}</div>
  </div>
</div>

<div class="section-title">Compliance Findings ({len(findings)} checks)</div>
<div class="findings-list">
{finding_rows}
</div>

<div class="section-title">Artifacts Generated ({len(artifacts)} files)</div>
<div class="artifact-grid">
{artifact_rows}
</div>

<div class="section-title">What To Do Next</div>
<div class="steps">
  {''.join(f"""<div class="step">
    <div class="step-num">{i+1}</div>
    <div class="step-text">{text}<br><span class="step-cmd">{cmd}</span></div>
  </div>""" for i,(text,cmd) in enumerate([
    ("Address the violations above — each finding includes the specific field and fix.", "squash scan ./your-model --policy eu-ai-act"),
    ("Re-run attestation once fixes are applied to get a new signed certificate.", "squash attest ./your-model --policy eu-ai-act"),
    ("Add squash to your CI pipeline — zero config, runs in under 10 seconds.", "squash attest ./your-model --fail-on-violation"),
  ]))}
</div>

<footer>
  <div class="footer-brand">
    <div class="logo-dot"></div>
    SQUASH · Prove your AI is trustworthy.
  </div>
  <div class="footer-links">
    <a href="https://getsquash.dev">getsquash.dev</a>
    <a href="https://github.com/konjoai/squash">GitHub</a>
    <a href="https://pypi.org/project/squash-ai">PyPI</a>
  </div>
</footer>

</div>
<script>
// Animate the score bar on load
window.addEventListener('load',function(){{
  var bar=document.getElementById('bar');
  if(bar){{bar.style.width='0';setTimeout(function(){{bar.style.width='{score}%'}},120)}}
}});
</script>
</body>
</html>"""

    report_path = output_dir / "squash-demo-report.html"
    report_path.write_text(html_out, encoding="utf-8")
    return report_path


def try_pdf(report_path: Path) -> Path | None:
    """Attempt PDF export via WeasyPrint; return path or None if unavailable."""
    try:
        from weasyprint import HTML as _HTML  # type: ignore[import]
        pdf_path = report_path.with_suffix(".pdf")
        _HTML(filename=str(report_path)).write_pdf(str(pdf_path))
        return pdf_path
    except Exception:
        return None
