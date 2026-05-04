"""squash/demo_report.py — Konjo Edition demo report generator.

Produces a self-contained, zero-dependency HTML page that contains:

  1. Side-by-side dual-model compliance comparison (top)
  2. Per-model findings + expandable file accordions (middle)
  3. Embedded interactive demo panels connected to the local server (bottom)

All CSS, JS, and content is inlined — opens in any browser with no network.
Design language mirrors demo/index.html exactly: dark (#0a0c12), Konjo purple
(#b794ff), animated score bars, interactive accordions.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Colour tokens (mirror demo/index.html :root) ──────────────────────────────
_BG     = "#0a0c12"
_BG_E   = "#11141d"
_BG_E2  = "#161a26"
_LINE   = "#232838"
_LINE_S = "#2f3548"
_INK    = "#e7eaf3"
_IDIM   = "#98a0b3"
_IFAINT = "#5a6378"
_ACC    = "#b794ff"
_ACC2   = "#8c5dff"
_CYAN   = "#5dd9ff"
_GREEN  = "#6df0c2"
_WARN   = "#f7b955"
_BAD    = "#ff6b8a"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sc(score: int) -> str:
    return _GREEN if score >= 80 else (_WARN if score >= 60 else _BAD)

def _sl(score: int) -> str:
    return "EXCELLENT" if score >= 90 else ("GOOD" if score >= 80 else ("NEEDS WORK" if score >= 60 else "HIGH RISK"))

def _fmt(n: int) -> str:
    if n < 1024:       return f"{n} B"
    if n < 1048576:    return f"{n/1024:.1f} KB"
    return f"{n/1048576:.1f} MB"

def _sev_color(sev: str, passed: bool) -> str:
    if passed: return _GREEN
    return _BAD if sev == "error" else _WARN

def _sev_icon(sev: str, passed: bool) -> str:
    if passed: return "✓"
    return "✗" if sev == "error" else "⚠"

def _sev_badge(sev: str, passed: bool) -> str:
    if passed: return "PASS"
    return "FAIL" if sev == "error" else "WARN"

def _ext_color(ext: str) -> str:
    return {
        "json": _CYAN, "spdx": _ACC, "safetensors": _GREEN,
        "gguf": _WARN, "html": _WARN, "pdf": _BAD,
    }.get(ext.lower(), _IDIM)


# ── Finding row (expandable accordion) ────────────────────────────────────────

def _finding_row(f: Any, idx: int) -> str:
    sev   = getattr(f, "severity", "error")
    ok    = getattr(f, "passed", False)
    fid   = html.escape(getattr(f, "rule_id", getattr(f, "id", f"F-{idx}")))
    field = html.escape(getattr(f, "field", ""))
    rat   = html.escape(getattr(f, "rationale", ""))
    rem   = html.escape(getattr(f, "remediation", ""))
    col   = _sev_color(sev, ok)
    lbl   = _sev_badge(sev, ok)
    icon  = _sev_icon(sev, ok)
    fix   = (f'<p class="f-fix"><strong style="color:{_WARN}">Fix:</strong> {rem}</p>'
             if rem and not ok else "")
    return f"""
<details class="finding {'f-pass' if ok else 'f-fail'}" style="border-left-color:{col}44">
  <summary class="f-head">
    <span class="f-icon" style="color:{col}">{icon}</span>
    <span class="f-id">{fid}</span>
    <span class="f-field mono">{field}</span>
    <span class="f-badge" style="background:{col}1a;color:{col};border-color:{col}44">{lbl}</span>
  </summary>
  <div class="f-body">
    <p class="f-rat">{rat}</p>
    {fix}
  </div>
</details>"""


# ── File accordion (expandable with syntax-highlighted JSON) ──────────────────

def _file_accordion(name: str, size: int, content: str | None) -> str:
    ext = Path(name).suffix.lstrip(".").lower()
    col = _ext_color(ext)
    size_s = _fmt(size)
    if content:
        try:
            parsed = json.loads(content)
            pretty = html.escape(json.dumps(parsed, indent=2)[:4000])
            if len(content) > 4000:
                pretty += "\n… (truncated)"
        except Exception:
            pretty = html.escape(content[:3000])
        body = f'<pre class="f-code">{pretty}</pre>'
    else:
        body = f'<p class="f-rat dim">Binary or large file — {size_s}</p>'

    return f"""
<details class="file-acc">
  <summary class="file-head">
    <span class="file-ext" style="color:{col}">{ext.upper() or "FILE"}</span>
    <span class="file-name mono">{html.escape(name)}</span>
    <span class="file-size dim">{size_s}</span>
  </summary>
  <div class="file-body">{body}</div>
</details>"""


# ── Score bar SVG pill ─────────────────────────────────────────────────────────

def _score_bar(score: int) -> str:
    col = _sc(score)
    filled = int(score / 100 * 38)
    empty  = 38 - filled
    return (
        f'<span class="sbar" style="color:{col}">'
        f'{"█" * filled}<span style="opacity:.25">{"░" * empty}</span>'
        f'</span>'
    )


# ── Interactive demo section HTML ─────────────────────────────────────────────

def _interactive_section(server_port: int = 8002) -> str:
    return f"""
<!-- ═══════════════ INTERACTIVE DEMO ═══════════════ -->
<div class="idemo-wrap" id="interactive">
  <div class="idemo-header">
    <div class="logo-dot"></div>
    <h2 class="idemo-title">Interactive Demo</h2>
    <div class="server-pill" id="srvPill">
      <span class="dot"></span><span id="srvLabel">checking…</span>
    </div>
  </div>
  <p class="idemo-sub">
    Live API calls to your local squash server.
    Run <code>squash demo --server</code> to start it.
  </p>

  <!-- Canon panel -->
  <div class="ipanel">
    <div class="ipanel-head">
      <h3>RFC 8785 Canonical JSON</h3>
      <p class="ipanel-sub">Prove two dicts with different key order produce identical bytes.</p>
    </div>
    <div class="irow">
      <div class="iblock">
        <label>Input JSON</label>
        <textarea id="canonInput" rows="6">{{
  "model_id": "llama-3.1-8b",
  "passed": true,
  "scores": [0.9, 0.8, 0.7]
}}</textarea>
        <button class="primary" onclick="runCanon()">Canonicalise →</button>
      </div>
      <div class="iblock">
        <label>Canonical output</label>
        <pre id="canonOut" class="iout">—</pre>
      </div>
    </div>
  </div>

  <!-- Attest panel -->
  <div class="ipanel">
    <div class="ipanel-head">
      <h3>Live Attestation</h3>
      <p class="ipanel-sub">Run a real squash attestation pipeline against a model ID.</p>
    </div>
    <div class="irow">
      <div class="iblock">
        <label>Model ID</label>
        <input id="attestModel" value="my-llm-v1" style="margin-bottom:8px"/>
        <label>Policy</label>
        <select id="attestPolicy">
          <option value="eu-ai-act">EU AI Act</option>
          <option value="nist-ai-rmf">NIST AI RMF</option>
        </select>
        <button class="primary" onclick="runAttest()" style="margin-top:10px">Attest →</button>
      </div>
      <div class="iblock">
        <label>Result</label>
        <pre id="attestOut" class="iout">—</pre>
      </div>
    </div>
  </div>

</div>

<script>
const BASE = "http://localhost:{server_port}";

async function checkServer() {{
  const pill = document.getElementById("srvPill");
  const lbl  = document.getElementById("srvLabel");
  try {{
    const r = await fetch(BASE + "/api/health", {{signal: AbortSignal.timeout(1500)}});
    if (r.ok) {{
      pill.classList.add("live");
      lbl.textContent = "server live";
      return;
    }}
  }} catch(e) {{}}
  pill.classList.add("offline");
  lbl.textContent = "squash demo --server";
}}

async function runCanon() {{
  const inp = document.getElementById("canonInput").value;
  const out = document.getElementById("canonOut");
  out.textContent = "…";
  try {{
    const obj = JSON.parse(inp);
    const r = await fetch(BASE + "/api/canon", {{
      method:"POST", headers:{{"Content-Type":"application/json"}},
      body: JSON.stringify({{payload: obj}})
    }});
    const d = await r.json();
    out.textContent = JSON.stringify(d, null, 2);
  }} catch(e) {{ out.textContent = "Error: " + e.message + "\\n\\nIs the server running?\\nsquash demo --server"; }}
}}

async function runAttest() {{
  const model = document.getElementById("attestModel").value;
  const policy = document.getElementById("attestPolicy").value;
  const out = document.getElementById("attestOut");
  out.textContent = "Attesting…";
  try {{
    const r = await fetch(BASE + "/api/attest", {{
      method:"POST", headers:{{"Content-Type":"application/json"}},
      body: JSON.stringify({{model_id: model, policy}})
    }});
    const d = await r.json();
    out.textContent = JSON.stringify(d, null, 2);
  }} catch(e) {{ out.textContent = "Error: " + e.message + "\\n\\nIs the server running?\\nsquash demo --server"; }}
}}

checkServer();
</script>"""


# ── Main CSS ──────────────────────────────────────────────────────────────────

_CSS = f"""
:root{{
  --bg:{_BG};--bg-e:{_BG_E};--bg-e2:{_BG_E2};
  --line:{_LINE};--line-s:{_LINE_S};
  --ink:{_INK};--idim:{_IDIM};--ifaint:{_IFAINT};
  --acc:{_ACC};--acc2:{_ACC2};--cyan:{_CYAN};--green:{_GREEN};
  --warn:{_WARN};--bad:{_BAD};
  --grad:linear-gradient(135deg,{_ACC} 0%,{_CYAN} 50%,{_GREEN} 100%);
  --r:10px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
html,body{{background:var(--bg);color:var(--ink);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;
  letter-spacing:-.005em;overflow-x:hidden;scroll-behavior:smooth}}
a{{color:var(--cyan);text-decoration:none}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}}
.dim{{color:var(--idim)}}
code{{background:var(--bg-e2);padding:1px 6px;border-radius:4px;font-size:12px;font-family:monospace}}
button,.primary{{
  font:inherit;cursor:pointer;border:1px solid var(--line-s);
  background:var(--bg-e2);color:var(--ink);padding:9px 18px;
  border-radius:8px;transition:border-color .15s,background .15s;
}}
button:hover{{border-color:var(--acc)}}
.primary{{background:var(--grad);color:{_BG};border:none;font-weight:600}}
.primary:hover{{filter:brightness(1.1)}}
input,select,textarea{{
  font:inherit;background:var(--bg-e2);border:1px solid var(--line);
  color:var(--ink);padding:8px 12px;border-radius:7px;outline:none;
  width:100%;margin-bottom:10px;
}}
input:focus,select:focus,textarea:focus{{border-color:var(--acc)}}

/* ── Layout ── */
.wrap{{max-width:1000px;margin:0 auto;padding:0 24px 80px}}

/* ── Header ── */
header{{padding:48px 0 36px;border-bottom:1px solid var(--line);margin-bottom:40px}}
.logo{{display:flex;align-items:center;gap:9px;font-size:12px;font-weight:700;
  letter-spacing:.09em;text-transform:uppercase;color:var(--idim);margin-bottom:18px}}
.logo-dot{{width:9px;height:9px;border-radius:50%;background:var(--grad);
  box-shadow:0 0 10px {_ACC}88}}
h1{{font-size:clamp(22px,4vw,36px);font-weight:800;letter-spacing:-.03em;
  background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;line-height:1.15;margin-bottom:10px}}
.hmeta{{display:flex;flex-wrap:wrap;gap:20px;font-size:13px;color:var(--idim)}}
.hmeta strong{{color:var(--ink)}}

/* ── Verdict ── */
.verdict{{display:inline-flex;align-items:center;gap:8px;padding:7px 16px;
  border-radius:100px;font-weight:700;font-size:13px;margin-bottom:30px}}

/* ── Section titles ── */
.stitle{{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ifaint);margin:36px 0 14px;
  display:flex;align-items:center;gap:10px}}
.stitle::after{{content:'';flex:1;height:1px;background:var(--line)}}

/* ── Comparison grid ── */
.cmp-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px}}
@media(max-width:640px){{.cmp-grid{{grid-template-columns:1fr}}}}

.cmp-card{{background:var(--bg-e);border:1px solid var(--line-s);border-radius:var(--r);
  padding:22px 20px}}
.cmp-name{{font-weight:700;font-size:14px;margin-bottom:14px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.cmp-score{{font-size:40px;font-weight:800;letter-spacing:-.04em;line-height:1}}
.cmp-denom{{font-size:16px;font-weight:400;color:var(--idim)}}
.cmp-label{{font-size:11px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;margin-top:3px}}
.sbar{{font-size:11px;letter-spacing:1px;display:block;margin:8px 0 12px;font-family:monospace}}
.cmp-stats{{display:flex;gap:16px;font-size:13px;color:var(--idim)}}
.cmp-stats span{{font-weight:600}}

/* ── Findings accordion ── */
details.finding{{
  background:var(--bg-e);border:1px solid var(--line);border-radius:var(--r);
  margin-bottom:6px;border-left:3px solid;cursor:pointer;
}}
details.finding summary{{
  display:flex;align-items:center;gap:10px;padding:11px 14px;
  list-style:none;user-select:none;
}}
details.finding summary::-webkit-details-marker{{display:none}}
.f-icon{{font-size:14px;width:16px;flex-shrink:0;text-align:center}}
.f-id{{font-family:monospace;font-size:12px;font-weight:700;color:var(--idim);flex-shrink:0}}
.f-field{{font-size:11px;color:var(--ifaint);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.f-badge{{font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;
  padding:2px 7px;border-radius:100px;border:1px solid;flex-shrink:0}}
.f-body{{padding:4px 14px 12px 40px}}
.f-rat{{font-size:13px;color:var(--idim);margin-bottom:6px}}
.f-fix{{font-size:13px;color:var(--idim)}}

/* ── File accordions ── */
details.file-acc{{
  background:var(--bg-e);border:1px solid var(--line);border-radius:var(--r);
  margin-bottom:5px;
}}
details.file-acc summary{{
  display:flex;align-items:center;gap:10px;padding:10px 14px;
  list-style:none;cursor:pointer;user-select:none;
}}
details.file-acc summary::-webkit-details-marker{{display:none}}
.file-ext{{font-size:10px;font-weight:700;letter-spacing:.06em;width:40px;flex-shrink:0}}
.file-name{{flex:1;font-size:13px;color:var(--idim)}}
.file-size{{font-size:12px;color:var(--ifaint);flex-shrink:0}}
.file-body{{padding:0 14px 12px;overflow:auto;max-height:360px}}
.f-code{{font-size:12px;color:{_CYAN};background:var(--bg-e2);border-radius:6px;
  padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-all;max-height:320px}}

/* ── Next steps ── */
.steps{{background:var(--bg-e);border:1px solid var(--line-s);border-radius:var(--r);padding:22px 24px}}
.step{{display:flex;gap:12px;padding:9px 0;border-bottom:1px solid var(--line)}}
.step:last-child{{border-bottom:none;padding-bottom:0}}
.step-num{{width:24px;height:24px;border-radius:50%;flex-shrink:0;margin-top:2px;
  background:{_ACC}1a;color:var(--acc);font-size:12px;font-weight:700;
  display:flex;align-items:center;justify-content:center}}
.step-cmd{{display:inline-block;margin-top:5px;background:var(--bg-e2);
  border:1px solid var(--line-s);border-radius:5px;padding:3px 9px;
  font-family:monospace;font-size:12px;color:var(--cyan)}}

/* ── Interactive demo ── */
.idemo-wrap{{
  margin-top:60px;padding-top:40px;border-top:2px solid var(--acc)22;
}}
.idemo-header{{display:flex;align-items:center;gap:12px;margin-bottom:8px}}
.idemo-title{{font-size:22px;font-weight:700;background:var(--grad);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.server-pill{{display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 10px;
  border-radius:100px;background:var(--bg-e);border:1px solid var(--line-s);color:var(--idim)}}
.server-pill .dot{{width:7px;height:7px;border-radius:50%;background:var(--idim)}}
.server-pill.live .dot{{background:var(--green);box-shadow:0 0 6px var(--green)88}}
.server-pill.live{{border-color:var(--green)44;color:var(--green)}}
.server-pill.offline .dot{{background:var(--warn)}}
.server-pill.offline{{border-color:var(--warn)44;color:var(--warn)}}
.idemo-sub{{font-size:14px;color:var(--idim);margin-bottom:28px}}
.ipanel{{background:var(--bg-e);border:1px solid var(--line);border-radius:var(--r);
  padding:24px;margin-bottom:16px}}
.ipanel-head{{margin-bottom:14px}}
.ipanel-head h3{{font-size:16px;font-weight:700;margin-bottom:4px}}
.ipanel-sub{{font-size:13px;color:var(--idim)}}
.irow{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:600px){{.irow{{grid-template-columns:1fr}}}}
.iblock label{{display:block;font-size:12px;font-weight:600;letter-spacing:.06em;
  text-transform:uppercase;color:var(--idim);margin-bottom:6px}}
.iout{{background:var(--bg-e2);border:1px solid var(--line);border-radius:7px;
  padding:12px;font-family:monospace;font-size:12px;color:var(--cyan);
  min-height:120px;overflow:auto;white-space:pre-wrap;word-break:break-all}}

/* ── Footer ── */
footer{{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;
  gap:10px;font-size:12px;color:var(--ifaint)}}
.fbrand{{display:flex;align-items:center;gap:7px;font-weight:600;color:var(--idim)}}
.flinks{{display:flex;gap:18px}}
.flinks a{{color:var(--ifaint);transition:color .15s}}
.flinks a:hover{{color:var(--cyan)}}
"""


# ── generate_comparison() — main public API ────────────────────────────────────

def generate_comparison(
    *,
    models: list[dict[str, Any]],
    policy: str,
    output_dir: Path,
    squash_version: str = "3.0.1",
    timestamp: str | None = None,
    server_port: int = 8002,
) -> Path:
    """Generate a dual-model side-by-side HTML report and return its path.

    Each entry in *models* must contain:
      name, score, findings, artifacts [(name, size, content|None)], elapsed_ms
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    policy_label = policy.upper().replace("-", " ")
    n_models = len(models)

    # ── Header metadata
    model_names = " vs ".join(m["name"] for m in models)
    overall_passed = all(m["score"] >= 70 for m in models)
    verdict_color = _GREEN if overall_passed else _BAD
    verdict_text  = "COMPLIANT" if overall_passed else "NON-COMPLIANT"
    verdict_icon  = "✓" if overall_passed else "✗"

    # ── Comparison cards
    cmp_cards = ""
    for m in models:
        sc   = _sc(m["score"])
        sl   = _sl(m["score"])
        errs = sum(1 for f in m["findings"] if not getattr(f, "passed", True) and getattr(f, "severity", "") == "error")
        wrns = sum(1 for f in m["findings"] if not getattr(f, "passed", True) and getattr(f, "severity", "") == "warning")
        pss  = sum(1 for f in m["findings"] if getattr(f, "passed", True))
        cmp_cards += f"""
<div class="cmp-card" style="border-top:3px solid {sc}">
  <div class="cmp-name" title="{html.escape(m['name'])}">{html.escape(m['name'])}</div>
  <div style="font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:{_IDIM};margin-bottom:10px">{html.escape(m.get('policy','eu-ai-act').upper().replace('-',' '))}</div>
  <div class="cmp-score" style="color:{sc}">{m['score']}<span class="cmp-denom">/100</span></div>
  <div class="cmp-label" style="color:{sc}">{sl}</div>
  {_score_bar(m['score'])}
  <div class="cmp-stats">
    <div><span style="color:{_GREEN}">{pss}</span> passed</div>
    <div><span style="color:{_BAD}">{errs}</span> violations</div>
    <div><span style="color:{_WARN}">{wrns}</span> warnings</div>
    <div><span style="color:{_IDIM}">{m['elapsed_ms']:.0f} ms</span></div>
  </div>
</div>"""

    # ── Per-model detail sections
    detail_sections = ""
    for m in models:
        finding_rows = "".join(_finding_row(f, i) for i, f in enumerate(m["findings"]))
        file_rows    = "".join(_file_accordion(n, s, c) for n, s, c in m["artifacts"])
        detail_sections += f"""
<div class="stitle">{html.escape(m['name'])} — Findings ({len(m['findings'])} checks)</div>
<div>{finding_rows}</div>
<div class="stitle">{html.escape(m['name'])} — Artifacts ({len(m['artifacts'])} files)</div>
<div>{file_rows}</div>
"""

    # ── Next steps
    steps_html = "".join(f"""
<div class="step">
  <div class="step-num">{i+1}</div>
  <div>
    <div>{text}</div>
    <span class="step-cmd">{cmd}</span>
  </div>
</div>""" for i, (text, cmd) in enumerate([
        ("Address violations — each finding includes the specific field and fix.",
         "squash scan ./your-model --policy eu-ai-act"),
        ("Re-attest once fixes are applied to get a new signed certificate.",
         "squash attest ./your-model --policy eu-ai-act"),
        ("Add squash to CI — zero config, automatic on every commit.",
         "squash attest ./your-model --fail-on-violation"),
    ]))

    # ── Score bar animation script (no backslash in f-string expression)
    _anim_parts = []
    for i, m in enumerate(models):
        sc = m["score"]
        _anim_parts.append(
            f"var b{i}=document.getElementById('bar{i}');"
            f"if(b{i}){{b{i}.style.width='0';"
            f"setTimeout(function(){{b{i}.style.width='{sc}%'}},150+{i}*120)}}"
        )
    anim_js = "window.addEventListener('load',function(){" + " ".join(_anim_parts) + "});"

    # ── Animated bar elements (CSS-based, since we used text chars above)
    # Inject invisible percentage bars for the animation hook
    bar_divs = ""
    for i, m in enumerate(models):
        bar_divs += f'<div id="bar{i}" style="display:none"></div>'

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Squash — {html.escape(model_names)} Compliance Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="logo"><div class="logo-dot"></div>SQUASH · KONJO EDITION</div>
  <h1>{html.escape(policy_label)} Compliance Report</h1>
  <div class="hmeta">
    <div>Policy &nbsp;<strong>{html.escape(policy_label)}</strong></div>
    <div>Models &nbsp;<strong>{html.escape(str(n_models))}</strong></div>
    <div>Generated &nbsp;<strong>{html.escape(timestamp)}</strong></div>
    <div>squash-ai &nbsp;<strong>v{html.escape(squash_version)}</strong></div>
  </div>
</header>

<div class="verdict" style="background:{verdict_color}18;color:{verdict_color};border:1px solid {verdict_color}44">
  {verdict_icon} {verdict_text}
</div>

<div class="stitle">Model Comparison</div>
<div class="cmp-grid">{cmp_cards}</div>

{detail_sections}

<div class="stitle">What To Do Next</div>
<div class="steps">{steps_html}</div>

{_interactive_section(server_port)}

<footer>
  <div class="fbrand"><div class="logo-dot"></div>SQUASH · Prove your AI is trustworthy.</div>
  <div class="flinks">
    <a href="https://getsquash.dev">getsquash.dev</a>
    <a href="https://github.com/konjoai/squash">GitHub</a>
    <a href="https://pypi.org/project/squash-ai">PyPI</a>
  </div>
</footer>

{bar_divs}
</div>
<script>{anim_js}</script>
</body>
</html>"""

    report_path = output_dir / "squash-demo-report.html"
    report_path.write_text(page, encoding="utf-8")
    return report_path


# ── Legacy single-model generate() — kept for backward compat ─────────────────

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
    squash_version: str = "3.0.1",
    timestamp: str | None = None,
) -> Path:
    """Single-model wrapper — delegates to generate_comparison()."""
    return generate_comparison(
        models=[{
            "name": model_id,
            "score": score,
            "findings": findings,
            "artifacts": [(n, s, None) for n, s in artifacts],
            "elapsed_ms": elapsed_ms,
        }],
        policy=policy,
        output_dir=output_dir,
        squash_version=squash_version,
        timestamp=timestamp,
    )


def try_pdf(report_path: Path) -> Path | None:
    """Attempt PDF export via WeasyPrint; return path or None if unavailable."""
    try:
        from weasyprint import HTML as _HTML  # type: ignore[import]
        pdf_path = report_path.with_suffix(".pdf")
        _HTML(filename=str(report_path)).write_pdf(str(pdf_path))
        return pdf_path
    except Exception:
        return None
