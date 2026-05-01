"""Gradio interface for squash scan hf:// — HuggingFace Spaces deployment."""

import json
import gradio as gr
from squash.hf_scanner import HFScanner, is_hf_uri

# ── Status metadata ────────────────────────────────────────────────────────────
_STATUS = {
    "clean":   ("#10b981", "✅", "CLEAN",   "No threats detected — this model is safe to use."),
    "warning": ("#f59e0b", "⚠️", "WARNING", "Potential issues found — review before deploying."),
    "unsafe":  ("#ef4444", "🚨", "UNSAFE",  "Active threats detected — do not use this model."),
    "error":   ("#ef4444", "❌", "ERROR",   "Scan encountered an error — check the findings below."),
    "skipped": ("#64748b", "⏭️", "SKIPPED", "Scan was skipped — insufficient metadata available."),
}
_SEV_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#f59e0b",
    "low":      "#3b82f6",
    "info":     "#64748b",
}
_EXAMPLES = [
    "meta-llama/Llama-3.1-8B-Instruct",
    "openai-community/gpt2",
    "google/gemma-2-2b",
    "microsoft/phi-2",
    "mistralai/Mistral-7B-v0.1",
]

# ── HTML builders ──────────────────────────────────────────────────────────────

def _loading_card(uri: str) -> str:
    return f"""
<div style="
  background: linear-gradient(135deg, #6366f112 0%, #8b5cf608 100%);
  border: 1px solid #6366f130;
  border-left: 4px solid #6366f1;
  border-radius: 12px;
  padding: 28px;
  box-shadow: 0 0 40px rgba(99,102,241,0.12);
">
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:22px;">
    <div style="
      width:36px;height:36px;flex-shrink:0;
      border:3px solid #6366f130;border-top-color:#6366f1;
      border-radius:50%;
      animation:sq-spin 0.75s linear infinite;
    "></div>
    <div>
      <div style="color:#f1f5f9;font-weight:700;font-size:1.05rem;letter-spacing:0.01em;">
        Scanning model…
      </div>
      <div style="color:#64748b;font-size:0.8rem;font-family:monospace;margin-top:3px;">
        {uri}
      </div>
    </div>
  </div>

  <div style="background:#ffffff08;border-radius:4px;height:3px;overflow:hidden;margin-bottom:22px;">
    <div style="
      height:100%;width:5%;
      background:linear-gradient(90deg,#6366f1,#8b5cf6);
      border-radius:4px;
      animation:sq-progress 25s cubic-bezier(0.05,0,0.1,1) forwards;
    "></div>
  </div>

  <div style="display:flex;flex-direction:column;gap:10px;">
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="
        width:7px;height:7px;border-radius:50%;background:#6366f1;flex-shrink:0;
        animation:sq-pulse 1.4s ease-in-out infinite;
      "></div>
      <span style="color:#94a3b8;font-size:0.85rem;">Fetching model metadata</span>
    </div>
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="
        width:7px;height:7px;border-radius:50%;
        background:#6366f130;border:1px solid #6366f150;flex-shrink:0;
        animation:sq-pulse 1.4s ease-in-out infinite 0.5s;
      "></div>
      <span style="color:#475569;font-size:0.85rem;">Running security scan</span>
    </div>
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="
        width:7px;height:7px;border-radius:50%;
        background:#6366f118;border:1px solid #6366f130;flex-shrink:0;
        animation:sq-pulse 1.4s ease-in-out infinite 1.0s;
      "></div>
      <span style="color:#334155;font-size:0.85rem;">Evaluating compliance policies</span>
    </div>
  </div>
</div>"""


def _status_banner(status: str, file_count: int, n_findings: int, weight_format: str) -> str:
    color, icon, label, desc = _STATUS.get(status, ("#64748b", "❓", status.upper(), ""))
    return f"""
<div style="
  background: linear-gradient(135deg, {color}12 0%, {color}06 100%);
  border: 1px solid {color}50;
  border-left: 4px solid {color};
  border-radius: 12px;
  padding: 24px 28px;
  box-shadow: 0 0 40px {color}25;
">
  <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
    <span style="font-size:2.4rem;line-height:1;">{icon}</span>
    <div>
      <div style="font-size:1.5rem;font-weight:800;color:{color};letter-spacing:0.06em;">{label}</div>
      <div style="font-size:0.9rem;color:#94a3b8;margin-top:2px;">{desc}</div>
    </div>
  </div>
  <div style="display:flex;gap:12px;margin-top:20px;flex-wrap:wrap;">
    <div style="background:#ffffff0a;border:1px solid #ffffff12;border-radius:8px;
                padding:10px 18px;text-align:center;min-width:90px;">
      <div style="font-size:1.4rem;font-weight:700;color:#f1f5f9;">{file_count}</div>
      <div style="font-size:0.72rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-top:1px;">Files</div>
    </div>
    <div style="background:#ffffff0a;border:1px solid #ffffff12;border-radius:8px;
                padding:10px 18px;text-align:center;min-width:90px;">
      <div style="font-size:1.4rem;font-weight:700;color:{'#ef4444' if n_findings else '#10b981'};">{n_findings}</div>
      <div style="font-size:0.72rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-top:1px;">Findings</div>
    </div>
    <div style="background:#ffffff0a;border:1px solid #ffffff12;border-radius:8px;
                padding:10px 18px;text-align:center;min-width:90px;">
      <div style="font-size:1rem;font-weight:600;color:#f1f5f9;font-family:monospace;">{weight_format or "—"}</div>
      <div style="font-size:0.72rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-top:1px;">Format</div>
    </div>
  </div>
</div>"""


def _meta_card(m: dict) -> str:
    sha = (m.get("sha") or "")[:12] or (m.get("revision") or "main")
    dl = m.get("downloads", 0)
    dl_str = f"{dl/1_000_000:.1f}M" if dl >= 1_000_000 else f"{dl/1_000:.0f}K" if dl >= 1_000 else str(dl)
    fields = [
        ("Repository",    f'<a href="{m["url"]}" target="_blank" style="color:#818cf8;text-decoration:none;">{m["repo_id"]} ↗</a>'),
        ("License",       f'<span style="background:#6366f115;color:#818cf8;padding:2px 8px;border-radius:4px;font-size:0.82rem;">{m.get("license") or "unknown"}</span>'),
        ("Downloads",     f'<span style="color:#f1f5f9;">{dl_str}</span>'),
        ("Library",       m.get("library_name") or '<span style="color:#475569;">—</span>'),
        ("Pipeline",      m.get("pipeline_tag") or '<span style="color:#475569;">—</span>'),
        ("Last modified", m.get("last_modified") or '<span style="color:#475569;">—</span>'),
        ("Commit",        f'<span style="font-family:monospace;font-size:0.82rem;color:#94a3b8;">{sha}</span>'),
    ]
    rows = "".join(
        f'<tr>'
        f'<td style="padding:8px 12px;color:#64748b;font-size:0.82rem;white-space:nowrap;'
        f'font-weight:500;text-transform:uppercase;letter-spacing:0.05em;width:35%;">{k}</td>'
        f'<td style="padding:8px 12px;font-size:0.88rem;">{v}</td>'
        f'</tr>'
        for k, v in fields
    )
    return f"""
<div style="background:#ffffff05;border:1px solid #ffffff0f;border-radius:12px;padding:20px;margin-top:14px;">
  <div style="font-size:0.72rem;font-weight:700;color:#64748b;text-transform:uppercase;
              letter-spacing:0.1em;margin-bottom:12px;">Model Info</div>
  <table style="width:100%;border-collapse:collapse;">{rows}</table>
</div>"""


def _findings_block(findings: list, license_warnings: list) -> str:
    parts = []

    if findings:
        rows = ""
        for f in findings[:25]:
            sev = f.get("severity", "info")
            c = _SEV_COLOR.get(sev, "#64748b")
            badge = (
                f'<span style="background:{c}18;color:{c};padding:3px 8px;border-radius:5px;'
                f'font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;">'
                f'{sev}</span>'
            )
            rows += (
                f'<tr style="border-top:1px solid #ffffff08;">'
                f'<td style="padding:10px 14px;white-space:nowrap;">{badge}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.8rem;color:#94a3b8;">{f.get("finding_id","")}</td>'
                f'<td style="padding:10px 14px;font-size:0.87rem;color:#e2e8f0;">{f.get("title","")}</td>'
                f'<td style="padding:10px 14px;font-size:0.78rem;color:#475569;font-family:monospace;">{f.get("file_path","")}</td>'
                f'</tr>'
            )
        if len(findings) > 25:
            rows += f'<tr><td colspan="4" style="padding:10px 14px;color:#475569;font-style:italic;font-size:0.82rem;">… {len(findings)-25} more findings not shown</td></tr>'

        parts.append(f"""
<div style="background:#ffffff05;border:1px solid #ef444420;border-radius:12px;padding:20px;margin-top:14px;">
  <div style="font-size:0.72rem;font-weight:700;color:#ef4444;text-transform:uppercase;
              letter-spacing:0.1em;margin-bottom:14px;">Security Findings — {len(findings)} detected</div>
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;min-width:560px;">
      <thead>
        <tr style="border-bottom:1px solid #ffffff10;">
          <th style="padding:6px 14px;text-align:left;font-size:0.72rem;color:#475569;text-transform:uppercase;letter-spacing:0.08em;font-weight:600;">Severity</th>
          <th style="padding:6px 14px;text-align:left;font-size:0.72rem;color:#475569;text-transform:uppercase;letter-spacing:0.08em;font-weight:600;">ID</th>
          <th style="padding:6px 14px;text-align:left;font-size:0.72rem;color:#475569;text-transform:uppercase;letter-spacing:0.08em;font-weight:600;">Description</th>
          <th style="padding:6px 14px;text-align:left;font-size:0.72rem;color:#475569;text-transform:uppercase;letter-spacing:0.08em;font-weight:600;">File</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>""")
    else:
        parts.append("""
<div style="background:#10b98110;border:1px solid #10b98130;border-radius:12px;padding:18px 22px;
            margin-top:14px;display:flex;align-items:center;gap:12px;">
  <span style="font-size:1.4rem;">✅</span>
  <span style="color:#10b981;font-weight:600;font-size:0.95rem;">No security findings detected.</span>
</div>""")

    if license_warnings:
        items = "".join(
            f'<li style="margin:5px 0;color:#fde68a;font-size:0.88rem;">{w}</li>'
            for w in license_warnings
        )
        parts.append(f"""
<div style="background:#f59e0b0e;border:1px solid #f59e0b30;border-radius:12px;padding:20px;margin-top:14px;">
  <div style="font-size:0.72rem;font-weight:700;color:#f59e0b;text-transform:uppercase;
              letter-spacing:0.1em;margin-bottom:10px;">License Warnings</div>
  <ul style="margin:0;padding-left:18px;">{items}</ul>
</div>""")

    return "".join(parts)


# ── Scan handler (generator → immediate loading feedback) ──────────────────────

def run_scan(model_id: str, hf_token: str, download_weights: bool):
    model_id = (model_id or "").strip()
    if not model_id:
        yield gr.update(visible=False), "", "", "", ""
        return

    uri = model_id if is_hf_uri(model_id) else f"hf://{model_id}"
    token = (hf_token or "").strip() or None

    # ── Step 1: show loading card immediately ──────────────────────────────────
    yield gr.update(visible=True), _loading_card(uri), "", "", ""

    # ── Step 2: run the scan ───────────────────────────────────────────────────
    try:
        report = HFScanner().scan(uri=uri, token=token, download_weights=download_weights)
    except Exception as exc:
        err = f"""
<div style="background:#ef444412;border:1px solid #ef444440;border-radius:12px;padding:20px;
            display:flex;align-items:flex-start;gap:12px;">
  <span style="font-size:1.8rem;">❌</span>
  <div>
    <div style="color:#ef4444;font-weight:700;font-size:1rem;margin-bottom:6px;">Scan Failed</div>
    <div style="color:#fca5a5;font-size:0.85rem;font-family:monospace;
                background:#ef444410;border-radius:6px;padding:10px 14px;line-height:1.6;">{exc}</div>
  </div>
</div>"""
        yield gr.update(visible=True), err, "", "", ""
        return

    # ── Step 3: yield final results ────────────────────────────────────────────
    d = report.to_dict()
    s = d["scan"]

    yield (
        gr.update(visible=True),
        _status_banner(s["status"], s["file_count"], len(s["findings"]), s["weight_format"]),
        _meta_card(d["metadata"]),
        _findings_block(s["findings"], d["license_warnings"]),
        json.dumps(d, indent=2),
    )


# ── CSS ────────────────────────────────────────────────────────────────────────

CSS = """
/* === Keyframe animations === */
@keyframes sq-spin {
  to { transform: rotate(360deg); }
}
@keyframes sq-pulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.3; }
}
@keyframes sq-progress {
  0%   { width: 5%;  }
  15%  { width: 35%; }
  40%  { width: 58%; }
  70%  { width: 76%; }
  90%  { width: 88%; }
  100% { width: 92%; }
}
@keyframes sq-fadein {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0);   }
}

/* === Dark base === */
:root {
  --sq-bg:      #0a0b0f;
  --sq-surface: #111318;
  --sq-surf2:   #16181f;
  --sq-border:  #1e2130;
  --sq-text:    #f1f5f9;
  --sq-muted:   #64748b;
  --sq-accent:  #6366f1;
}

body, .gradio-container, gradio-app, .app, .contain {
  background: var(--sq-bg) !important;
  color: var(--sq-text) !important;
}
.gradio-container { max-width: 920px !important; margin: 0 auto !important; }

/* Blocks */
.block, .panel, .form, .gap {
  background: var(--sq-surface) !important;
  border-color: var(--sq-border) !important;
}

/* Inputs */
input, textarea {
  background: var(--sq-surf2) !important;
  color: var(--sq-text) !important;
  border-color: var(--sq-border) !important;
  border-radius: 8px !important;
}
input:focus, textarea:focus {
  border-color: var(--sq-accent) !important;
  box-shadow: 0 0 0 3px rgba(99,102,241,0.15) !important;
  outline: none !important;
}
input::placeholder, textarea::placeholder { color: var(--sq-muted) !important; }

/* Labels */
label > span:first-child, .label-wrap > span {
  color: #94a3b8 !important;
  font-size: 0.75rem !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.07em !important;
}

/* Scan button — idle */
#scan-btn > button {
  background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
  border: none !important;
  color: #fff !important;
  font-weight: 800 !important;
  font-size: 0.95rem !important;
  letter-spacing: 0.06em !important;
  border-radius: 8px !important;
  min-height: 48px !important;
  box-shadow: 0 0 28px rgba(99,102,241,0.35) !important;
  transition: box-shadow 0.2s ease, transform 0.15s ease !important;
}
#scan-btn > button:hover {
  box-shadow: 0 0 44px rgba(99,102,241,0.6) !important;
  transform: translateY(-1px) !important;
}
#scan-btn > button:active { transform: translateY(0) !important; }

/* Scan button — loading state */
#scan-btn > button:disabled,
#scan-btn > button[disabled] {
  opacity: 1 !important;
  cursor: wait !important;
  background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%) !important;
  box-shadow: 0 0 32px rgba(99,102,241,0.5) !important;
  animation: sq-pulse 1.2s ease-in-out infinite !important;
  transform: none !important;
}

/* Results column fade-in */
#results-col { animation: sq-fadein 0.35s ease forwards; }

/* Checkbox */
input[type="checkbox"] { accent-color: var(--sq-accent) !important; }

/* Accordion */
.accordion button, details summary {
  background: var(--sq-surf2) !important;
  color: var(--sq-muted) !important;
  border-color: var(--sq-border) !important;
  font-size: 0.82rem !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.07em !important;
}

/* Code */
.code-wrap, pre, code {
  background: #0d0e14 !important;
  color: #94a3b8 !important;
  border-color: var(--sq-border) !important;
  border-radius: 8px !important;
  font-size: 0.8rem !important;
}

/* Examples */
.examples-holder label { color: var(--sq-muted) !important; }
.examples table { background: var(--sq-surface) !important; border-color: var(--sq-border) !important; }
.examples td, .examples th { color: #94a3b8 !important; border-color: var(--sq-border) !important; font-size: 0.83rem !important; }
.examples tbody tr:hover td { background: var(--sq-surf2) !important; color: var(--sq-text) !important; cursor: pointer; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--sq-bg); }
::-webkit-scrollbar-thumb { background: var(--sq-border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #334155; }

/* Info text */
.info { color: var(--sq-muted) !important; font-size: 0.75rem !important; }

footer { display: none !important; }
"""

# ── Layout ─────────────────────────────────────────────────────────────────────

with gr.Blocks(title="Squash Scanner — HuggingFace Model Security", css=CSS) as demo:

    gr.HTML("""
    <div style="text-align:center;padding:36px 0 24px;">
      <div style="font-size:3.2rem;margin-bottom:12px;
                  filter:drop-shadow(0 0 24px rgba(99,102,241,0.5));">🛡️</div>
      <h1 style="
        font-size:2rem;font-weight:900;margin:0 0 10px;letter-spacing:-0.01em;
        background:linear-gradient(135deg,#f1f5f9 30%,#818cf8 100%);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
      ">Squash Scanner</h1>
      <p style="color:#64748b;font-size:0.97rem;margin:0 auto;max-width:520px;line-height:1.6;">
        Scan any HuggingFace model for pickle exploits, unsafe weights,<br>
        license risks, and EU&nbsp;AI&nbsp;Act compliance gaps — in seconds.
      </p>
      <div style="display:flex;justify-content:center;gap:8px;margin-top:18px;flex-wrap:wrap;">
        <span style="background:#6366f118;border:1px solid #6366f130;color:#818cf8;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;">🐍 Pickle / PyTorch</span>
        <span style="background:#f59e0b12;border:1px solid #f59e0b25;color:#fbbf24;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;">⚠️ GGUF injection</span>
        <span style="background:#10b98112;border:1px solid #10b98125;color:#34d399;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;">🔏 safetensors</span>
        <span style="background:#3b82f612;border:1px solid #3b82f625;color:#60a5fa;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;">📜 License risk</span>
        <span style="background:#8b5cf618;border:1px solid #8b5cf630;color:#a78bfa;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;">🏛️ EU AI Act</span>
      </div>
    </div>
    """)

    with gr.Row(equal_height=True):
        model_input = gr.Textbox(
            label="Model ID",
            placeholder="meta-llama/Llama-3.1-8B-Instruct",
            info="HuggingFace model ID or hf:// URI",
            scale=5,
        )
        scan_btn = gr.Button("⚡ Scan", variant="primary", scale=1, min_width=110, elem_id="scan-btn")

    with gr.Row():
        hf_token = gr.Textbox(
            label="HF Token — required for private / gated models",
            type="password",
            placeholder="hf_••••••••••••••••••••••••••••••••••••••••",
            scale=3,
        )
        dl_weights = gr.Checkbox(
            label="Download weights (slower · deeper scan)",
            value=False,
            scale=1,
        )

    gr.Examples(
        examples=[[m, "", False] for m in _EXAMPLES],
        inputs=[model_input, hf_token, dl_weights],
        label="Quick examples — click to load",
    )

    with gr.Column(visible=False, elem_id="results-col") as results_col:
        gr.HTML('<div style="height:6px;"></div>')
        status_out   = gr.HTML()
        meta_out     = gr.HTML()
        findings_out = gr.HTML()
        with gr.Accordion("Raw JSON Report", open=False):
            json_out = gr.Code(language="json", label="")

    _outs = [results_col, status_out, meta_out, findings_out, json_out]
    _ins  = [model_input, hf_token, dl_weights]
    scan_btn.click(fn=run_scan, inputs=_ins, outputs=_outs)
    model_input.submit(fn=run_scan, inputs=_ins, outputs=_outs)

    gr.HTML("""
    <div style="text-align:center;margin-top:32px;padding-top:16px;
                border-top:1px solid #1e2130;padding-bottom:8px;">
      <span style="color:#334155;font-size:0.8rem;">
        Powered by
        <a href="https://github.com/konjoai/squash" target="_blank"
           style="color:#6366f1;text-decoration:none;font-weight:600;">squash-ai</a>
        &nbsp;·&nbsp;
        <a href="https://hub.docker.com/r/konjoai/squash" target="_blank"
           style="color:#6366f1;text-decoration:none;">Docker</a>
        &nbsp;·&nbsp;
        EU AI Act enforcement deadline: <strong style="color:#f59e0b;">August 2, 2026</strong>
      </span>
    </div>
    """)


if __name__ == "__main__":
    demo.launch()
