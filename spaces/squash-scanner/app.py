"""Gradio interface for squash scan hf:// — HuggingFace Spaces deployment."""

import json

import gradio as gr

from squash.hf_scanner import HFScanner, is_hf_uri

_SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "info": "#6b7280",
}
_STATUS_META = {
    "clean":   ("✅", "#22c55e"),
    "warning": ("⚠️", "#f59e0b"),
    "unsafe":  ("❌", "#ef4444"),
    "error":   ("❌", "#ef4444"),
    "skipped": ("⏭️", "#6b7280"),
}
_EXAMPLES = [
    "meta-llama/Llama-3.1-8B-Instruct",
    "openai-community/gpt2",
    "google/gemma-2-2b",
    "microsoft/phi-2",
    "mistralai/Mistral-7B-v0.1",
]


def _status_card(status: str, file_count: int, n_findings: int, weight_format: str) -> str:
    emoji, color = _STATUS_META.get(status, ("❓", "#6b7280"))
    return f"""
    <div style="background:{color}18;border:2px solid {color};border-radius:12px;padding:20px;">
      <h2 style="margin:0;color:{color};font-size:1.4rem;">{emoji}&nbsp;{status.upper()}</h2>
      <p style="margin:8px 0 0;color:#374151;font-size:0.95rem;">
        <strong>{file_count}</strong> files scanned &nbsp;·&nbsp;
        <strong>{n_findings}</strong> findings &nbsp;·&nbsp;
        weight format: <code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;">{weight_format or "unknown"}</code>
      </p>
    </div>"""


def _meta_card(m: dict) -> str:
    sha = (m.get("sha") or "")[:12] or (m.get("revision") or "main")
    rows = [
        ("Repo", f'<a href="{m["url"]}" target="_blank">{m["repo_id"]}</a>'),
        ("License", f'<code>{m.get("license") or "unknown"}</code>'),
        ("Downloads", f'{m.get("downloads", 0):,}'),
        ("Library", m.get("library_name") or "—"),
        ("Pipeline", m.get("pipeline_tag") or "—"),
        ("Last modified", m.get("last_modified") or "—"),
        ("Revision", f'<code>{sha}</code>'),
    ]
    trs = "".join(
        f'<tr><td style="padding:5px 10px;color:#64748b;white-space:nowrap;">{k}</td>'
        f'<td style="padding:5px 10px;">{v}</td></tr>'
        for k, v in rows
    )
    return f"""
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px;margin-top:14px;">
      <h3 style="margin:0 0 10px;color:#1e293b;font-size:1rem;">📦 Model Info</h3>
      <table style="width:100%;border-collapse:collapse;font-size:0.88rem;">{trs}</table>
    </div>"""


def _findings_card(findings: list, license_warnings: list) -> str:
    parts = []

    if findings:
        rows = ""
        for f in findings[:25]:
            sev = f.get("severity", "unknown")
            c = _SEVERITY_COLORS.get(sev, "#6b7280")
            badge = f'<span style="background:{c}18;color:{c};padding:2px 7px;border-radius:4px;font-size:0.78rem;font-weight:700;">{sev.upper()}</span>'
            rows += (
                f"<tr>"
                f'<td style="padding:7px 10px;">{badge}</td>'
                f'<td style="padding:7px 10px;font-size:0.83rem;font-family:monospace;">{f.get("finding_id","")}</td>'
                f'<td style="padding:7px 10px;font-size:0.85rem;">{f.get("title","")}</td>'
                f'<td style="padding:7px 10px;font-size:0.8rem;color:#64748b;">{f.get("file_path","")}</td>'
                f"</tr>"
            )
        if len(findings) > 25:
            rows += f'<tr><td colspan="4" style="padding:7px 10px;color:#94a3b8;font-style:italic;">… {len(findings)-25} more findings</td></tr>'

        parts.append(f"""
        <div style="margin-top:16px;">
          <h3 style="color:#1e293b;font-size:1rem;">🔍 Findings ({len(findings)})</h3>
          <div style="overflow-x:auto;border:1px solid #e2e8f0;border-radius:8px;">
            <table style="width:100%;border-collapse:collapse;">
              <thead style="background:#f1f5f9;">
                <tr>
                  <th style="padding:8px 10px;text-align:left;color:#475569;font-size:0.83rem;">Severity</th>
                  <th style="padding:8px 10px;text-align:left;color:#475569;font-size:0.83rem;">ID</th>
                  <th style="padding:8px 10px;text-align:left;color:#475569;font-size:0.83rem;">Title</th>
                  <th style="padding:8px 10px;text-align:left;color:#475569;font-size:0.83rem;">File</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>""")
    else:
        parts.append('<p style="color:#22c55e;font-weight:600;margin-top:16px;">✅ No security findings detected.</p>')

    if license_warnings:
        items = "".join(f'<li style="margin:3px 0;">{w}</li>' for w in license_warnings)
        parts.append(f"""
        <div style="background:#fffbeb;border:1px solid #f59e0b;border-radius:8px;padding:14px;margin-top:14px;">
          <h3 style="margin:0 0 8px;color:#92400e;font-size:1rem;">⚠️ License Warnings</h3>
          <ul style="margin:0;padding-left:18px;color:#78350f;font-size:0.9rem;">{items}</ul>
        </div>""")

    return "".join(parts)


def run_scan(
    model_id: str,
    hf_token: str,
    download_weights: bool,
) -> tuple:
    model_id = (model_id or "").strip()
    if not model_id:
        return gr.update(visible=False), "", "", "", ""

    uri = model_id if is_hf_uri(model_id) else f"hf://{model_id}"
    token = (hf_token or "").strip() or None

    try:
        report = HFScanner().scan(uri=uri, token=token, download_weights=download_weights)
    except Exception as exc:
        err = f'<div style="background:#fef2f2;border:1px solid #ef4444;border-radius:8px;padding:16px;color:#dc2626;"><strong>Scan failed:</strong> {exc}</div>'
        return gr.update(visible=True), err, "", "", ""

    d = report.to_dict()
    s = d["scan"]

    status_html = _status_card(s["status"], s["file_count"], len(s["findings"]), s["weight_format"])
    meta_html = _meta_card(d["metadata"])
    findings_html = _findings_card(s["findings"], d["license_warnings"])
    json_text = json.dumps(d, indent=2)

    return gr.update(visible=True), status_html, meta_html, findings_html, json_text


CSS = """
.gradio-container { max-width: 900px !important; margin: 0 auto; }
#squash-header { text-align: center; padding: 28px 0 4px; }
footer { display: none !important; }
"""

with gr.Blocks(title="Squash Scanner", theme=gr.themes.Soft(), css=CSS) as demo:

    gr.HTML("""
    <div id="squash-header">
      <h1 style="font-size:2rem;margin:0;">🛡️ Squash Scanner</h1>
      <p style="color:#64748b;margin:8px 0 0;font-size:1rem;">
        Scan any HuggingFace model for pickle exploits, unsafe weights, license risks,
        and EU&nbsp;AI&nbsp;Act compliance gaps — in seconds, no login required.
      </p>
    </div>
    """)

    with gr.Row():
        model_input = gr.Textbox(
            label="Model ID",
            placeholder="meta-llama/Llama-3.1-8B-Instruct",
            info='HuggingFace model ID or full hf:// URI',
            scale=4,
        )
        scan_btn = gr.Button("🔍 Scan", variant="primary", scale=1, min_width=100)

    with gr.Row():
        hf_token = gr.Textbox(
            label="HF Token (optional — required for private/gated models)",
            type="password",
            placeholder="hf_...",
            scale=3,
        )
        dl_weights = gr.Checkbox(
            label="Download weights (slower, full deep scan)",
            value=False,
            scale=1,
        )

    gr.Examples(
        examples=[[m, "", False] for m in _EXAMPLES],
        inputs=[model_input, hf_token, dl_weights],
        label="Quick examples",
    )

    with gr.Column(visible=False) as results_col:
        status_out = gr.HTML()
        meta_out = gr.HTML()
        findings_out = gr.HTML()
        with gr.Accordion("📄 Raw JSON report", open=False):
            json_out = gr.Code(language="json", label="Full squash report")

    _outputs = [results_col, status_out, meta_out, findings_out, json_out]
    _inputs = [model_input, hf_token, dl_weights]

    scan_btn.click(fn=run_scan, inputs=_inputs, outputs=_outputs)
    model_input.submit(fn=run_scan, inputs=_inputs, outputs=_outputs)

    gr.HTML("""
    <div style="text-align:center;margin-top:28px;padding-top:14px;border-top:1px solid #e2e8f0;
                color:#94a3b8;font-size:0.82rem;">
      Powered by
      <a href="https://github.com/konjoai/squash" target="_blank" style="color:#64748b;">squash-ai</a>
      &nbsp;·&nbsp;
      <a href="https://hub.docker.com/r/konjoai/squash" target="_blank" style="color:#64748b;">Docker</a>
      &nbsp;·&nbsp;
      EU AI Act enforcement: August 2, 2026 ⏰
    </div>
    """)

if __name__ == "__main__":
    demo.launch()
