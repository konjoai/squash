---
title: Squash Scanner
emoji: 🛡️
colorFrom: orange
colorTo: red
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: true
license: apache-2.0
short_description: Scan HuggingFace models for security vulnerabilities and EU AI Act compliance
---

# 🛡️ Squash Scanner

Scan any HuggingFace model for security vulnerabilities, unsafe weights, license risks, and EU AI Act compliance gaps — in seconds, no login required.

**Detects:**
- 🐍 Pickle / PyTorch exploit payloads (arbitrary code execution)
- 🔓 GGUF metadata injection and shell injection in tokenizer templates
- 📦 ONNX path traversal and SSRF via external data references
- ⚠️ safetensors header tampering
- 📜 License restrictions (commercial use, redistribution)
- 🏛️ EU AI Act Annex IV compliance gaps

**Powered by [squash-ai](https://github.com/konjoai/squash)** — the open-source AI supply chain security scanner. August 2, 2026 EU AI Act enforcement deadline. ⏰
