---
paths: ["**/api*", "**/signing*", "**/sbom*"]
---
# Security Rules
- Validate all inputs at the API boundary
- Never log model weights, raw prompts, or API keys at INFO level
- Rate-limit all API endpoints by default
- Set per-request scan timeouts — never let a scan block indefinitely
- Attestation reproducibility contract: byte-identical output for same inputs
- Sigstore signing: verify bundle completeness before claiming success
