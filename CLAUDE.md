# squash

The `pytest` of AI compliance — automated EU AI Act, NIST AI RMF, and OWASP LLM Top-10 checks for ML teams. CI/CD-native, open-core, developer-first. Runs in 10 seconds. Ships proof, not policy statements.

**v3.1.0** — 4308 tests passing. Apache 2.0. `pip install squash-ai`. EU AI Act enforcement: August 2, 2026.

## Stack
Python 3.10+ · FastAPI (optional) · cryptography (optional) · CycloneDX (optional) · Sigstore (optional) · setuptools · uv

## Commands
```bash
python -m pytest tests/ -x                    # full test suite
squash scan --model <path>                    # run compliance scan
squash attest --model <path>                  # generate Annex IV attestation
squash sbom --model <path>                    # generate ML-BOM (CycloneDX/SPDX)
squash sign --model <path>                    # Sigstore model signing
uvicorn squash.api:app --reload               # API server (squash[api])
docker build -t squash .                      # container build
```

## Critical Constraints
- No `unwrap()` — raise with a clear message or log + re-raise
- No silent failures — `logging.warning` when a fallback path swallows a real error
- `squash[api]` (FastAPI, uvicorn) is **optional** — core scan/attest/sbom/sign must work without it
- `squash[signing]` (cryptography, sigstore) is **optional** — never hard-depend in core paths
- `squash[sbom]` (cyclonedx-python-lib) is **optional** — feature-gate cleanly
- Attestation artifacts must be byte-identical across runs given the same inputs — this is the reproducibility contract
- Never log model weights, raw prompts, or API keys at INFO level or above
- Rate-limit all API endpoints by default
- Enforce per-request scan timeouts — never let a scan block indefinitely
- The EU AI Act deadline is **August 2, 2026** — every sprint before that date is load-bearing
- Version bumps touch `pyproject.toml` + `squash/__init__.py`

## Module Map
| Module | Role |
|--------|------|
| `squash/` | Core compliance engine: scan, attest, SBOM, policy-as-code |
| `squash/api.py` | FastAPI compliance API (optional, `squash[api]`) |
| `squash/signing.py` | Sigstore model signing + SLSA provenance (optional, `squash[signing]`) |
| `squash/sbom.py` | CycloneDX / SPDX ML-BOM generation (optional, `squash[sbom]`) |
| `vscode-extension/` | VS Code extension for inline compliance feedback |
| `action.yml` | GitHub Actions integration — `squash-ai/action@v1` |
| `integrations/` | CI/CD integrations (GitLab, CircleCI, etc.) |
| `spaces/` | HuggingFace Spaces demo |

## Planning Docs
- `SQUASH_MASTER_PLAN.md` — strategic roadmap to $10M ARR, tier/track status
- `TIER_MAP.md` — feature tier mapping (Tier 1–3, Track B/C)
- `AUDIT_BASELINE.md` — byte-identical reproducibility baseline
- `CHANGELOG.md` — all notable changes

## Skills
See `.claude/skills/` — auto-loaded when relevant.
Run `/konjo` to boot a full session (Brief + Discovery + Plan).
