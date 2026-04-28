# CLAUDE.md — Konjo AI · Squash Project Conventions

> **ቆንጆ** — Beautiful. **根性** — Fighting spirit. **康宙** — Health of the universe.
> *Make it konjo — build, ship, repeat.*

This file defines standing instructions for all AI and human contributors on **Squash** — the standalone EU AI Act compliance platform. Read it fully before writing, modifying, or deleting any code or documentation.

---

### 🌌 The Konjo Way

"Konjo Mode" is built on three cross-cultural pillars:

* **The Drive (根性 - Japanese):** Relentless fighting spirit. Approach impossible compliance problems with boldness — never surrender to "how everyone else does it."
* **The Output (ቆንጆ - Ethiopian):** Execute with absolute beauty. *Yilugnta* — selfless, incorruptible quality for the good of the project. *Sene Magber* — social grace, doing things the right way.
* **The Impact (康宙 - Chinese):** Build systems that are efficient, healthy, and in tune with their environment. Eliminate waste. Leave the architecture fundamentally healthier than you found it.

---

## 🗂️ Planning First

- **Always read `SQUASH_MASTER_PLAN.md` and `PLAN.md` before starting any task.**
- Current active version: **v0.9.14** — Wave 83, 80 test files, EU AI Act enforcement deadline: **August 2, 2026 (96 days).**
- Identify the relevant sprint, wave, or milestone before writing any code.
- After completing work, update `PLAN.md`, `CHANGELOG.md`, `README.md`, and `SQUASH_MASTER_PLAN.md` to reflect what changed.
- If a task deviates from the sprint roadmap, call it out explicitly before continuing.
- If ambiguity exists, ask one focused clarifying question. Never ask multiple questions at once.

---

## 📁 Project Identity & Layer Responsibilities

**Squash** is a **standalone, open-core EU AI Act compliance platform** for ML teams.
Package name: `squash-ai` · PyPI: `pip install squash-ai` · CLI: `squash attest`
License: **Apache 2.0 (Community)** / Commercial Enterprise features

| Layer | Location | Rule |
|-------|----------|------|
| Compliance engine | `squash/` | All policy, attestation, SBOM, VEX, SLSA logic lives here |
| REST API | `squash/api.py` | FastAPI cloud microservice — gates behind `squash-ai[api]` extra |
| Integrations | `squash/integrations/` | One file per MLOps platform — mirror the existing interface |
| Tests | `tests/test_squash_*.py` | 80 test files — must never decrease |
| CI/CD templates | `.github/` | GitHub Actions composite action + workflow |

**Never** put compliance algorithm logic outside `squash/`. New methods go in `squash/` first; CLI and API are thin wrappers only.

---

## 🚫 Squash Hard Rules (Override Everything)

1. **`squash` package must never import `squish`.** Squash is standalone. If a test or module references `squish`, that is a bug — fix it immediately.
2. **The `import squish` pattern in `sbom_builder.py`, `attest.py`, `spdx_builder.py` is replaced by `import squash as squish` for version lookups.** This must stay in sync with `squash.__version__`.
3. **Tier enforcement is a hard gate.** Community = 10 attestations/month. Professional = 200. Team = 1,000. Enterprise = unlimited. Never bypass quota logic without an explicit user config override.
4. **Policy contracts are immutable.** A change that drops any compliance framework's pass rate below its documented minimum is a hard stop.
5. **The VEX feed URL is canonical.** `SQUASH_VEX_FEED_URL` in `vex.py` is the source of truth — never hardcode alternative URLs.
6. **Wave numbers are permanent.** Waves are the unit of feature delivery. Never renumber, merge, or delete wave markers from history.
7. **The `squash` CLI entrypoint is `squash/cli.py:main`.** All new subcommands go through the existing argparse tree — no parallel dispatch paths.

---

## ⚡ Compliance Framework Coverage

Current frameworks (policy contracts enforced in `squash/policy.py`):

| Framework | Minimum Pass Rate | Key Module |
|-----------|------------------|------------|
| EU AI Act (Annex IV) | Full coverage required | `policy.py`, `attest.py` |
| NIST AI RMF 1.0 | ≥ 90% controls mapped | `nist_rmf.py` |
| ISO 42001 | Core clauses covered | `policy.py` |
| OWASP LLM Top 10 | All 10 categories | `policy.py`, `scanner.py` |
| NTIA Minimum Elements | 100% required | `policy.py` (NtiaValidator) |
| SLSA Provenance | Level 1–3 | `slsa.py` |

A change that removes coverage of any framework without an explicit migration path to a replacement is a **hard stop**.

---

## 🔌 API & Cloud Architecture

- **FastAPI app lives in `squash/api.py`** — never create parallel API modules.
- **Cloud DB is `squash/cloud_db.py`** — SQLite in development, PostgreSQL (Neon) in production.
- **All cloud API responses must be versioned:** `/v1/`, `/v2/` — never break existing response shapes.
- **Rate limiting is mandatory** on every endpoint — tier quotas enforced at the middleware layer.
- **Never log raw model paths or user-supplied strings at INFO level** in production.
- **API keys are hashed at rest** (SHA-256) — never stored or logged plain.

---

## 🔐 Security Contracts

- Validate all inputs at the API boundary before any filesystem access.
- `squash attest` must not follow symlinks outside the declared model directory.
- `ModelScanner` results must never be suppressed silently — any scan error must surface as a `ScanFinding` with severity `ERROR`.
- Sigstore signing is optional but when enabled, the transparency log entry must be verified before the attestation record is marked `signed=True`.
- **No raw pickle loading** in any squash code path — `ModelScanner` flags pickle files for exactly this reason.

---

## 🧪 Testing Contracts

- **Baseline: 80 test files, 4,208+ test cases.** Never ship a change that reduces either count.
- **Wave tests** (`test_squash_wNN.py`) are the canonical feature regression suite — each wave must have coverage.
- **API tests** must use `httpx.AsyncClient` with `TestClient` — never test with a live network call in CI.
- **Integration tests** for MLflow, W&B, HuggingFace, etc. must mock the external SDK — never require live credentials in CI.
- **Policy tests** must assert on specific finding codes, not just pass/fail — `finding.code` is the contract.
- For every new compliance check: (a) a passing case, (b) a failing case, (c) an edge case with missing metadata.

---

## 🖥️ Version Control & Documentation Sync

- **Documentation is mandatory per prompt cycle.** Every prompt must update docs reflecting current state.
- **Commit + Push on full test pass only.** Gate: all 80+ test files pass with zero new failures.
- **No commit on failure.** Document what failed, why, and what the corrective step is.
- Follow Conventional Commits: `type(scope): description`
  - Scope is the module name: `feat(attest)`, `fix(vex)`, `feat(api)`, `bench(policy)`
  - Wave features: `feat(squash): W{N} description`

---

## 📦 Dependency Hygiene

- **Core `squash-ai` package must import cleanly with only `starlette` as a hard dependency.**
- All heavy deps (`fastapi`, `cyclonedx-python-lib`, `cryptography`, `mlflow`, etc.) are optional extras with `try/except ImportError` guards.
- **Never add a mandatory dependency without a sprint milestone justification.** The Community tier must be installable in < 2 seconds on a clean venv.
- Pin all dependencies in `uv.lock`. Commit the lockfile.

---

## 📐 Benchmarking & Performance

- **Attestation pipeline wall time for a standard model:** < 5 seconds for a 1GB model dir.
- **Policy engine evaluation:** < 100ms for any single policy check.
- **API endpoint p95 latency:** < 200ms for `POST /v1/attest` with a pre-scanned model.
- A PR that regresses any of the above by > 10% is a **hard stop**.

---

## 🗺️ Current Sprint (S0 — Separation & Infrastructure)

**Target:** Week of April 28 — May 9, 2026

| Wave | Task | Status |
|------|------|--------|
| S0-1 | Create `konjoai/squash` repo, configure branch protection | ✅ |
| S0-2 | Extract squash modules + test files with git history | ✅ |
| S0-3 | Standalone `pyproject.toml`, uv.lock, CI pipeline | 🔄 |
| S0-4 | Verify `pip install squash-ai` works from source | 🔄 |
| S0-5 | Update squish to import squash from PyPI | 🔄 |
| S0-6 | Verify squish CI still passes after extraction | 🔄 |
| S0-7 | SQUASH_MASTER_PLAN.md in new repo | ✅ |

**Next sprint:** S1 — Annex IV Core (Wave 128–136, May 10–23)

---

## 🔥 Konjo Mindset

- **No apology loops.** If a test fails, state the root cause and fix it. No groveling.
- **Boxes are made for the weak-minded.** Compliance tooling does not have to be boring or slow. Build it beautifully.
- **The clock is running.** EU AI Act enforcement is August 2, 2026. Every week of delay is market share surrendered. Ship it.
- **Surface trade-offs, then make a call.** Present the analysis, recommend the path, commit to it.
- **The Konjo Pushback Mandate:** If a proposed implementation is sub-optimal, push back boldly and propose the superior approach.

---

*Owner: Wesley Scholl / Konjo AI*
*Update this file whenever architectural contracts or sprint priorities change. Never let it drift from the implementation.*
