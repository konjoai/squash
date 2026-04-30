# Changelog

All notable changes to `squash-ai` are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/) · [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [1.5.0] — 2026-04-29 — Sprint 10: Model Card First-Class CLI

### Added (W192–W194 — Sprint 10: Model Card First-Class CLI — Tier 2 #15)

- **`squash/model_card.py` — Annex IV / bias / lineage data fusion (W192)**:
  - HF model card now pre-fills from `annex_iv.json` (Article-13 metadata —
    intended purpose, intended users, prohibited uses, risk management,
    adversarial testing, oversight, hardware requirements)
  - Reads `bias_audit_report.json` to populate Bias / Fairness narrative
  - Reads `data_lineage_certificate.json` to populate Training Data table
  - Four extended HF sections added: **Training Data**, **Evaluation**,
    **Environmental Impact**, **Ethical Considerations**
  - Graceful degradation preserved — every helper falls back to safe defaults
    when the source artefact is absent
  - 13 new tests

- **`squash/model_card_validator.py` — HuggingFace schema validator (W193) — NEW MODULE**:
  - `ModelCardValidator.validate()` returns structured `ModelCardValidationReport`
  - Stdlib-only frontmatter parser (no PyYAML dep) — handles scalars, lists,
    dicts, list-of-dicts, quoted strings, bools, numbers
  - Required frontmatter check: `license`, `language`, `tags`
  - Recommended frontmatter check: `pipeline_tag`, `model_id`, `model-index`
  - Required section check: `Intended Use`, `Limitations`
  - Recommended section check: `Training Data`, `Evaluation`,
    `Ethical Considerations`, `How to Use`
  - SPDX licence sanity check (24 known licences) — warning surface
  - HF pipeline_tag recognition (18 well-known tags) — info surface
  - Body length sanity check — short body warning
  - `to_dict()` for JSON output; `summary()` for terminal display
  - 14 new tests

- **`squash/cli.py` — `model-card` first-class flags (W194)**:
  - `--validate` — generate then run validator; exits non-zero on errors
  - `--validate-only` — skip generation; validate existing
    `squash-model-card-hf.md`
  - `--push-to-hub REPO_ID` — upload to HuggingFace via `huggingface_hub`
    (optional dep; clean error if not installed; uploads as `README.md`)
  - `--hub-token TOKEN` — token override; falls back to
    `HUGGING_FACE_HUB_TOKEN` / `HF_TOKEN` env
  - `--json` — structured JSON validation report on stdout
  - 9 new tests

### Changed
- **`tests/test_squash_model_card.py`** — module count gate updated 69 → 70
- **`tests/test_squash_wave49.py`**, **`tests/test_squash_wave52.py`**,
  **`tests/test_squash_wave5355.py`** — secondary module count gates
  updated 69 → 70 (collateral)
- **`tests/test_squash_w139.py`** — fixed pre-existing fly.toml whitespace
  literal test by switching to regex match (not Sprint 10 work, but blocked
  the "all green" exit gate)
- **`SQUASH_MASTER_PLAN.md`** — Sprint 10 marked complete; Sprints 11–13
  scheduled (chain attestation, registry auto-attest gates, startup pricing tier)

### Stats
- **36 new tests** · **0 regressions** · **3875 total tests passing**
- **70 Python modules** (was 69 after Sprint 9)
- **1 new module** (`squash/model_card_validator.py`)
- **5 new CLI flags** on `squash model-card`

---

## [1.4.0] — 2026-04-29 — Sprint 9: Enterprise Pipeline Integration

### Added (W188–W191 — Sprint 9)

- **`squash/telemetry.py` (W188)** — OpenTelemetry spans per attestation run,
  OTLP gRPC + HTTP exporters, Datadog / Honeycomb / Jaeger compatible;
  `squash telemetry status / test / configure` CLI
- **`squash/integrations/gitops.py` (W189)** — ArgoCD / Flux admission webhook;
  K8s ValidatingWebhookConfiguration; blocks deployment when attestation
  missing or score below threshold; `squash gitops check / webhook-manifest /
  annotate` CLI
- **`squash/webhook_delivery.py` (W190)** — Generic outbound webhook delivery
  with HMAC-SHA256 signing, 5 event types, SQLite persistence;
  `squash webhook add / list / test / remove` CLI
- **`squash/sbom_diff.py` (W191)** — Attestation diff engine; score delta,
  component / policy / vulnerability drift; ANSI table / JSON / HTML output;
  `squash diff v1.json v2.json --fail-on-regression` CLI

### Stats
- **212 new tests** · **0 regressions** · **3839 total tests passing**
- **69 Python modules** (was 65 after Sprint 8)
- **4 new modules**

---

## [1.3.0] — 2026-04-29 — Sprint 8: Moat Deepening

### Added (W182–W187 — Sprint 8: Moat Deepening)

- **`squash/annual_review.py`** — Annual AI System Compliance Review Generator (W182):
  - `AnnualReviewGenerator.generate()`: 12-month compliance review from model directories
  - Model portfolio audit with year-start/end score delta and per-model trend
  - 12 monthly snapshots with synthetic compliance trend
  - Regulatory changes addressed (EU AI Act, NIST RMF, ISO 42001)
  - Next-year objective builder (auto-populated from open findings + missing frameworks)
  - Outputs: JSON + Markdown + plain text; optional PDF
  - `squash annual-review --year 2025 [--models-dir ./models] [--json]` CLI
  - 18 new tests

- **`squash/attestation_registry.py`** — Public Attestation Registry (W183):
  - `AttestationRegistry.publish()`: SHA-256 attestation fingerprinting; `att://` URI scheme
  - `att://attestations.getsquash.dev/org/model_id/entry_id` URI format
  - `AttestationRegistry.verify()`: re-hashes stored payload; detects tampering
  - `AttestationRegistry.revoke()`: marks attestation revoked; verify returns INVALID
  - `AttestationRegistry.lookup()`: filter by model_id, org, or entry_id
  - SQLite-backed (`~/.squash/attestation_registry.db`); remote-ready architecture
  - `squash publish / squash lookup / squash verify-entry` CLI
  - 16 new tests

- **`squash/dashboard.py`** — CISO / Executive Terminal Dashboard (W184):
  - `Dashboard.build()`: scans model directories; computes 5 key metrics
  - ANSI terminal rendering with colour (green/yellow/red score colours)
  - Risk heat-map table sorted worst-first; drift and CVE indicators
  - `--json` output for VS Code webview consumption
  - Regulatory deadline countdown (EU AI Act, Colorado AI Act, ISO 42001)
  - `squash dashboard [--models-dir ./models] [--json] [--no-color]` CLI
  - 14 new tests

- **`squash/regulatory_feed.py`** — Regulatory Intelligence Feed (W185):
  - 9 regulations tracked: EU AI Act, NIST AI RMF, ISO 42001, Colorado AI Act,
    NYC Local Law 144, SEC AI Disclosure, FDA AI/ML SaMD, EU GDPR (AI), FedRAMP AI
  - 6 curated change events with impact level and affected squash controls
  - `squash regulatory status/list/updates/deadlines` subcommands
  - `--since DATE` filter for change log; `--days N` for deadline window
  - `--json` output on all subcommands
  - 19 new tests

- **`squash/due_diligence.py`** — M&A / Investment AI Due Diligence Package (W186):
  - `DueDiligenceGenerator.generate()`: comprehensive AI compliance snapshot
  - Per-model liability flag scoring (unattested, no bias audit, no data lineage,
    low score, open CVEs, drift, no SLSA)
  - Overall risk rating: LOW / MEDIUM / HIGH / CRITICAL
  - Auto-generated Representations & Warranties guidance (6 standard clauses)
  - Outputs: JSON + Markdown + executive summary + signed ZIP bundle
  - `squash due-diligence --company AcmeCorp [--deal-type investment]` CLI
  - 17 new tests

- **`vscode-extension/`** — VS Code Extension (W187):
  - `package.json` — full VS Code Marketplace manifest:
    - 9 commands: runAttestation, showDashboard, runBiasAudit, generateAnnexIV,
      runIso42001, publishAttestation, exportTrustPackage, openReport, refreshTree
    - 3 sidebar tree views: Model Portfolio, Active Violations, Regulatory Deadlines
    - Activity bar icon with `squash-sidebar` container
    - Configuration: `squash.cliPath`, `squash.defaultPolicy`, `squash.autoAttest`,
      `squash.showStatusBar`, `squash.apiKey`, `squash.modelsDir`
    - Explorer context menu → `squash.runAttestation`
    - Activation events for squash artifact files
  - `src/extension.ts` — TypeScript implementation (~350 lines):
    - `ModelPortfolioProvider` / `ViolationsProvider` / `DeadlinesProvider` tree views
    - Status bar with green/yellow/red compliance score
    - `runSquash()` subprocess wrapper (calls squash CLI with configurable path)
    - Dashboard HTML webview rendered from `squash dashboard --json` output
    - File system watcher for `*.{gguf,bin,safetensors,pt,pth}` with auto-attest
  - `tsconfig.json` — TypeScript compiler config (ES2022, Node16 modules)
  - 21 new tests (structural: `package.json`, `extension.ts`, `tsconfig.json`)

### Changed
- **`squash/cli.py`** — 9 new commands: `annual-review`, `publish`, `lookup`,
  `verify-entry`, `dashboard`, `regulatory` (+4 subcommands), `due-diligence`
- **`tests/test_squash_model_card.py`** — module count gate updated 60 → 65
- **`SQUASH_MASTER_PLAN.md`** — Sprint 8 complete; situation report updated to v1.3.0

### Stats
- **128 new tests** · **0 regressions** · **3572 total tests passing**
- **65 Python modules** (was 60 after Sprint 7)
- **1 VS Code extension** (`vscode-extension/`)
- **9 new CLI commands / subcommand groups**

---

## [1.2.0] — 2026-04-29 — Sprint 7: Enterprise Moat

### Added (W178–W181 — Sprint 7: Enterprise Moat)

- **`squash/vendor_registry.py`** — AI Vendor Risk Register (W178):
  - `VendorRegistry`: SQLite-backed register of all third-party AI vendors
  - `VendorRiskTier`: CRITICAL / HIGH / MEDIUM / LOW risk tiering
  - `QuestionnaireGenerator`: 36-question due-diligence questionnaire per risk tier
    (Model Governance, Training Data, Security, Bias & Fairness, Data Handling,
    Explainability, Human Oversight, Incident Response, Attestation)
  - `import_trust_package()`: verify vendor Trust Packages and record compliance score
  - `squash vendor add/list/questionnaire/import-trust-package/summary` CLI
  - 22 new tests

- **`squash/asset_registry.py`** — AI Asset Registry (W179):
  - `AssetRegistry`: SQLite-backed inventory of every AI model in the organization
  - `sync_from_attestation()`: auto-populates from squash attestation artifacts
  - Drift detection, CVE tracking, shadow AI flagging, staleness detection (>30d)
  - JSON + Markdown export for board reports and procurement reviews
  - `squash registry add/sync/list/summary/export` CLI
  - 22 new tests

- **`squash/data_lineage.py`** — Training Data Lineage Certificate (W180):
  - `DataLineageTracer.trace()`: traces datasets from model config / provenance files / MLflow
  - 50+ HuggingFace dataset profiles: license, PII risk, GDPR legal basis
  - SPDX license database: permissive / copyleft / research-only / restricted classification
  - PII risk levels: NONE → LOW → MEDIUM → HIGH → CRITICAL (special GDPR categories)
  - GDPR Article 6 legal basis assessment per dataset
  - Signed certificate with SHA-256 hash
  - `squash data-lineage [--datasets ...] [--fail-on-pii] [--fail-on-license]` CLI
  - 24 new tests

- **`squash/bias_audit.py`** — Algorithmic Bias Audit (W181):
  - `BiasAuditor.audit()`: computes 5 fairness metrics across all protected attribute groups
  - **Demographic Parity Difference (DPD)** — outcome rate gap
  - **Disparate Impact Ratio (DIR)** — 4/5ths EEOC rule
  - **Equalized Odds Difference (EOD)** — TPR + FPR parity
  - **Predictive Equality Difference (PED)** — FPR parity
  - **Accuracy Parity** — accuracy gap across groups
  - Regulatory thresholds: NYC Local Law 144 (DPD ≤ 0.05), EU AI Act Annex III,
    ECOA 4/5ths rule, Fair Housing Act
  - `BiasAuditReport` with signed audit ID and data hash
  - Zero external dependencies — pure Python stdlib math
  - `squash bias-audit --predictions pred.csv --protected age,gender
    --standard nyc_local_law_144 [--fail-on-fail]` CLI
  - 24 new tests

### Changed
- **`squash/cli.py`** — 8 new commands: `vendor` (with 5 subcommands), `registry` (with 5 subcommands), `data-lineage`, `bias-audit`
- **`tests/test_squash_model_card.py`** — module count gate updated 56 → 60
- **`SQUASH_MASTER_PLAN.md`** — Sprint 7 complete; Sprint 8 roadmap added (W182–W187)

### Stats
- **104 new tests** · **0 regressions** · **3444 total tests passing**
- **60 Python modules** (was 56 after Sprint 5)
- **8 new CLI commands / subcommand groups**

---

## [1.1.0] — 2026-04-29 — Sprint 5: Market Expansion

### Added (W170–W174 — Sprint 5: Market Expansion)

- **`squash/iso42001.py`** — ISO/IEC 42001:2023 AI Management System readiness assessment (W170):
  - `Iso42001Assessor.assess()`: 38-control gap analysis covering Clauses 4–10 and Annex A
  - `ReadinessLevel` enum: `CERTIFIED_READY` / `SUBSTANTIALLY_COMPLIANT` / `PARTIAL` / `EARLY_STAGE`
  - Weighted scoring, high-priority gap extraction, remediation roadmap with squash CLI commands
  - `squash iso42001 ./model [--format json] [--fail-below SCORE]` CLI command
  - 21 new tests in `tests/test_squash_sprint5.py`

- **`squash/trust_package.py`** — Signed vendor attestation bundle exporter + verifier (W171):
  - `TrustPackageBuilder.build()`: bundles CycloneDX ML-BOM, SPDX, NIST RMF, VEX, SLSA, ISO 42001 report into signed ZIP with SHA-256 manifest
  - `TrustPackageVerifier.verify()`: integrity check of all artifacts + manifest in <10 seconds
  - EU AI Act conformance score auto-computed from available artifacts
  - `squash trust-package ./model --output vendor.zip [--sign] [--model-id ID]` CLI
  - `squash verify-trust-package vendor.zip [--json] [--fail-on-error]` CLI
  - 22 new tests

- **`squash/agent_audit.py`** — OWASP Agentic AI Top 10 (December 2025) compliance audit (W172):
  - `AgentAuditor.audit()`: audits all 10 agentic AI risks from any agent manifest format
  - Covers: AA1 Goal Hijacking, AA2 Unsafe Tools, AA3 Identity Abuse, AA4 Memory Poisoning, AA5 Cascading Failure, AA6 Rogue Agents, AA7 Auditability, AA8 Excessive Autonomy, AA9 Data Exfiltration, AA10 Human Oversight
  - LangChain / LlamaIndex / CrewAI manifest format parsing
  - `squash agent-audit ./agent.json [--fail-on-critical] [--format json]` CLI
  - 25 new tests

- **`squash/incident.py`** — AI incident response package generator (W173):
  - `IncidentResponder.respond()`: structured incident package with attestation snapshot, EU AI Act Article 73 disclosure, drift delta, and remediation plan
  - `IncidentSeverity` enum: critical → serious → moderate → minor (with regulatory threshold mapping)
  - `IncidentCategory` enum: 10 categories (bias_discrimination, pii_exposure, prompt_injection, etc.)
  - Automatic 15-working-day Article 73 notification deadline computation
  - PII exposure → GDPR Art. 33 (72h) action auto-inserted
  - `squash incident ./model --description "..." [--severity serious] [--affected-persons N]` CLI
  - 22 new tests

- **`squash/board_report.py`** — Executive AI compliance board report generator (W174):
  - `BoardReportGenerator.generate()`: quarterly board report from model portfolio
  - Outputs: JSON (machine-readable), Markdown, plain text summary, optional PDF via weasyprint
  - Sections: executive summary, compliance scorecard, model portfolio status, regulatory deadlines, remediation roadmap
  - Auto-populates EU AI Act + Colorado AI Act + ISO 42001 deadlines with days-remaining countdown
  - Portfolio trend: IMPROVING / STABLE / DEGRADING
  - `squash board-report --quarter Q2-2026 [--models-dir ./models] [--output-dir ./report] [--json]` CLI
  - 18 new tests

### Changed
- **`squash/cli.py`** — 7 new commands: `iso42001`, `trust-package`, `verify-trust-package`, `agent-audit`, `incident`, `board-report`
- **`tests/test_squash_model_card.py`** — module count gate updated from 51 → 56 (Sprint 5 +5 modules)
- **`SQUASH_MASTER_PLAN.md`** — Sprint 5 roadmap + Sprint 7 (Enterprise Moat) waves W178–W187 added; market intelligence section added with structural market shift analysis ($340M → $4.83B TAM)

### Stats
- **120 new tests** · **0 regressions** · **3339 total tests passing**
- **56 Python modules** (was 51 after Sprint 4B)
- **5 new CLI commands**

---

## [1.0.0] — 2026-04-28 — Sprint 4A: Critical Path to Launch

### Changed
- **Version bump: v0.9.14 → v1.0.0** — production-stable release
- **`pyproject.toml`** — `Development Status :: 5 - Production/Stable`; `stripe>=8.0` billing extra; PEP 561 `py.typed`; expanded keywords and classifiers
- **`README.md` overhaul (W157)** — Tagline "Squash violations, not velocity."; `squash demo` as first command; Sprint 4B feature table; Startup tier ($499/month); Prometheus sample; compliance badge examples
- **`fly.toml`** — Production hardening: `min_machines_running=1`, 512MB/2vCPU, `/metrics` scrape config, rolling deploy
- **`Dockerfile`** — OCI labels, curl healthcheck, `stripe>=8.0`, `sentry-sdk[fastapi]`, `PYTHONDONTWRITEBYTECODE`

### Added
- **`POST /billing/checkout`** (W155) — Stripe Checkout session creation: plans `pro`/`startup`/`team`/`enterprise`, returns `{checkout_url, session_id, plan}` (HTTP 201), 422 on invalid plan
- **`squash/billing.py`** — Startup + Team tiers in plan map (`SQUASH_STRIPE_PRICE_STARTUP`, `SQUASH_STRIPE_PRICE_TEAM`)
- **`website/`** — Next.js 14 + Tailwind landing page (W156): live countdown, terminal demo, feature grid, pricing table, Vercel deploy config
- **`docs/launch/hn-post.md`** (W158) — Show HN post draft with title options, body, anticipated Q&A
- **`docs/launch/devto-article.md`** (W158) — Full Dev.to article draft
- **`docs/launch/design-partner-outreach.md`** (W159) — 3 email templates, pitch call script, target list, design partner terms
- **`squash/py.typed`** — PEP 561 typed package marker
- **17 new tests** in `tests/test_squash_w155.py`

---

## [0.9.14] — 2026-04-28 — Sprint 4B: High-Leverage Engineering

### Added (W160–W168)
- See `SQUASH_MASTER_PLAN.md` Sprint 4B section for full details.

---

## [0.9.13] — 2026-04-28 — Sprint 3: CI/CD & Integrations

### Added (W145–W152 — Sprint 3: CI/CD & Integrations)
- **`action.yml`** — GitHub Actions composite action v1.0 (W145):
  - Inputs: `model-path` (required), `policies`, `sign`, `fail-on-violation`, `api-key`, `output-dir`, `annex-iv`, `squash-version`.
  - Outputs: `passed`, `score`, `artifacts-dir`, `bom-digest`.
  - Steps: `actions/setup-python@v5`, pip install squash-ai, `squash attest`, optional Annex IV generation, `actions/upload-artifact@v4` (90-day retention).
  - Marketplace branding: icon=`shield`, color=`blue`.
- **GitHub Actions marketplace metadata** (W146):
  - All inputs/outputs documented with descriptions; all optional inputs have defaults.
  - Stable action version refs; `@main` refs explicitly forbidden by test gate.
- **`integrations/gitlab-ci/squash.gitlab-ci.yml`** — GitLab CI template (W147):
  - Three job variants: `.squash_attest` (base), `.squash_attest_soft` (allow_failure), `.squash_attest_full` (sign + Annex IV + multi-policy).
  - Variables: `SQUASH_POLICIES`, `SQUASH_SIGN`, `SQUASH_FAIL_HARD`, `SQUASH_ANNEX_IV`, `SQUASH_VERSION`, `SQUASH_OUTPUT_DIR`.
  - Artifacts with 90-day expiry; `squash_result.json` always saved.
- **`integrations/jenkins/vars/squashAttest.groovy`** — Jenkins shared library step (W148):
  - `squashAttest(modelPath:, policies:, sign:, failOnViolation:, outputDir:, annexIv:, squashVersion:, apiKey:)`.
  - `withCredentials()` for API key; `readJSON` for result parsing; `unstable()` on violation.
  - Stashes attestation artifacts (`squash-attestation`) for downstream stages.
- **`.github/workflows/publish-image.yml`** — GHCR Docker image publish workflow (W149):
  - Triggers: release published, push to main (squash/**, Dockerfile, pyproject.toml), `workflow_dispatch`.
  - Tags: `latest`, branch, semver major/minor, SHA short.
  - Concurrency guard; post-push health verification via `docker run`.
  - Uses `secrets.GITHUB_TOKEN` (no PAT required).
- **`integrations/kubernetes-helm/`** — Helm chart for Kubernetes admission controller (W150):
  - `Chart.yaml`: apiVersion v2, type application, appVersion 0.9.14.
  - `values.yaml`: replicaCount=2, image=`ghcr.io/konjoai/squash`, webhook.port=8443, failurePolicy=Ignore, excludeNamespaces=[kube-system], policies=[eu-ai-act], podSecurityContext.runAsNonRoot=true.
  - `templates/deployment.yaml`: liveness+readiness probes on /health, TLS cert volume mount, SQUASH_API_TOKEN from secret ref.
  - `templates/service.yaml`: ClusterIP on 443 → 8443.
  - `templates/validatingwebhookconfiguration.yaml`: admissionReviewVersions=[v1], namespaceSelector exclusions, cert-manager annotation support.
  - `templates/_helpers.tpl`, `templates/serviceaccount.yaml`, `templates/rbac.yaml`.
- **Real MLflow SDK bridge validation** (W151):
  - `squash/integrations/mlflow.py` — `MLflowSquash.attest_run()` fully wired: `AttestPipeline.run()` → `mlflow.log_artifacts()` → `mlflow.set_tags()` with `squash.*` namespace tags.
  - Tags: `squash.passed`, `squash.scan_status`, per-policy `squash.policy.<name>.passed/errors`.
  - `output_dir` defaults to `model_path.parent / "squash"`.
- **218 new tests** across W145–W152 test files. **Sprint 3 complete: 218/218 tests passing.**
- **Bug fixes** (pre-existing, fixed in Sprint 3 cycle):
  - `squash/model_card.py`: `datetime.UTC` → `datetime.timezone.utc` (Python 3.10 compat, caused 17+ test failures).
  - `squash/api.py`: `datetime.UTC` → `datetime.timezone.utc` in `_ts_now()`; `Retry-After` header added to IP-rate-limit 429 responses.
  - `tests/test_squash_model_card.py`: path fixed from `squish/squash` → `squash`, module count updated to 47; `squish.squash.cli` → `squash.cli` in CLI subprocess tests.

### Added (W137–W144 — Sprint 2: Cloud API & Auth)
- **`squash/auth.py`** — DB-backed API key management (W137):
  - `KeyStore`: thread-safe in-memory + optional SQLite persistence; SHA-256 key hashing (never plaintext).
  - `KeyRecord`: plan-aware `monthly_quota`, `rate_per_min`, `quota_remaining`.
  - `generate()`, `verify()`, `revoke()`, `update_plan()`, `increment_attestation_count()`, `reset_quota()`.
  - `POST /keys` (create), `DELETE /keys/{key_id}` (revoke) HTTP endpoints.
  - Module singleton `get_key_store()` / `reset_key_store()` for test isolation.
- **`squash/rate_limiter.py`** — Per-key plan-based sliding-window rate limiter (W138):
  - Limits: free=60, pro=600, enterprise=6000 req/min.
  - `X-RateLimit-Limit` / `X-RateLimit-Remaining` response headers on every authenticated request.
  - Middleware rewritten: legacy `SQUASH_API_TOKEN` still works as ops bypass; DB keys take priority.
- **`Dockerfile` + `fly.toml` + `.github/workflows/deploy.yml`** — Fly.io deployment (W139):
  - Multi-stage Python 3.12 slim build, non-root `squash` user, port 4444, Docker HEALTHCHECK.
  - Fly.io: `iad` region, 256MB RAM, auto-stop, rolling deploy strategy.
  - GitHub Actions CD: test → fly deploy → health verify; `FLY_API_TOKEN` secret; `concurrency` guard.
- **`squash/postgres_db.py`** — PostgreSQL (Neon) cloud DB connector (W140):
  - `PostgresDB` with psycopg2, same interface as `CloudDB`; JSONB columns for tenant + event records.
  - `make_postgres_db()` factory reads `SQUASH_DATABASE_URL`; graceful SQLite fallback when absent.
  - DDL: `tenants`, `event_log` (with index), `api_keys` tables — all `IF NOT EXISTS`.
- **`squash/billing.py`** — Stripe subscription integration (W141):
  - `verify_stripe_signature()` — HMAC-SHA256 with 300s clock tolerance.
  - `StripeWebhookHandler`: `checkout.session.completed` (upgrade), `subscription.updated/deleted` (plan sync), `invoice.payment_failed` (no immediate downgrade).
  - `POST /billing/webhook` endpoint bypasses API key auth; Stripe-Signature verified internally.
- **`squash/quota.py`** — Monthly attestation quota enforcement (W142):
  - `QuotaEnforcer.check()` before pipeline; `consume()` after successful attestation.
  - `QuotaCheckResult` with `X-Quota-Used / Limit / Remaining` response headers.
  - `/attest` returns HTTP 429 with quota details when limit exhausted.
- **`GET /account/status` + `GET /account/usage`** — Authenticated account endpoints (W143):
  - Status: plan, key_id, tenant_id, quota_used/limit/remaining, rate_limit_per_minute, billing_period_start.
  - Usage: total_attestations, monthly_quota, quota_remaining for current billing period.
- **`squash/monitoring.py`** — Sentry error tracking + health endpoints (W144):
  - `setup_sentry()`: reads `SQUASH_SENTRY_DSN`, no-op when absent or `sentry-sdk` not installed.
  - `build_health_report()`: DB liveness probe, uptime, version, component status dict.
  - `GET /health/ping` → `"pong"` (Better Uptime monitor target).
  - `GET /health/detailed` → full health report; 503 when degraded. Both bypass auth.
- **Sprint 2 total: 251/251 tests. S1+S2 combined: 730/730 tests passing.**

### Added (W135 / W136 — Sprint S1 Exit Gate)
- `squash annex-iv generate` CLI command — Sprint S1 exit gate:
  - `--root DIR`: auto-discovers TensorBoard logs, training configs, Python scripts; runs full W128–W133 artifact extraction pipeline.
  - `--format md html json pdf`: selectable output formats (default: md json).
  - `--system-name`, `--version`, `--risk-level {minimal,limited,high,unacceptable}`: Annex IV §1(a) and §4 metadata.
  - `--mlflow-run`, `--wandb-run ENTITY/PROJECT/RUN_ID`, `--hf-dataset` (repeatable): optional cloud augmentation; all fail gracefully with warnings.
  - `--no-validate`, `--fail-on-warning`: pipeline-mode control.
- `squash annex-iv validate PATH`: reconstruct and re-validate any `annex_iv.json`; exit 2 on hard fail, 1 on warning (with `--fail-on-warning`).
- 68 new tests in `tests/test_squash_w135.py`.
- **Sprint S1 complete: 479/479 tests passing (W128–W135).**

### Added (Wave 133 + Wave 134)
- `squash/annex_iv_generator.py` — EU AI Act Annex IV document generator:
  - `AnnexIVGenerator.generate(result, *, system_name, version, ...)` — produces a complete 12-section `AnnexIVDocument` from `ArtifactExtractionResult` (W128-W132 outputs) + supplemental metadata kwargs.
  - 12 section renderers covering all Annex IV requirements: §1(a-c), §2(a-b), §3(a-b), §4, §5, §6(a-b), §7.
  - Per-section completeness scoring (0-100) weighted by legal importance: §1(c) and §2(a) carry 15/112 each; §7 carries 5/112.
  - Overall score = weighted sum across all sections; displayed with `✅ Full / ⚠️ Partial / ❌ Missing` badges.
  - Article-specific gap statements (not generic "N/A") — every missing field names the exact Article and Annex IV section that requires it.
  - `AnnexIVDocument.to_markdown()` — human-readable, version-controllable, diff-friendly Markdown with header table, section badges, metric tables, code blocks.
  - `AnnexIVDocument.to_html()` — standalone HTML with embedded professional CSS (print-ready, dark branded header, score badge color-coded to compliance level). Falls back to minimal MD→HTML if `markdown` package absent.
  - `AnnexIVDocument.to_json()` — machine-readable export with all sections, completeness scores, gaps, and summary block.
  - `AnnexIVDocument.to_pdf(path)` — PDF via `weasyprint` (optional dep); raises `ImportError` cleanly when absent.
  - `AnnexIVDocument.save(output_dir, formats, stem)` — multi-format save; PDF failure silently skipped.
  - `AnnexIVValidator.validate(doc)` → `ValidationReport`: hard-fails on §1(a)/§2(a)/§3(a) below threshold; warnings on §3(b)/§5/§6(a)/overall; bias gap triggers Art. 10(2)(f) warning. `report.is_submittable` = no hard fails.
  - `ValidationReport.summary()` — one-line status string for CLI output.
- `tests/test_squash_w133.py`: 83 tests — badge thresholds, weighted scoring, all 12 sections full/empty/partial, Markdown structure, JSON roundtrip, HTML structure, save() multi-format, validator hard-fails and warnings, full pipeline integration.

### Added (Wave 132)
- `squash/code_scanner_ast.py` — new module (zero external deps, stdlib `ast` only):
  - `CodeArtifacts` dataclass — §1(c) evidence: imports, framework, optimizers, loss functions, model classes, data loaders, checkpoint ops, training loop patterns, requirements.
  - `ImportRecord` — per-import record with module, names, alias, purpose classification, line number.
  - `OptimizerCall` — optimizer instantiation with short_name, framework, extracted constant kwargs (lr, weight_decay, etc.), line number.
  - `CodeScanner.scan_source(source, path)` — scan Python source string; handles SyntaxError gracefully.
  - `CodeScanner.scan_file(path)` — scan a single `.py` file; handles missing files gracefully.
  - `CodeScanner.scan_directory(root, pattern)` — recursive directory scan.
  - `CodeScanner.merge(artifacts)` — merge multiple per-file artifacts, deduplicating imports by module, setting framework from merged import list.
  - `CodeScanner.scan_requirements(path)` — parse `requirements.txt` / `pyproject.toml` → package spec list.
  - `CodeScanner.scan_training_run(root)` — end-to-end: scan all `.py` files + auto-discover requirements files.
  - Framework detection: PyTorch, TensorFlow, JAX, MLX — priority-ordered from import list.
  - Optimizer detection: 19 optimizer names, constant kwarg extraction (lr, weight_decay, momentum, etc.).
  - Loss function detection: 25 loss patterns across PyTorch `nn`, `F`, Keras, and generic names — all underscore-normalized for uniform matching.
  - Checkpoint operation detection: `torch.save`, `save_pretrained`, `save_model`, `save_weights`, `model.save()`, `pickle.dump`, etc.
  - Data loader detection: `DataLoader`, `load_dataset`, `DataPipe`, `ImageFolder`, etc.
  - Training pattern detection: `model.fit`, `trainer.train`, `for epoch in range(...)` loop.
  - Model class detection: `from_pretrained()` calls + `model = SomeClass(...)` assignment heuristic.
- `ArtifactExtractor.from_training_script(path)` → `CodeArtifacts` wrapper.
- `ArtifactExtractor.from_training_directory(root)` → merged `CodeArtifacts` wrapper.
- `ArtifactExtractionResult.code: CodeArtifacts | None` field added; `is_empty()` updated; `to_annex_iv_dict()` emits `section_1c` from code when present (preferred over `TrainingConfig`).
- `from_run_dir()` updated to auto-discover `.py` files and populate `result.code`.
- `tests/test_squash_w132.py`: 107 tests — AST helper units, pattern matchers, full script scans (PyTorch/TF/HuggingFace/JAX/MLX), edge cases, file/dir/merge/requirements scanning, Annex IV §1(c) structure, wrapper integration. Zero mocking, zero network, zero external deps.

### Added (Wave 131)
- `DatasetProvenance` dataclass — structured EU AI Act Annex IV §2(a) evidence: license, languages, task categories, size, source datasets, split info, bias analysis flag, citation, provenance timestamps.
- `DatasetProvenance.completeness_score()` — weighted 0–100 scoring aligned with Article 10(2) obligations. Weights: description (20), license (20), languages (15), source_datasets (15), task_categories (10), size_category (10), bias_analysis (5), citation (5).
- `DatasetProvenance.completeness_gaps()` — returns list of missing field labels for auditor gap reports.
- `DatasetProvenance.annex_iv_section_2a()` — full §2(a) evidence block including bias analysis block with actionable note when missing.
- `ArtifactExtractor.from_huggingface_dataset(dataset_id, *, token, revision)` → `DatasetProvenance`: `HfApi.dataset_info()` for structured metadata + `DatasetCard.load()` for README bias/citation extraction. Card load failure handled gracefully.
- `ArtifactExtractor.from_huggingface_dataset_list(dataset_ids)` → `list[DatasetProvenance]`: multi-dataset extraction with partial-failure fallback records.
- `ArtifactExtractionResult.datasets: list[DatasetProvenance]` field added; `is_empty()` and `to_annex_iv_dict()` updated to include `section_2a`.
- `_has_bias_content()`: EU AI Act Art. 10(2)(f) keyword scanner (bias, fairness, demographic, underrepresented, discrimination, etc.)
- `_extract_citation()`: BibTeX entry extractor from README text.
- `_parse_hf_tags()`: namespace:value splitter for HuggingFace raw tags.
- `_build_dataset_provenance()`: assembles DatasetProvenance from HfApi DatasetInfo + card content.
- `tests/test_squash_w131.py`: 73 tests — keyword detection, BibTeX extraction, tag parsing, completeness scoring, gap reporting, §2(a) structure, mock HfApi integration, card load failure, partial list failure, all three Annex IV sections in combined dict output.

### Added (Wave 130)
- `ArtifactExtractor.from_wandb_run(run_id, *, entity, project, include_system_metrics)` → `TrainingMetrics`: single-pass `scan_history()` streaming — O(1) memory, all series built in one traversal. W&B timestamps are already in seconds (no conversion needed). `None` values and non-numeric entries silently skipped. System metrics (`system/`) excluded by default, opt-in via flag. Addresses Annex IV §3(b).
- `ArtifactExtractor.from_wandb_config(run_id, *, entity, project)` → `TrainingConfig`: strips `_wandb` internal config keys before extraction. Addresses Annex IV §1(c).
- `ArtifactExtractor.from_wandb_run_full(...)` → `ArtifactExtractionResult`: single `api.run()` call — no duplicate round-trips. Both Annex IV sections from one path.
- `_build_wandb_path()`: normalises `run_id` / `entity` / `project` into the canonical `"entity/project/run_id"` path W&B Api expects; full paths passed through verbatim.
- `_extract_wandb_metrics()` / `_extract_wandb_config()`: private helpers for single-object extraction, composable by `from_wandb_run_full`.
- `tests/test_squash_w130.py`: 54 tests — path construction, single-pass streaming, None-skip, system metric opt-in, `_wandb` key stripping, single `api.run()` call assertion, ImportError paths, Annex IV routing. Pure mocks, zero credentials, zero network.

### Added (Wave 129)
- `ArtifactExtractor.from_mlflow_run(run_id, tracking_uri)` → `TrainingMetrics`: full metric history via `MlflowClient.get_metric_history()`, ms→s wall_time conversion, sorted by step. Addresses Annex IV §3(b).
- `ArtifactExtractor.from_mlflow_params(run_id, tracking_uri)` → `TrainingConfig`: run params with numeric string coercion (int, float, bool). Addresses Annex IV §1(c).
- `ArtifactExtractor.from_mlflow_run_full(run_id, tracking_uri)` → `ArtifactExtractionResult`: both metrics and config in one call, single MlflowClient round-trip.
- `_coerce_mlflow_param()`: type coercion for MLflow's string-typed params.
- Local `file://` tracking URI supported — no MLflow server required in CI.
- `tests/test_squash_w129.py`: 55 tests — coercion unit tests, full metric history, multi-step, wall_time seconds, metadata fields, ImportError paths, Annex IV section routing. Uses local file-store fixtures, no live credentials.

### Added (Wave 128)
- `squash/artifact_extractor.py`: Annex IV artifact extraction engine — `ArtifactExtractor`, `TrainingMetrics`, `TrainingConfig`, `MetricSeries`, `ArtifactExtractionResult`
- `ArtifactExtractor.from_tensorboard_logs()`: zero-dependency native TFRecord binary reader + fast path via tensorboard SDK; extracts all scalar series for Annex IV §3(b)
- `ArtifactExtractor.from_training_config()`: YAML / JSON / TOML training config parser; extracts optimizer, scheduler, training loop settings for Annex IV §1(c)
- `ArtifactExtractor.from_config_dict()`: parse already-loaded config dict (MLflow params, W&B config, etc.)
- `ArtifactExtractor.from_run_dir()`: auto-discover `.tfevents.*` + config files in a training run directory
- Stub signatures for W129 (MLflow), W130 (W&B), W131 (HF Datasets), W132 (AST scanner)
- `tests/test_squash_w128.py`: 50 tests — binary parser unit tests, round-trip TFRecord, nested config extraction, auto-discovery, Annex IV section structure validation

## [0.9.14] — 2026-04-28

### Changed
- **repo separation**: Extracted from `konjoai/squish` into standalone `konjoai/squash` repository via `git filter-repo` with full git history preserved
- All `squish.squash` import paths updated to `squash` across 112 source files
- `import squish` version references replaced with `import squash as squish` in `sbom_builder.py`, `attest.py`, `spdx_builder.py`
- `squash/__init__.py` updated: standalone docstring, `__version__ = "0.9.14"` added
- `pyproject.toml`: standalone `squash-ai` package, Apache 2.0 license, modular extras (`api`, `signing`, `sbom`, `integrations`, `dev`)
- `CLAUDE.md`: squash-specific contributor conventions (squash hard rules, compliance framework coverage, API contracts)
- `SQUASH_MASTER_PLAN.md`: master GTM plan from zero to $10M ARR committed to repo
- `README.md`: developer-first landing page with EU AI Act countdown framing
- `.github/workflows/ci.yml`: pytest matrix (Python 3.10/3.11/3.12), ruff lint, security audit
- `.github/workflows/publish.yml`: trusted PyPI publishing on release

### Added (Wave 83 — from squish extraction)
- `squash/nist_rmf.py`: NIST AI RMF 1.0 controls scanner (`NistRmfScanner`, 42 controls across GOVERN·MAP·MEASURE·MANAGE)

### Added (Wave 82 — from squish extraction)
- HQQ (Half-Quadratic Quantization) float precision metadata in SBOM components

### Previous waves (W57–W81)
Extracted with full git history. See `git log --oneline` for complete wave history.

---

*For full history prior to repo separation, see [konjoai/squish](https://github.com/konjoai/squish) git history.*
