# Changelog

All notable changes to `squash-ai` are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/) · [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased]

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
