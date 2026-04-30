# Changelog

All notable changes to `squash-ai` are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/) · [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [1.13.0] — 2026-04-30 — Sprint 27 W243–W245 / Track C-4: Continuous Regulatory Watch Daemon

### Added (W243–W245 — Track C / C4 — Continuous Regulatory Watch Daemon)

Turns squash from a quarterly compliance tool into a daily intelligence service. Poll SEC.gov, NIST.gov, EUR-Lex, and any custom RSS feed for new AI governance requirements, map them to squash policy controls, and surface gap analysis against the local model portfolio — all from a single cron-friendly command.

```bash
# One-shot poll (add to cron)
squash watch-regulatory --once --models-dir ./models --alert-channel slack

# 6-hour daemon
squash watch-regulatory --interval 6h --alert-channel slack

# Custom state legislature feed
squash watch-regulatory --once --extra-feed name=legiscan,url=https://...,keywords=artificial+intelligence

# Dry run — see what would surface without persisting
squash watch-regulatory --once --dry-run --json
```

- **`squash/regulatory_watch.py`** (NEW MODULE — W243–W244):
  - `RegulatoryEvent` — event_id, source, title, url, published, summary, severity, fetched_at
  - `GapAnalysisResult` — maps event → matched_reg_ids, squash_controls, models_to_re_attest, recommended_actions
  - `WatcherConfig` — sources, extra_feeds, timeout, max_events, alert_channel, db_path
  - **Source adapters** (duck-typed, graceful per-source failure):
    - `SecAdapter` — SEC press-release RSS; AI-relevance filtered
    - `NistAdapter` — NIST CSRC publications RSS; AI-relevance filtered
    - `EurLexAdapter` — EUR-Lex Official Journal RSS; AI-relevance filtered
    - `GenericRssAdapter` — any RSS 2.0 or Atom feed with configurable keyword filter
  - **RSS engine** (`_parse_rss`): namespace-aware Atom + RSS 2.0 parser (stdlib only); AI-relevance keyword filter (18 terms); severity scoring (HIGH/MEDIUM/LOW) from title + source
  - **SQLite deduplication** (`~/.squash/regulatory_events.db`): event IDs persisted; second poll returns 0 new events for already-seen items; `mark_all_seen()` for bulk catch-up
  - **Gap analysis** (`gap_analysis(event, models_dir)`):
    - 32-keyword → framework-ID mapping (EU_AI_ACT, NIST_AI_RMF, SEC_AI, FTC, FDA, CMMC, FEDRAMP, EU_GDPR, NYC_LL144, COLORADO_AI_ACT, …)
    - pulls squash CLI controls from `regulatory_feed.py` per matched regulation
    - discovers attested models in `models_dir` that should be re-attested
    - derives `days_to_act` from the regulation's enforcement deadline
  - **Alert routing** via `squash.notifications` for Slack/Teams/webhook channels
  - `parse_interval()` — parse `'6h'`, `'1d'`, `'30m'`, bare seconds

- **`squash/cli.py`** — `squash watch-regulatory` first-class command (W245):
  - `--once` / `--interval INTERVAL` (cron-friendly / continuous-daemon)
  - `--sources {sec,nist,eurlex}` (repeatable; default: all three)
  - `--extra-feed name=NAME,url=URL[,keywords=k1+k2]` (repeatable)
  - `--models-dir DIR` (gap analysis against local attestations)
  - `--alert-channel {stdout,slack,teams,webhook}`
  - `--db-path PATH` (override default `~/.squash/regulatory_events.db`)
  - `--dry-run` (fetch without persist; shows what would surface)
  - `--json` (structured JSON: new_events count + full gap_results array)
  - `--max-events N` (per-poll cap; default 50)
  - `--quiet`

- **`tests/test_squash_sprint27.py`** (NEW) — 63 tests:
  - RSS + Atom parsing; AI-relevance filter; severity scoring; event ID stability
  - `parse_interval` (6h, 1d, 30m, plain seconds, empty, invalid)
  - All 4 adapters with mocked `_http_get`; per-source graceful failure
  - `RegulatoryWatcher`: first-poll returns all, second-poll deduplicates, new event on third poll surfaces, `mark_all_seen`, `load_history`
  - Gap analysis: EU_AI_ACT match, NIST_AI_RMF match, squash controls from feed, attested models discovered, no-match has actions, `summary_text`, `to_dict`
  - Regulatory ID mapping: EU_AI_ACT, NIST_AI_RMF, multi-reg, no-keyword-returns-empty
  - CLI: help surface (10 flags), misconfig exit 2, once/no-events→0, event-summary printed, JSON output, dry-run, default-sources config

### Changed
- **Module count gates** (8 files) bumped 75 → 76 for `regulatory_watch.py`
- **`SQUASH_MASTER_PLAN.md`** — Track C / C4 marked **shipped**

### Stats
- **63 new tests** · **0 regressions** · **4260 total tests passing**
- **1 new module** (`regulatory_watch.py`) · 75 → 76 modules
- **1 new top-level CLI command** (`watch-regulatory`) with 10 flags
- **4 source adapters** covering the primary AI governance regulatory sources

---

## [1.12.0] — 2026-04-30 — Sprint 15 W208 / Track B-2: Branded PDF Compliance Report

### Added (W208 — Track B / B2 — Branded PDF Compliance Report)

The CISO leave-behind that closes deals. A fully branded executive PDF from `squash annex-iv generate --branded` with cover page, KPI scorecard, exec summary, full Annex IV body, and signature block. WeasyPrint-based; degrades to an HTML preview when WeasyPrint is absent.

```
squash annex-iv generate --root ./model \
  --system-name "BERT Sentiment Classifier" \
  --format pdf \
  --branded \
  --org "Acme Corp" \
  --author "ML Platform Team" \
  --output-dir ./compliance/
```

- **`squash/pdf_report.py`** (NEW MODULE) — complete branded PDF engine:
  - `BrandedPDFConfig(org_name, author, logo_path, accent_color, include_cover, include_exec_summary, include_signature, confidentiality_label)`
  - `PDFReportBuilder(config).build_html(doc)` → full HTML string (preview without WeasyPrint)
  - `PDFReportBuilder(config).build_from_document(doc)` → raw PDF bytes
  - `PDFReportBuilder(config).save(doc, output_dir, stem)` → writes `*.pdf` + `*.html`; degrades to HTML-only when WeasyPrint is absent
  - **Cover page** — dark navy background (#0a0f1a), Squash wordmark SVG embedded inline, system name, version, compliance score (colour-coded: ≥80% green / ≥40% amber / <40% red), attestation ID, metadata table, organisation + author
  - **Executive summary page** — 4-KPI scorecard (overall score, sections complete, sections missing, total gaps), full section completion table with status badges (✓ Complete / ⚠ Partial / ✗ Missing), per-section gap callout blocks
  - **Full Annex IV body** — all sections with dark-navy section headers, completeness badges, gap notes, attestation ID banner
  - **Signature block** — three approval lines (Legal Review / Compliance Officer / Engineering Lead)
  - HTML/XSS escaping throughout; `<script>`, `<style>` injection impossible
  - Logo fallback chain: custom path → Squash dark SVG → inline wordmark

- **`squash/templates/annex_iv_branded.css`** (NEW) — 370-line WeasyPrint-compatible CSS:
  - `@page` rules with running headers (`@top-right` confidentiality label, `@bottom-right` page counter, `@bottom-center` document title)
  - Named pages: `cover` (zero margins), `exec-summary` (custom top margin), default body
  - Brand design system: Inter + JetBrains Mono, `#22c55e` accent, `#0a0f1a` navy
  - Table-based layout for email-client-safe rendering
  - Email-client fallback CSS also included for HTML preview mode

- **`squash/templates/squash-logo-dark.svg`** + **`squash-logo-light.svg`** + **`squash-logo-mark.svg`** (NEW brand assets) — Squash wordmark extracted from marketing site design; embedded inline in the cover page

- **`squash/cli.py`** — `squash annex-iv generate` gains `--branded`, `--org`, `--author`, `--logo`, `--accent` flags:
  - `--branded` — triggers `PDFReportBuilder` after the normal save; WeasyPrint absence is a warning, not an error
  - `--org NAME` — organisation name on cover
  - `--author NAME` — preparer name on cover
  - `--logo PATH` — custom SVG/PNG logo (replaces Squash wordmark)
  - `--accent HEX` — brand accent override (default `#22c55e`)

- **`tests/test_squash_w208_pdf_report.py`** (NEW) — 47 tests:
  - BrandedPDFConfig defaults + coercion
  - Cover page: score colour classes, org/author, attestation ID, logo embedding, disable flag
  - Exec summary: KPI table, gap highlights, section badges, disable flag
  - Body: section blocks, gap notes, attestation ID banner
  - Signature block: three sig lines, labels, disable flag
  - Custom accent colour injection
  - HTML/XSS escaping
  - `save()`: WeasyPrint mock path, graceful degradation
  - Template files: CSS exists, contains brand green + @page rule + .cover-page
  - CLI: all 5 new flags in help, branded flow with WeasyPrint absent

**Module count:** 74 → 75 (`pdf_report.py` + `templates/` directory with 3 SVGs + 1 CSS — only `pdf_report.py` counts as a Python module)

---

## [1.11.0] — 2026-04-30 — Sprint 32 W257–W258 / Track B-8: LoRA / Adapter Poisoning Detection

### Added (W257–W258 — Track B / B8 — LoRA / Adapter Poisoning Detection)

LoRA adapters are perceived as "small therefore low-risk." They are not.
A LoRA adapter is a complete behavioural rewrite in megabytes. JFrog Security
(2024) found ~100 malicious models on HuggingFace, several establishing
reverse-shell on load. This sprint ships the first dedicated adapter security
gate in the compliance-as-code ecosystem.

```
# Block any non-safetensors adapter outright (policy gate)
squash scan-adapter --lora ./adapter.pt --require-safetensors
# → rc=2, CRITICAL: --require-safetensors violated

# Scan a safetensors adapter with signed certificate
squash scan-adapter --lora ./adapter.safetensors --sign
# → CLEAN · 2 tensors · 0 findings · Certificate: adapter-squash-adapter-scan.json

# Full JSON report for CI integration
squash scan-adapter --lora ./adapter.safetensors --json
# → {"risk_level": "CLEAN", "findings": [], "adapter_hash": "...", ...}
```

- **`squash/adapter_scanner.py`** (new module) — complete standalone adapter scanner:
  - `detect_format(path)` — magic-byte detection of safetensors vs. pickle vs. unknown
  - `scan_pickle_opcodes(path)` — GLOBAL, REDUCE, STACK_GLOBAL, NEWOBJ scan without deserialisation
  - `scan_shell_patterns(path)` — text-pattern sweep for injection strings (safe on any format)
  - `parse_safetensors_header(path)` — header integrity + out-of-bounds offset detection
  - `_analyse_tensors(path, tensors)` — per-tensor stats: mean, std, kurtosis, l2_norm, NaN/Inf
  - `_compute_concentration(stats)` — layer-concentration score (single layer > 85% of total L2 norm)
  - `scan_adapter(path, require_safetensors, sign, output_path)` → `AdapterScanReport`
  - Signed `squash-adapter-scan.json` certificate (HMAC-SHA256 of report payload)

- **`squash/cli.py`** — `squash scan-adapter` command:
  - `--lora <path>` — adapter file to scan
  - `--require-safetensors` — exit rc=2 if adapter is not safetensors format
  - `--sign` — embed HMAC-SHA256 signature in certificate JSON
  - `--output <path>` — custom certificate output path
  - `--json` — emit full JSON report to stdout for CI parsing

**Threat model covered (W257):**

| Threat | Detection | Severity |
|--------|-----------|----------|
| Pickle / PyTorch format | PK-001 GLOBAL/REDUCE/STACK_GLOBAL opcodes | CRITICAL |
| Pickle without explicit opcodes | PK-002 inherent execution risk | HIGH |
| `--require-safetensors` policy violation | PK-003 format gate | CRITICAL |
| Shell injection strings in any format | SH-001 pattern sweep | CRITICAL |
| safetensors OOB read vector | ST-006 offset > file size | CRITICAL |
| Malformed safetensors header | ST-001–ST-004 integrity checks | CRITICAL |
| NaN / Inf weights | WD-001/WD-002 float sentinel check | HIGH |
| Kurtosis anomaly (spike weights) | WD-003 excess kurtosis > 8 | HIGH/MEDIUM |
| High-value target (embed_tokens/lm_head) large magnitude | WD-004 | HIGH |
| Layer concentration (backdoor in one layer) | WD-005 > 85% L2 in single tensor | MEDIUM |

**Statistical thresholds tuned against (W258):**
- ≥3 known-clean adapter fixtures (F32 Gaussian, BF16 QLoRA, multi-layer)
- ≥1 known-malicious fixture per threat class (pickle+opcodes, kurtosis spike, NaN, OOB, shell injection)
- Clean kurtosis threshold: |kurtosis| < 8 for all 3 clean fixtures

**Module count:** 73 → 74 (adapter_scanner.py)

---

## [1.10.0] — 2026-04-30 — Sprint 15 W209/W210 / Track B-3: Compliance Digest

### Added (W209/W210 — Track B / B3 — Weekly / Monthly Email Digest)

The passive-retention surface. Squash stays in front of the CISO's eyes
between active sessions. A weekly or monthly portfolio email lands in
the inbox with five-metric posture, top-5 risk movers, and the August 2
countdown — no dashboard login required.

```
# Cron-friendly stdout dump (no SMTP needed)
squash digest send --period weekly --dry-run --models-dir ./models

# Render-only preview (text / HTML / JSON)
squash digest preview --models-dir ./models --format html --output ./digest.html

# Send via any SMTP (Resend / Mailgun / SES / direct)
SQUASH_SMTP_HOST=smtp.resend.com SQUASH_SMTP_FROM=ciso-digest@acme.com \
  squash digest send --period weekly --org "Acme ML" \
    --recipients ciso@acme.com --recipients vp-eng@acme.com \
    --dashboard-url https://app.getsquash.dev/acme
```

- **`squash/notifications.py` extension — `ComplianceDigestBuilder` (W209)**:
  - `ComplianceDigest` dataclass — period, subject, summary, top_movers,
    deadlines, html_body, text_body, dashboard_url, org_name
  - `DigestMover` — model_id, score, score_delta, violations, CVEs,
    risk tier, drift flag, last_attested
  - `DigestDeadline` — label, ISO date, days_remaining; sorted
    soonest-first; past deadlines bury at the end
  - `ComplianceDigestBuilder.build(period, models_dir|dashboard, org_name,
    dashboard_url, score_history, deadlines, now)`:
    1. consumes the existing `dashboard.Dashboard` (no new data sources)
    2. ranks the worst 5 model rows (violations DESC, score ASC, cves DESC)
    3. computes per-model score deltas when `score_history` is supplied
    4. counts down EU AI Act Aug 2, Colorado Jun 1, ISO 42001 Jan 1, 2027
    5. renders deterministic HTML + plain-text bodies
  - **HTML body is email-client safe** — inlined styles only, no
    `<style>` / `<link>` / `<script>` / `javascript:`, table-based
    layout, no remote images, no JS, defensive Outlook-friendly
  - HTML organisation: org header → H1 (period digest) → H2 Portfolio
    summary table → H2 Top 5 risk movers table (drift pill, score
    delta arrows ▲/▼/→) → H2 Regulatory deadlines table → footer
  - Plain-text body mirrors the same content in Markdown shape
    (cron-friendly stdout dump)

- **`squash/notifications.py` — SMTP send path (W209)**:
  - `SmtpConfig` dataclass with env-var fallbacks (`SQUASH_SMTP_HOST`,
    `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TLS`); `is_configured`
    property gates the live send
  - `send_email_digest(digest, recipients, smtp, dry_run)`:
    - dry-run path returns success without opening any socket
    - live path builds a `multipart/alternative` MIME message with
      both bodies, opens stdlib `smtplib.SMTP` with optional STARTTLS,
      sends to all recipients, surfaces SMTP errors as a structured
      `DigestSendResult`
  - **Resend / Mailgun / SES / Postmark all "supported"** by pointing
    `SQUASH_SMTP_*` at the provider's SMTP relay — zero
    provider-specific code in squash

- **`squash/cli.py` — `squash digest preview` / `squash digest send` (W210)**:
  - Two subcommands under a new top-level `digest` command
  - **`preview`** — renders to stdout (default text) or to file;
    `--format text|html|json`; `--output FILE`
  - **`send`** — emails via SMTP; `--recipients` (repeatable),
    `--dry-run`, `--smtp-host`, `--smtp-port`, `--smtp-from`,
    `--no-tls`
  - Common flags shared via `_add_common_digest_args`:
    `--period {weekly,monthly}`, `--models-dir`, `--org`,
    `--dashboard-url`, `--score-history JSON_FILE`, `--quiet`
  - Exit codes: 0 success / 1 send failed (SMTP / no recipients) /
    2 misconfig (bad period, bad score-history file, missing dep)

- **`tests/test_squash_w209_w210_digest.py` (NEW)** — 37 tests covering:
  - Builder: period validation, summary aggregation, top-mover
    ranking, top-5 cap, score-delta arrows, deadline soonest-first
    sort, past-deadline burial, subject-line composition,
    text/HTML/JSON serialisation, drift pill rendering, score-arrow
    rendering, `to_dict()` round-trip
  - SmtpConfig: env-var fallback, explicit-arg override,
    `is_configured` predicate
  - send_email_digest: no-recipients failure, dry-run path,
    unconfigured-SMTP failure, **`smtplib.SMTP` mocked at the import
    boundary** to verify `starttls`+`login`+`sendmail` calls,
    no-credentials path, error propagation
  - CLI: help surface, preview text/html/json formats, `--output`
    file write, `--score-history` happy + bad-input paths, `send
    --dry-run` with and without recipients, unconfigured SMTP exits 1

### Changed
- **`squash/notifications.py`** — adds digest types + SMTP path at the
  end of file; existing `NotificationDispatcher` semantics unchanged
- **`squash/cli.py`** — adds `digest` command with two subcommands
- **`SQUASH_MASTER_PLAN.md`** — Track B / B3 marked **shipped** alongside
  Sprint 15 W209/W210

### Stats
- **37 new tests** · **0 regressions** · **4064 total tests passing**
  (verified on a B3-only working tree; B5 in-flight work stashed aside
  for the verification)
- **0 new modules** — both waves are extensions to `notifications.py`
  and `cli.py`. Module count unchanged.
- **5 new CLI flags** (shared) + **5 send-only flags**

### Konjo notes
The Konjo discipline this sprint: **0 new modules.** The dashboard
already had every metric needed; B3 is purely a render layer + a
delivery layer over the existing telemetry. No graveyards, no parallel
data path, no provider-specific code (Resend / Mailgun / SES are all
SMTP relays — no need to write a Resend adapter when stdlib smtplib
already works against any of them). The `--dry-run` flag exposes the
exact same render the live send produces — "preview" and "send" are
the same code path branching on whether to hit the network. *건조*
applied to the surface area: one builder, two delivery paths, one CLI.

---

## [1.9.0] — 2026-04-30 — Sprint 14 W205 / Track B-1: Public HF Scanner

### Added (W205 — Track B / B1 — Public HuggingFace Model Scanner)

The first Track B parallel item. The free top-of-funnel growth tool any
ML engineer can run against any public HuggingFace model in one
command — no login, no enterprise SaaS, no sales call. Squash's
brand-builder on the platform with the largest concentration of ML
engineers in the world.

```
squash scan hf://meta-llama/Llama-3.1-8B-Instruct
squash scan hf://microsoft/phi-3@v2.0 --policy enterprise-strict --output-dir ./out
squash scan hf://acme/private --hf-token $HF_TOKEN --download-weights
```

- **`squash/hf_scanner.py` (NEW MODULE — W205)**:
  - `HFRef` / `RepoMetadata` / `HFScanReport` dataclasses
  - `parse_hf_uri(uri)` — strict URI parser supporting
    `hf://owner/model[@revision]` form (revisions can include `/` for
    branch names like `feat/my-branch`)
  - `is_hf_uri(s)` — cheap predicate, no network call
  - `HFScanner.scan(uri, ...)` — orchestrator that:
    1. parses the URI,
    2. lazily imports `huggingface_hub`,
    3. calls `snapshot_download` to a temp directory (light mode by
       default — skips weight files; opt-in via `download_weights=True`),
    4. fetches repo metadata via `HfApi.model_info` (license,
       downloads, last_modified, library_name, pipeline_tag, tags, sha),
    5. runs `ModelScanner.scan_directory` against the snapshot,
    6. optionally runs a policy preview via `PolicyEngine.evaluate`,
    7. flags license warnings (unknown / restricted / non-permissive),
    8. detects weight format from observed file suffixes,
    9. returns a structured `HFScanReport` with `to_json()` /
       `to_markdown()` / `save()` methods,
    10. cleans up the temp directory unless `keep_download=True`
  - License-warning logic with three buckets:
    - **Permissive** (apache-2.0, mit, bsd-3-clause, cc-by, openrail) —
      no warning
    - **Restricted** (llama2/3/3.1/3.2/3.3, gemma, deepseek, openrail-m) —
      warns about deployment-specific commercial / MAU restrictions
    - **Unknown / non-listed** — warns to verify manually
  - Markdown report includes repo metadata table, scan status
    (✅/⚠️/❌), findings table (truncates at 25 with "+N more" footer),
    license warnings, policy-preview table, link back to
    `getsquash.dev` for self-serve install

- **`squash/cli.py` — `squash scan hf://...` integration (W205)**:
  - `_cmd_scan` now detects `hf://` prefix on the positional argument
    and routes to a new `_cmd_scan_hf` handler — no new subcommand,
    just a transparent extension of the existing `squash scan`
  - 6 new flags applicable to `hf://` mode:
    - `--policy POLICY` (repeatable) — policy preview to evaluate
    - `--output-dir DIR` — where to write `squash-hf-scan.{json,md}`
      (default: cwd)
    - `--download-weights` — opt into full weight download (default
      light mode skips weights — keeps the public scanner fast and cheap)
    - `--keep-download` — retain the temp directory after scan
    - `--hf-token TOKEN` — HF Hub token for private/gated repos;
      falls back to `HUGGING_FACE_HUB_TOKEN` / `HF_TOKEN` env
    - `--quiet` — suppress non-essential output
  - Pass-through `--json-result` and `--sarif` flags now also apply
    to the hf:// path
  - Local-path scanning preserved verbatim (regression test included)
  - Exit-code matrix:
    - 0  scan clean
    - 1  scan unsafe (or malformed URI when not also using `--exit-2-on-unsafe`)
    - 2  configuration / dependency error / malformed URI / missing huggingface_hub

- **`tests/test_squash_w205_hf_scanner.py` (NEW)** — 40 tests covering:
  - URI parsing edge cases (basic, with revision, slash-revision,
    missing prefix, malformed, owner-only, `is_hf_uri` predicate)
  - `RepoMetadata.to_dict` + `HFScanReport` JSON / Markdown
    serialisation including findings-table truncation at 25 + policy
    preview table
  - `save()` writes both JSON + Markdown
  - License-warning logic for all 4 license buckets
  - Weight-format detection (safetensors / gguf / pickle /
    metadata-only fallback)
  - End-to-end `HFScanner.scan()` with `huggingface_hub` mocked at the
    `sys.modules` import boundary — tests `revision` is forwarded,
    light-mode default skips weights, `--download-weights` lifts the
    filter, `keep_download=True` preserves the temp dir, missing
    `huggingface_hub` raises clean ImportError
  - CLI dispatch via subprocess + a runtime shim that injects the
    mocked `huggingface_hub` before `squash.cli` imports it — tests
    help surface, malformed URI rc=2, clean scan writes both
    artefacts, policy preview lands in the JSON, `@revision` carried
    through, **local-path regression guard** confirms existing
    behaviour is untouched

### Changed
- **Module count gates** (5 files: `test_squash_model_card.py`,
  `test_squash_wave49.py`, `test_squash_wave52.py`,
  `test_squash_wave5355.py`, `test_squash_sprint11/12/13.py`) all bumped
  71 → 72 with explanatory comments noting the gate now tracks current
  count rather than sprint-snapshot count.
- **`SQUASH_MASTER_PLAN.md`** — Track B / B1 marked **shipped**
  alongside Sprint 14 W205.

### Stats
- **40 new tests** · **0 regressions** · **4027 total tests passing**
- **1 new module** (`squash/hf_scanner.py`) · 71 → 72 modules
- **6 new CLI flags** on `squash scan` (hf:// mode)
- **First Track B item shipped** — the parallel-track operating model
  is now active.

### Konjo notes
The Konjo discipline this sprint: B1 is the highest-leverage parallel
item that depends only on the existing scanner + policy modules. Same
calendar week ships A1/A2 (Track A) + C1 (Track C) too — exactly the
parallelisation insight the master plan codifies. The hf:// path
extends `squash scan` rather than introducing a new top-level
subcommand: one user-facing entry point, two backends, zero learning
overhead. Light-mode default (no weight download) keeps the public
scanner fast & cheap; `--download-weights` is opt-in for users who
want the full security audit. *건조* applied to the surface area.

---

## [1.8.0] — 2026-04-30 — Sprint 13: Startup Pricing Tier ($499/mo)

### Added (W202–W204 — Sprint 13: Startup Pricing Tier — Tier 2 #19)

Open the seed/Series A revenue band with a $499/mo Startup tier. The
gap between Free → Pro ($299) → Team ($899) was exactly where the
highest-velocity buyers sit. This sprint closes it and turns the Pro
plan into a stepping stone rather than a ceiling.

- **`squash/auth.py` — Plan registry expansion (W202)**:
  - New `PLAN_LIMITS["startup"]` — 500 attestations/mo, 1200 req/min,
    `max_seats: 3`, entitlements: annex_iv + drift_alerts + slack +
    teams + **vex_read** + **github_issues**
  - New `PLAN_LIMITS["team"]` — 1000 attestations/mo, 3000 req/min,
    `max_seats: 10`, entitlements add jira + linear + saml_sso + hitl +
    audit_export
  - All five plans (free / pro / startup / team / enterprise) now
    carry consistent `max_seats` and `entitlements` keys
  - 13 named entitlement constants exported from `squash.auth`
    (`ENTITLEMENT_VEX_READ`, `ENTITLEMENT_SLACK_DELIVERY`, etc.)
  - `KeyRecord.max_seats`, `KeyRecord.entitlements`,
    `KeyRecord.has_entitlement(name)` — three new properties / methods
  - `to_dict()` now exposes `max_seats` + `entitlements` for API consumers

- **`squash/auth.py` — `has_entitlement()` helper (W203)**:
  - `has_entitlement(plan, name) -> bool` — central lookup function
  - Empty plan returns False for everything (safe default for
    unauthenticated callers); unknown plans behave like `free`
  - `plan_max_seats(plan) -> int | None` — seat-cap lookup

- **`squash/notifications.py` — gated dispatch (W203)**:
  - `NotificationDispatcher.notify(..., plan="")` — new optional kwarg
  - When `plan` is supplied AND lacks `slack_delivery` / `teams_delivery`,
    that channel is silently skipped (logged at DEBUG)
  - `plan=""` (default) preserves existing un-gated CLI / library behaviour

- **`squash/ticketing.py` — gated dispatch (W203)**:
  - `TicketDispatcher.create_ticket(..., plan="")` — new optional kwarg
  - GitHub backend requires `github_issues` (startup+); Jira requires
    `jira` (team+); Linear requires `linear` (team+)
  - On entitlement miss: returns `TicketResult(success=False)` with a
    structured `error` message naming the missing entitlement

- **`squash/billing.py` — Stripe Startup checkout (W204)**:
  - `create_checkout_session(plan="startup", ...)` flows through the
    existing checkout flow using `SQUASH_STRIPE_PRICE_STARTUP` env var
  - `POST /billing/checkout` (api.py W155) already accepted `startup` —
    Sprint 13 adds test coverage to lock the behaviour
  - Stripe webhook → plan sync via `_price_to_plan()` already mapped
    Startup; tests cover the round-trip

### Changed
- **`tests/test_squash_w137.py`** — `TestPlanLimits.test_all_plans_present`
  updated to recognise the 5-plan registry (was 3)
- **`SQUASH_MASTER_PLAN.md`** — Sprint 13 marked complete; full
  **Tier 3 sprint breakdown** added (Sprints 14–18, waves W205–W220)
  covering all 8 Tier 3 features:
  - Sprint 14: Public Security Scanner & HF Spaces (#23 + #27)
  - Sprint 15: Branded PDF Reports & Compliance Email Digest (#24 + #25)
  - Sprint 16: IaC & Runtime API Gates (#26 + #28)
  - Sprint 17: Cryptographic Provenance: Blockchain Anchoring (#29)
  - Sprint 18: SOC 2 Type II Readiness (#30)

### Stats
- **35 new tests** · **0 regressions** · **3987 total tests passing**
- **0 new modules** (Sprint 13 is extensions only) · 71 modules unchanged
- **2 new plans** (`startup`, `team`) · **13 named entitlement constants**
- **Tier 2 of the master plan now 100% complete.**

### Konjo notes
The Konjo discipline this sprint: keep gating *additive*. Every dispatcher
keeps its existing un-gated behaviour when `plan=""` (the default). Tests
only see the gate when they explicitly pass a plan. No breaking changes,
no migration required, no surface area for regression. Five plans now
share one entitlement vocabulary — *建造* (the discipline of subtraction)
applied to the policy surface.

---

## [1.7.0] — 2026-04-29 — Sprint 12: Model Registry Auto-Attest Gates

### Added (W198–W201 — Sprint 12: Registry Auto-Attest Gates — Tier 2 #18)

Make registration in MLflow / W&B / SageMaker Model Registry the
enforcement gate for compliance. A model that fails attestation cannot
reach production. Compliance is enforced at the moment of promotion,
not discovered later in audit.

- **`squash/integrations/mlflow.py` — `MLflowSquash.register_attested()` (W198)**:
  - Attest, then call `mlflow.register_model` only on policy success
  - On policy fail (default `fail_on_violation=True`): raises
    `AttestationViolationError` and **never calls `register_model`**
  - On `fail_on_violation=False`: registers anyway, lets the failed
    `squash.passed=false` tag drive downstream gates
  - Tags new ModelVersion with `squash.passed`, `squash.attestation_id`,
    `squash.scan_status`, `squash.policy.<name>.passed`, plus optional
    user-supplied `tags={...}`
  - 6 new tests (happy path, refuse path, import error, fail_on_violation
    toggle, attestation tag, extra tags merged)

- **`squash/integrations/wandb.py` — `WandbSquash.log_artifact_attested()` (W199)**:
  - Attest, then build a fresh `wandb.Artifact` containing both model
    files and squash artefacts, then call `run.log_artifact()` only on pass
  - Artifact metadata block carries `squash.passed`, `squash.attestation_id`,
    `squash.scan_status`, and per-policy pass/fail/error/warning counts
  - On policy fail (default): raises `AttestationViolationError`,
    `run.log_artifact` is **never called**
  - `aliases=` argument forwarded to W&B (`["latest", "production"]` …)
  - 6 new tests (happy path, refuse path, import error, metadata
    contents, alias forwarding, soft-gate mode)

- **`squash/integrations/sagemaker.py` — `SageMakerSquash.register_model_package_attested()` (W200)**:
  - Attest, then `sagemaker.create_model_package(...)` with
    `ModelApprovalStatus="Approved"` only on policy pass
  - On policy fail (default): raises `AttestationViolationError`,
    no ModelPackage is created
  - On `fail_on_violation=False`: ModelPackage is created with
    `approval_status_on_fail` (default `"Rejected"`,
    `"PendingManualApproval"` also supported) so audit trail records the
    attempt
  - All squash attestation results recorded as AWS tags on the new
    ModelPackage; `squash:gate_decision` tag captures the approval status
  - 6 new tests (Approved on pass, Rejected on fail soft-mode,
    PendingManualApproval custom status, refuse path, tag attachment,
    import error)

- **`squash/cli.py` — `squash registry-gate` first-class command (W201)**:
  - Unified pre-registration gate for CI/CD pipelines:
    `squash registry-gate --backend {mlflow|wandb|sagemaker|local} \
       --uri <URI> --model-path ./model --policy <P>`
  - Backend-specific URI validation (rejects ARNs for mlflow,
    `models:/...` for sagemaker, etc.) — exits 2 on misconfig
  - Always emits `registry-gate.json` under `--output-dir` containing
    structured `decision: allow|refuse|record-only`, attestation_id,
    per-policy pass/fail, scan_status
  - `--allow-on-fail` for soft-gate mode (records but exits 0)
  - `--json` for machine-readable stdout (CI parsing)
  - 9 new tests (help, local backend, --allow-on-fail, JSON output,
    URI validation per backend, missing model path)

### Changed
- **`squash/cli.py`** — added `registry-gate` top-level subcommand and
  `_validate_registry_uri()` helper
- **`squash/integrations/sagemaker.py`** — extracted `_result_to_tags()`
  helper shared between `tag_model_package()` and
  `register_model_package_attested()`

### Stats
- **28 new tests** · **0 regressions** · **3952 total tests passing**
- **0 new modules** (Sprint 12 is extensions only) · 71 modules unchanged
- **3 new in-process gate methods** (one per supported registry)
- **1 new top-level CLI command** (`registry-gate`) with 9 flags

### Konjo notes
The gate-vs-record distinction is the core idea. Production model
registries are the moment compliance becomes real. Sprint 12 turns
squash from passive observer into an active gate at exactly that moment
— without forcing it: `fail_on_violation=False` preserves the soft
mode for orgs that want to record-and-route rather than block.

---

## [1.6.0] — 2026-04-29 — Sprint 11: Chain & Pipeline Attestation

### Added (W195–W197 — Sprint 11: Chain & Pipeline Attestation — Tier 2 #16)

The EU AI Act regulates the deployed system, not individual model weights.
A modern AI system is a chain — RAG (retriever → embedder → LLM), a
tool-using agent (LLM + tool-belt), or a multi-LLM ensemble (parallel
branches). Squash now attests the whole chain as a single signed unit.

- **`squash/chain_attest.py` — Composite chain attestation engine (W195) — NEW MODULE**:
  - `ChainComponent` / `ChainSpec` / `ComponentAttestation` / `ChainAttestation` dataclasses
  - `ChainAttestPipeline.run()` — iterates components, delegates each to
    `AttestPipeline`, aggregates worst-case
  - **Composite score formula**:
      `score = 100 − 25·errors − 5·warnings − 50·(scan failed)` per
      component, clipped [0, 100]; composite = `min(component scores)`
  - **Worst-case policy roll-up**: a chain passes a policy iff every
    attestable component passes it
  - **HMAC-SHA256 signing** over canonical JSON serialisation; default
    deterministic per-chain key, override with `signing_key`
  - **Tamper detection** via `verify_signature()` — flips on any change
    to chain_id / components / scores / policy roll-up
  - JSON / Markdown rendering (`save()`, `to_markdown()`, `to_json()`)
  - JSON / YAML chain-spec loader (`load_chain_spec`); PyYAML optional
  - 30 new tests

- **`squash/integrations/langchain.py` — `attest_chain()` Runnable graph walker (W196)**:
  - Walks any LangChain Runnable graph duck-style (no LangChain SDK
    dependency); recognises:
    - `RunnableSequence` (linear LLM chain) → `ChainKind.SEQUENCE`
    - `RunnableParallel` (multi-LLM ensemble) → `ChainKind.ENSEMBLE`
    - Tool-using agents (`AgentExecutor.tools`) → `ChainKind.AGENT`
    - RAG retrievers, embedders, tools, LLMs auto-classified by role
  - Hosted-API LLMs (`ChatOpenAI`, `ChatAnthropic`, `Bedrock`, `Cohere`,
    `AzureOpenAI`, `Google`, …) auto-flagged `external=True` and
    excluded from the score (recorded in report for vendor risk review)
  - Edge topology preserved; duplicate component names auto-suffixed
    while edges are retargeted onto new unique names
  - 12 new tests

- **`squash/cli.py` — `squash chain-attest` first-class command (W197)**:
  - `squash chain-attest ./chain.json [--policy P] [--output-dir DIR]`
  - `squash chain-attest myapp.chains:rag_pipeline` — Python module
    path resolution to a LangChain Runnable
  - `--verify <chain-attest.json>` — HMAC verification, exits non-zero
    on tamper
  - `--fail-on-component-violation` — exits 1 when composite_passed=False
  - `--chain-id REPO_ID` — override the chain identifier
  - `--sign-components` — Sigstore-sign each component BOM during attest
  - `--json` / `--quiet` — structured / silent output
  - 7 new tests

### Changed
- **`tests/test_squash_model_card.py`**, **`tests/test_squash_wave49.py`**,
  **`tests/test_squash_wave52.py`**, **`tests/test_squash_wave5355.py`** —
  module count gates updated 70 → 71
- **`SQUASH_MASTER_PLAN.md`** — Sprint 11 marked complete; situation report
  updated to v1.6.0; remaining Tier 2 items: #18 registry auto-attest,
  #19 startup pricing tier

### Stats
- **49 new tests** · **0 regressions** · **3924 total tests passing**
- **71 Python modules** (was 70 after Sprint 10)
- **1 new module** (`squash/chain_attest.py`)
- **1 new top-level CLI command** (`chain-attest`) with 8 flags
- **Three chain topologies covered**: RAG (sequence), tool-using agent,
  multi-LLM ensemble (parallel)

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
