# Changelog

All notable changes to `squash-ai` are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/) · [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [2.2.0] — 2026-04-30 — C10: Runtime Hallucination Monitor (W267-W269)

> EU AI Act Article 9(1)(f) requires post-market monitoring throughout the AI system lifecycle.
> 18% production hallucination rate · 39% of chatbots reworked in 2024.

### Added (W267-W269 / Track C / C10)

- **`squash/hallucination_monitor.py`** — Runtime hallucination monitor:
  - `RequestSampler` — configurable sample-rate (default 5%) interceptor; scores live
    request/response pairs; thread-safe; zero overhead on unsampled requests
  - `RollingWindow` — fixed-size append-only ring buffer (default 1000 entries); JSONL
    persisted so the monitor survives restarts; Wilson 95% CI on demand; `since=` filter
  - `score_live_response()` — three modes: **grounded** (full C7 scorer with GT), **RAG
    context-only** (token overlap against context), **black-box** (structural heuristics:
    absolute claim detection, hedging language, entity density)
  - `BreachEngine` — confirmed breach requires BOTH point estimate > threshold AND CI lo
    > threshold; prevents false alarms from small samples; fires `on_breach` callback
  - `notify_breach()` — routes breach events to existing `webhook_delivery` + logs to
    `attestation_registry` (no new storage format)
  - `score_batch()` — offline/cron scoring of collected request/response pairs
  - `build_monitor_report()` — OK / WARN / BREACH status report
  - `run_monitor()` — daemon and `--once` cron modes
- **CLI: `squash hallucination-monitor`** — 4 subcommands:
  - `run --endpoint URL [--sample-rate 0.05] [--threshold 0.10] [--once]`
  - `score --response TEXT [--context TEXT] [--ground-truth TEXT]`
  - `status [--state-dir PATH]`
  - `batch --requests-file requests.json [--fail-on-breach]`
- **40 new tests**: score_live_response (3 modes), RollingWindow (append/rate/since/persist
  /eviction/clear), RequestSampler (rates/force/thread-safety), BreachEngine (confirmed/
  noise/insufficient), score_batch, CLI smoke

### Distinct from C7

C7 attests a model pre-deploy on a fixed probe set.
C10 monitors live traffic continuously — EU AI Act Art. 9 post-market monitoring obligation.

---

## [2.1.0] — 2026-04-30 — C7 ★: Hallucination Rate Attestation (W251-W252)

> **$67.4B in 2024 AI hallucination losses · 47% of executives made decisions on hallucinated content.**
> `squash hallucination-attest` converts this into a signed domain-calibrated certificate.

### Added (W251-W252 / Track C / C7 ★)

- **`squash/hallucination_attest.py`** — Signed hallucination rate certificate:
  - 200 built-in domain probes (40 × 5 domains): legal (2% threshold), medical (2%), financial (3%), code (5%), general (10%)
  - Faithfulness scorer: token F1 + 3-gram cosine + negation conflict + unsupported entity check — pure stdlib, deterministic
  - Wilson score 95% CI; minimum 10 probes enforced for statistical validity
  - Ed25519 signing (same keypair as anchor + drift cert); `verify_certificate()` for tamper detection
  - OpenAI-compatible + simple POST model client; `mock://` for offline testing
- **CLI: `squash hallucination-attest attest|verify|show|list-probes`**
  - `--fail-on-exceed` flag for CI gating
- **51 new tests**: probe set coverage, faithfulness scorer edge cases, all 5 domains, sign/verify, CLI smoke
- EU AI Act Art. 13 transparency requirement — first signed, CI-bounded hallucination rate certificate

---

## [2.0.0] — 2026-04-30 — C2: AI Washing Detection (W223-W225)
## [1.15.0] — 2026-04-30 — Sprint 24 W235–W237 / Track C-6: AI Insurance Risk Package

### Added (W235–W237 — Track C / C6 — AI Insurance Risk Package)

New buyer motion: Chief Risk Officer + insurance procurement.
AI cyber-insurance is crystallising in 2026. Underwriters demand
standardised evidence packages before quoting. Squash generates the
whole submission in one command.

```bash
squash insurance-package --models-dir ./models --org "Acme Corp"
squash insurance-package --models-dir ./models --zip ./insurance-bundle.zip
squash insurance-package --models-dir ./models --json --underwriter munich-re
```

- **`squash/insurance.py`** (NEW MODULE — W235–W236):
  - `ModelRiskProfile` — per-model: risk tier (HIGH/MEDIUM/LOW), compliance score, CVE count, drift events, incident count, bias status, last_attested, attestation_id, scan_status, control presence flags
  - `InsurancePackage` — aggregate: risk score 0–100, compliance score, response-plan status, total models, risk distribution, to_json/to_markdown/save/save_zip
  - `InsuranceBuilder.build(models_dir, org_name)` — reads squash artefacts (attest, scan, VEX, drift, incident, bias, lineage, annex IV) from model dir tree; graceful degradation when artefacts absent
  - **Risk tier scoring formula:** `risk = 100 − compliance_score + 20×(critical_cves>0) + 10×(scan_unsafe) + 10×(drift>5) + 15×(incidents>0) + 20×(no_policy)`, clipped [0,100]
  - **Multi-model discovery** — auto-detects per-model subdirectories or single-model root

  - **`MunichReAdapter`** (W236) — Munich Re AI cyber schema: 5 control domains (Technical Security, Operational Excellence, AI Governance, Data Quality Provenance, Incident Resilience) each rated A–D, overall AI Maturity Level 1–4, coverage recommendation (STANDARD / ENHANCED / SPECIALIST)
  - **`CoalitionAdapter`** (W236) — Coalition AI Risk Assessment: 5 categories (AI Model Security, AI Operational Risk, AI Governance, AI Incident History, Third-Party AI Risk) scored 0–100 with weighted aggregate; assessment text per category
  - **`GenericAdapter`** (W236) — flat, field-rich schema for underwriters without a published format

- **`squash/cli.py`** — `squash insurance-package` first-class command (W237):
  - `--models-dir PATH` (default: cwd)
  - `--org NAME`
  - `--output-dir DIR` (writes `insurance-package.{json,md}`)
  - `--zip PATH` (writes signed ZIP bundle with integrity manifest)
  - `--json` (structured JSON to stdout)
  - `--underwriter {munich-re,coalition,generic}` (print specific format with --json)
  - `--quiet`

- **ZIP bundle** (`save_zip()`): 6 files + integrity.sha256 SHA-256 manifest:
  - `insurance-package.json` · `insurance-munich-re.json` · `insurance-coalition.json` · `insurance-generic.json` · `insurance-executive-summary.md` · `integrity.sha256`

- **`tests/test_squash_sprint24.py`** (NEW) — 48 tests:
  - InsuranceBuilder: empty/populated dirs, CVE counting (affected vs fixed), risk tier scoring, bias fail detection, model ID extraction
  - ModelRiskProfile: to_dict() fields, controls block
  - MunichReAdapter: schema, maturity level range, 5 domains, A–D rating, coverage recommendation, empty→low maturity
  - CoalitionAdapter: schema, 5 categories, score 0–100, higher compliance → higher score
  - GenericAdapter: schema, required sections, model_profiles
  - InsurancePackage: to_json() structure, 3 adapter formats in JSON, 7 markdown sections, save(), save_zip() (6 files + manifest), SHA-256 integrity, executive summary
  - CLI: help (7 flags + 3 underwriters), default writes artefacts, JSON structure, munich-re/coalition outputs, --zip bundle, misconfig exit 2, populated > empty compliance, multi-model directory

### Stats
- **48 new tests** · **0 regressions** · **4356 total tests passing**
- **1 new module** (`insurance.py`) · 77 → 78 modules
- **1 new CLI command** (`insurance-package`) with 7 flags
- **3 underwriter adapters** (Munich Re, Coalition, Generic)

---

## [1.15.0] — 2026-05-01 — Sprint 36 W259–W261 / Track C-9: Carbon / Energy Attestation

### Added (W259–W261 — Track C / C9 — Carbon / Energy Attestation — CSRD buyer)

The ESG / sustainability office is a new buyer motion. CSRD applies to all large EU companies from 2025. Squash carbon attestation is the machine-readable, cryptographically signed proof these frameworks demand.

```
# BERT-base in Ireland, 100K inferences/day
squash attest-carbon \
  --model-id bert-base \
  --params 110M \
  --region eu-west-1 \
  --hardware a100 \
  --inferences-per-day 100000 \
  --csrd --sign

# 7B model in Stockholm (green grid) vs Sydney (coal)
squash attest-carbon --model-id llama-7b --params 7B --region eu-north-1 --json
squash attest-carbon --model-id llama-7b --params 7B --region ap-southeast-2 --json

# Enrich existing ML-BOM with energy fields
squash attest-carbon --model-id bert-base --params 110M --region us-east-1 --bom ./mlbom.json
```

- **`squash/carbon_attest.py`** (NEW) — complete carbon + energy attestation engine:

  **W259 — FLOP estimator × carbon intensity × compute engine:**
  - `estimate_flops(param_count, architecture, seq_len)` — 6 architecture families: transformer (2·N·L, Kaplan 2020), MoE (2·(N/8)·L sparse routing), embedding (capped L=128), diffusion (2·N·T_steps, T=20), CNN (2·N), RNN (2·N·L)
  - Hardware efficiency table: A100/H100/H200/TPU-v4/TPU-v5/RTX4090/CPU (TFLOPs/W from datasheets)
  - PUE table per provider (AWS 1.20, GCP 1.10, Azure 1.18, on-premise 1.60)
  - `lookup_grid_intensity(region, cache, live)` — 90+ regions covering all major AWS/GCP/Azure zones + ISO country codes; live Electricity Maps API with SQLite cache
  - `estimate_energy(flop_estimate, hardware, utilization, tokens, pue)` → kWh/inference, kWh/1M-tokens
  - `CarbonAttestation.compute(...)` → gCO₂eq/inference, kgCO₂eq/day, tCO₂eq/year (location + market-based), HMAC-SHA256 signed

  **W260 — CSRD/CSDDD/UK PRA/OMB-DOE/EU AI Act field mapping:**
  - `to_csrd(renewable_energy_fraction, scope3_embodied_factor)` → ESRS E1-4/E1-5 Scope 2 (location + market-based) + Scope 3 estimated fields
  - `to_regulatory(framework)` → csrd | csddd | uk_pra_ss1_23 | omb_doe | eu_ai_act

  **W261 — ML-BOM CycloneDX enrichment + CLI:**
  - `enrich_mlbom(bom_path, cert)` — injects `environmentalConsiderations.squash_carbon` into first component; adds `squash-carbon-attestation` external reference; idempotent

- **`squash/cli.py`** — `squash attest-carbon` subcommand:
  - `--model-id`, `--params` (int or shorthand 110M/7B/1.5T), `--region`, `--architecture`, `--hardware`
  - `--inferences-per-day`, `--tokens-per-inference`, `--seq-len`, `--utilization`, `--pue`
  - `--renewable-fraction`, `--live-intensity` (Electricity Maps)
  - `--sign`, `--output`, `--bom` (ML-BOM enrichment), `--csrd`, `--framework`, `--json`

**Grid intensity table covers 90+ regions:**
- AWS: all 25 current production regions
- GCP: all 35 current production regions
- Azure: 30+ regions
- Country codes: DE, FR, GB, US, CN, IN, AU, JP, KR, BR, SE, NO, FI, CH

**Module count:** 86 → 88 (carbon_attest.py; 2 additional modules added by concurrent sprints).

---

## [1.14.0] — 2026-04-30 — Sprint 22 W229–W231 / Track C-5: Regulatory Examination Simulation

### Added (W229–W231 — Track C / C5 — Regulatory Examination Simulation)

78% of executives can't pass an AI governance audit in 90 days.
`squash simulate-audit` closes that gap in 60 seconds. Mock regulatory
examination from the examiner's perspective — answers pulled from squash
attestation data, gaps flagged, prioritised remediation roadmap included.

```bash
squash simulate-audit --regulator EU-AI-Act --models-dir ./model
squash simulate-audit --regulator NIST-RMF --json
squash simulate-audit --regulator SEC --output-dir ./compliance/
squash simulate-audit --regulator FDA --fail-below 60
```

- **`squash/audit_sim.py`** (NEW MODULE — W229–W230):
  - `ExamQuestion` — q_id, article, question, answer_sources, answer_cli, weight (1–3), category, days_to_close
  - `ExamAnswer` — status (PASS/PARTIAL/FAIL/N/A), evidence_found/missing, gap_description, remediation
  - `ReadinessReport` — overall_score, readiness_tier, answers, roadmap, executive summary; `to_json()`, `to_markdown()`, `save()`
  - `AuditSimulator.simulate(model_path, regulator)` → `ReadinessReport`
  - **Scoring:** score = 100 × Σ(earned) / Σ(max), where PASS=2/PARTIAL=1/FAIL=0 × weight; **critical-gate cap** — any weight-3 fail caps score at 74 regardless of other results
  - **Tiers:** AUDIT_READY ≥80 · SUBSTANTIAL 60–79 · DEVELOPING 40–59 · EARLY_STAGE <40
  - **Evidence detection** — file-presence scan of model_path/ and model_path/squash/ against canonical squash artefact names; instant, no network calls

- **4 regulator profiles** (W230):
  - **EU-AI-Act (38 questions)** — Art. 9 (risk management system), Art. 10 (data governance + bias), Art. 11 (Annex IV technical documentation), Art. 12 (record-keeping + logs), Art. 13 (transparency + model card), Art. 14 (human oversight), Art. 15 (accuracy / robustness / cybersecurity), Art. 17/16 (QMS + conformity), Art. 25/53/61/72/73 (supply chain / GPAI / post-market / incident reporting)
  - **NIST-RMF (30 questions)** — GOVERN 1.1–6.1 (policies, accountability, roles, training, monitoring, third-party, concentration), MAP 1.1–5.1 (context, risk tolerance, benefits/harms, scientific basis), MEASURE 1.1–4.1 (metrics, test sets, bias, drift, cybersecurity, societal effects), MANAGE 1.1–5.1 (risk plans, responses, monitoring, residual risk, improvement)
  - **SEC (22 questions)** — AI disclosure, OMB M-26-04 model cards, investment-adviser oversight, AI capability claim verification, cybersecurity disclosures, data governance, bias testing, operational controls, audit trail, AI-washing, concentration risk, change management
  - **FDA (20 questions)** — SaMD risk classification, 510(k) clearance, analytical/clinical validation, PCCP (change control plan), QMS 21 CFR 820, intended use, labelling §801, adverse event reporting, training data demographics, subgroup performance (bias), cybersecurity §524B, version control, post-market monitoring, FMEA, 21 CFR Part 11, human factors, supply chain, transparency

- **`squash/cli.py`** — `squash simulate-audit` first-class command (W231):
  - `--regulator {EU-AI-Act,NIST-RMF,SEC,FDA}` (default: EU-AI-Act)
  - `--models-dir PATH` (default: cwd)
  - `--output-dir DIR` (writes `audit-readiness.{json,md}`)
  - `--json` (structured JSON to stdout)
  - `--fail-below N` (exit 1 if score < N — CI gate)
  - `--quiet`

- **`tests/test_squash_sprint22.py`** (NEW) — 48 tests:
  - ExamQuestion / ExamAnswer field assertions
  - Scoring maths: all-pass=100, all-fail=0, critical-gate cap at 74, partial=50, all 4 tier transitions
  - Profile size assertions (38/30/22/20 questions)
  - EU-AI-Act profile: unique IDs, all fields non-empty, critical gates present, categories covered
  - AuditSimulator: all 4 regulators run without error, empty score=0/EARLY_STAGE, answer count matches, bad regulator raises ValueError, executive summary populated
  - Populated dir: score>0, passing+partial>0, scores in 0–100, roadmap order (weight desc)
  - ReadinessReport: valid JSON, all markdown sections, score in Markdown, question IDs in Markdown, remediation commands present, save() writes both files, answers count in JSON, tier in JSON
  - CLI: help surface (6 flags + 4 regulators), default run writes artefacts, JSON output structure (squash_version/regulator/remediation_roadmap), NIST-RMF 30 questions, SEC 22, FDA 20, fail-below gates (score<1→1, score<100→1, 0→0), Markdown has roadmap, populated dir scores higher than empty

### Changed
- **Module count gates** (8 files) bumped 76 → 77 for `audit_sim.py`
- **`SQUASH_MASTER_PLAN.md`** — Track C / C5 marked **shipped**

### Stats
- **48 new tests** · **0 regressions** · **4308 total tests passing**
- **1 new module** (`audit_sim.py`) · 76 → 77 modules
- **1 new top-level CLI command** (`simulate-audit`) with 6 flags
- **4 regulatory profiles** · 110 examiner questions total

---

## [1.14.0] — 2026-05-01 — Sprint 35 W265–W266 / Track C-8: Model Deprecation Watch

### Added (W265–W266 — Track C / C8 — Model Deprecation Watch)

OpenAI / Anthropic / Google / Meta / Mistral sunset models quarterly. Every sunset breaks a version-tied Annex IV record. Most teams discover deprecations the day inference returns a 404. Squash deprecation-watch fires alerts before that day arrives.

```
# Scan asset registry against all 5 provider feeds
squash deprecation-watch --lead-time 30

# Check a specific model
squash deprecation-watch --check gpt-4-0613

# List all known deprecations as JSON
squash deprecation-watch --list --json

# Alert on Slack, fail CI if any alerts
squash deprecation-watch --alert-channel slack --fail-on-alert
```

- **`squash/deprecation_watch.py`** (NEW) — complete deprecation watch engine (W265):
  - `DeprecationEntry` — provider, model_id, aliases, sunset_date, impact (BREAKING/SOFT/INFORMATIONAL), successor_model, days_until_sunset, is_sunsetted, `matches()` with segment-aware prefix matching
  - `DeprecationAlert` — asset × entry match with days_remaining, migration_effort, re_attestation_checklist, `is_urgent()`, `summary()`
  - `DeprecationStore` — SQLite cache (`~/.squash/deprecation_cache.db`) for entries + scan history
  - `DeprecationWatcher` — main engine: `load_feeds()`, `scan()`, `check_model()`, `list_entries()`
  - 5-provider built-in feed: **OpenAI** (7 entries: gpt-4-0613, gpt-3.5-turbo-0613, text-davinci-003, gpt-4-32k, gpt-4-vision-preview, dall-e-2, whisper-1), **Anthropic** (4: claude-1, claude-instant-1, claude-2, claude-3-opus), **Google** (3: chat-bison/PaLM 2, gemini-1.0-pro, embedding-gecko), **Meta** (2: llama-1, llama-2), **Mistral** (3: mistral-tiny, mistral-small-2312, open-mistral-7b)
  - Real announced deprecation dates from provider release notes

- **Migration effort estimator (W266):** heuristic based on impact × environment × risk tier — CRITICAL (BREAKING + prod + high-risk) → HIGH → MEDIUM → LOW

- **Re-attestation checklist (W266):** per-model checklist with squash-specific commands (`squash attest`, `squash publish`, `squash annex-iv generate`, `squash iso42001`, etc.)

- **Alert routing (W266):** `route_alerts()` → stdout | slack | json; delegates Slack to `squash/notifications.py`

- **`squash/cli.py`** — `squash deprecation-watch` subcommand:
  - `--lead-time DAYS` (default 30), `--provider`, `--check MODEL_ID`, `--list`
  - `--model-ids` (comma-sep, bypass registry), `--alert-channel`, `--checklist`
  - `--json`, `--fail-on-alert`, `--include-informational`, `--include-sunsetted`

**Module count:** 85 → 86 (deprecation_watch.py). All count guards updated.

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

### Added

- **`squash/washing_detector.py`** — AI washing detection engine (W223-W225 / Track C / C2):

  **Claim Extractor** (`ClaimExtractor`, 28 patterns across 9 claim types)
  Deterministic regex-based extraction over Markdown, HTML, plain text, PDF, DOCX.
  Pattern taxonomy covers: `ACCURACY_CLAIM` (benchmarks, error rates), `COMPLIANCE_CLAIM`
  (EU AI Act, GDPR, HIPAA, NIST RMF, SOX), `CERTIFICATION_CLAIM` (ISO 42001, FedRAMP,
  SOC 2), `SAFETY_CLAIM` (no hallucinations, bias-tested, safe-for-clinical),
  `FAIRNESS_CLAIM` (unbiased, demographic parity), `DATA_CLAIM` (training data size/source,
  no-PII), `SECURITY_CLAIM` (pen-tested, no backdoors, enterprise-grade),
  `SUPERLATIVE_CLAIM` (world's first, outperforms GPT-4, 100% guaranteed),
  `CAPABILITY_CLAIM` (medical diagnosis, legal advice, financial recommendations).
  **95.7% recall** on the 50-claim SEC/FTC enforcement benchmark — above the 90% spec target.

  **Divergence Engine** (`DivergenceEngine`, 12 cross-reference rules)
  Cross-references extracted claims against `AttestationEvidence` (master_record.json,
  bias_audit.json, data_lineage.json). Four finding types:
  - `FACTUAL_MISMATCH` (CRITICAL): claim contradicts signed attestation evidence
    (e.g. "EU AI Act compliant" when eu-ai-act score = 38/100)
  - `UNSUPPORTED_CLAIM` (HIGH): claim type has a known evidence requirement and
    no evidence exists
  - `UNDOCUMENTED_SUPERLATIVE` (CRITICAL/MEDIUM): absolute claims without verifiable basis
  - `TEMPORAL_MISMATCH` (HIGH): compliance claim backed by attestation >90 days old

  **Rules:** EU AI Act/GDPR/HIPAA/NIST/ISO 42001 score thresholds; passed=False gate;
  no-hallucination absolute claim always flagged; bias audit required for
  fairness/bias-safety claims; PII absence requires data lineage; security scan required
  for security claims; security scan FAIL → CRITICAL; high-stakes domains (medical/legal/
  financial) always CRITICAL regardless of attestation state; staleness check (90-day window).

  **Report** (`WashingReport`) — schema `squash.washing.report/v1`;
  `CLEAN/LOW/MEDIUM/HIGH/CRITICAL` verdict; `to_json()`, `to_markdown()`, `summary()`;
  JSON round-trip via `load_report()`. Every finding names its `rule_id`, `legal_risk`,
  and specific `remediation` — handed directly to legal counsel without translation.

  **Evidence Loader** (`load_evidence`, `AttestationEvidence`) — loads and normalises
  master_record.json, bias_audit.json, and data_lineage.json into a typed evidence
  object with framework score lookup (with canonical aliases for all framework variants).

- **CLI: `squash detect-washing`** — 2 subcommands:
  - `scan <doc_paths...> [--master-record PATH] [--bias-audit PATH] [--data-lineage PATH]
    [--model-id ID] [--format text|json|md] [--fail-on low|medium|high|critical]`
  - `report <report.json>` — render a saved report

- **`tests/test_washing_detector.py`** — 38 tests:
  - 50-claim extraction benchmark; recall ≥ 90% assertion (actual: 95.7%)
  - No-false-positive test on 5 clean sentences
  - All 12 divergence rules tested (fires + doesn't-fire)
  - JSON round-trip; Markdown render; summary
  - Evidence loader: master record, bias audit, data lineage
  - End-to-end clean/washing doc with good/bad evidence
  - CLI parser registration and scan subcommand

### Context

SEC "Operation AI Comply" (2024) produced enforcement actions. The SEC's 2026
examination priorities list AI-related disclosures as a top-tier focus.
`squash detect-washing` is the first ML compliance tool that compares prose
capability claims against signed attestation evidence automatically.

---

## [1.9.0] — 2026-04-30 — B10: License Conflict Detection (W196)

### Added

- **`squash/license_conflict.py`** — SPDX licence conflict engine (W196 / B10):

  **Knowledge Base** (`LicenseKnowledgeBase` / `resolve_spdx`)
  73 SPDX identifiers + 9 AI model custom licences fully described: permissive
  (MIT, Apache-2.0, BSD variants, CC0), weak copyleft (LGPL, MPL-2.0),
  strong copyleft (GPL-2.0/3.0), network copyleft (AGPL-3.0), ShareAlike
  (CC-BY-SA-4.0, ODbL-1.0), non-commercial (CC-BY-NC family), and AI custom
  licences (LLaMA 2/3, Gemma, Mistral, BLOOM/OpenRAIL, Falcon, Code Llama).
  Canonical alias map normalises variant spellings (gpl3, apache2, llama2, etc.)
  and gracefully falls back to `LicenseRef-unknown` for unresolved identifiers.

  **SPDX Expression Parser** (`LicenseExpression`)
  Compound SPDX expressions: `MIT OR Apache-2.0`, `GPL-2.0-only WITH
  Classpath-exception-2.0`. Picks the most permissive option from OR-joined
  choices using a kind-score ordering — no regex abuse, explicit token split.

  **12 Conflict Rules** (`ConflictChecker`)
  | Rule | Description |
  |------|-------------|
  | LC-001 | Non-commercial licence in commercial/SaaS deployment (CRITICAL) |
  | LC-002 | AGPL network-copyleft trigger in SaaS API (HIGH) |
  | LC-003 | Strong copyleft in closed-source commercial product (HIGH) |
  | LC-004 | ShareAlike dataset may contaminate model weights (MEDIUM, unsettled law) |
  | LC-005 | NoDerivatives licence — fine-tuning prohibited (HIGH) |
  | LC-006 | LLaMA 2 commercial use threshold (MEDIUM, flagged for awareness) |
  | LC-007 | LLaMA 2/3 competing-product prohibition (HIGH) |
  | LC-008 | Gemma competing-model prohibition (MEDIUM) |
  | LC-009 | BLOOM/OpenRAIL use-restriction clauses (MEDIUM) |
  | LC-010 | Unknown/unresolved licence — all rights reserved (HIGH) |
  | LC-011 | GPL-2.0-only incompatible with Apache-2.0 (HIGH) |
  | LC-012 | Version-locked copyleft mixing (e.g. GPL-2.0-only + GPL-3.0-only) (HIGH) |

  **Scanner** (`LicenseScanner`)
  Walks project trees extracting licences from: `requirements.txt`,
  `pyproject.toml`, `package.json`, `Cargo.toml`, `LICENSE`/`COPYING`
  files (text-sniffing), model card `README.md` (YAML frontmatter), model
  `config.json`/`master_record.json`, `dataset_infos.json`, and provenance
  JSON. `tomllib` (Python 3.11+) or `tomli` for TOML; graceful skip on Python
  3.9/3.10 without it. Curated licence map for 45+ well-known packages.

  **Obligation Extractor** (`extract_obligations`)
  Attribution requirements, source-disclosure obligations, AGPL network-user
  source rights, LLaMA "Built with Meta Llama" attribution — all surfaced as
  actionable strings in the report.

  **Report** (`LicenseConflictReport`)
  Schema `squash.license.conflict.report/v1`; CLEAN/LOW/MEDIUM/HIGH/CRITICAL
  risk; `to_json()`, `to_markdown()`, `summary()`; JSON round-trip via
  `load_report()`.

- **CLI: `squash license-check`** — 3 subcommands:
  - `scan <path> [--use-case research|commercial|open_source|saas_api|internal|government] [--format text|json|md] [--fail-on medium|high|critical]`
  - `explain <SPDX_ID>` — print full metadata for any known licence
  - `report <report.json>` — render a saved report

- **`tests/test_license_conflict.py`** — 55 tests covering all 12 conflict
  rules, knowledge base, expression parser, scanner, obligations, end-to-end
  clean/conflicted projects, JSON round-trip, and CLI smoke.

### Konjo notes

- 건조 — no external SPDX library; the knowledge base is a Python data
  structure. TOML parsing is stdlib-first with a graceful skip — no hard dep.
- ᨀᨚᨐᨚ — every conflict finding names its rule_id, legal basis, and specific
  remediation. An auditor can trace LC-011 to the FSF licence compatibility
  list in a single step.
- 康宙 — read-only scan; no network; no model execution. Safe in air-gap.
- 根性 — the compatibility matrix is conservative: when in doubt, flag. A
  false positive costs a legal consultation; a missed conflict costs production.

---

## [1.8.0] — 2026-04-30 — B9: Training Data Poisoning Detection (W195)

### Added

- **`squash/data_poison.py`** — six-layer training data poisoning scanner (W195 / B9):

  **Layer 1 — Threat Intelligence** (`ThreatIntelChecker`)
  Cross-references dataset file hashes against a curated registry of known-poisoned
  and known-compromised datasets. Definitive detection with zero false positives on
  a match. Seed set covers Badnets SST-2, Hidden Killer clean-label, and documented
  HuggingFace supply-chain incidents.

  **Layer 2 — Label Integrity** (`LabelIntegrityChecker`)
  Shannon entropy analysis, class imbalance ratio (flagged at >50x), and per-class
  Z-score spike detection (flagged at z > 4). Reads CSV/TSV/JSONL label files.
  Label-flipping attacks always leave an entropy signature detectable by this layer.

  **Layer 3 — Duplicate Injection Detection** (`DuplicateDetector`)
  SHA-256 content-hash duplicate rate per file. Adversarial sample amplification
  (inserting the same poisoned sample N times) is flagged at >5% duplicate rate
  (MEDIUM) and >20% (HIGH). Covers JSONL, CSV, TSV, and plain text.

  **Layer 4 — Statistical Outlier Detection** (`OutlierDetector`)
  Z-score analysis on numerical feature columns (threshold z > 5). Adversarially
  crafted inputs lie off the data manifold and are extreme outliers. Constant
  columns (synthetic data indicator) are also flagged. Numpy-accelerated with
  stdlib `statistics` fallback for air-gapped environments.

  **Layer 5 — Backdoor Trigger Pattern Scan** (`TriggerPatternScanner`)
  Searches for 9 known NLP backdoor trigger tokens (Badnets `cf`, Hidden Killer
  `mn`, instruction-tuning poison `tq`, zero-width space, BOM markers, GPT special
  tokens). Also detects Unicode homoglyph character mixing (Latin + Cyrillic/Greek
  in the same token — the invisible-trigger attack class from Boucher et al. 2022).

  **Layer 6 — Provenance Chain Integrity** (`ProvenanceIntegrityChecker`)
  Flags missing provenance records, file modification timestamps post-dating claimed
  creation dates, and suspicious source URL patterns (Mega.nz, Pastebin, anonfiles,
  darkweb/onion domains).

  **Aggregation** — weighted risk score → `CLEAN / LOW / MEDIUM / HIGH / CRITICAL`.
  CRITICAL check hit immediately elevates report regardless of aggregate score.
  Prioritised remediations generated per flagged layer.

- **CLI: `squash data-poison`** — 2 subcommands:
  - `scan <dataset_path> [--format text|json|md] [--out PATH] [--fail-on low|medium|high|critical] [--provenance PATH]`
  - `report <report.json>` — render a previously saved report
- **`tests/test_data_poison.py`** — 39 tests covering all six layers, end-to-end
  clean/poisoned datasets, JSON round-trip, Markdown render, and CLI smoke.
  Module count gates updated (71→72); full suite clean.

### Literature basis

- Gu et al. 2019 — Badnets: Identifying Vulnerabilities in the ML Model Supply Chain
- Turner et al. 2019 — Label-Consistent Backdoor Attacks
- Shafahi et al. 2018 — Poison Frogs! Targeted Clean-Label Poisoning Attacks
- Schwarzschild et al. 2021 — Just How Toxic Is Data Poisoning?
- Wan et al. 2023 — Poisoning Language Models During Instruction Tuning
- Boucher et al. 2022 — Bad Characters: Imperceptible NLP Attacks
- OWASP LLM Top 10 2025 — LLM04: Data and Model Poisoning

### Konjo notes

- 건조 — pure stdlib core; numpy optional for Layer 4. No model execution, no
  network calls, no daemons. Safe in FedRAMP / CMMC air-gapped environments.
- 根性 — six independent detection layers means no single bypass defeats the
  scanner. An attacker who avoids layer 3 (dedup) still faces layers 2 and 5.
- 康宙 — the scanner is a read-only pass over existing dataset artefacts.
  No data is copied, modified, or sent anywhere.
- কুঞ্জ — the report is a portable JSON document that an ML security team can
  run as part of CI, attach to a model card, and hand to an auditor. Every
  finding includes a reference to the underlying paper or standard.

---

## [1.7.0] — 2026-04-30 — B7: Drift SLA Certificate (W194)

### Added

- **`squash/drift_certificate.py`** — Drift SLA Certificate generator (W194 / Tier 3 B7):
  - `DriftSLASpec` — typed SLA contract: model, framework, min_score, window_days,
    max_violation_rate, min_snapshots, org. Input validation on all parameters.
  - `ScoreLedger` — append-only JSONL ledger of compliance score snapshots per model per
    framework. Populated from `master_record.json` files via `ingest()` or directly via
    `add_snapshot()`. Supports time-window, model, and framework filtering.
  - `SLAEvaluator` — computes SLA result over a ledger slice: passes/fails, compliance
    rate, score stats (min/max/avg/p10), violation count, contiguous violation windows.
    Mathematically exact: violation rate is per-snapshot, not per-calendar-day bucket.
  - `ViolationWindow` — contiguous run of below-threshold snapshots with min score.
  - `DriftCertificate` — signed certificate envelope with `squash.drift.certificate/v1`
    schema marker; `body_dict()` produces the canonical signed surface (excludes sig/key);
    `to_markdown()`, `to_html()`, `to_json()` renderers; HTML is print-ready for PDF via
    weasyprint.
  - `DriftCertificateIssuer` — signs certificates with Ed25519 (same keypair as
    `LocalAnchor`); public key embedded in envelope; `verify()` detects tampered spec,
    tampered result, unknown schema, and unsigned certs.
  - `load_certificate()` — round-trip JSON deserialiser.
  - `SQUASH_DRIFT_LEDGER` env var for CI/air-gap ledger path override.
- **CLI: `squash drift-cert`** — 5 subcommands:
  - `ingest <master_record.json>` — append snapshot to ledger
  - `issue --model --framework --min-score --window [--priv-key] [--out] [--format]`
  - `verify <cert.json>` — signature + self-consistency check
  - `show <cert.json>` — human-readable Markdown render
  - `export <cert.json> --format md|html|pdf` — export certificate
- **`tests/test_drift_certificate.py`** — 30 tests:
  - DriftSLASpec validation (invalid score, window, rate, min_snapshots)
  - ScoreLedger: add/query, model filter, time-window filter, master_record ingest
  - SLAEvaluator: all-pass, violation-rate exceeded, within-budget, insufficient
    snapshots, no snapshots, violation windows, score statistics
  - DriftCertificate: body_dict excludes signature, JSON round-trip, Markdown/HTML render
  - DriftCertificateIssuer: sign+verify roundtrip, tampered spec fails, tampered result
    fails, unsigned cert → false, unknown schema → false
  - Env-var override; CLI parser registration; end-to-end ingest→issue→verify

### Konjo notes

- 건조 — the SLA evaluation is a pure function over the ledger; no network, no daemon,
  no background worker. The ledger is a single JSONL file.
- ᨀᨚᨐᨚ — `violation_rate = violations / snapshots` is computed to full float precision,
  not rounded to a daily bucket. A certificate is wrong or it is right — no rounding mode.
- 康宙 — the ledger is append-only; certificates are issued on-demand from history.
  Tamper detection is a first-class property: changing any field in the certificate body
  breaks the Ed25519 signature immediately.
- কুঞ্জ — a Drift SLA Certificate is the artefact an insurance underwriter, enterprise
  procurement team, or board-level CISO can actually hold. "Model M stayed above 80/100
  on EU AI Act for 90 days, signed, verifiable." That is the garden squash builds for
  the next person.

---

## [1.6.0] — 2026-04-30 — B6: Audit-Trail Blockchain Anchoring (W193)

### Added

- **`squash/anchor.py`** — Merkle-tree audit-trail anchoring (W193 / Tier 3 #29):
  - `MerkleTree` — domain-separated (RFC 6962) binary Merkle tree; pure stdlib SHA-256;
    odd-level duplicate-tail to prevent phantom-node attacks; O(n) build, O(log n) proof.
  - `MerkleProof` — frozen, self-contained inclusion proof that verifies with stdlib only;
    no squash code, no network, no trust in the issuer beyond holding their public key.
  - `LocalAnchor` — Ed25519 signature over `root || leaf_count || timestamp`;
    public key embedded in the anchor record so verifiers need no separate key fetch;
    works in air-gapped / FedRAMP environments; signing payload is canonical JSON.
  - `OpenTimestampsAnchor` — submits Merkle root to the Bitcoin-backed OTS aggregator
    network; produces a `.ots` file; verification via `ots verify` at a Bitcoin node.
  - `EthereumAnchor` — posts root as EVM calldata (`0x73717368` magic + 32-byte root +
    uint64 leaf_count) via Foundry `cast`; chain-agnostic (mainnet, Base, Optimism, Polygon);
    verifiable by anyone with `cast tx <hash> input`.
  - `AnchorLedger` — append-only JSONL ledger (`~/.squash/anchor/`); stage→commit→verify
    workflow; `export_proof()` emits a portable, self-contained `squash.anchor.proof/v1`
    doc that a third party can verify with 30 lines of stdlib Python.
  - `canonical_json()` + `hash_attestation()` — deterministic attestation hashing;
    two organisations producing semantically identical attestations get bit-identical hashes,
    enabling cross-organisation verification.
  - `verify_proof()` — standalone reference verifier; the auditor's side of the protocol.
- **CLI: `squash anchor`** — 6 subcommands:
  - `add <master_record.json>` — stage into pending batch
  - `commit --backend local|opentimestamps|ethereum` — build Merkle root + anchor
  - `verify <attestation_id>` — Merkle inclusion + backend witness check
  - `proof <attestation_id> [--out PATH]` — emit portable proof JSON
  - `list` — all committed anchors (ANSI + `--json`)
  - `status` — pending batch + last anchor
- **`tests/test_anchor.py`** — 23 tests:
  - Canonical hashing: key-order invariant, whitespace-free, Unicode-stable
  - Merkle tree: 1-leaf, 2-leaf, 3-leaf (odd), 50-leaf; all proofs verify
  - Tampered leaf / tampered root / tampered path → FAIL
  - LocalAnchor sign/verify roundtrip; tampered root → FAIL
  - AnchorLedger stage → commit → per-attestation verify
  - Cross-instance durability (fresh reader after writer commits)
  - Portable proof verified by `verify_proof()` with no ledger access
  - Post-anchor record tamper: anchored proof still holds; new hash diverges (tamper detection)
  - Empty-batch commit raises; multi-commit ordering preserved
  - `SQUASH_ANCHOR_DIR` env override; CLI subcommand registration; status on empty ledger

### Konjo notes

- 건조 — the cryptographic construction (domain-separated Merkle, canonical JSON, embedded
  public key) strips to the essential invariants. No blockchain SDK dependency; the only
  external dep for the local backend is `cryptography`, already in the squash tree.
- ᨀᨚᨐᨚ — a portable proof is a single JSON file. Any auditor can carry it to any machine
  and verify with stdlib hashlib + cryptography. No squash code required, no network call,
  no trust in the issuer beyond their public key.
- 康宙 — the ledger is append-only. Compromises are new entries, never rewrites.
  No goroutines, no daemons, no background workers.

---

## [1.5.0] — 2026-04-30 — B4: Terraform / Pulumi Provider

### Added — Tier 3 #26 (B4) Terraform/Pulumi provider

- **`integrations/terraform/`** — full Terraform provider in Go, built on
  `terraform-plugin-framework` v1.13.0:
  - `squash_attestation` resource — runs `squash attest`, captures the
    master record JSON, exposes `attestation_id`, `overall_score`,
    `passed`, `framework_scores`, SBOM/signature paths. Replacement on
    `model_path` change preserves an immutable provenance trail.
  - `squash_policy_check` resource — declarative compliance gate; fails
    `terraform apply` when score drops below `min_score` or when
    `require_passed = true` and the upstream attestation did not pass.
    Lets a regression block every dependent resource via the dependency
    graph (no admission controller required).
  - `squash_compliance_score` data source — read an existing
    `master_record.json` without re-running the pipeline; surfaces
    `top_frameworks` for compact downstream gating.
  - Provider config: `cli_path`, `models_dir`, `policy`, `api_key`
    (sensitive), `offline` — every field has an env-var fallback for
    CI/air-gap parity.
  - **`internal/squashcli/`** — stdlib-only core (zero external deps).
    Argv builder + master-record JSON parser + injectable `Runner`
    interface. Tested offline; the package the FedRAMP / CMMC story
    rests on.
  - 7 squashcli tests + 9 provider schema/helper tests = 16 Go tests
    passing under `go test -race -count=1`.
  - Build: `make build` / `make install` / `make test` / `make test-core`.
- **`integrations/terraform/pulumi/`** — Pulumi parity:
  - `examples/typescript` and `examples/python` show the
    `@pulumi/command` shell-out pattern that works today.
  - README documents the Pulumi Terraform bridge path for strongly-typed
    multi-language SDKs once the provider is published to the Registry.
- **Examples** (`integrations/terraform/examples/`):
  - `basic` — single model, signed, gated.
  - `multi-model-gate` — `for_each` over a model registry.
  - `data-source-gate` — gate a deploy on a CI-produced record.
- **Registry-format docs** under `integrations/terraform/docs/`:
  `index.md`, `resources/attestation.md`, `resources/policy_check.md`,
  `data-sources/compliance_score.md`.
- **`integrations/terraform/terraform-registry-manifest.json`** —
  protocol v6 manifest for Terraform Registry publication.

### Konjo notes

- 건조 (dry): provider is a typed declarative facade — zero duplicate
  SBOM/policy logic. The squash CLI remains the single source of truth.
- ᨀᨚᨐᨚ (seaworthy): stdlib-only core means the provider can be audited
  and shipped to air-gapped environments without a HashiCorp dep tree
  audit on the critical path.
- 康宙 (health of the universe): one process per `terraform apply`, no
  goroutines, no daemons, no background workers.

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
