# PLAN.md — squash short-horizon execution plan

This document tracks the *next-up* sprint pipeline. The long-term roadmap
(11 tracks × ~90 sprints) lives in [SQUASH_MASTER_PLAN.md](./SQUASH_MASTER_PLAN.md);
this file is the working surface for the things actually being scheduled
in the next 30–60 days.

Order of operations on every sprint:
1. Read this file plus `SQUASH_MASTER_PLAN.md` and `CLAUDE.md`.
2. Identify the relevant lane below and verify dependencies.
3. Ship the code + tests + CHANGELOG + version bump.
4. Update this file with what landed, what's next.

---

## Researched Feature Roadmap

The quick-check / shareable-verdict surface (`POST /quick-check`,
`GET /r/{hash}`, `demo/index.html`) has shipped its first viral wave (v3.7.0).
The next set of features turns the demo into a defensible buyer surface:
clauses become actionable, every scan becomes auditable, and every gap
becomes a number a CFO can read. Items are grouped by priority and
complexity; **P1 / Low complexity is implemented this sprint.**

### 🔴 P1 — Critical / Low complexity (implement now)

| ID | Feature | Surface | Status |
|---|---|---|---|
| **P1-A** | **Clause-level redline diff + remediation.** For each failing clause, the API returns the missing-clause text, the issue, a suggested passing version, and a risk level. The demo UI renders a side-by-side diff with red/green highlighting on the verdict card. | `GET /r/{hash}/remediation` → `[{clause_id, label, issue, original, suggested_fix, risk_level}]`, `demo/index.html` diff view | **shipping this sprint** |
| **P1-B** | **Audit trail + immutable scan history.** Every quick-check is recorded with timestamp, input SHA-256, framework, verdict, score, sub-scores. Append-only SQLite. Demo UI shows a recent-scan panel with a 24-point sparkline of pass-rate. | `GET /history?limit=&offset=` → `{total, entries: […]}`, `demo/index.html` history panel | **shipping this sprint** |
| **P1-C** | **Financial risk quantification.** Each missing clause is tagged with a USD exposure range derived from a clause-type → risk-band lookup table (uncapped liability → $50K–$500K, missing breach notification → $20K–$2M, etc.). Surfaced on the verdict card. | `GET /r/{hash}/remediation` cells include `dollar_low_usd`, `dollar_high_usd`; verdict card renders aggregate exposure | **shipping this sprint** |

### 🟠 P2 — High impact / Medium complexity (next sprints)

| ID | Feature | Surface |
|---|---|---|
| **P2-A** | **Custom policy playbook builder.** User-defined rule sets via JSON config. Rules specify clause patterns, risk weights, pass/fail thresholds. Stored per-org. | `POST /playbooks`, `GET /playbooks`, `GET /playbooks/{id}`; CLI `squash playbook init` / `validate` |
| **P2-B** ✅ | **Multi-framework clause-level scan + clustering + risk trend.** Three new endpoints under `/api/*` shipped this sprint: scan clauses against SOC2 / HIPAA / PCI-DSS in one pass, cluster clauses by TF-IDF cosine, query a persisted risk-exposure trend. | `POST /api/compliance/scan`, `POST /api/analysis/cluster`, `GET /api/trends/risk`, `POST /api/analyses` — **shipped** |
| **P2-C** | **Developer API + CI/CD integration.** Async scan jobs, webhook callbacks, GitHub Action YAML, headless CLI. | `POST /jobs`, `GET /jobs/{id}`, `POST /jobs/{id}/cancel`; `/.github/actions/squash/`; `squash scan --file contract.txt --framework gdpr` |
| **P2-D** | **Bulk portfolio scanning.** `POST /bulk` accepts an array of texts or a ZIP. Returns aggregate stats plus per-document verdicts. SSE progress stream. | `POST /bulk`, `GET /bulk/{job_id}/stream` (SSE), `GET /bulk/{job_id}` |

### 🟡 P3 — Strategic (future sprints)

| ID | Feature | Surface |
|---|---|---|
| **P3-A** | **Clause confidence scores.** Each flagged clause gets a confidence percentage (model-derived). Rendered as a meter on the demo card. | Adds `confidence: 0..1` to every missing/matched entry. |
| **P3-B** | **Jurisdiction-aware scoring.** `jurisdiction: "EU" | "US-CA" | "UK"` adjusts which clause rules apply, which thresholds bind, and which currency the exposure is denominated in. | New `jurisdiction` field on `/quick-check`, defaulting to "EU". |
| **P3-C** | **Collaborative annotation.** Flag clauses as false positives, add notes, share annotated scans via URL with comment threads. | `POST /r/{hash}/annotations`, `GET /r/{hash}/annotations`. |

---

## Current sprint — P1 ship list

| Wave | Module / Surface | Tests |
|---|---|---|
| W-A | `squash/clause_remediation.py` (NEW) — `RemediationCatalog`, `build_remediation()`, per-clause original/issue/suggested_fix/risk_level. | `tests/test_clause_remediation.py` |
| W-B | `squash/scan_history.py` (NEW) — append-only SQLite-backed `ScanHistory` with `record()`, `list()`, `pass_rate_sparkline()`. | `tests/test_scan_history.py` |
| W-C | `squash/financial_risk.py` (NEW) — `RISK_TABLE` lookup, `quantify(clause_id)` returns `(low_usd, high_usd)`, aggregate helper. | `tests/test_financial_risk.py` |
| W-D | `squash/api.py` — new routes `GET /r/{hash}/remediation`, `GET /history`. Quick-check records into history on every call. | `tests/test_api_p1_endpoints.py` |
| W-E | `demo/index.html` — diff view (red/green) inside verdict card; financial-exposure chip; new "Recent scans" panel with sparkline. | manual + parser smoke |
| W-F | CHANGELOG entry + version bump to **3.8.0**. | — |

---

## Done log (recent sprints)

- **P2-E** — contract primitives: `/api/extract/obligations` (regex obligation
  extractor with party/modal/deadline/condition), `/api/contracts/diff` (TF-IDF
  cosine bipartite-match redline + risk_delta), `/api/alerts` (SQLite-backed
  saved-search rules with HMAC-signed webhook fan-out, auto-evaluated on every
  `/api/compliance/scan`). 49 new tests.
- **P2-B** — `/api/compliance/scan` (SOC2 + HIPAA + PCI-DSS), `/api/analysis/cluster` (TF-IDF k-means++), `/api/trends/risk` (SQLite-backed risk-exposure trend). 44 new tests.
- **v3.8.0** — P1 ship: redline diff + audit trail + financial exposure (P1-A/B/C)
- **v3.7.0** — viral SVG card · trending stats · UI overhaul (PR #7 merged)
- **D4** — multi-jurisdiction compliance matrix
- **D1** — squash GitHub App (Check Runs)
- **C1 ★** — `squash freeze` emergency response

---

**Next review:** after P1 ships and the CFO/auditor user-test loop returns.
