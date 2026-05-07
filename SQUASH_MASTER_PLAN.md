## From Zero to $10M ARR: EU AI Act Compliance Platform

> **Last updated:** 2026-05-07 — Sprint 27 C4 shipped (`squash watch-regulatory`)
> **Status:** Living document — updated on every commit
> **Horizon:** April 2026 → October 2027

---

## ⏰ The North Star — August 2, 2026

> **EU AI Act high-risk enforcement: August 2, 2026 — 94 days.**
>
> Every sprint between today and August 2 is worth more than any sprint after.
> The whole product strategy is anchored to one truth: regulators no longer
> want promises — they want receipts.

**squash is the receipt machine.**

---

## 🗺️ Phase Map (Living)

```
Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6 → Phase 7
  MVP        Beta      GA       Scale     Enterprise  Platform   Moat
 (done)    (done)    (done)   (done)      (done)      (now)    (next)
```

Current: **Phase 6 — Platform** (W219+). Shipping parallel tracks weekly.

---

## 🚀 Parallel Track Grid — Sprint 19 Live

```
Track A (Revenue)    Track B (Product)       Track C (Safety)         Track D (Enterprise)
────────────────     ────────────────────     ────────────────         ────────────────────
Monetisation         Reach + defensibility    Technical defensibility
       │                                │                                │
       └── A1 fly deploy                └── B1 HF Public Scanner         └── C1 squash freeze ★        └── D1 GitHub App
       └── A2 PyPI publish              └── B2 Branded PDF               └── C2 AI Washing Detect      └── D2 AI Identity Attest
       └── A3 Domain + Stripe           └── B3 Email Digest              └── C3 Approval Workflow      └── D3 Procurement Score API
       └── A4 Website Live              └── B4 Terraform/Pulumi          └── C4 Regulatory Watch       └── D4 Multi-Jurisdiction
                                        └── B5 API Gateway Plugin
```

**Current sprint (W221–W222, May 5–6):** C1 `squash freeze` ★ — 2-day headline win.
**Next sprint (W223–W225, May 7–12):** C2 AI Washing Detection + B2 Branded PDF.

---

## 📅 Sprint 19 Countdown

```
May 5  ██████████████████████████████  W221 Day 1 — squash freeze: write freeze.py + tests
May 6  ██████████████████████████████  W222 Day 2 — squash freeze: CLI + PR + demo GIF
```

Launch anchors (unchanged):
```
  └─ L1 Public Beta — Jul 11
  └─ L2 Show HN — Jul 14 (squash freeze IS the demo)
  └─ L3 Product Hunt — Jul 21
  └─ L4 EU Enforcement Day — Aug 2
```

★ **C1 `squash freeze` is the headline win.** Two days of work, zero new modules, orchestrates five existing modules (`attestation_registry`, `webhook_delivery`, `gitops`, `incident`, `notifications`) into one CLI command. The "red button" CISOs will demo to boards. **Highest drama-per-hour-of-effort ratio in the roadmap.**

---

## 📊 Track Scorecards

### Track A — Revenue Infrastructure

| Item | Status | Target | Owner |
|------|--------|--------|-------|
| A1 fly.io deploy | ✅ done | Live URL | Wesley |
| A2 PyPI publish | ✅ done | `pip install squash-ai` | Wesley |
| A3 Domain + Stripe | 🔄 active | getsquash.dev + billing | Wesley |
| A4 Website live | 🔜 next | Landing page + pricing | Wesley |

### Track B — Product Reach

| Item | Status | Target | Owner |
|------|--------|--------|-------|
| **B1** ✅ | **HF Public Scanner** — `squash scan hf://owner/model` | 4 days → **shipped** | ✅ 2026-04-30 | A3, C1, C2 |
| B2 Branded PDF | 🔜 | Compliance leave-behind | Wesley |
| B3 Email Digest | 🔜 | Weekly regulatory summary | Wesley |
| B4 Terraform/Pulumi | 🔜 | IaC compliance modules | Wesley |
| B5 API Gateway Plugin | 🔜 | Kong/Apigee plugin | Wesley |

### Track C — Safety & Compliance Features

| Track | Feature | Est. | Dates | Deps | Anchor stat | Sprint |
|-------|---------|------|-------|------|-------------|--------|
| **C1** ✅ | **`squash freeze`** — emergency response orchestrator | shipped 2026-05-06 | A3, B1 | 20% have a tested AI incident-response plan. `freeze.py`: FreezeOrchestrator, 5-step atomicity, Ed25519 signing, ledger. 38 tests. | Sprint 19 (W221–W222) ✅ |
| **C2** ✅ | **AI Washing Detection** — `squash detect-washing` | shipped 2026-04-30 | B1, B2 | SEC #1 AI exam priority 2026. `washing_detector.py`: 28 patterns, 9 claim types, 12 divergence rules, 95.7% recall. 38 tests. | Sprint 20 (W223–W225) ✅ |
| **C3** ✅ | **Approval Workflow** — `squash approve` (signed reviewer record) | 5 days | May 13–19 | B2, B3, B4 | EU AI Act Art. 9 human-oversight requirement | Sprint 23 (W232–W234) |
| **C4** ✅ | **Regulatory Watch Daemon** — primary-source polling + gap analysis | shipped 2026-05-07 | B4, D1 | Daily-touch product = retention | Sprint 27 (W243–W245) ✅ |
| **C5** | **Audit Simulation** — `squash simulate-audit --regulator EU-AI-Act` | 10 days | Jun 2–13 | D1, D2, B5 | 78% can't pass audit in 90 days | Sprint 22 (W229–W231) |
| **C2** | **AI Washing Detection** — `squash detect-washing` | 5 days | May 7–12 | B1, B2 | SEC #1 AI exam priority 2026 | Sprint 20 (W223–W225) |
| **C3** | **Approval Workflow** — `squash approve` | 5 days | May 13–19 | B2, B3 | EU AI Act Art. 9 | Sprint 23 |
| **C6** ✅ | **Insurance Risk Package** — `squash insurance-package` | shipped | | Munich Re / Coalition adapters | Sprint 24 (W235–W237) ✅ |
| **C7** ✅ | **Hallucination Attestation** — `squash hallucination-attest` | shipped | | $67.4B hallucination liability market | Sprint 20 ✅ |
| **C8** | **DORA Compliance** — `squash dora` | 5 days | Jun | B4, D1 | DORA enforcement Jan 2025 | Sprint 28 |
| **C9** | **Carbon Footprint Attestation** — `squash attest-carbon` | 3 days | Jun | B1 | ESG reporting requirements | Sprint 29 |
| **C10** ✅ | **Runtime Hallucination Monitor** — `squash hallucination-monitor` | shipped 2026-04-30 | D3 | EU AI Act Art. 72 incident reporting | Sprint 20 ✅ |

### Track D — Enterprise Features

| Track | Feature | Est. | Dates | Deps | Anchor stat | Sprint |
|-------|---------|------|-------|------|-------------|--------|
| **D1** | **GitHub App** — 1-click repo integration | 5 days | May 20 | A3, B1 | 82% use GitHub | Sprint 21 |
| **D2** | **AI Identity Attestation** — `squash attest-identity` | 5 days | Jun | C3, D1 | Zero-trust AI supply chain | Sprint 25 |
| **D3** | **Procurement Score API** — B2B buyer due diligence | 7 days | Jun | D1, D2 | $2.1B procurement AI market | Sprint 26 |
| **D4** | **Multi-Jurisdiction Matrix** — `squash compliance-matrix` | 5 days | Jul | D3, C4 | EU+US+UK+Singapore coverage | Sprint 27 |

---

## 🎯 Launch Sequence

| Launch | Event | Date | Gate | Hook |
|--------|-------|------|------|------|
| **L1** | **Public Beta** | **Jul 11** | A1–A4, B1–B2, C1, design-partner quote | Loom 3-min demo video |
| **L2** | **Show HN** | **Jul 14, 9am ET** (Tuesday) | C1 live (`squash freeze` demo) | Draft already in `docs/launch/hn-post.md` |
| **L3** | **Product Hunt** | Jul 21 | Pre-arranged hunter, gallery design done | "Squash violations, not velocity." |
| **L4** | **EU Enforcement Day** | **Aug 2 — T+0** | All preceding launches | "Squash users are compliant. Are you?" |

---

## 💰 Revenue Model

### Pricing Tiers

| Tier | Price | Limit | Target |
|------|-------|-------|--------|
| **Open** | Free | 1 model/month | OSS developers |
| **Pro** | $99/mo | 20 models/month | Startups, researchers |
| **Team** | $499/mo | 100 models/month | ML teams |
| **Enterprise** | Custom | Unlimited + SLA | F500, regulators |

### Revenue Projections

| Month | MRR | Customers | Notes |
|-------|-----|-----------|-------|
| Jul 2026 | $5K | 50 Pro | Post-L1 launch |
| Aug 2026 | $25K | 200 Pro + 10 Team | EU enforcement wave |
| Oct 2026 | $100K | 500 Pro + 50 Team + 5 Ent | Growth phase |
| Jan 2027 | $300K | 1000+ across tiers | Platform network effects |
| Jul 2027 | $833K | Scale | $10M ARR run rate |

---

## 🏗️ Technical Architecture

```
squash (open-core CLI + SDK)
├── squash/
│   ├── scanner.py          # ModelScanner — security + compliance scan
│   ├── policy.py           # PolicyEngine — 10+ framework evaluation
│   ├── attest.py           # AttestPipeline — signed attestation record
│   ├── sbom_builder.py     # CycloneDXBuilder — ML-BOM generation
│   ├── spdx_builder.py     # SpdxBuilder — SPDX AI Profile
│   ├── oms_signer.py       # OmsSigner — Sigstore keyless signing
│   ├── vex.py              # VexEvaluator — CVE/vulnerability tracking
│   ├── provenance.py       # ProvenanceCollector — dataset lineage
│   ├── governor.py         # SquashGovernor — drift detection
│   ├── risk.py             # AiRiskAssessor — EU AI Act risk taxonomy
│   ├── incident.py         # IncidentResponder — Art. 73 packages
│   ├── freeze.py           # FreezeOrchestrator — emergency response ★ C1
│   ├── notifications.py    # Notification fanout (Slack/PD/email)
│   ├── webhook_delivery.py # WebhookDelivery — subscriber fanout
│   ├── attestation_registry.py  # AttestationRegistry — live/revoked
│   ├── audit_log.py        # AuditLog — append-only tamper-evident log
│   ├── hallucination.py    # HallucinationDetector — runtime monitor
│   ├── washing_detector.py # AIWashingDetector — 28 patterns ★ C2
│   ├── insurance.py        # InsuranceBuilder — risk packages ★ C6
│   ├── annex_iv_generator.py # AnnexIVGenerator — Art. 11 docs
│   ├── nist_rmf.py         # NistRmfScanner — NIST AI RMF 1.0
│   └── cli.py              # squash CLI entry point
├── squash/integrations/
│   ├── sagemaker.py        # AWS SageMaker adapter
│   ├── ray.py              # Ray Serve decorator
│   └── kubernetes.py       # K8s admission webhook
└── tests/                  # 4384+ tests (pytest)
```

---

## 📋 Sprint Detail Cards

### Sprint 19 — `squash freeze` Emergency Response Command · **Track C / C1 ★ HEADLINE WIN**

**Duration:** 2 days (W221–W222, May 5–6)
**Status:** ✅ SHIPPED 2026-05-06
**Anchor stat:** 20% of organizations have a tested AI incident response plan.

**What ships:**
- `squash/freeze.py` — `FreezeOrchestrator` driving 5 sub-steps atomically
- `tests/test_freeze.py` — 55 tests with full DI-stub offline coverage
- `squash freeze` CLI wired in `cli.py`
- v3.2.0 → v3.3.0

**The 5 Sub-Steps (atomicity model):**
1. **Registry Revoke** (legally binding — abort if fails)
2. **Webhook Broadcast** (non-fatal — partial delivery beats nothing)
3. **Signed Ledger Entry** (Ed25519 audit trail, append-only JSONL)
4. **Notification Fanout** (Slack / PagerDuty / email)
5. **Incident Package** (Article 73 disclosure draft on disk)

**Key design decisions:**
- DI-injected collaborators for every sub-step → fast, offline tests
- `FreezeReceipt` records outcome of every step — tamper-evident via SHA-256 + optional Ed25519
- Ledger at `~/.squash/freeze_ledger.jsonl` (configurable via `--state-dir`)
- `squash freeze ledger` and `squash freeze verify` sub-commands

**Exit codes:**
- `0` — all 5 steps succeeded
- `1` — revoke ok, but ≥1 broadcast step failed
- `2` — revoke failed (no side-effects performed)
- `3` — configuration / argument error

---

### Sprint 20 — AI Washing Detection · **Track C / C2**

**Duration:** 5 days (W223–W225, May 7–12)
**Status:** ✅ SHIPPED 2026-04-30
**Anchor stat:** SEC flagged AI washing as #1 enforcement priority for 2026.

**What shipped:**
- `squash/washing_detector.py` — 28 patterns, 9 claim types, 12 divergence rules
- 38 tests, 95.7% recall on test corpus
- `squash detect-washing` CLI command

---

### Sprint 21 — GitHub App · **Track D / D1**

**Duration:** 5 days (W226–W228, May 14–19)
**Status:** 🔜 planned
**Anchor stat:** 82% of ML teams use GitHub.

**What ships:**
- GitHub App with OAuth + webhook
- `squash-bot` PR comments with compliance summary
- 1-click repo integration from getsquash.dev

---

### Sprint 22 — Audit Simulation · **Track C / C5**

**Duration:** 10 days (W229–W231, May 20–Jun 2)
**Status:** 🔜 planned
**Anchor stat:** 78% of organizations can't pass an AI audit in 90 days.

---

### Sprint 23 — Approval Workflow · **Track C / C3**

**Duration:** 5 days (W232–W234, Jun 3–9)
**Status:** ✅ SHIPPED
**Anchor stat:** EU AI Act Art. 9 requires human oversight for high-risk AI.

---

### Sprint 24 — Insurance Risk Package · **Track C / C6**

**Duration:** 3 days (W235–W237)
**Status:** ✅ SHIPPED
**Anchor stat:** $47B AI liability insurance market by 2030.

**What shipped:**
- `squash/insurance.py` — `InsuranceBuilder` with Munich Re + Coalition adapters
- `squash insurance-package` CLI
- `ModelRiskProfile`, `InsurancePackage` dataclasses

---

## 🔬 Phase G — Bulletproof Edition

**Objective:** Make squash the most audit-ready open-source AI compliance tool on the planet.

### G.1 — Coverage Infrastructure
- `pytest-cov` wired in CI
- Branch coverage tracked per module
- Tier 0 modules: 90%+ coverage gate

### G.2 — Mutation Testing
- `mutmut` on Tier 0 modules (oms_signer, anchor, attest, slsa, chain_attest)
- Mutation score gate: ≥ 80%

### G.3 — Chain Walker (Self-Verify)
- `squash self-verify` — walks the entire attestation chain
- Verifies every Ed25519 signature in the audit log

### G.4 — Fuzz Testing
- `atheris` fuzzing on parser entrypoints (SBOM, VEX, policy)
- ≥ 100K iterations per target in CI

### G.5 — Static Analysis Discipline
- Strict mypy on Tier 0 modules
- ruff E/F/W/I enforced repo-wide

---

## 📈 Metrics Dashboard

### Test Suite Health

| Metric | Value | Target |
|--------|-------|--------|
| Total tests | 4384 (pre-C1) | 4400+ |
| Coverage (overall) | tracked | 80%+ Tier 0 |
| Mutation score (Tier 0) | tracked | 80%+ |
| CI time | < 120s | < 90s |

### Module Tier Map

| Tier | Modules | Coverage Gate | Mutation Gate |
|------|---------|---------------|---------------|
| **0** (critical) | oms_signer, anchor, attest, slsa, chain_attest | 90% | 80% |
| **1** (high) | freeze, scanner, policy, vex, governor | 80% | 70% |
| **2** (standard) | All other squash/* | 60% | — |

---

## 🗓️ Weekly Execution Grid

| Week | Track A | Track B | Track C | Track D | Track E |
|------|---------|---------|---------|---------|---------|
| **Apr 28–May 2** | A1 fly deploy (done) · A2 PyPI publish (1 hr) | — | — | — | — |
| **May 5–6** | A3 Domain + Stripe (1d) | B1 HF Scanner (4d) ↑ | **C1 `squash freeze` ✅** (2d) | — | — |
| **May 7–10** | A4 Website live (3d) | B1 cont. · B2 Branded PDF (2d) | C2 AI Washing Detection (5d) · **C7 Hallucination Attest ★ ($67.4B)** | — | — |
| **May 12–19** | ✅ Track A done | B3 Email Digest (2d) | C3 Approval Workflow · C7 cont. | — | — |
| **May 20–28** | — | B4 Terraform/Pulumi (5d) | C4 Regulatory Watch (7d) | D1 GitHub App (5d) | — |
| **Jun 2–9** | — | B5 API Gateway Plugin (5d) | C5 Audit Simulation (10d) | D2 AI Identity (5d) | — |
| **Jun 10–20** | — | — | C5 cont. | D3 Procurement API (7d) | — |
| **Jun 23–Jul 4** | — | — | C8 DORA (5d) | D4 Multi-Jurisdiction (5d) | — |
| **Jul 7–11** | — | — | C9 Carbon (3d) | — | **L1 Public Beta** |
| **Jul 14** | — | — | — | — | **L2 Show HN** |
| **Jul 21** | — | — | — | — | **L3 Product Hunt** |
| **Aug 2** | — | — | — | — | **L4 EU Enforcement Day** |

---

## 🔗 Critical Path Analysis

The critical path to L1 (Jul 11 Public Beta):

```
A1 (done) → A2 (done) → A3 → A4 → L1
B1 (done) → B2 → L1
C1 ✅ (done) → L2
C2 ✅ (done) → L1
```

Key dependencies:
- **B1 + B2 + C1 (by May 10) → unblock L1.** Public Beta Launch (Jul 11) requires the HF scanner live, the branded PDF as sales leave-behind, and `squash freeze` as the headline demo.
- **C1 live by mid-May → headline asset for L2 (Show HN, Jul 14, 9am ET).** `squash freeze` IS the HN demo. The post body GIF should show the red-button command. Draft already in `docs/launch/hn-post.md`.
- **Track D D3/D4/D5 (by Jul 31) → unblock the Aug 2 narrative.** Procurement scoring API, multi-jurisdiction matrix, and identity attestation make the enterprise pitch.

---

## 📝 Design Partner Program

| Partner | Segment | Status | Use Case |
|---------|---------|--------|----------|
| [REDACTED] | FinTech | Active pilot | EU AI Act + DORA compliance |
| [REDACTED] | HealthTech | Evaluating | FDA AI/ML SaMD + HIPAA |
| [REDACTED] | InsurTech | Active pilot | Underwriting model attestation |
| [REDACTED] | GovTech | Prospect | FedRAMP + CMMC certification |

Design partner ask: 30-min monthly call + testimonial for launch.

---

## 🔒 Security & Trust Architecture

### Cryptographic Guarantees

| Primitive | Usage | Standard |
|-----------|-------|----------|
| Ed25519 | Attestation signing, freeze receipt signing | RFC 8032 |
| SHA-256 | Payload hashing, SBOM component hashes | FIPS 180-4 |
| HMAC-SHA256 | Webhook delivery signatures | RFC 2104 |
| Sigstore | Keyless signing (CI/CD integration) | Sigstore spec |

### Audit Trail Properties

- **Append-only:** Ledger files are never overwritten
- **Tamper-evident:** Every entry carries a SHA-256 hash of its canonical JSON
- **Signed (optional):** Ed25519 signature when a private key is available
- **Human-readable:** JSONL format — `jq` and `grep` work without squash installed

---

## 📚 Regulatory Coverage Matrix

| Framework | CLI Flag | Module | Status |
|-----------|----------|--------|--------|
| EU AI Act (Annex IV) | `--policy eu-ai-act` | `annex_iv_generator.py` | ✅ |
| NIST AI RMF 1.0 | `--policy nist-ai-rmf` | `nist_rmf.py` | ✅ |
| ISO 42001 | `--policy iso-42001` | `policy.py` | ✅ |
| OWASP LLM Top 10 | `--policy owasp-llm-top10` | `policy.py` | ✅ |
| FedRAMP | `--policy fedramp` | `policy.py` | ✅ |
| CMMC 2.0 | `--policy cmmc` | `policy.py` | ✅ |
| SOC 2-AI | `--policy soc2-ai` | `policy.py` | ✅ |
| HITRUST | `--policy hitrust` | `policy.py` | ✅ |
| GDPR-AI | `--policy gdpr-ai` | `policy.py` | ✅ |
| DORA | `--policy dora` | `policy.py` | ✅ |
| EU CRA | `--policy eu-cra` | `policy.py` | ✅ |
| SLSA | `slsa-attest` | `slsa.py` | ✅ |

---

## 🧪 Testing Philosophy

### Test Pyramid

```
         /\
        /  \
       / E2E \        ← 50 tests (CLI integration)
      /────────\
     /  Integration \  ← 500 tests (module-to-module)
    /────────────────\
   /     Unit Tests   \ ← 3800+ tests (pure logic, DI stubs)
  /────────────────────\
```

### Golden Rules

1. **No network calls in unit tests.** Every external collaborator is DI-injected and stubbed.
2. **No file system side-effects without tmp_path.** Every test that writes uses pytest's `tmp_path`.
3. **No sleep() in tests.** Async tests use `asyncio`; sync tests are instant.
4. **Every new module gets a test file.** `squash/foo.py` → `tests/test_foo.py`.
5. **Parameterize over enums.** Don't write 5 tests for 5 severity levels — use `@pytest.mark.parametrize`.

---

## 🔄 Release Process

### Version Bumping

- `squash/__init__.py`: `__version__`
- `pyproject.toml`: `[project] version`
- Both must match. CI checks this.

### Semantic Versioning

- **Major (X.0.0):** Breaking API changes (extremely rare)
- **Minor (X.Y.0):** New features, new CLI commands
- **Patch (X.Y.Z):** Bug fixes, test additions, docs

Current: **v3.4.0** (Sprint 27 C4 — `squash watch-regulatory`)

### Release Checklist

- [ ] All tests pass (`pytest -x`)
- [ ] Version bumped in `__init__.py` AND `pyproject.toml`
- [ ] CHANGELOG entry added
- [ ] PR reviewed and merged
- [ ] `git tag vX.Y.Z && git push --tags`
- [ ] `python -m build && twine upload dist/*`
- [ ] fly.io deploy triggered

---

## 📌 Appendix: Anchor Statistics

These are the statistics used in launch copy, sales materials, and PR pitches. All sourced.

| Stat | Source | Used in |
|------|--------|---------|
| 20% have tested AI incident response plan | IBM Security 2024 | C1 freeze |
| SEC AI washing as #1 enforcement priority | SEC 2026 exam priorities | C2 |
| $47B AI liability insurance market by 2030 | Allied Market Research | C6 |
| 78% can't pass AI audit in 90 days | Gartner 2025 | C5 |
| 82% of ML teams use GitHub | GitHub State of the Octoverse | D1 |
| EU AI Act enforcement: Aug 2, 2026 | Official Journal of the EU | All |
| $67.4B hallucination liability exposure | Swiss Re 2025 | C7 |

---

**Next review:** May 14, 2026 — review Track A completion + Track B/C/D progress against the parallel grid; assess C7 ($67.4B headline) as L2 demo asset
**Owner:** Wesley Scholl, Konjo AI