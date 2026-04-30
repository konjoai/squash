# SQUASH — Master Grand Plan
## From Zero to $10M ARR: EU AI Act Compliance Platform

> **Last updated:** 2026-04-30
> **Status:** Living document — updated on every commit
> **Horizon:** April 2026 → October 2027

---

## ⏰ The North Star — August 2, 2026

> **EU AI Act high-risk enforcement: August 2, 2026 — 94 days.**
>
> Every sprint between today and August 2 is worth more than any sprint after.
> The whole product strategy is anchored to one truth: regulators no longer
> want policy statements. **They want proof.** Squash generates proof, in
> CI, in 10 seconds. Everything else is decoration on this load-bearing
> insight.

The proof gap, not a technology gap. That is the through-line of the
master plan.

---

## ⚡ Brand Identity & Taglines

### The Primary Brand Line

> **"Squash violations, not velocity."**

This is the line. Four words. It captures the exact pain — compliance tools slow teams down, squash doesn't. Works on the homepage hero, conference badge, LinkedIn post opener, HN title. Every ML engineer who has watched a compliance process delay a release will feel it.

### Secondary Lines (Contextual Use)

| Context | Line |
|---------|------|
| Technical audiences (HN, Dev.to) | "Squash it in CI. Not in court." |
| Pricing page (below cost comparison) | "Squash the €35M fine." |
| GitHub README hero / paid ads | "Ship fast. Squash risk faster." |
| EU urgency / countdown clock | "Squash what the regulators find first." |
| Enterprise security buyer | "Squash the audit. Not your roadmap." |
| Conference talk opener | "Squash bugs, violations, and the €35M fine." |

### Product Identity

> Squash is the `pytest` of AI compliance. It runs in CI, it fails loudly, it produces machine-readable artifacts, and it integrates with the tools engineers already use.

That's the moat. Credo AI and OneTrust are form-filling tools. Squash is a pipeline primitive. Lean into this identity in all copy, the HN post, LinkedIn content, and design partner conversations.

---

---

## ⚡ Situation Report (April 30, 2026) — Post Sprint 13 ✅ COMPLETE — Tier 2 100% DONE

| Metric | Value |
|--------|-------|
| **EU AI Act enforcement deadline** | August 2, 2026 — **94 days** |
| **Squash code maturity** | v1.8.0 · Sprint 13 complete · 3987 tests passing · **Tier 2 100% complete** |
| **Python modules** | 71 standalone modules + VS Code extension · 100+ git commits |
| **Annex IV coverage** | ✅ 100% — 12-section generator, completeness scoring, PDF export |
| **ISO 42001 coverage** | ✅ — 38-control readiness assessment, gap analysis, remediation roadmap |
| **Trust Package** | ✅ — Signed vendor attestation bundle, `squash verify-trust-package` CLI |
| **Agent Compliance** | ✅ — OWASP Agentic AI Top 10 audit, MCP agent manifest attestation |
| **Incident Response** | ✅ — EU AI Act Article 73 incident package, signed incident report |
| **Board Report** | ✅ — Executive board report generator, quarterly compliance scorecard |
| **Vendor Risk Register** | ✅ NEW — AI vendor register, risk tiering, questionnaire generator, Trust Package import |
| **AI Asset Registry** | ✅ NEW — Model inventory, auto-sync from CI, shadow AI flagging, drift/CVE tracking |
| **Data Lineage Certificate** | ✅ NEW — Training dataset tracing, SPDX license check, PII risk, GDPR assessment |
| **Bias Audit** | ✅ — DPD/DIR/EOD/PED; NYC Local Law 144; EU AI Act Annex III; ECOA 4/5ths |
| **Annual Review** | ✅ NEW — Full annual review: attestation history, trend, regulatory changes, next-year objectives |
| **Attestation Registry** | ✅ NEW — `att://` URI scheme; SHA-256 integrity; revocation; org-scoped lookup |
| **CISO Dashboard** | ✅ NEW — 5-metric panel; risk heat-map; ANSI terminal + JSON for VS Code webview |
| **Regulatory Feed** | ✅ NEW — 9 regulations tracked; enforcement deadlines; change log; squash control mapping |
| **M&A Due Diligence** | ✅ NEW — Complete AI DD package; R&W guidance; liability flag scoring; ZIP bundle |
| **VS Code Extension** | ✅ NEW — Full TypeScript scaffold; 9 commands; sidebar tree; status bar; dashboard webview |
| **OpenTelemetry** | ✅ NEW (Sprint 9) — `squash/telemetry.py`; OTLP gRPC+HTTP; spans per attestation; Datadog/Honeycomb/Jaeger |
| **ArgoCD/Flux GitOps Gate** | ✅ NEW (Sprint 9) — K8s ValidatingWebhookConfiguration; admission deny on missing/low score; `squash gitops check` CLI |
| **Generic Webhook Delivery** | ✅ NEW (Sprint 9) — HMAC-signed outbound webhooks; 5 event types; SQLite persistence; `squash webhook` CLI |
| **SBOM Diff** | ✅ NEW (Sprint 9) — `squash diff v1.json v2.json`; score delta, component/policy/vuln drift; table/JSON/HTML |
| **Model Card First-Class CLI** | ✅ NEW (Sprint 10) — `squash model-card --validate / --validate-only / --push-to-hub`; Annex IV / bias / lineage data fusion; HF schema validator (`squash/model_card_validator.py`); 4 new HF sections (Training Data, Evaluation, Environmental Impact, Ethical Considerations) |
| **Chain & Pipeline Attestation** | ✅ NEW (Sprint 11) — `squash/chain_attest.py` composite engine; `ChainAttestation` with HMAC-SHA256 signing + tamper detection; LangChain Runnable graph walker (`attest_chain()` — RAG / agent / multi-LLM ensemble shapes); `squash chain-attest <spec.json|module:var>` CLI with `--verify`, `--fail-on-component-violation` |
| **Registry Auto-Attest Gates** | ✅ NEW (Sprint 12) — Active gates in MLflow / W&B / SageMaker integrations: `MLflowSquash.register_attested()`, `WandbSquash.log_artifact_attested()`, `SageMakerSquash.register_model_package_attested()` (raises `AttestationViolationError`, refuses registration on policy fail); `squash registry-gate` unified CLI for CI/CD with backend-specific URI validation and structured `registry-gate.json` decision output |
| **Startup Pricing Tier** | ✅ NEW (Sprint 13) — `Plan.STARTUP` ($499/mo, 500 attestations, 3 seats) + `Plan.TEAM` ($899/mo, 1000 attestations, 10 seats) registered in `PLAN_LIMITS`; 13 named entitlement bits (`vex_read`, `slack_delivery`, `github_issues`, `jira`, `linear`, `saml_sso`, `hitl`, `audit_export`, `on_premise`, `air_gapped`, …); gating in `notifications.py` + `ticketing.py` via optional `plan=` kwarg; Stripe Startup checkout via `SQUASH_STRIPE_PRICE_STARTUP` |
| **Repo status** | ✅ Separated from `konjoai/squish` — standalone Apache 2.0 repo |
| **Production status** | Dockerfile + fly.toml written; **not yet deployed** |
| **PyPI status** | `pyproject.toml` ready; **not yet published** |
| **Integration surface** | GitHub Actions, GitLab CI, Jenkins, Azure DevOps, Helm, MLflow, W&B, HuggingFace, SageMaker, Vertex AI, Ray, Kubernetes, Slack, Teams, JIRA, Linear, GitHub Issues |
| **TAM (updated)** | $340M today → $4.83B by 2034 (35–45% CAGR) · 75%+ of orgs will have formal AI governance by end of 2026 |
| **Regulatory urgency** | EU AI Act Aug 2 · Colorado AI Act June 2026 · SEC top AI/cybersecurity exam priority · Italy fined OpenAI €15M for GDPR |
| **Competitor pricing** | Credo AI $30K–$150K/yr · OneTrust $50K–$200K/yr |
| **Squash target pricing** | $0 (Community) → $299 (Pro) → $499 (Startup) → $899 (Team) → $4K+ (Enterprise) |

**The clock is running.** High-risk AI enforcement hits August 2, 2026 — **94 days**. Every week of delay is market share surrendered to whoever ships first.

**Tier 1 + Tier 2 of the master plan: 100% complete (April 30, 2026).** Tier 3 sequencing reprioritised; Tier 4 (11 new market-opportunity sprints, W221–W250) scheduled in this revision. Every Tier 4 sprint operationalises one statistic from the Market Intelligence section above.

**Market context update (April 2026):** The regulatory shift is structural, not cyclical. 75% of organizations will have formal AI governance frameworks by end of 2026 (up from <30% in 2023). The EU AI Act, Colorado AI Act (June 2026), SEC AI disclosure priority, and Italy's OpenAI GDPR fine confirm that regulators have crossed from intent to enforcement. **They no longer want policy statements. They want proof. Squash generates proof.**

**What's complete:** 100+ commits. v1.8.0. 71 Python modules + VS Code extension. **3987 tests passing across 13 completed sprints.** Full engineering surface: Annex IV engine, ISO 42001 readiness, Trust Package exporter/verifier, OWASP Agentic AI Top 10, incident response, board report generator, cloud API + auth, CI/CD integration layer, Prometheus metrics, OpenTelemetry, ArgoCD/Flux GitOps gate, generic webhook delivery, SBOM diff, model-card first-class CLI + HF schema validator, **chain & pipeline composite attestation (RAG / agent / ensemble) with HMAC-SHA256 signing**, **registry auto-attest gates (MLflow / W&B / SageMaker)**, **5-tier pricing (Free / Pro / Startup $499 / Team $899 / Enterprise) with 13 entitlement bits**, Stripe billing, attestation registry, public regulatory feed (9 frameworks), M&A due-diligence package generator, JIRA/Linear/GitHub ticketing, FastAPI/Django compliance middleware, `squash demo`, `squash init`, `squash watch`, `squash install-hook`, `squash chain-attest`, `squash registry-gate`, shields.io-compatible badge SVG endpoint.

**What's not done yet:** PyPI publication, live Fly.io production deployment, website, domain, Stripe checkout links, onboarding emails, and the launch itself. Sprint 4A is the critical path.

---

## 🛤 Parallel Track Roadmap — The Canonical Execution Model

**Sequential sprint numbering is retired as the operating model.** From May 2 onward, work runs across **four parallel tracks plus the launch sequence and a research lane.** Tracks A/B/C/D each have an owner-track and zero blocking dependencies on the others once Track A item A1 is live.

The parallelisation insight that produced the Tier 1+2 surface — Sprints 5, 7, 8, 9 all ran simultaneously — becomes the standing operating model for everything that follows. Sequential cadence was a vestige of the early-repo phase; it no longer applies.

```
TRACK A (Launch Pipeline)        TRACK B (Tier 3 Engineering)     TRACK C (New Opportunities)      TRACK D (Enterprise Moat)
  └─ critical path, solo          └─ parallel, independent         └─ parallel, research items     └─ post-launch defensibility
       │                                │                                │                              │
       └── A1 fly deploy                └── B1 HF Public Scanner         └── C1 squash freeze ★        └── D1 GitHub App
       └── A2 PyPI publish              └── B2 Branded PDF               └── C2 AI Washing Detect      └── D2 AI Identity Attest
       └── A3 Domain + Stripe           └── B3 Email Digest              └── C3 Approval Workflow      └── D3 Procurement Score API
       └── A4 Website Live              └── B4 Terraform/Pulumi          └── C4 Regulatory Watch       └── D4 Multi-Jurisdiction
                                        └── B5 API Gateway Plugin        └── C5 Audit Simulation       └── D5 Industry Benchmark
                                        └── B6 Blockchain Anchor         └── C6 Insurance Package      └── D6 SOC 2 Type II
                                                                                                       
LAUNCH SEQUENCE                                                          RESEARCH LANE (post-launch)
  └─ L1 Public Beta — Jul 11                                              └─ R1 Red-Team / Prompt Injection — Sep–Oct
  └─ L2 HN Show HN — Jul 14, 9am ET                                       └─ R2 AI Cost / ROI Attestation — Oct–Nov
  └─ L3 Product Hunt — Jul 21
  └─ L4 EU Enforcement Day — Aug 2
```

★ **C1 `squash freeze` is the headline win.** Two days of work, zero new modules, orchestrates five existing modules (`attestation_registry`, `webhook_delivery`, `gitops`, `incident`, `notifications`) into one CLI command. The "red button" CISOs will demo to boards. **Highest drama-per-hour-of-effort ratio in the entire roadmap.** Goes in the first press release.

---

### Track A — Launch Pipeline (critical path, solo execution)

The non-delegable, sequential actions only the founder can perform. **9 days end-to-end, May 2 → May 10.** Every Tier 3 / Tier 4 cloud-dependent item is blocked by A1 (live API).

| ID | Item | Effort | Date | Blocks | Notes |
|---|---|---|---|---|---|
| **A1** | **Production Deploy** — `fly deploy` | 2 hrs | **May 2** | A2, A3, all cloud-dependent items | Dockerfile + fly.toml ready. Set env vars, deploy, verify `/health/ping`. |
| **A2** | **PyPI Publish** — `pip install squash-ai` | 1 hr | May 3 | All install docs | `python -m build && twine upload dist/*`. Verify in clean venv. |
| **A3** | **Domain + Stripe Live** — getsquash.dev + Stripe products | 1 day | May 5 | A4 (website) | Buy domain, point to Vercel, create Stripe products ($299/$499/$899/$4K+), wire checkout, activate Resend. `billing.py` Stripe webhooks already written. |
| **A4** | **Website Live** — Vercel deploy of `website/` | 3 days | May 7–10 | First inbound | Next.js scaffold built. Activate countdown timer, pricing page, demo GIF, EU deadline urgency banner. |

### Track B — Tier 3 Engineering (parallel, independent)

Pure engineering that has zero dependency on Track A once A1 is live. Each item maps 1:1 to a previously-defined Tier 3 sprint specification.

| ID | Item | Effort | Date | ∥ With | Foundation | Sprint Spec |
|---|---|---|---|---|---|---|
| **B1** | **HF Public Scanner** — `squash scan hf://owner/model` | 4 days | **May 5–8** | A3, C1, C2 | `scanner.py` + `policy.py` exist; new HF API fetch layer | Sprint 14 (W205) |
| **B2** | **Branded PDF Report** — cover + exec summary on existing `to_pdf()` | 2 days | May 8–10 | A4, C2, C3 | `annex_iv_generator.to_pdf()` works; design + template only | Sprint 15 (W208) |
| **B3** | **Email Digest** — Weekly/monthly portfolio posture | 2 days | May 12–14 | C3, C4 | `notifications.py` + Resend already configured | Sprint 15 (W209–W210) |
| **B4** | **Terraform/Pulumi Provider** — Go provider + Pulumi component | 10 days | May 15–26 | C3, C4, D1 | API stable after A1; new repo `terraform-provider-squash/` | Sprint 16 (W211–W214) |
| **B5** | **API Gateway Plugin** — Kong + AWS Lambda authorizer | 8 days | May 27–Jun 5 | D1, C5 | Two packages (Kong Go/Lua + AWS Python) | (de-scoped Tier 3 #28; reinstated as B5) |
| **B6** | **Blockchain Anchoring** — Ethereum OP_RETURN of attestation hash | 6 days | Jun 6–13 | D1, C5 | `provenance.py` exists; new web3.py + tx builder | Sprint 17 (W215–W217) |
| **B7** | **Drift SLA Certificate** — `squash drift-sla --threshold 0.05 --window 30d` | 4 days | May 28–Jun 2 | B5, C4 | `drift.py` already computes PSI/KS; new SLA cert + breach event | Sprint 31 (W253–W254) |
| **B8** | **LoRA / Adapter Poisoning Detection** — `squash scan-adapter --lora ./adapter.safetensors` | 5 days | Jun 5–11 | B6, D1 | `scanner.py` + ModelScan; new behavioural-comparison + weight-delta anomaly | Sprint 32 (W257–W258) |
| **B9** | **Data Poisoning + Pipeline Integrity Attestation** — `squash attest-pipeline --datasets ./data/` | 7 days | Jun 12–22 | C5, D2 | `data_lineage.py` + `scanner.py`; new dataset hash verifier + label-distribution anomaly | Sprint 34 (W262–W264) |
| **B10** | **License Conflict Detector** — `squash license-check --deployment-type commercial-saas` | 5 days | May 18–23 | B4, C3 | `data_lineage.py` SPDX layer; new 200+ LLM license DB + deployment-type rules | Sprint 33 (W255–W256) — OMB M-26-04 deadline |

### Track C — New Opportunities (parallel, research-driven)

High-ROI items derived from market research. Each operationalises a specific anchor stat from the Market Intelligence section.

| ID | Item | Effort | Date | ∥ With | Anchor Stat | Sprint Spec |
|---|---|---|---|---|---|---|
| **C1 ★** | **`squash freeze`** — emergency response orchestrator | **2 days** | **May 5–6** | A3, B1 | 20% have a tested AI incident-response plan | Sprint 19 (W221–W222) |
| **C2** | **AI Washing Detection** — `squash detect-washing` | 5 days | May 7–12 | B1, B2 | SEC #1 AI exam priority 2026 | Sprint 20 (W223–W225) |
| **C3** | **Approval Workflow** — `squash approve` (signed reviewer record) | 5 days | May 13–19 | B2, B3, B4 | EU AI Act Art. 9 human-oversight requirement | Sprint 23 (W232–W234) |
| **C4** | **Regulatory Watch Daemon** — primary-source polling + gap analysis | 7 days | May 20–28 | B4, D1 | Daily-touch product = retention | Sprint 27 (W243–W245) |
| **C5** | **Audit Simulation** — `squash simulate-audit --regulator EU-AI-Act` | 10 days | Jun 2–13 | D1, D2, B5 | 78% can't pass audit in 90 days | Sprint 22 (W229–W231) |
| **C6** | **Insurance Risk Package** — Munich Re / Coalition format | 7 days | Jun 16–24 | D2, D3 | AI cyber-insurance market crystallising late 2026 | Sprint 24 (W235–W237) |
| **C7 ★** | **Hallucination Rate Attestation** — `squash hallucination-attest --domain legal` | 5 days | **May 9–15** | C2, B2 | **$67.4B in 2024 losses · 47% decisions on hallucinated content** | Sprint 30 (W251–W252) |
| **C8** | **Model Deprecation Watch** — `squash deprecation-watch` cross-references registry vs provider sunsets | 4 days | Jun 25–30 | C6, D2 | OpenAI / Anthropic / Google sunsets break attested deployments quarterly | Sprint 35 (W265–W266) |
| **C9** | **Carbon / Energy Attestation** — `squash attest-carbon --deployment-region us-east-1` | 6 days | Jul 1–9 | D3 | CSRD reporting (all large EU orgs from 2025) · OMB DOE AI data-centre rule | Sprint 36 (W259–W261) |
| **C10** | **Runtime Hallucination Monitor** — `squash monitor --mode hallucination --endpoint http://...` | 6 days | Jul 7–15 | D3 | EU AI Act Art. 9 post-market monitoring · 18% production hallucination rate | Sprint 37 (W267–W269) |
| **C11** | **Genealogy + Copyright Contamination Cert** — `squash genealogy --memorisation-probe ./probes/` | 7 days | Jul 21–30 | D5 | NYT v. OpenAI legal theory · GC buyer · Books3 / copyleft-code exposure | Sprint 39 (W272–W274) |

### Track D — Enterprise Moat (post-launch defensibility)

Higher-effort items that build the long-term moat. Most depend on Track A's live API and benefit from launch volume to validate.

| ID | Item | Effort | Date | ∥ With | Anchor Stat | Sprint Spec |
|---|---|---|---|---|---|---|
| **D1** | **GitHub App** — Marketplace listing + PR auto-comment | 15 days | Jun 1–20 | C5, B5, D2 | 1 user → 50-user network effect | new (not yet sprinted; promote to Sprint 30 if needed) |
| **D2** | **AI Identity Attestation** — `squash attest-identity` | 8 days | Jun 15–25 | D1, C5, C6 | 92% lack AI identity visibility · 73% CISO want-to-buy | Sprint 21 (W226–W228) |
| **D3** | **Procurement Scoring API** — `GET /v1/score/{vendor}` | 10 days | Jul 1–15 | D4, D5 | Two-sided marketplace, SSL-CA-of-AI play | Sprint 28 (W246–W248) |
| **D4** | **Multi-Jurisdiction Matrix** — `squash compliance-matrix --regions ...` | 8 days | Jul 10–20 | D3, D5 | Multinational legal-mapping is 1-week consult per deploy | Sprint 26 (W240–W242) |
| **D5** | **Industry Benchmarking** — `squash industry-benchmark --sector ...` | 7 days | Jul 20–28 | D3, D4 | QBR conversation starter; data-density unlock | Sprint 29 (W249–W250) |
| **D6** | **SOC 2 Type II** — readiness phase + auditor selection | 6 mo | Aug 2026+ | (external) | Procurement unblocker for $50K+ ACV | Sprint 18 (W218–W220) |
| **D7** | **AI Vendor Concentration Risk** — `squash vendor-concentration` aggregates Asset Registry by provider | 5 days | Aug 5–11 | D6 onboarding, R1 | NIST AI RMF GOVERN function · CRO buyer · 5-provider average AI stack | Sprint 38 (W270–W271) |

### Launch Sequence (red, date-locked)

These dates are critical-path dependencies. Everything in Tracks B/C/D scheduled before each launch event must ship or that launch arrives with gaps.

| ID | Event | Date | Requires | Asset |
|---|---|---|---|---|
| **L1** | **Public Beta Launch** | Jul 11 | A1–A4, B1–B2, C1, design-partner quote | Loom 3-min demo video |
| **L2** | **Show HN** | **Jul 14, 9am ET** (Tuesday) | C1 live (`squash freeze` demo) | Draft already in `docs/launch/hn-post.md` |
| **L3** | **Product Hunt** | Jul 21 | Pre-arranged hunter, gallery design done | "Squash violations, not velocity." |
| **L4** | **EU Enforcement Day** | **Aug 2 — T+0** | All preceding launches | "Squash users are compliant. Are you?" |

### Research Lane (post-launch)

| ID | Item | Effort | Window | Foundation |
|---|---|---|---|---|
| **R1** | **Red-Team / Prompt Injection Scanner** — `squash red-team --test-suite owasp-llm-top10` | 10 days | Sep–Oct 2026 | `evaluator.py` + `scanner.py`; new attack-prompt library |
| **R2** | **AI Cost / ROI Attestation** — `squash cost-attest` for CFO buyer | 8 days | Oct–Nov 2026 | `telemetry.py` + `metrics.py` already capture cost/token |

### The Critical Parallelism Insight

**While Track A burns 9 sequential days from May 2 → May 10 on deployment items only the founder can do**, both Track B (HF Scanner, 4 days) and Track C (`squash freeze`, 2 days) can start on May 5 and finish before A4 is live. This is how the same week ships three independently valuable artefacts. Sprints 5, 7, 8, 9 already proved this works — the master plan now codifies it as the standing model.

The moment **A1** completes (May 2 — deploy day), all four tracks are fully unblocked. Anything sequenced after A1 in this roadmap that can't articulate a concrete dependency on its predecessors should be moved earlier.

---

## 📊 Market Intelligence — Anchor Statistics & Messaging Framework

These are the load-bearing statistics. Every product decision, sprint
brief, sales conversation, and piece of marketing copy should be
traceable back to one of them. They define the proof gap.

### The Proof Gap (executive layer)

| Stat | Source | What It Unlocks |
|---|---|---|
| **78%** of business executives lack strong confidence they could pass an independent AI governance audit within 90 days | Grant Thornton 2026 AI Impact Survey | The CFO / Audit Committee narrative. Sprint 22 (`squash simulate-audit`) is the direct response. |
| **22%** of orgs confident they could pass an AI governance audit in 90 days | Grant Thornton 2026 | The negative framing of the same stat — used in HN posts and design-partner outreach. |
| **20%** of organizations have a tested AI incident response plan | Industry research, 2026 | Sprint 19 (`squash freeze`) lands here — emergency response as a feature. |
| **4×** revenue-growth multiple for orgs with strong AI governance | Industry research | The CFO ROI line, not just risk-averter pitch. |

### The Hallucination Crisis (general counsel + CFO layer)

| Stat | Source | What It Unlocks |
|---|---|---|
| **$67.4 billion** in global AI hallucination losses in 2024 | 2024 industry research | **The headline stat for the entire squash story.** Sprint 30 (`squash hallucination-attest`) is the direct product. |
| **47%** of enterprise AI users made at least one major business decision based on hallucinated content | 2024–2025 enterprise survey | Hallucination is operational risk, not edge-case risk. C7 lands here. |
| **4.3 hours/week** spent per knowledge worker verifying AI outputs ≈ **$14,200/employee/year** in hallucination mitigation | Productivity studies, 2025 | The CFO ROI math. Squash converts this hidden cost into a one-line attestation. |
| **18%** hallucination rate in live enterprise chatbot deployments · **5–15%** in RAG systems even with retrieval working | Production telemetry studies | Sprint 37 (`squash monitor --mode hallucination`) — runtime SLA distinct from pre-deploy. |
| **39%** of AI customer-service bots pulled or reworked in 2024 due to hallucination errors | 2024 deployment retrospective | Confirms hallucination monitoring as a continuous-compliance requirement, not one-time test. |
| **34%** more confident language used by models *when hallucinating* than when factual | MIT research, 2025 | The legal-exposure framing for Sprint 39 (Genealogy + Copyright Contamination Cert). |

### The Drift / Data-Integrity Crisis (CISO + ML platform layer)

| Stat | Source | What It Unlocks |
|---|---|---|
| **35%** error-rate jump in models left unmonitored 6+ months on new data | 2024 MLOps survey | Sprint 31 (`squash drift-sla`) — formal drift SLA certificate. |
| **67%** of orgs at scale reported a critical issue from statistical misalignment unnoticed for >1 month | 2024 enterprise survey | Same buyer; same product. Drift is silent until it's expensive. |
| **90%** of AI models fail to reach production due to fragile pipelines | MLOps research | Sprint 34 (`squash attest-pipeline`) — training pipeline integrity attestation. |
| **~100** malicious models discovered on HuggingFace with embedded code-execution payloads (some establishing reverse-shell on load) | JFrog Security 2024 | Sprint 32 (`squash scan-adapter`) for LoRA + Sprint 34 for pipelines both land here. |
| **0.001%** of training data poisoned is enough to fundamentally degrade model reliability | Adversarial-ML research | Statistical detection threshold for the data-poisoning module. Order-of-magnitude proof point. |

### The AI Identity Crisis (CISO layer)

| Stat | What It Unlocks |
|---|---|
| **92%** of organizations lack full visibility into their AI identities | Sprint 21 (`squash attest-identity`) — AI Identity Governance |
| **95%** doubt their ability to detect or contain misuse of AI agents | Sprint 21 + the existing `agent_audit.py` + `governor.py` audit log |
| **16%** effectively govern AI agent access to core business systems | Sprint 21 — least-privilege validation hooks |
| **60%** still use login-based auth for AI systems (no rotation) | Sprint 21 — token rotation policy attestation |
| **73%** of CISOs would invest immediately if budget allowed | The buyer is already pre-sold — squash needs only to be *findable* and *verifiable* |

### Messaging Framework — Six Lines, Five Audiences

| Audience | The Line |
|---|---|
| ML Engineers (HN, dev.to, Slack) | "Squash violations, not velocity." |
| CISOs (LinkedIn, conferences) | "92% of orgs can't see their AI identities. Squash makes them visible." |
| CFO / Audit Committee | "78% can't pass an audit in 90 days. Squash compresses the readiness window from 6 weeks to 15 minutes." |
| Chief Risk Officer / Insurance buyer | "AI cyber-insurance underwriters need quantified risk. Squash generates the package." |
| Procurement / Vendor risk | "Verify any vendor's AI compliance posture in 10 seconds. `squash lookup`." |
| Regulators / Auditors | "Cryptographically signed proof. Sigstore-backed. Tamper-evident." |

### The Through-Line

The proof gap, not a technology gap. Every Tier 4 sprint operationalises
exactly one of the gap dimensions. No vanity features, no speculative
adjacencies. If a sprint can't be tied back to a stat in this section,
it doesn't ship.

---

## 🧭 Market Intelligence Update (April 2026)

### The Structural Shift

The AI compliance market is not a niche. It is a structural shift:
- **$340M → $4.83B by 2034** at 35–45% CAGR
- **75%+ of organizations** will have formal AI governance frameworks by end of 2026 (up from <30% in 2023)
- EU AI Act enforces **August 2, 2026** (95 days)
- Colorado AI Act enforces **June 2026**
- SEC elevated AI and cybersecurity to **top examination priorities** (displacing crypto)
- Italy fined OpenAI **€15 million** for GDPR violations in training data
- FTC ran **"Operation AI Comply"** targeting deceptive AI marketing
- Average enterprise runs **66 GenAI apps**, 65% without IT approval
- Shadow AI added **$670K** to average breach cost in 2025

### Unaddressed Pain Points Squash Must Own

| Pain | Solution | Wave | Priority |
|------|----------|------|----------|
| Vendor questionnaire nightmare (4-week manual process) | Trust Package + `squash verify-trust-package` | W171 ✅ | 🔥 Highest |
| AI vendor risk on buyer side (Shadow AI, 66 apps) | AI Vendor Risk Register (future) | W178 | High |
| Model sprawl documentation ("what AI do you have deployed?") | AI Asset Registry (future) | W179 | High |
| OWASP Agentic AI Top 10 (40% of apps will have agents by 2026) | Agent Audit | W172 ✅ | 🔥 First-mover |
| Training data GDPR liability (Italy fined OpenAI €15M) | Data Lineage Certificate (future) | W180 | High |
| ISO 42001 certification ($50K–$200K consultant market) | ISO 42001 Readiness | W170 ✅ | High |
| AI incident response (no tooling exists) | Incident Package | W173 ✅ | High |
| Board/CISO quarterly report (20-30 pages manual) | Board Report Generator | W174 ✅ | High |
| Bias audit (Workday lawsuit, NYC Local Law 144) | Bias Audit (future) | W181 | Medium-High |
| Annual AI system review (week-long manual process) | Annual Review Generator (future) | W182 | Medium |

### The Trust Registry Moat

Every company using squash publishing attestations to a public registry at `attestations.getsquash.dev` creates the **SSL Certificate Authority equivalent for AI compliance**. Buyers verify any vendor's posture by querying the registry — not by reading a 40-page questionnaire. The Sigstore signing infrastructure already exists. The registry is the product expression of it.

### Compliance-as-Code Identity

Squash's identity claim that no competitor owns: **compliance is a gate in your pipeline, not a form you fill out.** Credo AI and OneTrust sell to compliance teams. Squash sells to engineers. Engineers deploy it everywhere. Compliance teams watch the dashboard. This is the correct go-to-market motion and a fundamentally different distribution strategy than every incumbent.

---

## Part I: The Separation Decision

### Why Squash Is Its Own Repo ✅ COMPLETE

**1. Brand clarity.** Squish = Apple Silicon inference optimization. Squash = AI compliance platform for regulated enterprises. A CISO shopping for EU AI Act compliance tooling should never land on a repo full of INT4 quantization benchmarks.

**2. Licensing.** Squish runs under BUSL-1.1. Squash runs under Apache 2.0 (Community) + Commercial Enterprise. Open-sourcing the full compliance layer is a GTM weapon.

**3. Velocity.** Squash releases must happen independently. Enterprise customers cannot wait for a Squish SQUIZD format sprint to clear before getting their VEX feed update.

**4. Funding.** Investors will not fund a repo that also contains an Apple Silicon inference server.

**5. Hiring.** Squash engineers are compliance/platform/backend. Squish engineers are ML systems. Different interview loops, different cultures.

### What Lives in `konjoai/squash` ✅

```
squash/                         (standalone repo)
├── squash/                     (compliance engine)
│   ├── api.py                  (FastAPI cloud API)
│   ├── attest.py
│   ├── chat.py
│   ├── cicd.py
│   ├── cli.py                  (`squash` CLI entry point)
│   ├── cloud_db.py
│   ├── drift.py
│   ├── edge_formats.py
│   ├── evaluator.py
│   ├── governor.py
│   ├── integrations/           (MLflow, W&B, K8s, LangChain, SageMaker, Vertex AI, Ray, HF)
│   ├── lineage.py
│   ├── mcp.py
│   ├── model_card.py
│   ├── nist_rmf.py
│   ├── oms_signer.py
│   ├── policy.py               (10+ policy templates)
│   ├── provenance.py
│   ├── rag.py
│   ├── remediate.py
│   ├── report.py
│   ├── risk.py
│   ├── sarif.py
│   ├── sbom_builder.py
│   ├── scanner.py
│   ├── slsa.py
│   ├── spdx_builder.py
│   └── vex.py
├── tests/                      (80 test files, 4,208+ test cases)
├── .github/workflows/          (CI, publish)
├── SQUASH_MASTER_PLAN.md       (this file)
├── PLAN.md                     (wave-by-wave roadmap)
├── CHANGELOG.md
├── CLAUDE.md                   (AI contributor guidelines)
├── pyproject.toml              (squash-ai package, Apache 2.0)
└── README.md
```

### Connection Between Squash and Squish

```
squish compress ./my-model --quant int4
    ↓ (produces model artifact)
squash attest ./my-model --policy eu-ai-act
    ↓ (compliance gate)
squash sign --model ./my-model
    ↓ (cryptographic provenance)
Deploy with confidence
```

---

## Part II: What Squash Actually Is

### The One-Sentence Pitch

**Squash automates EU AI Act compliance so ML teams spend engineering time building, not documenting.**

### The Problem It Solves (In Real Numbers)

- EU regulation could create a €17B–€38B compliance market by 2030
- Annual compliance expenses per AI system: up to €29,277 per company
- Non-compliance fines: up to €35 million or 7% of global annual turnover
- Documentation preparation: up to 40% of total assessment costs
- Manual Annex IV for a typical mid-market company: $150K–$400K/year

**Squash eliminates that overhead.**

### What Makes Squash Different

| Capability | Credo AI ($30–150K) | Vanta/Drata ($10–50K) | **Squash** |
|-----------|---------------------|----------------------|------------|
| AI-SBOM (CycloneDX ML-BOM) | ✗ | ✗ | ✅ |
| EU AI Act Annex IV auto-generation | ✗ | ✗ | ✅ |
| CI/CD native (GitHub Actions, Jenkins) | ✗ | ✗ | ✅ |
| MLflow / W&B integration | ✗ | ✗ | ✅ |
| ModelScan security scanning | ✗ | ✗ | ✅ |
| Sigstore signing + SLSA provenance | ✗ | ✗ | ✅ |
| VEX feed (live vulnerability tracking) | ✗ | ✗ | ✅ |
| Open-core (self-hostable) | ✗ | ✗ | ✅ |
| Developer-first CLI | ✗ | ✗ | ✅ |
| Starting price | $30,000/yr | $10,000/yr | **$0/mo** |

---

## Part III: Product Tiers & Pricing

### Community (Free — Apache 2.0)
- Full `squash attest` CLI
- CycloneDX 1.7 ML-BOM + SPDX SBOM generation
- EU AI Act, NIST AI RMF, OWASP LLM Top 10 policy checks
- Sigstore signing (keyless)
- SLSA Level 1 provenance
- ModelScan security scanning
- GitHub Actions composite action
- Self-hosted only · Community support
- **Limit: 10 model attestations/month**

### Professional ($299/month)
Everything in Community, plus:
- 200 model attestations/month · Cloud API
- Annex IV auto-generation · 30-day history
- Slack/Teams notifications · MLflow + W&B logging
- Multi-framework compliance (ISO 42001, FedRAMP, CMMC, SOC 2-AI)
- CSV/PDF audit export · Drift detection · Compliance badges
- Email support (48h SLA)

### Startup ($499/month) ← **NEW — captures seed/Series A segment**
Everything in Professional, plus:
- 500 model attestations/month
- Up to 3 users · multi-user dashboard
- VEX feed read access (no subscription alerts)
- Slack notifications with drift alerts
- JIRA/Linear/GitHub Issues auto-ticketing
- Priority email support (24h SLA)

### Team ($899/month)
Everything in Startup, plus:
- 1,000 model attestations/month
- Multi-tenant cloud dashboard
- VEX feed subscription (live CVE monitoring + push alerts)
- Real-time drift detection
- Azure DevOps + Jenkins integrations
- Kubernetes admission controller · HITL approval workflows
- SageMaker + Vertex AI + Ray integrations
- SAML SSO · 90-day audit log
- Custom policy templates · Priority support (24h SLA)

### Enterprise (Custom — from $4,000/month)
Everything in Team, plus:
- Unlimited attestations
- On-premise / air-gapped deployment
- Dedicated account manager · Private Slack channel
- SLA: 4h response, 99.9% uptime
- EU data residency option
- Custom compliance frameworks
- 1-year minimum term

### Revenue Model

```
Community (free)          → 10,000 users by Month 6
    → 3% conversion
Professional ($299/mo)    → 300 customers = $89,700 MRR
    → 8% conversion
Team ($899/mo)            → 24 customers = $21,576 MRR
    → 15% conversion
Enterprise ($4K+/mo)      → 4 contracts = $16,000 MRR
                                         ───────────
                          TOTAL MRR: ~$127,276 → ~$1.5M ARR (Month 12)
```

---

## Part IV: Production Release Checklist

### Phase 1: Repository Separation (by May 9) ✅ IN PROGRESS

- [x] Create `konjoai/squash` repo on GitHub
- [x] Extract all `squash/` modules with full git history (`git filter-repo`)
- [x] Extract all `tests/test_squash_*.py` files
- [x] Update all `squish.squash` imports to `squash`
- [x] Set up standalone `pyproject.toml` (package name: `squash-ai`)
- [x] Configure GitHub Actions CI pipeline
- [x] Set up `uv.lock` with squash-only dependencies (193 packages resolved)
- [ ] Create `squash` PyPI package (publish to PyPI)
- [ ] Set up branch protection (`main` requires passing CI)
- [x] Verify squish still passes all 4,200+ tests after extraction (95 core squash tests passing)

### Phase 2: Production Hardening (by June 6)

**API & Infrastructure:**
- [ ] Deploy cloud API to production (FastAPI on Fly.io)
- [ ] Set up PostgreSQL cloud DB (Neon — serverless)
- [ ] Implement API key authentication (token-based)
- [ ] Rate limiting (per-tier enforcement)
- [ ] Error monitoring (Sentry)
- [ ] Uptime monitoring (Better Uptime)
- [ ] Health check endpoint · Versioned API (`/v1/`)

**Artifact Extraction Engine (Annex IV):**
- [x] Wave 128: TensorBoard event file parser + training config parser (50 tests)
- [x] Wave 129: MLflow API integration — from_mlflow_run(), from_mlflow_params(), from_mlflow_run_full() — 55 tests
- [x] Wave 130: W&B API integration — from_wandb_run(), from_wandb_config(), from_wandb_run_full() — single-pass scan_history() streaming — 54 tests
- [x] Wave 131: HF Datasets provenance — DatasetProvenance, completeness_score(), §2(a) rendering, multi-dataset list, bias detection — 73 tests
- [x] Wave 132: Python AST code scanner — CodeScanner, CodeArtifacts, optimizer/loss/checkpoint/framework detection, zero-dep stdlib ast — 107 tests
- [x] Wave 133: Annex IV document generator — 12 sections, weighted completeness scoring, Article-specific gaps, AnnexIVValidator — 83 tests
- [x] Wave 134: PDF pipeline — to_pdf() via weasyprint, to_html() with embedded CSS, multi-format save() — included in W133 shipment
- [ ] Wave 135: `squash annex-iv-generate` CLI command
- [ ] Wave 136: `squash annex-iv-validate` CLI command

**CLI Completion:**
- [ ] `squash artifact-extract --root ./my-run`
- [ ] `squash annex-iv-generate --artifacts ./artifacts.json`
- [ ] `squash login` for cloud API auth
- [ ] `squash status` for account/quota information

**CI/CD Integration:**
- [ ] GitHub Actions composite action v1.0
- [ ] GitLab CI template
- [ ] Jenkins shared library step
- [ ] Docker image (`ghcr.io/konjoai/squash:latest`)
- [ ] Helm chart for Kubernetes deployment

### Phase 3: Go-to-Market Readiness (by June 20)

- [ ] Domain acquired (getsquash.dev or squash.ai)
- [ ] Landing page live with EU AI Act countdown clock
- [ ] Pricing page · Documentation site
- [ ] Stripe integration (subscription management)
- [ ] Onboarding email sequence (5-email drip)
- [ ] Discord server launched
- [ ] Terms of Service + Privacy Policy (GDPR-compliant)
- [ ] DPA template for Enterprise

### Phase 4: Launch (by July 11)

- [ ] Public beta announcement (email list, LinkedIn, X/Twitter)
- [ ] Product Hunt launch
- [ ] HackerNews Show HN post
- [ ] Dev.to article: "How we automated EU AI Act compliance in a CI/CD pipeline"
- [ ] EU AI Act deadline countdown on website
- [ ] Case study from 1 design partner published

---

## Part V: The Website

### Domain
First choice: **squash.ai** | Fallback: **getsquash.dev** | Fallback: **squash.run**

### Hero Section

```
SQUASH

Automated EU AI Act Compliance
for ML Teams.

Squash generates your Annex IV documentation,
runs policy checks against 10+ frameworks, and
produces cryptographically signed audit records —
all inside your CI/CD pipeline.

[  Install CLI  ]    [  View Docs  ]    [  Book Demo  ]

⏰ EU AI Act high-risk enforcement: 96 days remaining
```

**The countdown clock is non-negotiable.** The deadline is real.

### Key Metrics Bar
```
4,200+ tests passing  |  10 policy frameworks  |  CycloneDX 1.7  |  SLSA Level 3
```

### The Problem (Pain → Cost)
```
Documentation preparation = 40% of total compliance cost
Manual Annex IV = 3–6 months engineering time
Missed deadline = up to €35M or 7% of global annual turnover

Your team didn't sign up to write compliance docs.
```

### How It Works (3 steps)
```
1. Install    pip install squash-ai
2. Attest     squash attest ./my-model --policy eu-ai-act
3. Ship       ✓ Annex IV generated · Policy: PASS · Signed
```

---

## Part VI: Go-to-Market Execution

### Customer Segments

**Priority 1 — ML/AI Platform Teams at EU-Adjacent Companies (Weeks 1–12)**
- Profile: 10–200 person engineering org deploying AI in HR, credit, medical devices
- Pain: "We have 96 days and no compliance process."
- Find them: LinkedIn ("Head of ML Platform"), MLOps Community Slack, EU AI Act LinkedIn groups

**Priority 2 — AI Consulting Firms (Weeks 4–16)**
- Profile: Boutique AI consultancies building models for BFSI, healthcare, HR tech
- Pain: Compliance docs are a deliverable they can't bill for
- Value: Squash converts 6 weeks → 10 minutes

**Priority 3 — Enterprise Security/Platform Teams (Weeks 8–24)**
- Profile: 500+ person companies, CISOs adding AI governance
- Value: Fills the gap Vanta/Drata leave for AI-specific requirements

### Email Sequences

**Welcome (Day 0):** "You're in. Here's how to run your first attestation."
**Day 3 (no run):** "Quick question about your EU AI Act timeline"
**Day 7 (run done):** "Your first attestation passed — what that means for compliance"
**Day 10:** "EU AI Act deadline: 86 days. What's your plan?"
**Day 14:** "The single most expensive compliance mistake ML teams make"

### Where to Advertise

**Free (do first):**
1. GitHub README optimization with demo GIF and badges
2. HackerNews Show HN — Tuesday morning 9am ET
3. Product Hunt — build following first, then launch day
4. Dev.to / Hashnode technical deep dives
5. LinkedIn organic — 3 posts/week
6. MLOps Community / HuggingFace Discord

**Paid (after MVP):**
1. LinkedIn Ads — target "Head of ML Platform" + financial/healthcare industries in EU
2. Dev newsletter sponsorships — TLDR AI ($500/issue), The Batch
3. Podcast appearances — Practical AI, TWIML AI

---

## Part VII: Sprint Roadmap

### Sprint 0 — Separation & Infrastructure (May 2–9) 🔄 IN PROGRESS

| Wave | Task | Status |
|------|------|--------|
| S0-1 | Create `konjoai/squash` repo, configure branch protection | ✅ |
| S0-2 | Extract squash modules + test files with git history | ✅ |
| S0-3 | Standalone `pyproject.toml`, uv.lock, CI pipeline | ✅ |
| S0-4 | Verify `pip install squash-ai` works from source | 🔄 |
| S0-5 | Update squish to import squash from PyPI | 🔄 |
| S0-6 | Verify squish CI still passes after extraction | 🔄 |
| S0-7 | `SQUASH_MASTER_PLAN.md` in new repo | ✅ |

**Exit criteria:** `pip install squash-ai && squash attest --help` works. All 80 squash test files pass.

---

### Sprint 1 — Annex IV Core (May 10–23, 2 weeks) ✅ COMPLETE

| Wave | Task | Days | Status |
|------|------|------|--------|
| W128 | TensorBoard event file parser | 2 | ✅ 48 tests |
| W129 | MLflow SDK integration (real, not mock) | 2 | ✅ 55 tests |
| W130 | W&B API integration | 1.5 | ✅ 54 tests |
| W131 | Dataset provenance tracker (HF Datasets) | 2 | ✅ 73 tests |
| W132 | Python AST code scanner | 1.5 | ✅ 107 tests |
| W133 | Annex IV document generator (12 sections, Markdown/HTML/JSON/PDF) | 3 | ✅ 83 tests |
| W134 | PDF export pipeline (weasyprint) | 1 | ✅ bundled in W133 |
| W135 | `squash annex-iv generate` CLI command | 1 | ✅ 68 tests |
| W136 | `squash annex-iv validate` CLI command | 1 | ✅ bundled in W135 |

**Exit criteria satisfied:** `squash annex-iv generate --root ./training-run` produces valid Annex IV documentation (MD/HTML/JSON/PDF). 479/479 Sprint S1 tests passing.

---

### Sprint 2 — Cloud API & Auth (May 24–June 6, 2 weeks) ✅ COMPLETE

| Wave | Task | Days | Status |
|------|------|------|--------|
| W137 | API key auth + bearer token middleware | 2 | ✅ 52 tests — `squash/auth.py`, KeyStore, POST/DELETE /keys |
| W138 | Rate limiting middleware (per-tier attestation counter) | 1.5 | ✅ 36 tests — `squash/rate_limiter.py`, per-key plan limits |
| W139 | Deploy to Fly.io (Dockerfile, fly.toml, GitHub Actions) | 2 | ✅ 22 tests — Dockerfile (multi-stage), fly.toml, deploy.yml |
| W140 | PostgreSQL cloud DB (Neon — replace SQLite in production) | 2 | ✅ 26 tests — `squash/postgres_db.py`, psycopg2, JSONB schema |
| W141 | Stripe integration (subscription plans, webhook handlers) | 2 | ✅ 38 tests — `squash/billing.py`, webhook + signature verification |
| W142 | Attestation counter + quota enforcement endpoints | 1 | ✅ 36 tests — `squash/quota.py`, /attest quota gate |
| W143 | `GET /account/status` + `GET /account/usage` | 0.5 | ✅ 26 tests — authenticated account endpoints |
| W144 | Health check + monitoring (Sentry, Better Uptime) | 1 | ✅ 27 tests — `squash/monitoring.py`, /health/ping, /health/detailed |

**Exit criteria satisfied:** 251/251 Sprint 2 tests. 730/730 S1+S2 total. Stripe webhook enforces plan. Quota blocks /attest at monthly limit.

---

### Sprint 3 — CI/CD & Integrations (June 7–20, 2 weeks) ✅ COMPLETE

| Wave | Task | Days |
|------|------|------|
| W145 | GitHub Actions composite action v1.0 | 2 | ✅ 35 tests — `action.yml` at repo root, composite action, 8 inputs, 4 outputs, upload-artifact step |
| W146 | GitHub Actions marketplace submission | 0.5 | ✅ 17 tests — branding (icon=shield, color=blue), all inputs/outputs documented, stable version refs enforced |
| W147 | GitLab CI template | 1 | ✅ 24 tests — `integrations/gitlab-ci/squash.gitlab-ci.yml`, 3 variants (base/soft/full) |
| W148 | Jenkins shared library step | 1 | ✅ 17 tests — `integrations/jenkins/vars/squashAttest.groovy`, Map params, withCredentials, readJSON, stash |
| W149 | Docker image (`ghcr.io/konjoai/squash:latest`) | 1 | ✅ 17 tests — `.github/workflows/publish-image.yml`, semver+SHA+latest tags, GITHUB_TOKEN auth |
| W150 | Helm chart for Kubernetes admission controller | 2 | ✅ 40 tests — `integrations/kubernetes-helm/`: Chart.yaml, values.yaml, Deployment, Service, ValidatingWebhookConfiguration, _helpers.tpl |
| W151 | Real MLflow SDK bridge | 1 | ✅ 16 tests — `MLflowSquash.attest_run()` fully wired: AttestPipeline.run → mlflow.log_artifacts → mlflow.set_tags with squash.* tags |
| W152 | Integration test suite — all CI/CD targets | 2 | ✅ 52 tests — cross-cutting integration: GitHub Actions, GitLab CI, Jenkins, GHCR, Helm, MLflow bridge, CLI sanity |

**Exit criteria satisfied:** 218/218 Sprint 3 tests. 948/948 S1+S2+S3 total. All CI/CD targets covered. Helm chart deployable. MLflow SDK fully wired.

---

### Sprint 4A — Critical Path to Launch (June 21–July 4, 2 weeks) ✅ ENGINEERED — Pending Deploy

**All code shipped 2026-04-28. Awaiting external actions (domain, PyPI publish, Fly.io deploy, Stripe account).**

| Wave | Task | Days | Status |
|------|------|------|--------|
| W153 | Domain + DNS + Fly.io production deploy | 1 | ✅ `fly.toml` + `Dockerfile` hardened · **ACTION: `fly deploy`** |
| W154 | PyPI publication (`pip install squash-ai` v1.0.0) | 0.5 | ✅ `pyproject.toml` v1.0.0, `publish.yml` ready · **ACTION: create GitHub Release** |
| W155 | Stripe checkout endpoint live | 1 | ✅ `POST /billing/checkout` implemented · **ACTION: set Stripe env vars in Fly.io** |
| W156 | Landing page live (Next.js + Tailwind, Vercel) | 4 | ✅ `website/` built · **ACTION: `vercel deploy`** |
| W157 | GitHub README overhaul | 1 | ✅ COMPLETE — tagline, demo, Sprint 4B features, Startup tier |
| W158 | HN post draft + Dev.to article draft | 1 | ✅ COMPLETE — `docs/launch/` |
| W159 | Design partner outreach | ongoing | ✅ Templates, pitch script, target list in `docs/launch/design-partner-outreach.md` |

**Pending human actions to reach full launch state:**
1. `fly deploy --config fly.toml` (requires `FLY_API_TOKEN`)
2. `fly secrets set SQUASH_STRIPE_SECRET_KEY=... SQUASH_STRIPE_PRICE_PRO=... SQUASH_STRIPE_PRICE_STARTUP=... SQUASH_STRIPE_PRICE_TEAM=...`
3. Create GitHub Release `v1.0.0` → triggers `publish.yml` → PyPI publish
4. `cd website && vercel deploy --prod` (requires Vercel account linked to `getsquash.dev`)
5. Set Vercel env vars: `NEXT_PUBLIC_API_URL=https://api.getsquash.dev`

**Exit criteria tracking:**
- `pip install squash-ai` from PyPI: ⏳ pending Release v1.0.0
- Fly.io production live: ⏳ pending `fly deploy`
- Stripe checkout live: ✅ code complete; ⏳ pending env var secrets
- Landing page: ✅ code complete; ⏳ pending `vercel deploy`
- Design partner: ⏳ pending outreach (templates ready)

---

### Sprint 4B — High-Leverage Engineering (June 21–July 11, parallel with 4A) ✅ COMPLETE

**Shipped 2026-04-28. Commit: cba4619. 311 new tests, 0 regressions.**
2299 Sprint 3+4B tests passing. 51 Python modules. 4 new modules shipped.

| Wave | Task | Days | Priority | Status |
|------|------|------|----------|--------|
| W160 | `squash demo` command — zero-friction first value | 1 | 🔥 Highest ROI | ✅ |
| W161 | Compliance badge SVG endpoint — shields.io compatible, viral | 0.5 | 🔥 Viral mechanism | ✅ |
| W162 | `squash init` — auto-detect ML framework, scaffold `.squash.yml`, dry-run | 2 | High | ✅ |
| W163 | Slack/Teams webhook notifications (`squash/notifications.py`) | 1 | High | ✅ |
| W164 | Prometheus metrics endpoint (`squash/metrics.py`, `/metrics` route) | 1 | High | ✅ |
| W165 | JIRA/Linear/GitHub Issues auto-ticketing (`squash/ticketing.py`) | 1.5 | Medium-High | ✅ |
| W166 | FastAPI/Django compliance middleware (`squash/middleware.py`) | 1.5 | Medium-High | ✅ |
| W167 | `squash watch` continuous drift detection mode | 1 | Medium | ✅ |
| W168 | Pre-commit hook installer (`squash install-hook`) | 0.5 | Medium | ✅ |
| W169 | Integration test suite for Sprint 4B | 1 | Required | ✅ merged into W160+W165+W166+W167 test files |

**Sprint 4B exit criteria: ALL MET**
- `squash demo` produces complete attestation in <10s ✅
- Badge SVG endpoint live at `/badge/{framework}/{status}` ✅
- `/metrics` emits Prometheus text format 0.0.4 with 7 labeled metrics ✅
- Slack/Teams/generic webhook fires on attestation events ✅
- JIRA/Linear/GitHub Issues ticketing dispatched on violations ✅
- FastAPI ASGI + Django WSGI middleware with `X-Squash-Compliant` header ✅
- `squash watch` polls model dir and re-attests on file change ✅
- `squash install-hook` installs executable git hook with backup safety ✅

---

### Sprint 5 — Market Expansion (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 5 high-value modules, 170+ new tests, 0 regressions.**

Value/effort matrix drove this sprint: highest-value features with existing module foundations were prioritized first.

| Wave | Task | Effort | Strategic Value | Status |
|------|------|--------|-----------------|--------|
| W170 | ISO 42001 Readiness Assessment (`squash iso42001`) | Low | Unlocks ISO certification market; consultants embed squash in every engagement | ✅ |
| W171 | Trust Package Exporter + Verifier (`squash trust-package` / `squash verify-trust-package`) | Medium | Eliminates 4-week vendor questionnaire process; premium feature; two-sided marketplace seed | ✅ |
| W172 | OWASP Agentic AI Top 10 Agent Audit (`squash agent-audit`) | Medium | First-mover in agentic compliance; 40% of apps will embed agents by 2026; maps to existing mcp.py | ✅ |
| W173 | Incident Response Package (`squash incident`) | Medium | Tool CISOs reach for in first hour after AI incident; EU AI Act Article 73 disclosure automation | ✅ |
| W174 | Board Report Generator (`squash board-report`) | Low | Eliminates 20-30 page manual quarterly report; direct enterprise buyer unlock | ✅ |

**Sprint 5 exit criteria: ALL MET**
- `squash iso42001 --model ./model` produces 38-control gap analysis with remediation roadmap ✅
- `squash trust-package --model ./model` produces signed, verifiable vendor attestation ZIP ✅
- `squash verify-trust-package ./vendor.zip` returns pass/fail in <10 seconds ✅
- `squash agent-audit --manifest agent.json` covers all 10 OWASP Agentic AI risks ✅
- `squash incident --model ./model --timestamp ISO8601` produces EU AI Act Article 73 compliant report ✅
- `squash board-report --quarter Q2-2026` generates executive-ready PDF with scorecard ✅

---

### Sprint 9 — Enterprise Pipeline Integration (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 4 new modules, 212 new tests, 0 regressions.**

| Wave | Module / Feature | What It Delivers | Status |
|------|-----------------|-----------------|--------|
| W188 | `squash/telemetry.py` | OpenTelemetry spans per attestation run — OTLP gRPC+HTTP, Datadog/Honeycomb/Jaeger; `squash telemetry status/test/configure` | ✅ |
| W189 | `squash/integrations/gitops.py` | ArgoCD/Flux admission webhook — K8s ValidatingWebhookConfiguration; blocks deployment without attestation or below min score; `squash gitops check/webhook-manifest/annotate` | ✅ |
| W190 | `squash/webhook_delivery.py` | Generic outbound webhook delivery — HMAC-SHA256 signed; 5 event types; SQLite persistence; `squash webhook add/list/test/remove` | ✅ |
| W191 | `squash/sbom_diff.py` | Attestation diff engine — score delta, component/policy/vulnerability drift; ANSI table/JSON/HTML output; `squash diff v1.json v2.json --fail-on-regression` | ✅ |

**Sprint 9 exit criteria: ALL MET**
- `squash telemetry status` shows OTel configuration; `squash telemetry test` emits test span ✅
- `squash gitops check --manifest deployment.yaml` passes/fails based on squash annotations ✅
- `squash gitops webhook-manifest --url https://...` outputs K8s ValidatingWebhookConfiguration YAML ✅
- `squash webhook add/list/test/remove` manage persistent outbound endpoints ✅
- `squash diff v1.json v2.json` outputs score delta, component/policy/vuln changes ✅
- `squash diff --fail-on-regression` exits non-zero on compliance regression ✅
- 3839/3839 tests passing · 0 regressions

---

### Sprint 10 — Model Card First-Class CLI (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 1 new module, 36 new tests, 0 regressions.**

**Goal:** Promote `squash model-card` from a basic dump-from-artifacts utility into a first-class, HuggingFace-publication-ready CLI surface that is pre-filled from the richest available sources (Annex IV documentation, bias audit, data-lineage certificate) and validates against the HF model card schema before push.

**Why now:** HuggingFace requires a model card at publication time. Annex IV technical documentation contains the strongest narrative content squash can produce — currently not threaded into the model card. Bias audit and data lineage are the two sections HF reviewers (and EU regulators) inspect first. A `--push-to-hub` flow turns squash into the last command a user runs before publishing a model.

| Wave | Module / Feature | What It Delivers | Status |
|------|-----------------|-----------------|--------|
| W192 | `squash/model_card.py` enhancement | Reads `annex_iv.json` (if present) and pre-fills HF card sections — Intended Use, Limitations, Evaluation, Risk; reads `bias_audit_report.json` to populate Bias / Fairness section; reads `data_lineage_certificate.json` to populate Training Data section. Adds extended HF sections: Training Data, Evaluation, Environmental Impact, Ethical Considerations. | ✅ |
| W193 | `squash/model_card_validator.py` (NEW) | HF model card schema validator — checks required YAML frontmatter fields (`license`, `language`, `tags`, `pipeline_tag`), section completeness, and produces a structured `ModelCardValidationReport` with severities (`error` / `warning` / `info`). | ✅ |
| W194 | CLI: `squash model-card --validate` / `--validate-only` / `--push-to-hub` | `--validate` generates then runs the validator, non-zero exit on errors. `--validate-only` skips generation. `--push-to-hub REPO_ID` uploads `squash-model-card-hf.md` to a HuggingFace repo as `README.md` via `huggingface_hub` (optional dep) — graceful no-op if not installed. `--json` for structured report. | ✅ |

**Sprint 10 exit criteria: ALL MET**
- `squash model-card ./model --format hf` pre-fills sections from `annex_iv.json` when present ✅
- `squash model-card ./model --validate-only --json` emits structured report; non-zero exit on errors ✅
- `squash model-card ./model --push-to-hub user/model` works with `huggingface_hub` installed; clean error (rc=2) when not ✅
- Bias & data-lineage sections render only when source artefacts exist (graceful degradation preserved) ✅
- 70 modules; module count gate updated ✅
- 3875/3875 tests passing · 0 regressions ✅

---

### Sprint 11 — Chain & Pipeline Attestation (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 1 new module, 49 new tests, 0 regressions.**

**Goal:** Attest entire RAG / agent / multi-model pipelines as a single composite unit. Today squash attests one model at a time — production AI systems are LangChain chains, LlamaIndex query engines, and multi-step agent workflows. Compliance must apply to the whole pipeline.

**Why now:** Gartner: 40% of GenAI apps ship as agent chains by end of 2026. EU AI Act treats the deployed system, not individual models, as the regulated unit. A composite attestation is the only honest answer.

| Wave | Module / Feature | What It Delivers | Status |
|------|-----------------|-----------------|--------|
| W195 | `squash/chain_attest.py` (NEW) | Composite chain attestation engine — `ChainAttestation` aggregates per-component attestations into a single HMAC-SHA256–signed record with composite score (worst-case roll-up: `min(component scores)`) and per-policy worst-case AND-roll-up. JSON + Markdown rendering; YAML/JSON spec loader; round-trip + tamper-detection via `verify_signature()`. | ✅ |
| W196 | `squash/integrations/langchain.py` extension | `attest_chain(chain, policies=...)` walks the LangChain `Runnable` graph duck-style (no SDK dep): RunnableSequence → SEQUENCE, RunnableParallel → ENSEMBLE, AgentExecutor.tools → AGENT. Auto-classifies LLM / retriever / embedding / tool roles; flags hosted-API LLMs (`ChatOpenAI`, `ChatAnthropic`, …) as `external` and excludes from score. | ✅ |
| W197 | CLI: `squash chain-attest` | Resolves spec from JSON / YAML file or `module.path:variable_name` Python import; produces `chain-attest.json` + `chain-attest.md`; `--verify` for HMAC tamper-check; `--fail-on-component-violation` for CI gating; `--chain-id`, `--sign-components`, `--json`, `--quiet`. | ✅ |

**Sprint 11 exit criteria: ALL MET**
- `attest_chain(chain, policies=[...])` returns `ChainAttestation` covering all chain components ✅
- `squash chain-attest ./chain.json` produces composite signed attestation ✅
- Composite score correctly rolls up worst-case across components (`min` of attestable, ignoring skipped) ✅
- Tests cover RAG (sequence: embedder → retriever → LLM), tool-using agent (LLM + tool-belt), and multi-LLM ensemble (parallel) ✅
- HMAC-SHA256 signing + `verify_signature()` tamper detection covered by 5 dedicated tests ✅
- 71 modules; module count gates updated; 3924/3924 tests passing · 0 regressions ✅

---

### Sprint 12 — Model Registry Auto-Attest Gates (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 0 new modules (extensions only), 28 new tests, 0 regressions.**

**Goal:** Make registration in MLflow / W&B / SageMaker Model Registry the enforcement gate for compliance. A model that fails attestation cannot be registered. Compliance is enforced at the moment of promotion to production, not discovered later.

**Why now:** Model registries are the production gate of every serious ML org. Squash already has framework-aware integrations — this sprint turns them from passive observers into hard gates.

| Wave | Module / Feature | What It Delivers | Status |
|------|-----------------|-----------------|--------|
| W198 | `squash/integrations/mlflow.py` extension | `MLflowSquash.register_attested(model_uri, name, model_path, policies, fail_on_violation=True)` — runs attest before `mlflow.register_model`; on policy fail raises `AttestationViolationError` and `register_model` is **never called**; tags new ModelVersion with `squash.attestation_id` + per-policy results. | ✅ |
| W199 | `squash/integrations/wandb.py` extension | `WandbSquash.log_artifact_attested(run, artifact_name, model_path, ...)` — builds fresh `wandb.Artifact` on policy pass with attestation files included; metadata block carries `squash.attestation_id` + per-policy passed/errors/warnings; on fail raises and `run.log_artifact` is never called. | ✅ |
| W200 | `squash/integrations/sagemaker.py` extension | `SageMakerSquash.register_model_package_attested(...)` — `create_model_package(...)` with `ModelApprovalStatus="Approved"` on pass; refuses creation on fail (or creates with `Rejected` / `PendingManualApproval` when `fail_on_violation=False`); `squash:gate_decision` tag captures intent. | ✅ |
| W201 | CLI: `squash registry-gate` (NEW) | Unified pre-registration gate: `squash registry-gate --backend {mlflow|wandb|sagemaker|local} --uri <URI> --model-path ./model --policy <P>`. Backend-specific URI validation (mlflow `models:/...` or `runs:/...`; wandb `wandb://`; sagemaker `arn:aws:sagemaker:`). Always emits structured `registry-gate.json` with `decision: allow|refuse|record-only`. `--allow-on-fail` for soft-gate mode. | ✅ |

**Sprint 12 exit criteria: ALL MET**
- All three registries gain `*_attested` helpers that fail loudly on policy violation ✅
- `squash registry-gate <backend>` validates URI per backend; exits 2 on misconfig ✅
- Each helper attaches `squash.attestation_id` + per-policy tags as registry-side metadata ✅
- Tests cover happy path AND refuse-to-register path for all three backends; SDK libs (mlflow / wandb / boto3) mocked at the `sys.modules` import boundary ✅
- 0 new modules (extensions only); 71 module count unchanged ✅
- 3952/3952 tests passing · 0 regressions ✅

---

### Sprint 13 — Startup Pricing Tier (April 30, 2026) ✅ COMPLETE

**All code shipped 2026-04-30. 0 new modules (extensions only), 35 new tests, 0 regressions. Tier 2 is now 100% complete.**

**Goal:** Open the seed/Series A revenue band with a $499/mo Startup tier — too big for free, can't justify $899 Team. 500 attestations/mo, 3 users, VEX read + GitHub Issues + Slack delivery entitlements.

**Why now:** Free → $299 → $899 leaves a wide gap that is exactly where the highest-velocity buyers sit. A $499 tier captures them at the moment they first need an attestation feed, before they need SAML SSO.

| Wave | Module / Feature | What It Delivers | Status |
|------|-----------------|-----------------|--------|
| W202 | `squash/auth.py` plan expansion | `PLAN_LIMITS` gains `startup` (500/mo, 3 seats, 1200 req/min) and `team` (1000/mo, 10 seats, 3000 req/min); every plan now carries consistent `max_seats` + `entitlements`. 13 named entitlement constants exported. `KeyRecord.has_entitlement(name)` + `.max_seats` + `.entitlements` properties; `to_dict()` exposes both. | ✅ |
| W203 | Entitlement gating | `auth.has_entitlement(plan, name)` central helper. `NotificationDispatcher.notify(..., plan="")` and `TicketDispatcher.create_ticket(..., plan="")` accept optional plan; on entitlement miss the channel is silently skipped (notifications) or returns structured `TicketResult(success=False)` (ticketing). `plan=""` (default) preserves un-gated behaviour. | ✅ |
| W204 | Stripe Startup checkout | `create_checkout_session(plan="startup", ...)` wired through `SQUASH_STRIPE_PRICE_STARTUP`; tests cover the happy path and the "price ID missing" error path. Webhook `_price_to_plan()` round-trips Startup price IDs. `POST /billing/checkout` accepts `startup` (was wired in W155, now test-locked). | ✅ |

**Sprint 13 exit criteria: ALL MET**
- `Plan.STARTUP` and `Plan.TEAM` registered with correct quota, rate, seats, entitlements ✅
- `has_entitlement(plan, name)` returns False for free/pro on `vex_read` / `github_issues`; True on startup+ ✅
- Slack delivery skipped silently when caller passes `plan` without `slack_delivery` entitlement ✅
- GitHub-issue ticketing returns structured failure when caller passes a plan without `github_issues` ✅
- `create_checkout_session(plan="startup")` returns valid Stripe URL with correct `metadata.squash_plan` ✅
- 0 new modules; 71 module count unchanged ✅
- 3987/3987 tests passing · 0 regressions ✅

---

## Tier 3 Sprint Breakdown — 12-Month Enterprise Moat (Sprints 14–18)

The eight Tier 3 features (#23–#30) are batched into five sprints by proximity of work and shared dependencies. Sprints execute roughly once per month; the entire Tier 3 plan runs Sept 2026 → Apr 2027 and turns squash from product into infrastructure. Wave numbering continues unbroken: W205 → W220.

---

### Sprint 14 — Public Security Scanner & HF Spaces (Tier 3 #23 + #27) · **Track B / B1**

**Goal:** Top-of-funnel growth through a free, public-facing security tool. `squash scan hf://meta-llama/Llama-3.1-8B-Instruct` becomes the share-link asset for HuggingFace community + a HF Space that anyone can use without `pip install`. Brand build, organic acquisition, design-partner discovery.

**Why now:** Tier 1 + Tier 2 made squash a paid product. Tier 3 needs a free top-of-funnel that scales without sales. HF has 1M+ public models — every one is a potential security demo.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W205 | `squash/cli.py` — `squash scan hf://` | Resolves `hf://owner/model` to a temp download via `huggingface_hub.snapshot_download`; runs ModelScanner; emits `squash-hf-scan.json` + Markdown summary. |
| W206 | `squash-hf-space/` directory (NEW) | Gradio app that wraps `squash scan hf://` for browser users; HF Spaces deployment manifest (`README.md` with HF YAML frontmatter, `app.py`, `requirements.txt`). |
| W207 | `docs/hf-space.md` + deploy script | HF Spaces deploy script (`scripts/deploy_hf_space.py`); social-share asset (`docs/og-image-scan.png` placeholder); landing copy. |

**Sprint 14 exit criteria:**
- `squash scan hf://meta-llama/Llama-3.1-8B-Instruct` succeeds for ≥3 well-known HF models without auth
- `squash-hf-space/app.py` boots locally with `gradio` installed and produces structurally identical scan output
- HF Spaces YAML frontmatter passes HF Spaces schema; deploy script is dry-runnable in CI
- 0 new top-level squash modules (CLI subcommand only); module count stays at 71

---

### Sprint 15 — Branded PDF Reports & Compliance Email Digest (Tier 3 #24 + #25) · **Track B / B2 + B3**

**Goal:** Two passive-retention assets that land in the CISO's inbox without engineering effort. Branded PDF Annex IV report (cover page + exec summary + company logo hooks) is the deliverable that closes enterprise deals. Weekly/monthly portfolio digest email keeps squash present at the executive layer between attestation runs.

**Why now:** Sprint 5 shipped Annex IV + Trust Package. Both produce Markdown by default. Branded PDF + email is the layer between "engineering can attest" and "executives notice we attest."

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W208 | `squash/annex_iv_generator.py` extension | Branded PDF: cover page (org logo, system name, score, generated date, attestation-ID QR code), 1-page exec summary, full Annex IV body, signature block. WeasyPrint-based; CSS template under `squash/templates/annex_iv_branded.css`. |
| W209 | `squash/notifications.py` extension — `ComplianceDigestBuilder` | Builds weekly/monthly portfolio digest from attestation history (`Squash dashboard.build()` data): 5-metric panel, top-5 risk movers, regulatory deadline countdown, links back to the Squash app. HTML + plain-text email bodies. |
| W210 | `squash/cli.py` — `squash digest send` | Renders + emails the digest via SMTP (or any configured `notifications.py` channel). Cron-friendly: `squash digest send --period weekly --recipients ciso@acme.com`; supports `--dry-run` with stdout output. |

**Sprint 15 exit criteria:**
- `squash annex-iv generate ... --format pdf --branded` produces a PDF with cover, exec summary, body
- `ComplianceDigestBuilder.build(period="weekly")` returns rendered HTML + plain text
- `squash digest send --period weekly --dry-run` prints both bodies to stdout; non-dry-run hits SMTP
- 0 new modules (extensions only); 0 regressions

---

### Sprint 16 — Terraform + Pulumi Provider (Tier 3 #26) · **Track B / B4**

**Goal:** Move squash from "tool the engineer runs" to "infrastructure the org provisions." Terraform and Pulumi resources let platform / DevOps teams embed squash attestation in IaC pipelines — `terraform apply` fails when the model's attestation is missing, expired, or below score threshold. Two providers cover ~95% of the IaC market: HashiCorp's Terraform and Pulumi.

**Why now:** Tier 2 made the build-time gate. Sprint 16 makes IaC the build-time gate's home. Once squash lives in `main.tf`, removing it requires a PR — that is the friction that converts adoption into stickiness.

**Why no runtime gates here:** Kong / AWS API Gateway runtime plugins were considered and explicitly de-scoped. The compliance-conscious deployers are already gated at registry promotion time (Sprint 12) and at GitOps time (Sprint 9 `gitops.py`). A third runtime point of enforcement is duplication for marginal lift.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W211 | `terraform-provider-squash/` (NEW, Go) | Provider scaffold with `squash_attestation` data source (read attestation by ID or URI) + `squash_policy_gate` resource (block `terraform apply` on policy violation). Build instructions + `examples/` directory with minimal HCL. |
| W212 | `terraform-provider-squash/` — model gate resource | `squash_model_gate` resource that wraps a model artefact reference (S3 URI / MLflow URI / HF repo); on `terraform plan` calls squash REST API and surfaces violations as Terraform diagnostics. |
| W213 | `pulumi-squash/` (NEW, Python) | Pulumi provider as a Python package wrapping the squash REST API; exposes `Attestation`, `PolicyGate`, `ModelGate` resources matching the Terraform shapes 1:1 so users can switch IaC tools without re-learning the model. |
| W214 | `squash/cli.py` — `squash iac-config` + integration tests | CLI generator: `squash iac-config terraform > main.tf` emits HCL skeleton; `squash iac-config pulumi > __main__.py` emits Pulumi skeleton. End-to-end tests verify both providers against an in-memory squash API. |

**Sprint 16 exit criteria:**
- `terraform-provider-squash` builds with `go build`; `terraform plan` works against a stubbed squash API
- `pulumi-squash` installs from a wheel; `pulumi up` succeeds with example program against the same stubbed API
- `squash iac-config terraform | pulumi` emits ready-to-paste skeletons
- Both providers fail `apply` / `up` cleanly on policy violation with structured diagnostics
- 0 new Python modules under `squash/` (provider code lives outside the Python package); module count stays at 71; 0 regressions

---

### Sprint 17 — Cryptographic Provenance: Blockchain Anchoring (Tier 3 #29) · **Track B / B6**

**Goal:** Immutable on-chain proof of attestation existence at a moment in time. Required for high-assurance verticals (BFSI, healthcare, defense) where regulators demand tamper-evident audit trails. Sigstore's transparency log is good but private-CA; a public chain (Ethereum mainnet via OP_RETURN-style data, or Bitcoin OP_RETURN) is the strongest available proof.

**Why now:** Squash already produces signed CycloneDX BOMs. Anchoring is the last link. BFSI design partners are blocked on this — the regulator wants proof that cannot be forged by the vendor.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W215 | `squash/provenance.py` extension — `BlockchainAnchor` | `BlockchainAnchor.anchor(attestation_id)` writes the SHA-256 of the attestation JSON to Ethereum (transactions to a known squash registry contract) or Bitcoin OP_RETURN. Wallet provider abstraction supports `infura://`, `alchemy://`, and self-hosted RPC URLs. |
| W216 | `squash/provenance.py` extension — `BlockchainAnchor.verify` | Given a tx hash + attestation file, retrieves the on-chain payload, recomputes the SHA-256, returns PASS/FAIL. Supports both block explorers (etherscan / blockchain.info) and direct RPC. |
| W217 | `squash/cli.py` — `squash anchor` / `squash verify-anchor` | Two new CLI commands: `squash anchor ./squash-attest.json --chain ethereum` (returns tx hash); `squash verify-anchor --tx 0xabc --attestation ./squash-attest.json` (PASS/FAIL). Optional `--ens-name acme-prod` records a human-readable label. |

**Sprint 17 exit criteria:**
- `BlockchainAnchor.anchor()` produces a signed Ethereum transaction payload (mocked RPC in tests)
- `BlockchainAnchor.verify()` round-trips a known anchored attestation back to PASS
- `squash anchor` and `squash verify-anchor` CLI exit codes match (0 on PASS, 1 on FAIL, 2 on misconfig)
- Test coverage uses mocked Web3.py / requests at the import boundary — no real chain calls in CI
- 0 new modules (extension to `provenance.py`); module count unchanged at 73

---

### Sprint 18 — SOC 2 Type II Readiness (Tier 3 #30) · **Track D / D6**

**Goal:** Close the enterprise procurement loop. SOC 2 Type II is the single most-requested item in MEDDPICC — without it most $50K+ ACVs can't even start. Squash already has the building blocks (audit trail, signed attestations, policy engine, evidence packages); Sprint 18 wraps them in the SOC 2 control catalogue and produces an auditor-ready evidence bundle.

**Why now:** Tier 2 + Tier 1 + Sprints 14–17 give us the technical surface. Sprint 18 turns that surface into SOC 2 evidence on demand.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W218 | `squash/soc2.py` (NEW) | SOC 2 Type II control catalogue (Trust Services Criteria — Security, Availability, Processing Integrity, Confidentiality, Privacy). 65 control objectives with squash-component mapping (e.g. CC6.1 → squash signing, CC7.2 → squash audit log). |
| W219 | `squash/soc2.py` — `EvidenceCollector` | Pulls from `squash/governor.py` audit log + attestation history + policy results + RBAC config; produces per-control evidence dossiers (JSON + Markdown). Handles 1-year evidence collection windows for Type II vs. point-in-time for Type I. |
| W220 | `squash/cli.py` — `squash soc2 readiness` / `squash soc2 evidence` | `squash soc2 readiness` produces a coverage report (% of controls with evidence, gaps, remediation steps); `squash soc2 evidence --output bundle.zip` builds an auditor-ready ZIP (controls index, dossiers, signed attestations, integrity manifest). |

**Sprint 18 exit criteria:**
- `squash soc2 readiness` produces a coverage report covering all 65 TSC controls; squash-mapped controls show evidence
- `squash soc2 evidence --output ./bundle.zip` produces a valid ZIP with controls index, evidence dossiers, and a SHA-256 manifest
- Evidence collection works against a 12-month attestation history fixture
- 1 new module (`soc2.py`); module count → 74; gates updated
- 0 regressions

---

## Tier 4 — Market-Opportunity Sprints (Sprints 19–29) · _continues into Tier 5 (Sprints 30–39)_

Tier 1+2 made squash a paid product; Tier 3 made it long-tail
infrastructure. Tier 4 is what wins the next 18 months: each sprint
operationalises exactly one statistic from the Market Intelligence
section above, capturing a buyer motion that does not yet have a
canonical product. Eleven sprints, 30 waves, W221 → W250.

The unifying thesis: **regulators no longer want policy statements,
they want proof.** Tier 4 produces proof for every audience —
executives, CISOs, auditors, insurance underwriters, procurement.
No competitor has all of these. Most have none.

**Tier 4 sprint sequencing rules:**
1. Hard regulatory deadlines first (SEC AI-washing, EU Article 73 incidents)
2. Buyer-pre-sold motions next (CISO 73% want-to-buy)
3. Network-effect plays last (procurement scoring API, industry benchmarks)

---

### Sprint 19 — `squash freeze` Emergency Response Command · **Track C / C1 ★ HEADLINE WIN**

> ★ **Highest drama-per-hour ratio in the entire roadmap.** 2-day build, zero new modules, orchestrates five existing subsystems. **CISOs will demo this command to their boards. It is the headline asset of L2 (Show HN, Jul 14).** Press release lead. Sales-deck demo. Lock the post-body GIF for `docs/launch/hn-post.md` to be the `squash freeze` red-button command running.

**Goal:** The "red button." A single CLI command that revokes a model's attestation, pushes a signed revocation to the public registry, triggers the GitOps webhook to block all new deployments, posts Slack/webhook alerts, and generates an EU AI Act Article 73 incident-disclosure draft. **All five subsystems already exist** — Sprint 19 is integration work, not new modules.

**The stat:** Only 20% of organizations have a tested AI incident response plan. Squash makes the response a *command*, not a runbook.

**Why now:** EU AI Act Article 73 requires incident notification within 15 days. Today the org's first ten hours after a discovered violation are panic phone calls. Sprint 19 turns those ten hours into ten seconds.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W221 | `squash/cli.py` — `squash freeze` command | Single-shot orchestrator: takes `--attestation-id` (or `--model-path`), runs `attestation_registry.revoke()`, fires `webhook_delivery.notify()` event `attestation.frozen`, calls `gitops.webhook_block()` to inject a denylist annotation, dispatches `notifications.notify(event="attestation.frozen", plan=...)`, builds an `incident.IncidentPackage`. Atomic — any sub-step failure rolls back upstream side-effects. |
| W222 | `squash freeze` — Article 73 disclosure template | Auto-generates an Article 73 incident-disclosure draft (PDF + Markdown) from the IncidentPackage; pre-fills serious-incident classification, affected systems, deployer impact, mitigation steps. Includes fields for the human approver to sign before the 15-day clock. |

**Sprint 19 exit criteria:**
- `squash freeze --attestation-id att://...` revokes, alerts, blocks GitOps, drafts disclosure in <10 s
- Atomic rollback verified by injected failure tests at every sub-step
- 0 new modules; 0 regressions

---

### Sprint 20 — AI Washing Detection (`squash detect-washing`) · **Track C / C2**

**Goal:** Scan marketing collateral, investor decks, model cards, and product landing pages for AI capability claims; cross-reference against actually attested model capabilities; flag every divergence. SEC's top examination priority for 2026. No competitor has this product.

**The stat:** SEC's 2026 examination priorities elevated AI / cyber to the top tier; "Operation AI Comply" already produced enforcement actions. Disclosure that overstates capability is now a fraud risk, not a marketing risk.

**Why now:** The deadline is *now* — first wave of SEC AI-claim enforcement is already in court. Squash is the only tool that can compare prose claims against signed attestation evidence at scale.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W223 | `squash/washing_detector.py` (NEW) | Capability-claim extractor: parses Markdown / HTML / PDF / DOCX inputs (reusing `code_scanner_ast.py` parsing infrastructure where possible) and returns a normalised list of factual claims (e.g. "fine-tuned on 10M prompts", "passes BIG-bench at 87%", "GDPR-compliant"). |
| W224 | `washing_detector.py` — divergence engine | Cross-references extracted claims against the attestation registry's per-model capability metadata + bias audit + Annex IV evaluation section. Each divergence ranked by severity (factual mismatch / undocumented superlative / unsupported claim). |
| W225 | CLI: `squash detect-washing` + report builder | `squash detect-washing --docs ./investor-deck.pdf --models acme/* --severity high`. Produces a divergence report (JSON + Markdown) suitable for legal review. Fail-on-high-severity flag for CI on marketing-copy repos. |

**Sprint 20 exit criteria:**
- 1 new module (`washing_detector.py`); module count → 72 + Sprint 18 → 73; gates updated
- Divergence engine produces deterministic output across input formats
- 90%+ recall on a benchmark set of 50 hand-labelled marketing claims
- Tests use sample fixtures only (no live SEC filings)

---

### Sprint 21 — AI Identity Governance (`squash attest-identity`) · **Track D / D2**

**Goal:** Verify OAuth scopes, validate least-privilege, check token rotation policy, attest identity configuration of an AI agent or service account. Integrates with Okta, Azure AD, AWS IAM. **Zero competitors.** Extends existing `agent_audit.py` + `governor.py` audit log.

**The stat:** 73% of CISOs would invest immediately if budget allowed; 92% of orgs lack full visibility into AI identities; 16% effectively govern AI agent access. The buyer is pre-sold; the product just has to exist.

**Why now:** AI agents are proliferating faster than identity tooling. Most orgs are giving agents long-lived service-account credentials with no rotation. Squash is the only tool that can *attest* an identity configuration matches policy at any given timestamp.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W226 | `squash/identity_governor.py` (NEW) | Identity-attestation engine: ingests Okta / Azure AD / AWS IAM principals via their respective SDKs (mocked at boundary), produces an `IdentityAttestation` per agent — scopes, last rotation, MFA status, token-type, least-privilege score. Sigstore-signed. |
| W227 | `identity_governor.py` — least-privilege analyzer | Compares each principal's actual permissions to a declared least-privilege policy file (`identity-policy.yml`); flags every excess permission with severity + remediation. Supports IAM JSON, Azure AD role definitions, Okta groups. |
| W228 | CLI: `squash attest-identity` + integrations | `squash attest-identity okta://acme.okta.com --principals "ai-agent-*"`; `squash attest-identity aws-iam --role-arn arn:aws:iam:...`. Adds Okta / Azure AD / AWS IAM clients under `squash/integrations/` (lazy-imported, optional deps). |

**Sprint 21 exit criteria:**
- 1 new module (`identity_governor.py`); 3 new integration adapters; module count tracked accordingly
- Least-privilege analyser produces deterministic violation list across all three providers
- All SDK calls mocked at the import boundary in tests; 0 live identity-provider calls in CI

---

### Sprint 22 — Regulatory Examination Simulation (`squash simulate-audit`) · **Track C / C5**

**Goal:** Run a mock regulatory examination against the attested model portfolio. Pulls answers from existing attestation data (Annex IV, ISO 42001, NIST RMF, SEC, FDA), flags gaps, produces a readiness score + prioritized remediation plan. Frames itself as a $5K–$15K professional-service deliverable wrapped in a 60-second CLI.

**The stat:** Only 22% confident they could pass an AI governance audit in 90 days. Squash compresses the readiness cycle from 6 weeks to 15 minutes.

**Why now:** This is the highest-leverage CFO / Audit-Committee narrative. The product writes itself once you assemble the existing attestation primitives.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W229 | `squash/audit_simulator.py` (NEW) | Examination orchestrator: takes a regulator profile (`eu-ai-act` / `nist-rmf` / `sec-ai-disclosure` / `fda-ml-samd`), pulls per-control evidence from `attestation_registry`, `iso42001`, `regulatory_feed`, `data_lineage`, `bias_audit`. Returns a `ReadinessReport` with per-control PASS/PARTIAL/FAIL + prioritised gaps. |
| W230 | `audit_simulator.py` — examination Q&A library | Each regulator profile carries 30–80 examiner questions with the squash-side answer source. Built from real examination transcripts where public; synthesised from regulatory guidance where not. |
| W231 | CLI: `squash simulate-audit` + Markdown output | `squash simulate-audit --regulator eu-ai-act --models ./models --output ./readiness/`. Produces JSON + Markdown + executive summary; opinionated 90-day remediation roadmap with each gap mapped to the squash command that would close it. |

**Sprint 22 exit criteria:**
- 1 new module (`audit_simulator.py`); module count tracked
- Readiness report covers ≥4 regulator profiles, each with ≥30 questions
- Remediation roadmap is actionable (each gap → concrete squash command)

---

### Sprint 23 — Model Deployment Approval Workflow (`squash approve`) · **Track C / C3**

**Goal:** Generate cryptographically signed approval records — reviewer identity, attestation state at moment of review, timestamp, explicit approval/rejection rationale. Sigstore handles the crypto; squash provides the workflow shell. Required by EU AI Act Article 9 and NIST AI RMF "GOVERN" pillar.

**The stat:** Both EU AI Act Article 9 and NIST AI RMF require *documented* human oversight. Most orgs have it as Confluence pages. Squash makes it cryptographic.

**Why now:** The approval moment is where the Article 9 risk-management responsibility crystallises. A signed approval record is the single piece of evidence a regulator wants on day one of an examination.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W232 | `squash/approval_workflow.py` (NEW) | `ApprovalRecord` dataclass: reviewer identity (Sigstore identity / GitHub OAuth / email-OIDC), attestation snapshot (full content-hash), decision (`APPROVED` / `REJECTED` / `APPROVED_WITH_CONDITIONS`), rationale, timestamp, conditions. Sigstore-signed. |
| W233 | `approval_workflow.py` — multi-reviewer orchestration | Threshold approvals (`require ≥2 of 3 reviewers`), role-gated (`require Compliance + Engineering`), with deterministic ordering and pending-state persistence in `~/.squash/approvals.db`. |
| W234 | CLI: `squash approve` / `squash request-approval` | `squash request-approval --attestation att://... --reviewers ciso@acme,vp-eng@acme`; `squash approve <approval-id> --decision APPROVED --rationale "Bias audit clean, drift baseline acceptable"`. Email / Slack notifications on approval-state changes (gated by `slack_delivery` entitlement). |

**Sprint 23 exit criteria:**
- 1 new module (`approval_workflow.py`); module count tracked
- Sigstore signature verifies on approval records
- Multi-reviewer threshold logic covered for 1-of-1, 2-of-3, role-gated cases

---

### Sprint 24 — AI Insurance Package (`squash insurance-package`) · **Track C / C6**

**Goal:** Generate standardised risk-quantification packages for AI cyber-insurance underwriting. Maps to Munich Re / Coalition / AIG frameworks. Output is a single signed ZIP: model inventory + risk tier, compliance score by framework, historical incident log, drift events, CVE exposure, bias results, response plan. **Opens a new buyer motion: Chief Risk Officer + insurance procurement.**

**The stat:** AI cyber-insurance market crystallising in late 2026. Underwriters are publicly demanding standardised risk packages. Squash is positioned to be the de facto package format.

**Why now:** First-mover advantage on the underwriting standard is enormous. Whoever's package format underwriters accept first becomes the default for everyone else.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W235 | `squash/insurance.py` (NEW) | `InsurancePackage` builder: aggregates `attestation_registry`, `incident`, `vex`, `bias_audit`, `drift` data into a single normalised risk record per model. Risk tiers map to Munich Re / Coalition published categories. |
| W236 | `insurance.py` — underwriter-format adapters | Two output adapters: `MunichReAdapter` (their published JSON schema) and `CoalitionAdapter` (theirs). Generic JSON adapter for any underwriter that hasn't published a schema. Each adapter is round-trippable. |
| W237 | CLI: `squash insurance-package` + signed ZIP | `squash insurance-package --underwriter munich-re --org acme --output ./insurance.zip`. ZIP contains JSON, signed attestation chain, exec summary PDF, integrity manifest. Optional Sigstore signature over the whole bundle. |

**Sprint 24 exit criteria:**
- 1 new module (`insurance.py`); module count tracked
- Munich Re + Coalition adapter shapes match published schemas (with tests against sample-fixtures)
- Generic adapter is documented as the fallback for non-standard underwriters

---

### Sprint 25 — Compliance SLA Dashboard (Tier 4 — enterprise procurement) · **Off-track research bonus**

> Not in the parallel-track grid (no track ID). Held as a pure-extension item that can be picked up opportunistically whenever a Track B / Track D slot is free. Reclassify if a procurement design partner asks for it.



**Goal:** Per-model SLA tracking — revalidation frequency, attestation expiry, remediation SLA, breach status. Extends the existing `dashboard.py` + `attestation_registry.py` with configurable breach alerts. Turns squash from a point-in-time tool into an SLA-managed service. Required by enterprise procurement contracts.

**The stat:** Enterprise procurement increasingly demands SLA documentation for any AI tool in the supply chain. Today most ML teams document SLAs in spreadsheets. Squash makes them queryable.

**Why now:** Required for any 6-figure deal. Procurement won't sign without SLA terms; squash should generate them, not require the customer to write them.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W238 | `squash/dashboard.py` extension — SLA tracker | New `SLAPolicy` dataclass per model: revalidation_days, max_attestation_age, max_remediation_days, escalation_recipients. Loaded from `~/.squash/sla.yml` or per-model `.squash-sla.yml`. Status computed against `attestation_registry` history. |
| W239 | `dashboard.py` — breach alerts + CLI surface | Cron-friendly `squash dashboard --check-sla` exits non-zero on any breach; emits structured event `sla.breach` to webhook delivery. Dashboard view adds `SLA` column with traffic-light status + days-to-breach. |

**Sprint 25 exit criteria:**
- 0 new modules (extensions only); 0 regressions
- `squash dashboard --check-sla` exits 1 on breach, 0 on green
- SLA policy file format documented

---

### Sprint 26 — Multi-Jurisdiction Compliance Matrix (`squash compliance-matrix`) · **Track D / D4**

**Goal:** `squash compliance-matrix --regions eu,us,uk,sg,ca` runs every applicable policy check simultaneously, generates a cross-referenced matrix showing which attestation fields satisfy which requirements in which jurisdictions, identifies gaps. Eliminates months of manual legal-mapping work per model deployment for multinationals.

**The stat:** A multinational LLM deployment touches 6+ jurisdictions on average. Today the legal compliance mapping is a one-week consulting engagement per deployment.

**Why now:** Multi-jurisdiction is the buying pain for the highest-ACV segment. Squash already has 9 frameworks in `regulatory_feed.py` — just needs the cross-reference layer.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W240 | `squash/compliance_matrix.py` (NEW) | `ComplianceMatrix.build()`: takes a list of regions (`eu`, `us`, `uk`, `sg`, `ca`, `au`, …) and an attestation, returns a 2D matrix `requirement × jurisdiction → status`. Reuses policy.py rules + regulatory_feed regulations. |
| W241 | `compliance_matrix.py` — gap analyser + remediation | For each `(requirement, jurisdiction) = FAIL` cell, identifies the closest-matching squash control + remediation step. Outputs a sequenced remediation plan that maximises coverage per fix. |
| W242 | CLI: `squash compliance-matrix` + HTML report | `squash compliance-matrix --regions eu,us,uk --models ./models --output ./matrix.html`. HTML output is colour-coded, sortable by jurisdiction or by requirement, exportable as legal-review PDF. |

**Sprint 26 exit criteria:**
- 1 new module (`compliance_matrix.py`); module count tracked
- Matrix correctly cross-references at least 5 jurisdictions × 9 frameworks
- HTML output renders without JavaScript dependencies

---

### Sprint 27 — Continuous Regulatory Watch Daemon · **Track C / C4**

**Goal:** Real-time monitoring of primary regulatory sources — SEC.gov, NIST.gov, EUR-Lex, state-legislature feeds. Parses new guidance, maps to squash policy framework, sends structured alerts with gap analysis against attested models. **Turns squash from a quarterly tool into a daily intelligence service.**

**The stat:** Regulatory cadence is accelerating: EU AI Act delegated acts, SEC guidance, state-level AI bills, FDA SaMD updates. The org that learns about a new requirement on Day 1 instead of Day 90 has a 90-day moat.

**Why now:** Daily-touch products win retention. A weekly-touch product loses to whichever competitor adds daily.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W243 | `squash/regulatory_watch.py` (NEW) | Polling daemon: subscribes to SEC EDGAR, NIST publication feed, EUR-Lex AI Act register, state-legislature RSS. Each source parsed by a small adapter; new entries normalised into `RegulatoryEvent` records persisted in `~/.squash/regulatory.db`. |
| W244 | `regulatory_watch.py` — gap analysis on new events | When a new event lands, runs a diff against `regulatory_feed.py`'s current control mapping and the user's attested models; surfaces "this new event would cause models X,Y to need re-attestation" with severity + days-to-act. |
| W245 | CLI: `squash watch-regulatory` daemon + alert delivery | `squash watch-regulatory --interval 6h --alert-channel slack`. Runs as a background daemon (or one-shot for cron). Alerts route through `notifications.py` (subject to `slack_delivery` / `teams_delivery` entitlements). |

**Sprint 27 exit criteria:**
- 1 new module (`regulatory_watch.py`); module count tracked
- 4 source adapters covered: SEC, NIST, EUR-Lex, generic state-RSS
- Gap analyser produces deterministic alert text given known fixture events

---

### Sprint 28 — AI Procurement Scoring API · **Track D / D3**

**Goal:** Public REST endpoint `GET api.getsquash.dev/v1/score/{vendor_name}` returning a compliance score for any vendor with published trust packages. **The credit-score API for AI compliance.** Freemium: basic score free, breakdown requires Pro, real-time monitoring is Enterprise. Network effect: more vendors → more buyers → more vendors. **The SSL-CA-of-AI play.**

**The stat:** Every Fortune 500 procurement team is now writing AI vendor questionnaires. They take 4 weeks each. Squash already has Trust Packages (W171). Sprint 28 turns the trust package into a queryable API.

**Why now:** Whoever's score the buyer asks for becomes the de facto standard. Aggressive timing wins this category.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W246 | `squash/api.py` extension — `GET /v1/score/{vendor}` | Public unauthenticated endpoint returning `{score, last_attested, frameworks, breakdown_url}`. Free-tier rate-limited; Pro tier unlocks `breakdown` field with per-framework scores. Backed by `attestation_registry` + `vendor_registry`. |
| W247 | `squash/api.py` extension — `GET /v1/score/{vendor}/history` | Time-series of vendor scores over the past 12 months. Enterprise-tier real-time webhook (`squash webhook` register the vendor; on every new attestation by that vendor, fire `vendor.score_changed`). |
| W248 | CLI: `squash score <vendor>` + landing-page integration | `squash score acme-corp` returns the same data as the API. Public-website widget snippet that any vendor can embed: live `getsquash.dev/badge/vendor/acme-corp` SVG. Documentation for procurement teams. |

**Sprint 28 exit criteria:**
- 0 new modules (api.py extensions only)
- Public endpoint stable under 100 RPS load test
- Free / Pro / Enterprise tier gating verified by entitlement tests
- Embeddable badge SVG mirrors shields.io semantics

---

### Sprint 29 — Compliance Drift Rate Benchmarking (`squash industry-benchmark`) · **Track D / D5**

**Goal:** Anonymized aggregate analytics across all squash users — drift rate by model family, most common violations by framework, average time-to-first-drift, score distribution by industry sector. `squash industry-benchmark --sector financial-services` shows how a company compares to sector peers. **Built specifically to be the conversation starter in enterprise QBRs.**

**The stat:** Every enterprise customer wants to know "how do I compare?" Squash is uniquely positioned: only product with a cross-customer dataset of compliance attestations.

**Why now:** Aggregate-data products require N customers before they can launch — by Sprint 29 squash should have enough volume to publish meaningful percentiles.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W249 | `squash/benchmark.py` (NEW) | Aggregate analytics builder: anonymises per-tenant attestation streams (DP-style noise on small buckets, k-anonymity ≥10), computes industry-sector aggregates (drift-rate p50/p90, top-N violation classes, score-distribution histogram). Privacy review checklist included. |
| W250 | CLI: `squash industry-benchmark` + report builder | `squash industry-benchmark --sector financial-services --period 6mo --output ./qbr.pdf`. Output is QBR-ready: cover page, exec summary ("you are at p72 in your sector"), per-metric comparison tables, opportunities-for-improvement section. |

**Sprint 29 exit criteria:**
- 1 new module (`benchmark.py`); module count tracked
- Anonymisation passes a documented privacy-review checklist (k-anonymity, no per-tenant identifiability)
- QBR report builds without proprietary fonts (stdlib + WeasyPrint only)

---

## Tier 5 — Research-Anchored Sprints (Sprints 30–39)

Ten new sprints derived from documented operational pain — every one
grounded in a quantified statistic (see Market Intelligence above).
Wave numbering W251–W274 (24 waves total). Each Tier 5 sprint
operationalises one anchor stat.

The thread: **the problem isn't that the risk doesn't exist, it's that
there's no signed, auditable, machine-readable proof the risk was
measured and addressed.** That is what squash generates. Every Tier 5
deliverable is one more proof artefact.

---

### Sprint 30 — Hallucination Rate Attestation (`squash hallucination-attest`) · **Track C / C7 ★ HEADLINE STAT**

> ★ **The single most-quoted statistic in the squash story sits here: $67.4B in 2024 AI hallucination losses, 47% of executives made decisions on hallucinated content, $14,200/employee/year in mitigation cost.** Sprint 30 is the product that converts that pain into a one-line attestation. Lead every press release, every HN post, every CFO conversation with this stat.

**Goal:** Signed certificate that measures a model's hallucination rate on a domain-specific probe dataset (legal, medical, financial, code, general), records the Vectara-equivalent score, flags whether the rate exceeds the deployment-domain threshold (legal AI at 6.4% is very different from general knowledge at 0.8%), and generates a certificate suitable for vendor trust packages.

**Why now:** EU AI Act Article 13 (Aug 2 enforcement) requires transparency for AI outputs. Hallucination documentation goes from best-practice to compliance requirement on Day 1. No competitor produces a signed, attested hallucination rate.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W251 | `squash/hallucination_attest.py` (NEW) | `HallucinationAttester.attest(model_endpoint, domain)`: runs a curated probe set per domain (Vectara HHEM-style), measures faithfulness against ground-truth references, computes domain-adjusted hallucination rate, signs the result. Five built-in domains: `legal`, `medical`, `financial`, `code`, `general`. |
| W252 | CLI: `squash hallucination-attest` + Trust Package integration | `squash hallucination-attest --model http://model.local:8080 --domain legal`. Signed cert under `squash-hallucination.json`; auto-included in Trust Package export; threshold gate flag (`--max-rate 0.05`) for CI. |

**Sprint 30 exit criteria:**
- 1 new module (`hallucination_attest.py`); module count tracked
- 5 domains × ≥40 probes each shipped as built-in fixtures
- Threshold gate blocks attestation on overshoot

---

### Sprint 31 — Drift SLA Certificate (`squash drift-sla`) · **Track B / B7**

**Goal:** Formal drift SLA certificate. `squash drift-sla --threshold 0.05 --window 30d` monitors PSI + KS statistic on model outputs over a rolling window, compares to a signed baseline attestation, issues a green/yellow/red drift cert. Used in regulated industries (BFSI / healthcare) as evidence of EU AI Act post-market continuous monitoring.

**The stat:** 35% error-rate jump in models left unmonitored 6+ months · 67% of orgs at scale hit a critical statistical-misalignment issue unnoticed for >1 month.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W253 | `squash/drift.py` extension — SLA certificate engine | `DriftSLA(threshold=0.05, window_days=30)`: rolling PSI/KS evaluator that emits structured `DriftCertificate` (signed) with green/yellow/red status, breach timestamp, recommended action. |
| W254 | CLI: `squash drift-sla` + breach alerting | `squash drift-sla --baseline ./squash-attest.json --threshold 0.05 --window 30d`; cron-friendly exit codes (0 green, 1 yellow, 2 red); breach event fires through `webhook_delivery.notify(event="drift.sla_breach")`. |

**Sprint 31 exit criteria:**
- 0 new modules (extension); 0 regressions
- PSI + KS computed deterministically against fixture distributions
- Breach event verified against existing webhook delivery

---

### Sprint 32 — LoRA / Adapter Poisoning Detection (`squash scan-adapter`) · **Track B / B8**

**Goal:** `squash scan-adapter --lora ./adapter.safetensors --base-model ./model` runs behavioural-comparison testing between the base model and the LoRA-applied model, flags statistical anomalies in the weight-delta distribution that could indicate backdoor injection, checks adapter provenance + signing, generates a signed adapter safety certificate. Includes `--require-safetensors` to block pickle-format adapters outright.

**The stat:** ~100 malicious models found on HuggingFace with embedded code-execution payloads (JFrog 2024) · LoRA adapters perceived as "small therefore low-risk" — wrong — they carry full behavioural rewrite capability.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W257 | `squash/scanner.py` extension — LoRA delta analyser | Behavioural-diff harness: load base + adapter, run a fixed prompt set through both, compute output-distribution distance + weight-delta statistical fingerprint; flag anomalies vs. clean-fine-tune baselines. |
| W258 | CLI: `squash scan-adapter` + safetensors gate | `squash scan-adapter --lora ./adapter.safetensors`; `--require-safetensors` returns rc=2 on pickle-format input; signed `squash-adapter-scan.json` written. |

**Sprint 32 exit criteria:**
- 0 new modules (scanner extension)
- Statistical anomaly threshold tuned against ≥3 known-clean and ≥1 known-malicious adapter fixtures
- Pickle-format input rejected before any deserialisation

---

### Sprint 33 — License Conflict Detector (`squash license-check`) · **Track B / B10 — OMB M-26-04**

**Goal:** `squash license-check --model ./model --deployment-type commercial-saas --user-count 50000` parses model licence file, checks against a curated DB of 200+ LLM licences (Llama 2/3/3.1, Mistral, DeepSeek, Gemma, OpenRAIL, Apache, MIT, …), flags conflicts with the intended deployment (commercial-saas, federal, MAU-thresholds, derivative-works), generates a signed compliance cert.

**The stat:** OMB M-26-04 (Dec 2025, effective March 2026) — federal agencies must request model cards, evaluation artefacts, and acceptable-use policies before LLM purchase. **Already past deadline.** California AB 2013 effective Jan 1, 2026.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W255 | `squash/license_check.py` (NEW) | LLM licence database (200+ entries) keyed by SPDX-extended identifier; per-licence rules (MAU thresholds, federal-use clauses, derivative restrictions); `LicenseChecker.check(model_path, deployment_type, user_count)` → signed `LicenseCertificate`. |
| W256 | CLI: `squash license-check` + OMB-M-26-04 profile | `squash license-check --omb-m-26-04` profile bundles federal-procurement requirements; emits the model card + AUP + eval artefacts referenced by the directive in one bundle. |

**Sprint 33 exit criteria:**
- 1 new module (`license_check.py`); module count tracked
- 200+ licences with deployment-specific rules
- OMB profile produces the exact artefact set the directive requires

---

### Sprint 34 — Data Poisoning + Pipeline Integrity (`squash attest-pipeline`) · **Track B / B9**

**Goal:** `squash attest-pipeline --config training_config.yaml --datasets ./data/` verifies each training dataset against known-clean hash signatures, flags anomalous label distributions (label-flipping signatures), validates dataset-download URLs against original-source checksums, generates a signed pipeline-integrity certificate.

**The stat:** 90% of AI models fail to reach production due to fragile pipelines · 0.001% of training data poisoned suffices to fundamentally degrade reliability · ~100 malicious HF models found 2024.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W262 | `squash/data_lineage.py` extension — hash verification | Per-dataset SHA-256 verification against a curated known-clean catalogue (HF Datasets, Common Crawl snapshots, etc.); ingest extension to `LineageCertificate`. |
| W263 | `squash/scanner.py` extension — label-distribution anomaly | Statistical detector for label-flipping signatures: KS test on label distributions vs. expected; configurable per-dataset baseline. |
| W264 | CLI: `squash attest-pipeline` + signed pipeline cert | Combines W262 + W263 into a pipeline-integrity attestation; signed JSON with per-dataset verdicts + overall PASS/FAIL. |

**Sprint 34 exit criteria:**
- 0 new modules (extensions only)
- Label-flipping detector validated against synthetic-poisoned fixtures
- Pipeline cert round-trips through Sigstore verification

---

### Sprint 35 — Model Deprecation Watch (`squash deprecation-watch`) · **Track C / C8**

**Goal:** Background monitor of every major AI provider's deprecation calendar (OpenAI, Anthropic, Google, Meta, Mistral). Cross-references squash Asset Registry. Fires alerts with configurable lead time when a registered model approaches sunset. Each alert carries the re-attestation requirements + estimated migration effort.

**The stat:** Original Claude retired Jan 5, 2026 · DALL-E 2/3 retire May 12 · Assistants API sunsets Aug 26 · video models deprecated March 2026. Every sunset breaks a tied-to-version Annex IV record.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W265 | `squash/deprecation_watch.py` (NEW) | Provider-specific deprecation feed adapters (OpenAI, Anthropic, Google, Meta, Mistral); persisted SQLite cache; cross-reference engine against `asset_registry`. |
| W266 | CLI: `squash deprecation-watch` + alert routing | `squash deprecation-watch --lead-time 30d --alert-channel slack`; per-model migration-effort estimator; re-attestation checklist generator. |

**Sprint 35 exit criteria:**
- 1 new module (`deprecation_watch.py`); module count tracked
- 5 provider feeds covered
- Cross-reference produces deterministic alerts against fixture registry

---

### Sprint 36 — Carbon / Energy Attestation (`squash attest-carbon`) · **Track C / C9 — CSRD buyer**

**Goal:** `squash attest-carbon --model ./model --deployment-region us-east-1` calculates kWh/inference using FLOP count + regional grid carbon intensity (Electricity Maps API), computes CO₂ equivalents per inference + per 1M tokens, generates a CSRD-mappable carbon attestation, embeds energy fields in the CycloneDX ML-BOM.

**The stat:** EU AI Act will require large AI systems to report energy + life-cycle impacts · CSRD applies to all large EU companies from 2025 · OMB DOE rule on AI data-centre lifecycle reporting drafted Jan 2025.

**The new buyer:** ESG / sustainability office. Different budget holder from the CISO. Critical for opening the second beachhead.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W259 | `squash/carbon_attest.py` (NEW) | FLOP estimator (per architecture family) × regional carbon intensity (live Electricity Maps cache); `CarbonAttestation.compute(model, region)` returns gCO₂eq/inference + kWh/1M-tokens. |
| W260 | `carbon_attest.py` — CSRD field mapping | `to_csrd()` adapter that maps the certificate to CSRD Scope 2 + Scope 3 fields; same for CSDDD + UK PRA SS1/23. |
| W261 | CLI: `squash attest-carbon` + ML-BOM enrichment | `squash attest-carbon ...` writes the standalone cert AND injects the energy fields into the model's CycloneDX ML-BOM as AI-specific environmental section. |

**Sprint 36 exit criteria:**
- 1 new module (`carbon_attest.py`); module count tracked
- Electricity Maps cache layer (offline-replayable)
- CSRD field mapping verified against published schema

---

### Sprint 37 — Runtime Hallucination Monitor (`squash monitor --mode hallucination`) · **Track C / C10**

**Goal:** Sidecar runtime monitor for live inference endpoints. Samples a configurable percentage of outputs, runs each through a lightweight faithfulness scorer, tracks rolling hallucination rate, fires alerts on threshold breach, logs violations to attestation registry.

**The stat:** EU AI Act Article 9 mandates post-market monitoring throughout AI-system lifecycle · 18% production hallucination rate in enterprise chatbots · 5–15% in RAG even with retrieval working · 39% of customer-service bots pulled in 2024.

**Distinct from C7 (pre-deploy):** C7 attests the model before launch; C10 is the continuous-SLA enforcement that regulators increasingly demand.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W267 | `squash/monitoring.py` extension — hallucination scorer | Lightweight faithfulness scorer (perplexity + retrieval-grounded check for RAG endpoints); rolling-window aggregator with configurable sample-rate. |
| W268 | `monitoring.py` — breach alert + registry log | Threshold-breach event fires `webhook_delivery.notify(event="hallucination.threshold_breach")`; violations logged to `attestation_registry` with timestamp + sample. |
| W269 | CLI: `squash monitor --mode hallucination` daemon | `squash monitor --mode hallucination --endpoint http://localhost:8080 --sample-rate 0.05 --threshold 0.10`; cron / k8s-deployment-friendly. |

**Sprint 37 exit criteria:**
- 0 new modules (extension)
- Faithfulness scorer correlates ≥0.7 with human judgement on a labelled fixture
- Daemon mode runs without leaking memory across 1M-sample fixture

---

### Sprint 38 — AI Vendor Concentration Risk (`squash vendor-concentration`) · **Track D / D7**

**Goal:** `squash vendor-concentration --registry ./registry.json` aggregates the AI Asset Registry by provider, calculates the percentage of critical business processes dependent on each, flags single-points-of-failure (configurable threshold), assesses migration cost on a per-provider outage / sunset, generates a CRO-readable concentration-risk attestation.

**The stat:** Average enterprise AI stack runs 5+ providers (OpenAI, Anthropic, Google, Meta, Mistral) without central visibility · NIST AI RMF GOVERN function explicitly requires third-party AI dependency management.

**The new buyer:** Chief Risk Officer. Distinct conversation from CISO.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W270 | `squash/vendor_registry.py` extension — concentration analyser | `ConcentrationAnalyser.compute(registry, asset_registry)`: per-provider % of critical processes, single-point-of-failure flag, migration-cost matrix. |
| W271 | CLI: `squash vendor-concentration` + CRO report | Markdown + JSON output mapped to NIST AI RMF GOVERN-1.1 + GOVERN-6.1; ZIP bundle with executive summary + per-provider deep dive. |

**Sprint 38 exit criteria:**
- 0 new modules (extension)
- Concentration metric deterministic across fixture registries
- NIST AI RMF GOVERN field mapping verified

---

### Sprint 39 — Model Genealogy + Copyright Contamination (`squash genealogy`) · **Track C / C11**

**Goal:** `squash genealogy --model ./model --memorisation-probe ./probes/copyright/` traces model derivation chain, identifies base-model family + known training-data composition, flags known copyright-heavy sources (Books3, copyleft code, news-heavy Common Crawl), runs a memorisation probe (verbatim-reproduction test on copyrighted texts), generates a signed copyright-contamination-risk cert tiered by deployment domain.

**The stat:** NYT v. OpenAI established the legal theory · MIT research: hallucinating models use 34% more confident language than factual ones · hundreds of US court rulings on AI hallucination in legal filings during 2025 · $67.4B in losses links back to the same root.

**The new buyer:** General Counsel. Approving an AI deployment for content generation, legal drafting, or code assistance is a contract-and-liability decision; squash gives the GC the certificate they currently lack.

| Wave | Module / Feature | What It Delivers |
|------|-----------------|-----------------|
| W272 | `squash/genealogy.py` (NEW) | Derivation-chain extractor: walks model card + lineage cert + base-model registry to produce a signed `Genealogy` record (`base → fine-tune-1 → fine-tune-2 → adapter`). |
| W273 | `genealogy.py` — memorisation probe engine | Loads a curated probe set of known copyrighted passages (configurable per legal jurisdiction); prompts the model in a way that triggers verbatim-completion if memorised; scores reproduction rate. |
| W274 | CLI: `squash genealogy` + tiered contamination cert | `squash genealogy --deployment-domain content-generation` (tiered thresholds: legal-drafting strictest, internal-summarisation laxest); cert auto-included in Trust Package; `--block-on-contamination` flag for CI. |

**Sprint 39 exit criteria:**
- 1 new module (`genealogy.py`); module count tracked
- Memorisation probe deterministic against fixture probes
- Tiered thresholds documented per deployment-domain category

---

### Sprint 6 — Launch (July 11–August 2)

| Date | Action |
|------|--------|
| July 4  | Sprint 4A complete — site live, PyPI live, Stripe live |
| July 11 | **Public Beta launch** — email list, Discord, LinkedIn |
| July 14 | **HackerNews Show HN** — Tuesday morning 9am ET (`squash demo` as the hook) |
| July 15 | **Dev.to launch article** — "How we automated EU AI Act compliance in a CI/CD pipeline" |
| July 17 | **LinkedIn long-form post** — EU AI Act 16 days away |
| July 21 | **Product Hunt launch** |
| July 24 | **3-minute Loom demo video** — `squash demo` → `squash attest` → GitHub Actions output → dashboard |
| July 24 | **Webinar** — EU AI Act Compliance for ML Teams: Live Demo |
| August 2 | **EU AI Act Enforcement Day** — "Squash users are compliant. Are you?" |

---

### Sprint 7 — Enterprise Moat (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 4 new modules, 104 new tests, 0 regressions.**

| Wave | Task | Strategic Value | Status |
|------|------|-----------------|--------|
| W178 | AI Vendor Risk Register (`squash vendor`) | Two-sided marketplace foundation; eliminates 66-apps-untracked shadow AI problem | ✅ |
| W179 | AI Asset Registry (`squash registry`) | Enterprise answer to "what AI do you have?"; auto-populates from CI/CD | ✅ |
| W180 | Training Data Lineage Certificate (`squash data-lineage`) | GDPR §6 liability reduction; SPDX license check; PII risk flags; €15M fine prevention | ✅ |
| W181 | Bias Audit (`squash bias-audit`) | Workday lawsuit defense; NYC Local Law 144; EU AI Act Annex III; pure Python, no deps | ✅ |

**Sprint 7 exit criteria: ALL MET**
- `squash vendor add/list/questionnaire/import-trust-package/summary` functional ✅
- `squash registry add/sync/list/summary/export` functional ✅
- `squash data-lineage` traces datasets, checks 50+ known HF dataset profiles, SPDX license db, PII risk ✅
- `squash bias-audit` computes DPD, DIR (4/5ths), EOD, PED for all protected attributes ✅
- NYC Local Law 144, EU AI Act Annex III, ECOA 4/5ths rule thresholds implemented ✅

---

### Sprint 8 — Moat Deepening (April 29, 2026) ✅ COMPLETE

**All code shipped 2026-04-29. 6 waves, 128 new tests, 0 regressions.**

| Wave | Module / Asset | What It Delivers | Status |
|------|----------------|-----------------|--------|
| W182 | `annual_review.py` | Annual review generator: 12-month attestation history, compliance trend, model portfolio audit, regulatory changes addressed, next-year objectives | ✅ |
| W183 | `attestation_registry.py` | Public attestation registry: `att://` URIs, SHA-256 integrity, revocation, org lookup, verify-in-10-seconds (`squash publish` / `squash lookup` / `squash verify-entry`) | ✅ |
| W184 | `dashboard.py` | CISO terminal dashboard: 5-metric panel, risk heat-map, portfolio sort, ANSI colour, `--json` for VS Code webview | ✅ |
| W185 | `regulatory_feed.py` | Regulatory intelligence feed: 9 regulations (EU AI Act, NIST RMF, ISO 42001, Colorado, NYC LL144, SEC, FDA, GDPR, FedRAMP), 6 recent change events, deadline countdown | ✅ |
| W186 | `due_diligence.py` | M&A/investment AI due diligence package: model inventory, liability flag scoring, R&W guidance, ZIP bundle (`squash due-diligence`) | ✅ |
| W187 | `vscode-extension/` | Full VS Code extension scaffold: TypeScript, 9 commands, 3 sidebar tree views, status bar, dashboard webview, `package.json` with Marketplace metadata | ✅ |

**Sprint 8 exit criteria: ALL MET**
- `squash annual-review --year 2025` produces JSON + Markdown + summary ✅
- `squash publish / lookup / verify-entry` operate against SQLite registry ✅
- `squash dashboard` renders ANSI terminal; `--json` returns structured data ✅
- `squash regulatory status/list/updates/deadlines` covers 9 regulations ✅
- `squash due-diligence` generates ZIP bundle with R&W guidance ✅
- VS Code extension `package.json` + `extension.ts` passes 21 structural tests ✅

---

## Part VII-B: The Full Feature Roadmap (Ordered by Impact)

All 30 features ranked by acquisition impact, revenue leverage, and defensibility. The first 12 should be live before or at launch. Items 13–22 are Sprint 5–6. Items 23–30 are the 12-month enterprise moat.

### Tier 1 — Launch-Critical (before August 2, 2026)

| # | Feature | Module/Location | Impact |
|---|---------|----------------|--------|
| 1 | **`squash demo` command** | `squash/cli.py` + bundled sample model | Zero-friction first value. Run it, see a full attestation in 10 seconds. The "aha moment" command. Tweet the output. |
| 2 | **Compliance badge SVG endpoint** | `squash/api.py` `GET /badge/{framework}/{attestation_id}` | Installed-base virality. Every attested repo displays a badge = free marketing + social proof. shields.io compatible. |
| 3 | **`squash init` command** | `squash/cli.py` | Auto-detect ML framework (PyTorch/TF/MLflow/W&B/HF), scaffold `.squash.yml`, dry-run. Eliminates biggest onboarding friction. |
| 4 | **GitHub App** | GitHub Marketplace | Org-level install, auto-comments on PRs with compliance diff, blocks merge on policy fail. Acts as network effect: 1 user → 50 users at a company. |
| 5 | **Slack/Teams webhook** | `squash/notifications.py` | Drift alert, VEX CVE hit, CI fail → team channel. Makes squash part of daily operational rhythm. |
| 6 | **Browser-based playground** | Fly.io function + API | Paste HuggingFace ID or upload model.json, get full attestation in browser. Zero install. Converts README visitors. |
| 7 | **Prometheus `/metrics` endpoint** | `squash/metrics.py` + `api.py` | Enterprise platform teams live in Grafana. Squash becomes a dashboard tile, not a separate login. |
| 8 | **JIRA/Linear/GitHub Issues auto-ticketing** | `squash/ticketing.py` | Violation found → ticket auto-created with remediation steps. Closes the loop from "problem detected" to "work item created." |
| 9 | **FastAPI/Django compliance middleware** | `squash/middleware.py` | `from squash.middleware import ComplianceMiddleware`. 5 lines of code. Developer-led bottom-up growth. Adds `X-Squash-Attestation-ID` to inference response headers. |
| 10 | **`squash watch` mode** | `squash/cli.py` | Continuous drift detection in local dev. Model file changes → terminal notification. Builds the habit. |
| 11 | **Pre-commit hook** | `squash/cli.py` (`squash install-hook`) | `git pre-commit` runs attestation on model files. Compliance feedback at commit stage, not 15 min into CI. |
| 12 | **Direct HuggingFace Hub attestation** | `squash/cli.py` (`squash attest hf://`) | `squash attest hf://microsoft/phi-3`. Attest before downloading. Model procurement security scanner. |

### Tier 2 — Sprint 5–6 (August–September 2026)

| # | Feature | Module/Location | Impact |
|---|---------|----------------|--------|
| 13 | **VS Code extension** | Separate `squash-vscode` repo | Compliance status in sidebar. Engineers see squash daily without running a command. |
| 14 | **Public attestation registry** | `attestations.getsquash.dev` | Attestations published at shareable URLs. Verifiable by buyers, regulators, procurement. "npm audit" equivalent for AI. |
| 15 | **Model card auto-generation** | `squash/model_card.py` (already exists) | `squash model-card` as first-class CLI command. HF-compatible, pre-filled from Annex IV data. Required by HF for model publication. |
| 16 | **LangChain/LlamaIndex chain attestation** | `squash/integrations/langchain.py` | Attest entire RAG pipelines and agent chains. Multi-model pipeline compliance as a unit. |
| 17 | **SBOM diff command** | `squash/cli.py` (`squash diff v1 v2`) | Delta in compliance posture between model versions. Essential for model governance reviews. |
| 18 | **Model registry integrations** | `squash/integrations/` | Auto-attest on registration in MLflow/W&B/SageMaker Model Registry. Enforcement gate before production promotion. |
| 19 | **Startup pricing tier ($499/mo)** | Stripe + `squash/billing.py` | Captures seed/Series A segment. Too big for free, can't justify $899. 500 attestations, 3 users, VEX read, Slack. |
| 20 | **OpenTelemetry traces** | `squash/telemetry.py` | Every attestation run emits OTel spans. Integrates with Datadog, Honeycomb, Jaeger. Enterprise observability teams adopt immediately. |
| 21 | **ArgoCD/Flux GitOps integration** | `squash/integrations/gitops.py` | Block model deployment in GitOps pipeline if compliance score below threshold. |
| 22 | **Generic outbound webhook** | `squash/api.py` | Configurable webhook POSTing attestation events to any URL. PagerDuty, Opsgenie, ServiceNow, custom SOAR. One primitive, infinite connectors. |

### Tier 3 — 12-Month Enterprise Moat (September 2026–April 2027)

| # | Feature | Module/Location | Impact |
|---|---------|----------------|--------|
| 23 | **`squash scan hf://` public security scanner** | Free public tool | Anyone checks any HuggingFace model for security issues. Top-of-funnel brand builder. |
| 24 | **Branded PDF compliance report** | `squash/annex_iv_generator.py` (to_pdf() exists) | Cover page + exec summary. Email to the CISO. |
| 25 | **Compliance email digest** | `squash/notifications.py` | Weekly/monthly portfolio posture summary. Passive retention. |
| 26 | **Terraform/Pulumi provider** ✅ B4 (2026-04-30) | `integrations/terraform/` (Go, terraform-plugin-framework v1.13.0) — `squash_attestation` + `squash_policy_check` resources, `squash_compliance_score` data source, Pulumi `command` shell-out examples + bridge path documented. 16 Go tests passing under `-race -count=1`. | Compliance as infrastructure. DevOps teams adopt immediately. |
| 27 | **Pre-built HuggingFace Spaces deployment** | HF Spaces | Free, visible to entire HF community. Zero marketing cost. |
| 28a | **Drift SLA Certificate** ✅ B7 (2026-04-30) | `squash/drift_certificate.py` — DriftSLASpec + ScoreLedger + SLAEvaluator + DriftCertificateIssuer; `squash drift-cert ingest|issue|verify|show|export`; 30 tests passing. Signed `squash.drift.certificate/v1` JSON + HTML + PDF export. | Prove sustained compliance for insurance, enterprise procurement, and board reporting. |
| 28c | **License Conflict Detection** ✅ B10 (2026-04-30) | `squash/license_conflict.py` — 73 SPDX IDs + 9 AI model licences, 12 conflict rules (LC-001–LC-012), LicenseScanner (req.txt/pyproject/package.json/Cargo.toml/README/dataset_infos), `squash license-check scan|explain|report` CLI. 55 tests. | Legal compliance gating for model deployment. |
| 28b | **Training Data Poisoning Detection** ✅ B9 (2026-04-30) | `squash/data_poison.py` — 6-layer scanner: threat intel, label integrity, duplicate injection, statistical outliers, backdoor trigger patterns, provenance integrity. `squash data-poison scan|report` CLI. 39 tests. OWASP LLM04 / Badnets / Hidden Killer / Wan 2023. | ML supply-chain security gate. |
| 29 | **Audit trail blockchain anchoring** ✅ B6 (2026-04-30) | `squash/anchor.py` — Merkle-batch commitment, LocalAnchor (Ed25519), OpenTimestampsAnchor (Bitcoin), EthereumAnchor (EVM calldata via cast), portable `squash.anchor.proof/v1` docs, `squash anchor` CLI (add/commit/verify/proof/list/status). 23 tests passing. | Immutable proof for financial services/medical/defense. |
| 30 | **SOC 2 Type II** | Business/legal | Enterprise procurement unblocked. Start readiness phase now. |

---

### Strategic Rationale

Every feature in Tier 1 that puts squash in the developer's daily workflow (watch mode, pre-commit hook, IDE extension, Slack notifications) compounds into stickiness that makes churn nearly impossible.

Every feature that generates a shareable artifact (badge, PDF report, public attestation registry, branded model card) is free marketing.

Every feature that automates the ticket, the deployment gate, or the API block (GitHub App, JIRA integration, ArgoCD hook, API gateway plugin) turns squash from a tool into infrastructure. **Tools get replaced. Infrastructure doesn't.**

---

### The Design Partner Imperative

One named company using squash — even in closed beta — with a quote and a rough case study is worth more than any launch copy. Target: boutique AI consulting firms that build models for BFSI or healthcare and currently charge clients for compliance documentation. Squash turns that billable work into a 10-minute CLI run. They save the client money AND improve their own margins. That's the pitch.

**The case study headline:** "Reduced Annex IV documentation from 6 weeks to 15 minutes."

---

### The US Market Regulatory Angle

The master plan has been EU-focused. That's right for launch timing. But the parallel US narrative for US enterprise buyers:
- **NIST AI RMF** compliance for government contractors (already built in squash)
- **FedRAMP AI** for federal procurement (CMMC templates in squash)
- **SEC AI disclosure requirements** (materializing)
- **State AI bills** — Colorado, Illinois, Texas (emerging enforcement)

The US enterprise buyer who doesn't care about GDPR absolutely cares about a DoD contract. Surface FedRAMP/CMMC more aggressively in the website and sales materials.

---

## Part VIII: ARR Scaling Plan

| Milestone | Timeline | Monthly Revenue | Key Driver |
|-----------|----------|-----------------|------------|
| $15K ARR | Month 3 | $1,250 | Design partners |
| $100K ARR | Month 7 | $8,333 | HN/PH launch |
| $500K ARR | Month 12 | $41,667 | Enterprise + partner |
| $1M ARR | Month 18 | $83,333 | Category leadership |
| $5M ARR | Month 30 | $416,667 | Series A |
| $10M ARR | Month 42 | $833,333 | Series B |

---

## Part IX: Costs & Runway

### Infrastructure (Month 1–12)

| Item | Monthly Cost |
|------|-------------|
| Fly.io (API server, 2 instances) | $50 |
| Neon PostgreSQL (serverless) | $25 |
| Sentry (error monitoring) | $26 |
| Better Uptime | $20 |
| Resend (email) | $20 |
| Vercel (website) | $20 |
| Domain + SSL | $20/month amortized |
| **Total** | **~$200/month** |

### When to Hire

| Revenue | First Hire |
|---------|-----------|
| $10K MRR | Nobody. Solo. |
| $25K MRR | 1 contract dev (compliance/backend) |
| $50K MRR | 1 FT engineer or 1 FT account executive |
| $83K MRR ($1M ARR) | Marketing hire + AE |
| $150K MRR | Series A territory — full team build |

---

## Part X: The Living Document Protocol

**On every commit:**
- Update "Last updated" timestamp at top
- Mark completed checklist items with ✅
- Add new waves to Sprint Roadmap
- Update ARR milestone tracking if changed

**On every sprint completion:**
- Add retrospective note (what worked, what didn't, what changed)
- Update next sprint goals

**Monthly:** Update revenue figures, customer count, GitHub stars, revise ARR plan.

**Quarterly:** Full competitive landscape re-scan, pricing review, market sizing update.

---

## Quick Reference: The August 2 Countdown — Parallel Track Mode — 94 Days

The North Star execution sequence between today (April 30) and the EU AI
Act enforcement deadline. **All four tracks run in parallel; only Track A
is critical-path-sequential.** Anything not on this table is a
distraction until August 2 ships.

| Window | Track A · Critical Path | Track B · Engineering | Track C · Opportunities | Track D · Moat | Launch |
|---|---|---|---|---|---|
| **May 2** | A1 `fly deploy` (2 hrs) | — | — | — | — |
| **May 3** | A2 PyPI publish (1 hr) | — | — | — | — |
| **May 5–6** | A3 Domain + Stripe (1d) | B1 HF Scanner (4d) ↑ | **C1 `squash freeze` ★** (2d) | — | — |
| **May 7–10** | A4 Website live (3d) | B1 cont. · B2 Branded PDF (2d) | C2 AI Washing Detection (5d) · **C7 Hallucination Attest ★ ($67.4B)** | — | — |
| **May 12–19** | ✅ Track A done | B3 Email Digest (2d) | C3 Approval Workflow · C7 cont. | — | — |
| **May 15–26** | — | B4 Terraform/Pulumi (10d) | C4 Regulatory Watch (7d) | — | — |
| **May 18–23** | — | **B10 License Conflict (OMB)** (5d) | — | — | — |
| **May 27–Jun 5** | — | B5 API Gateway · **B7 Drift SLA** (4d) | C5 Audit Simulation kickoff | — | — |
| **Jun 5–13** | — | B6 Blockchain · **B8 LoRA Poisoning** (5d) | C5 cont. | D1 GitHub App (15d) · D2 Identity Attest (8d) | — |
| **Jun 12–22** | — | **B9 Data Poisoning + Pipeline** (7d) | — | D2 cont. | — |
| **Jun 16–30** | — | — | C6 Insurance · **C8 Deprecation Watch** (4d) | D2 cont. | — |
| **Jul 1–9** | — | — | **C9 Carbon Attest (CSRD)** (6d) | D3 Procurement API kickoff | — |
| **Jul 7–15** | — | — | **C10 Runtime Hallucination Mon** (6d) | D3 cont. · D4 Multi-Jurisdiction kickoff | — |
| **Jul 16–28** | — | — | — | D4 cont. · D5 Benchmarking | Pre-launch staging |
| **Jul 21–30** | — | — | **C11 Genealogy/Copyright Cert** (7d) | D5 cont. | — |
| **Jul 11** | — | — | — | — | **L1 Public Beta** |
| **Jul 14, 9am ET** | — | — | — | — | **L2 Show HN** |
| **Jul 21** | — | — | — | — | **L3 Product Hunt** |
| **Aug 2 — T+0** | — | — | — | — | **L4 EU Enforcement Day** |
| **Aug 5–11** | — | — | — | **D7 Vendor Concentration** (5d) | Post-launch surge |
| **Aug 2 → 2027** | — | — | R1/R2 (Red-Team · Cost) | D6 SOC 2 (6 mo) | Hardening |

### Critical-Path Gates (date-locked dependencies)

- **A1 (May 2) → unblocks B1, C1, all cloud-dependent items.** If A1 slips, every parallel track that depends on a live API moves with it. Do A1 first.
- **B1 + B2 + C1 (by May 10) → unblock L1.** Public Beta Launch (Jul 11) requires the HF scanner live, the branded PDF as sales leave-behind, and `squash freeze` as the headline demo.
- **C1 live by mid-May → headline asset for L2 (Show HN, Jul 14, 9am ET).** `squash freeze` IS the HN demo. The post body GIF should show the red-button command. Draft already in `docs/launch/hn-post.md`.
- **Track D D3/D4/D5 (by Jul 31) → unblock the Aug 2 narrative.** Procurement scoring API, multi-jurisdiction matrix, and industry benchmarking each turn squash from "tool" to "infrastructure" — the framing of the Aug 2 press surge.
- **C7 Hallucination Attestation (by mid-May) → unblocks the $67.4B headline arc** for HN, LinkedIn, every CFO conversation. The single most-quoted statistic in the squash story should be the lead, not a footnote.
- **B10 License Conflict (by May 23) → unblocks federal procurement.** OMB M-26-04 deadline already passed (March 2026) — every federal customer is non-compliant by default until squash gives them the certificate. First-mover lock on the federal segment.
- **B9 Pipeline Integrity + B7 Drift SLA (by Jun 22) → unblock the regulated-industries narrative** (BFSI, healthcare): pre-deploy pipeline integrity + post-deploy drift SLA = closed-loop continuous-compliance evidence.
- **C10 Runtime Hallucination Monitor (by Jul 15) → unblocks the EU AI Act Article 9 post-market-monitoring narrative**, which is the regulator's explicit ongoing-obligation pillar.

### Parallelisation Discipline

Sprints 5, 7, 8, 9 already ran simultaneously. That cadence is the **standing operating model** from May 2 forward. Every track item lists its `∥ With` set explicitly so a glance reveals what can run side-by-side.

The headline parallelisation: **Track A (9 days, solo) overlaps Track B item B1 (4 days) and Track C item C1 (2 days) starting May 5.** The same calendar week ships three independently valuable artefacts. That is the multiplier the Tier 1+2 surface was built on, now made explicit for everything that follows.

The legacy "Sprint 14 → Sprint 29" sequential numbering is preserved below as **deep-dive specifications** (each one tagged with its track ID) but is no longer the canonical execution model. The roadmap is the four-track grid above.

---

*"The deadline is real. The market is real. The proof gap is everyone's gap except squash's. Ship it."*

---

**Document version:** 1.6 (Tier 5 — 10 research-anchored sprints W251–W274 added)
**Next review:** May 14, 2026 — review Track A completion + Track B/C/D progress against the parallel grid; assess C7 ($67.4B headline) as L2 demo asset
**Owner:** Wesley Scholl, Konjo AI
