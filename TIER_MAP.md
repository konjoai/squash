# TIER_MAP.md — Squash module classification for Phase G coverage gates

> **Generated:** 2026-05-01 · companion to `AUDIT_BASELINE.md` and `SQUASH_MASTER_PLAN.md` Phase G.
> **Purpose:** every module in `squash/` is classified into one of five tiers. Coverage / mutation / type-strictness gates apply per tier. CI is configured (Phase 5) to fail on any regression.

## Tier definitions and gates

| Tier | Definition | Line cov | Branch cov | Mutation score | mypy | Repro test required |
|------|------------|---------:|-----------:|---------------:|------|----:|
| **0 — Cryptographic core** | Code that signs, hashes, canonicalises, or anchors a payload that the user (or a regulator) will rely on as evidence. A bug here invalidates every attestation. | **100%** | **100%** | **≥ 90%** | `--strict` | ✅ |
| **1 — Signed report emitters** | Modules that produce a signed certificate, a signed BOM, an Annex-IV-grade report, or a content-addressed registry entry. They consume Tier 0 to produce evidence. | ≥ 95% | ≥ 90% | ≥ 80% | `--strict` | ✅ |
| **2 — Operational integrations** | CI hooks, registries, webhooks, gateways, dashboards, billing, governance UI. Side-effecting; integrates with external systems. | ≥ 85% | ≥ 75% | ≥ 60% | `--strict` (best-effort on third-party stubs) | optional |
| **3 — Internal infra** | Auth, rate-limiting, persistence, telemetry, plumbing. No direct user-visible attestation. | ≥ 80% | ≥ 70% | ≥ 50% | `--strict` | optional |
| **4 — Glue / data** | `__init__`, `py.typed`, `data/*.json`, `templates/*`, trivially declarative modules. | ≥ 50% | n/a | n/a | n/a | n/a |

A module's tier is the **maximum** of the tiers of any signature path it lies on. If `module X` is imported by anything Tier 0, X is at least Tier 1.

---

## Tier 0 — Cryptographic core (5)

> The vault. 100/100/90 — non-negotiable.

| Module | Why Tier 0 |
|--------|------------|
| [squash/oms_signer.py](squash/oms_signer.py) | Ed25519 signing primitive, key handling |
| [squash/anchor.py](squash/anchor.py) | Transparency-log primitive, in-process canonical-JSON helper (to be replaced with RFC 8785 in Phase 2) |
| [squash/attest.py](squash/attest.py) | Root attestation pipeline; produces the signed in-toto-shaped object |
| [squash/slsa.py](squash/slsa.py) | SLSA in-toto Statement builder (provenance) |
| [squash/chain_attest.py](squash/chain_attest.py) | Composite signing across multi-component chains (RAG / agent / ensemble) |

**Phase 2 work (all five):** swap canonical encoder, inject clock, replace `uuid.uuid4()` with `uuid5(NAMESPACE, canonical_payload)`, add reproducibility test asserting byte-identical SHA-256 across two runs with frozen clock.

---

## Tier 1 — Signed report emitters (~40)

> Every cert, every BOM, every regulator-facing report. 95/90/80.

### Certificate emitters
- [squash/hallucination_attest.py](squash/hallucination_attest.py)
- [squash/drift_certificate.py](squash/drift_certificate.py)
- [squash/carbon_attest.py](squash/carbon_attest.py)
- [squash/data_lineage.py](squash/data_lineage.py) (`LineageCertificate`)
- [squash/identity_governor.py](squash/identity_governor.py)
- [squash/freeze.py](squash/freeze.py)
- [squash/incident.py](squash/incident.py)
- [squash/agent_audit.py](squash/agent_audit.py)
- [squash/copyright.py](squash/copyright.py)
- [squash/genealogy.py](squash/genealogy.py)
- [squash/audit_sim.py](squash/audit_sim.py)
- [squash/attestation_registry.py](squash/attestation_registry.py)
- [squash/trust_package.py](squash/trust_package.py)

### BOM / SBOM / SARIF / VEX builders
- [squash/sbom_builder.py](squash/sbom_builder.py)
- [squash/sbom_diff.py](squash/sbom_diff.py)
- [squash/spdx_builder.py](squash/spdx_builder.py)
- [squash/sarif.py](squash/sarif.py)
- [squash/vex.py](squash/vex.py)

### Regulator-facing report generators
- [squash/annex_iv_generator.py](squash/annex_iv_generator.py)
- [squash/iso42001.py](squash/iso42001.py)
- [squash/nist_rmf.py](squash/nist_rmf.py)
- [squash/soc2.py](squash/soc2.py)
- [squash/compliance_matrix.py](squash/compliance_matrix.py)
- [squash/model_card.py](squash/model_card.py)
- [squash/model_card_validator.py](squash/model_card_validator.py)
- [squash/annual_review.py](squash/annual_review.py)
- [squash/board_report.py](squash/board_report.py)
- [squash/pdf_report.py](squash/pdf_report.py)
- [squash/report.py](squash/report.py)

### Scanners / risk scorers feeding signed payloads
- [squash/license_conflict.py](squash/license_conflict.py) *(also: split into `database.py / scanner.py / reporter.py` in Phase 5)*
- [squash/data_poison.py](squash/data_poison.py)
- [squash/adapter_scanner.py](squash/adapter_scanner.py)
- [squash/hf_scanner.py](squash/hf_scanner.py)
- [squash/scanner.py](squash/scanner.py)
- [squash/code_scanner_ast.py](squash/code_scanner_ast.py)
- [squash/artifact_extractor.py](squash/artifact_extractor.py)
- [squash/evaluator.py](squash/evaluator.py)
- [squash/benchmark.py](squash/benchmark.py)
- [squash/bias_audit.py](squash/bias_audit.py)
- [squash/washing_detector.py](squash/washing_detector.py)
- [squash/hallucination_monitor.py](squash/hallucination_monitor.py)
- [squash/regulatory_feed.py](squash/regulatory_feed.py)
- [squash/regulatory_watch.py](squash/regulatory_watch.py)
- [squash/deprecation_watch.py](squash/deprecation_watch.py)
- [squash/procurement_scoring.py](squash/procurement_scoring.py)
- [squash/due_diligence.py](squash/due_diligence.py)
- [squash/insurance.py](squash/insurance.py)

---

## Tier 2 — Operational integrations (~30)

> CI/CD plumbing, registries, side-effecting connectors. 85/75/60.

### Service surface
- [squash/api.py](squash/api.py)
- [squash/cli.py](squash/cli.py) *(also: split into `squash/cli/<cmd>.py` in Phase 5; `main` is currently CC F)*
- [squash/middleware.py](squash/middleware.py)
- [squash/dashboard.py](squash/dashboard.py)
- [squash/chat.py](squash/chat.py)
- [squash/mcp.py](squash/mcp.py)

### Workflow / governance
- [squash/cicd.py](squash/cicd.py)
- [squash/github_app.py](squash/github_app.py)
- [squash/approval_workflow.py](squash/approval_workflow.py)
- [squash/governor.py](squash/governor.py)
- [squash/monitoring.py](squash/monitoring.py)
- [squash/remediate.py](squash/remediate.py)

### Registries / asset management
- [squash/asset_registry.py](squash/asset_registry.py)
- [squash/vendor_registry.py](squash/vendor_registry.py)

### Outbound delivery / notifications / billing
- [squash/webhook_delivery.py](squash/webhook_delivery.py)
- [squash/notifications.py](squash/notifications.py)
- [squash/ticketing.py](squash/ticketing.py)
- [squash/billing.py](squash/billing.py)
- [squash/edge_formats.py](squash/edge_formats.py)
- [squash/rag.py](squash/rag.py)

### `squash/integrations/*`
All connectors (`mlflow.py`, `wandb.py`, `huggingface.py`, `sagemaker.py` (if present), `vertex.py`, `ray.py`, `kubernetes.py`, `slack.py`, `teams.py`, `jira.py`, `linear.py`, `github_issues.py`, `gitlab.py`, `jenkins.py`, `azure_devops.py`, `azure_ad.py`, `aws_iam.py`, `gateway.py`, `gitops.py`, `helm.py`, `circleci/*`, `kubernetes_helm/*`, `langchain.py`).

---

## Tier 3 — Internal infra (~10)

> Plumbing. 80/70/50.

- [squash/auth.py](squash/auth.py)
- [squash/rate_limiter.py](squash/rate_limiter.py)
- [squash/quota.py](squash/quota.py)
- [squash/postgres_db.py](squash/postgres_db.py)
- [squash/cloud_db.py](squash/cloud_db.py)
- [squash/policy.py](squash/policy.py)
- [squash/risk.py](squash/risk.py)
- [squash/metrics.py](squash/metrics.py)
- [squash/telemetry.py](squash/telemetry.py)
- [squash/lineage.py](squash/lineage.py) *(thin wrapper; promote to Tier 1 if it grows)*

---

## Tier 4 — Glue / data

- `squash/__init__.py`
- `squash/py.typed`
- `squash/data/*.json`
- `squash/templates/*`
- `integrations/circleci/*.yml`, `integrations/kubernetes_helm/**`

---

## Mapping summary

| Tier | Module count | Cumulative LOC (approx, `wc -l`) |
|------|--------------:|--------------:|
| 0 | 5 | ~3,400 |
| 1 | ~40 | ~30,000 |
| 2 | ~30 (incl. 19+ integrations) | ~22,000 (cli.py alone is 10,829) |
| 3 | ~10 | ~3,500 |
| 4 | n/a | data + templates only |

**Total:** ~67,900 LOC across `squash/`. The Phase G mandate: **every Tier 0 line is byte-identity-tested, every Tier 1 module gets a reproducibility test, every signed payload uses RFC 8785 + injected clock + uuid5.**

---

## How to update this map

A module's tier changes when its **role** changes — not when its size changes. Specifically:

- A module **joins Tier 0** the day it touches signing keys, canonical bytes, or transparency-log primitives.
- A module **joins Tier 1** the day it emits a payload that is later signed (even if it doesn't sign itself).
- A module **drops a tier** only when the signed-payload surface is fully extracted into another file. Update this map *in the same PR* that changes the role.

CI in Phase 5 enforces this map: `scripts/check_tier_map.py` parses the table and asserts every `squash/*.py` is listed exactly once.
