# Squash — Squash violations, not velocity.

**The `pytest` of AI compliance. Runs in your CI/CD pipeline. Ships in 10 seconds.**

[![PyPI](https://img.shields.io/pypi/v/squash-ai?color=brightgreen&label=pip%20install%20squash-ai)](https://pypi.org/project/squash-ai/)
[![CI](https://github.com/konjoai/squash/actions/workflows/ci.yml/badge.svg)](https://github.com/konjoai/squash/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/squash-ai)](https://pypi.org/project/squash-ai/)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Annex%20IV%20ready-green)](https://getsquash.dev)
[![Reproducibility](https://img.shields.io/badge/Bulletproof%20Edition-byte--identical-purple)](AUDIT_BASELINE.md)
[![SLSA](https://img.shields.io/badge/SLSA-Build_L3-success)](https://slsa.dev/spec/v1.0/levels)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/konjoai/squash/badge)](https://scorecard.dev/viewer/?uri=github.com/konjoai/squash)
[![Sigstore Cosign](https://img.shields.io/badge/Sigstore-cosign%20signed-blue)](https://docs.sigstore.dev/)
[![RFC 8785](https://img.shields.io/badge/canonical%20JSON-RFC%208785-yellow)](https://datatracker.ietf.org/doc/html/rfc8785)
[![RFC 3161](https://img.shields.io/badge/timestamp-RFC%203161-yellow)](https://datatracker.ietf.org/doc/html/rfc3161)

> **⏰ EU AI Act high-risk enforcement: August 2, 2026**
>
> Non-compliance: up to **€35M or 7% of global turnover.** Annex IV documentation alone takes 3–6 months manually. Squash does it in 10 seconds.

---

## See it in 10 seconds

```bash
pip install squash-ai
squash demo
```

```
────────────────────────────────────────────────────
  Squash violations, not velocity.
  Running demo attestation on sample BERT model…
────────────────────────────────────────────────────

  Model:   bert-base-uncased (sample)
  Policy:  eu-ai-act

✅ Attestation PASSED

  Artifacts generated:
    cyclonedx-mlbom.json                   48,392 bytes
    sbom.spdx.json                         22,104 bytes
    attestation.json                        3,841 bytes
    annex-iv-technical-documentation.md    18,299 bytes
    provenance.json                         1,203 bytes

────────────────────────────────────────────────────
  This is squash. It runs in CI in <10 seconds.
  pip install squash-ai && squash attest ./your-model
────────────────────────────────────────────────────
```

---

## Install

```bash
# Community (free, Apache 2.0)
pip install squash-ai

# With REST API server
pip install "squash-ai[api]"

# Full feature set
pip install "squash-ai[api,signing,sbom]"
```

---

## CI/CD in one line

### GitHub Actions

```yaml
- uses: konjoai/squash@v1
  with:
    model-path: ./my-model
    policy: eu-ai-act
    fail-on-violation: true
```

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/konjoai/squash/main/integrations/gitlab-ci/squash.gitlab-ci.yml'
```

### CLI

```bash
squash attest ./my-model \
  --policy eu-ai-act \
  --policy nist-ai-rmf \
  --sign \
  --fail-on-violation
```

Output:

```
✓ CycloneDX 1.7 ML-BOM            → cyclonedx-mlbom.json
✓ SPDX 2.3 SBOM                   → sbom.spdx.json
✓ EU AI Act Annex IV: PASS        → annex-iv.md
✓ NIST AI RMF: PASS (42/42)
✓ OWASP LLM Top 10: PASS
✓ SLSA Level 2 provenance         → provenance.json
✓ ModelScan: PASS (0 findings)
✓ Signed via Sigstore Rekor
```

---

## Why Squash

| Without Squash | With Squash |
|---------------|-------------|
| Annex IV documentation: 3–6 months | Annex IV documentation: 10 seconds |
| Compliance consultant: €150K–€400K/yr | Squash Professional: $299/month |
| Manual risk assessment per model | `squash attest ./model --policy eu-ai-act` |
| Violation discovered in audit | Violation blocked in CI before merge |
| Zero visibility | `squash_models_compliant_ratio 0.979` in Grafana |

---

## Features

| Capability | Detail |
|-----------|--------|
| **EU AI Act Annex IV** | All 12 required documentation sections, auto-generated |
| **CycloneDX 1.7 ML-BOM** | Machine-readable model bill of materials |
| **SPDX 2.3 SBOM** | Full dependency and lineage graph |
| **10+ Policy Frameworks** | EU AI Act · NIST AI RMF · ISO 42001 · OWASP LLM Top 10 · FedRAMP · CMMC |
| **ModelScan Security** | Pickle exploits, serialization attacks, unsafe ops |
| **Sigstore Signing** | Keyless signing via Rekor transparency log |
| **SLSA Provenance** | Level 1–3 provenance attestation |
| **VEX Feed** | Live CVE tracking for deployed AI model components |
| **Drift Detection** | Alerts when model behavior diverges from attested baseline |
| **Prometheus `/metrics`** | Grafana-compatible attestation counts, violations, latency |
| **Slack / Teams Alerts** | Webhook notifications on violations, drift events, CVE hits |
| **JIRA / Linear / GitHub Issues** | Auto-creates tickets on policy violations |
| **FastAPI / Django Middleware** | `X-Squash-Compliant` header on every inference response |
| **Compliance Badge** | `![Squash](https://api.getsquash.dev/badge/eu-ai-act/compliant)` |
| **`squash watch`** | Re-attests on model file change — continuous local compliance |
| **`squash install-hook`** | git pre-push hook — blocks non-compliant pushes |
| **10 MLOps Integrations** | MLflow · W&B · HuggingFace · LangChain · SageMaker · Vertex AI · Ray · Kubernetes |
| **Open-core** | Community tier free forever under Apache 2.0 |

---

## Set up a new project in 60 seconds

```bash
squash init ./my-model
# Auto-detects PyTorch / TensorFlow / JAX / MLflow / HuggingFace
# Writes .squash.yml, runs a dry-run attestation
```

---

## Compliance badge in your README

```markdown
![Squash EU AI Act compliant](https://api.getsquash.dev/badge/eu-ai-act/compliant)
```

Available statuses: `compliant` · `non-compliant` · `partial` · `unknown`  
Available frameworks: `eu-ai-act` · `nist-ai-rmf` · `iso-42001` · anything

---

## Policy Frameworks

| Framework | Status | Key Checks |
|-----------|--------|------------|
| EU AI Act (Annex IV) | ✅ Full | Technical documentation, risk classification, human oversight |
| NIST AI RMF 1.0 | ✅ Full | 42 controls: GOVERN · MAP · MEASURE · MANAGE |
| OWASP LLM Top 10 | ✅ Full | LLM01–LLM10 vulnerability categories |
| ISO 42001 | ✅ Core | Clause 6, 8, 9 |
| NTIA Minimum Elements | ✅ Full | 7 required SBOM fields |
| FedRAMP AI | ✅ Core | Federal AI procurement requirements |
| CMMC Level 2 | ✅ Core | DoD contractor AI requirements |

---

## Python API

```python
from squash import AttestPipeline, AttestConfig

result = AttestPipeline.run(AttestConfig(
    model_path="./my-model",
    policies=["eu-ai-act", "owasp-llm"],
    sign=True,
    fail_on_violation=True,
))

print(f"Passed: {result.passed}")
print(f"Attestation ID: {result.attestation_id}")
```

---

## REST API

```bash
pip install "squash-ai[api]"
uvicorn squash.api:app --host 0.0.0.0 --port 4444

curl -X POST http://localhost:4444/v1/attest \
  -H "Authorization: Bearer $SQUASH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model_path": "/models/bert-base", "policies": ["eu-ai-act"]}'
```

---

## Prometheus metrics

```
# HELP squash_attestations_total Total attestation runs
squash_attestations_total{result="passed",policy="eu-ai-act"} 142
squash_models_compliant_ratio 0.979
squash_api_latency_seconds_bucket{le="0.1"} 138
```

---

## Tiers & Pricing

| Tier | Price | Attestations/mo | Features |
|------|-------|-----------------|----------|
| **Community** | Free | 10 | Full CLI, SBOM, policy checks, signing, self-hosted |
| **Professional** | $299/mo | 200 | Cloud API, Annex IV auto-generation, drift alerts, Slack/Teams |
| **Startup** | $499/mo | 500 | Everything in Pro + VEX read, 3 users, GitHub Issues ticketing |
| **Team** | $899/mo | 1,000 | Multi-tenant, SAML SSO, HITL workflows, audit export |
| **Enterprise** | Custom | Unlimited | On-premise, air-gapped, EU data residency, dedicated support |

[Start free →](https://getsquash.dev) · [Pricing →](https://getsquash.dev/pricing)

---

## Architecture

```
squash attest ./my-model
    │
    ├── ModelScanner      → Security scan (pickle, unsafe ops, CVEs)
    ├── CycloneDXBuilder  → ML-BOM (CycloneDX 1.7)
    ├── SpdxBuilder       → SBOM (SPDX 2.3)
    ├── PolicyEngine      → EU AI Act · NIST · OWASP · ISO checks
    ├── SlsaBuilder       → SLSA Level 1–3 provenance
    ├── AnnexIVGenerator  → All 12 Annex IV sections (MD/HTML/PDF)
    ├── VexEvaluator      → Live CVE vulnerability feed
    ├── OmsSigner         → Sigstore keyless signing
    ├── DriftDetector     → Baseline behavioral comparison
    └── AttestPipeline    → Signed audit record (JSON)
```

---

## Development

```bash
git clone https://github.com/konjoai/squash
cd squash
pip install -e ".[api,signing,sbom,dev]"

# Run all tests (2,299 passing)
python -m pytest tests/ -v --timeout=120

# Try it immediately
squash demo

# Watch mode
squash watch ./my-model
```

---

## License

Community edition: [Apache 2.0](LICENSE)

Enterprise features (cloud API, multi-tenant dashboard, VEX feed, on-premise) are available under a commercial license. [Contact →](mailto:wesleyscholl@gmail.com)

---

*Built by [Konjo AI](https://konjo.ai) · "Squash violations, not velocity."*
