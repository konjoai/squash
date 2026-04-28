# Squash — Automated EU AI Act Compliance

**Squash automates EU AI Act compliance so ML teams spend engineering time building, not documenting.**

[![CI](https://github.com/konjoai/squash/actions/workflows/ci.yml/badge.svg)](https://github.com/konjoai/squash/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/squash-ai)](https://pypi.org/project/squash-ai/)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/squash-ai)](https://pypi.org/project/squash-ai/)

> ⏰ **EU AI Act high-risk enforcement: August 2, 2026**

---

## What Squash Does

Squash generates your **Annex IV technical documentation**, runs **policy checks** against 10+ regulatory frameworks, and produces **cryptographically signed audit records** — all inside your CI/CD pipeline.

```bash
pip install squash-ai
squash attest ./my-model --policy eu-ai-act
```

```
✓ CycloneDX 1.7 ML-BOM generated    → ./my-model/cyclonedx-mlbom.json
✓ SPDX 2.3 SBOM generated           → ./my-model/sbom.spdx.json
✓ EU AI Act policy: PASS (18/18)    → ./my-model/attestation.json
✓ OWASP LLM Top 10: PASS (10/10)
✓ NIST AI RMF: PASS (42/42 controls)
✓ SLSA Level 2 provenance           → ./my-model/provenance.json
✓ ModelScan security: PASS (0 findings)
✓ Signed via Sigstore Rekor
```

---

## Why Squash

| Problem | Cost |
|---------|------|
| Annex IV documentation (manual) | 3–6 months engineering time |
| Non-compliance fine | up to €35M or 7% of global turnover |
| Compliance consultant (typical) | €150K–€400K/year per AI system |
| **Squash (automated)** | **< 5 seconds in CI/CD** |

---

## Features

| Capability | Detail |
|-----------|--------|
| **EU AI Act Annex IV** | Auto-generates all 12 required documentation sections |
| **CycloneDX 1.7 ML-BOM** | Machine-readable model bill of materials |
| **SPDX 2.3 SBOM** | Full dependency and lineage graph |
| **10+ Policy Frameworks** | EU AI Act · NIST AI RMF · ISO 42001 · OWASP LLM Top 10 · FedRAMP · CMMC · NTIA |
| **ModelScan Security** | Detects pickle exploits, serialization attacks, unsafe ops |
| **Sigstore Signing** | Keyless signing via Rekor transparency log |
| **SLSA Provenance** | Level 1–3 provenance attestation |
| **VEX Feed** | Live vulnerability tracking for AI model components |
| **Drift Detection** | Alerts when model behavior diverges from attested baseline |
| **10 MLOps Integrations** | MLflow · W&B · HuggingFace · LangChain · SageMaker · Vertex AI · Ray · Kubernetes · Azure DevOps · CircleCI |
| **Open-core** | Community tier free and self-hostable under Apache 2.0 |

---

## Installation

```bash
# Community (free, Apache 2.0)
pip install squash-ai

# With REST API server
pip install "squash-ai[api]"

# With cryptographic signing
pip install "squash-ai[signing,sbom]"

# All features
pip install "squash-ai[all]"
```

---

## Quick Start

### CLI attestation

```bash
squash attest ./my-model \
  --policy eu-ai-act \
  --policy nist-ai-rmf \
  --sign \
  --fail-on-violation
```

### GitHub Actions

```yaml
- name: Squash compliance gate
  uses: konjoai/squash-action@v1
  with:
    model-path: ./my-model
    policy: eu-ai-act
    fail-on-violation: true
```

### Python API

```python
from squash import AttestPipeline, AttestConfig

config = AttestConfig(
    model_path="./my-model",
    policies=["eu-ai-act", "owasp-llm"],
    sign=True,
)
result = AttestPipeline(config).run()
print(f"Policy: {'PASS' if result.passed else 'FAIL'}")
print(f"Attestation ID: {result.attestation_id}")
```

### REST microservice

```bash
uvicorn squash.api:app --host 0.0.0.0 --port 4444
curl -X POST http://localhost:4444/v1/attest \
  -H "Authorization: Bearer $SQUASH_API_KEY" \
  -d '{"model_path": "/models/my-model", "policies": ["eu-ai-act"]}'
```

---

## Policy Frameworks

| Framework | Status | Key Checks |
|-----------|--------|------------|
| EU AI Act (Annex IV) | ✅ Full | Technical documentation, risk classification, human oversight |
| NIST AI RMF 1.0 | ✅ Full | 42 controls across GOVERN · MAP · MEASURE · MANAGE |
| OWASP LLM Top 10 | ✅ Full | LLM01–LLM10 vulnerability categories |
| ISO 42001 | ✅ Core | Clause 6 (Planning), Clause 8 (Operation), Clause 9 (Evaluation) |
| NTIA Minimum Elements | ✅ Full | 7 required SBOM fields |
| FedRAMP AI | 🔄 Sprint 2 | Federal AI procurement requirements |
| CMMC Level 2 | 🔄 Sprint 2 | DoD contractor AI requirements |

---

## Tiers & Pricing

| Tier | Price | Attestations/mo | Features |
|------|-------|-----------------|----------|
| **Community** | Free | 10 | Full CLI, SBOM, policy checks, signing, self-hosted |
| **Professional** | $299/mo | 200 | Cloud API, Annex IV auto-generation, drift alerts, audit export |
| **Team** | $899/mo | 1,000 | Multi-tenant dashboard, VEX feed, SAML SSO, HITL workflows |
| **Enterprise** | Custom | Unlimited | On-premise, air-gapped, dedicated support, EU data residency |

[See full pricing →](https://getsquash.dev/pricing)

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
    ├── VexEvaluator      → Live vulnerability feed
    ├── OmsSigner         → Sigstore keyless signing
    └── AttestPipeline    → Signed audit record (JSON)
```

---

## Integration with Squish

Squash and [Squish](https://github.com/konjoai/squish) form the complete AI deployment stack for regulated environments:

```bash
# Build and compress with Squish
squish compress ./my-model --quant int4

# Gate on compliance with Squash
squash attest ./my-model --policy eu-ai-act --sign

# Deploy with confidence
```

Squish handles Apple Silicon inference optimization. Squash handles compliance. Different buyers, different toolchains, one ecosystem.

---

## Development

```bash
git clone https://github.com/konjoai/squash
cd squash
pip install -e ".[api,signing,sbom,dev]"

# Run tests
python -m pytest tests/ -v --timeout=120

# Run a specific wave's tests
python -m pytest tests/test_squash_wave83.py -v
```

---

## License

Community edition: [Apache 2.0](LICENSE)

Enterprise features (cloud API, multi-tenant dashboard, VEX feed subscription, on-premise deployment) are available under a commercial license. [Contact us →](mailto:wesleyscholl@gmail.com)

---

*Built by [Konjo AI](https://konjo.ai) · Make it konjo — build, ship, rest, repeat.*
