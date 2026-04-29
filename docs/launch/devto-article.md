# How We Automated EU AI Act Compliance in a CI/CD Pipeline

**Target publication:** Dev.to · July 15, 2026  
**Tags:** `python`, `ai`, `devops`, `compliance`  
**Reading time:** ~8 minutes

---

## Draft

---

The EU AI Act high-risk enforcement deadline is August 2, 2026. If your team builds or deploys AI systems in Europe — or to European users — you need Annex IV technical documentation for every high-risk AI system.

Annex IV has 12 required sections:

1. General description of the AI system
2. Description of elements and development process
3. Detailed description of monitoring, functioning, and control
4. Description of appropriateness of performance metrics
5. Risk management documentation
6. Description of data governance
7. Description of human oversight measures
8. Description of cybersecurity measures
9. List of technical standards applied
10. Measures to achieve energy efficiency
11. Life cycle and audit trail documentation
12. Post-market monitoring plan

Producing this manually takes 3–6 months per AI system. Most ML teams don't have that kind of time — and the fine for non-compliance is up to €35 million or 7% of global annual turnover.

So I built [Squash](https://github.com/konjoai/squash) to automate it.

---

## What squash does in 10 seconds

```bash
pip install squash-ai
squash attest ./my-model --policy eu-ai-act
```

This produces:

- **CycloneDX 1.7 ML-BOM** — machine-readable model bill of materials
- **SPDX 2.3 SBOM** — full software dependency and lineage graph
- **All 12 Annex IV sections** — as Markdown, HTML, and PDF
- **SLSA Level 2 provenance** — cryptographic chain of custody
- **Policy evaluation** — pass/fail against EU AI Act criteria
- **Sigstore signing** — keyless signing via Rekor transparency log
- **ModelScan results** — security check for pickle exploits, unsafe ops

---

## The CI/CD integration

Here's the GitHub Actions integration:

```yaml
- name: Squash compliance gate
  uses: konjoai/squash@v1
  with:
    model-path: ./my-model
    policy: eu-ai-act
    fail-on-violation: true
    sign: true
    annex-iv: true
```

This blocks the merge if the model fails EU AI Act policy checks. The Annex IV documentation is generated as an artifact attached to every workflow run.

For GitLab CI:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/konjoai/squash/main/integrations/gitlab-ci/squash.gitlab-ci.yml'

squash_attest:
  extends: .squash_attest
  variables:
    SQUASH_POLICY: "eu-ai-act"
    SQUASH_FAIL_ON_VIOLATION: "true"
```

For Jenkins:

```groovy
squashAttest(
  modelPath: "./models",
  policies: ["eu-ai-act", "nist-ai-rmf"],
  failOnViolation: true
)
```

---

## The Python API

If you prefer to integrate programmatically:

```python
from squash import AttestPipeline, AttestConfig

result = AttestPipeline.run(AttestConfig(
    model_path="./my-model",
    policies=["eu-ai-act", "nist-ai-rmf"],
    sign=True,
    fail_on_violation=True,
    annex_iv=True,
))

if not result.passed:
    print("Policy violations:")
    for v in result.violations:
        print(f"  - {v.policy}: {v.description}")
    sys.exit(1)
```

---

## The framework middleware

One thing I wanted to get right was making compliance visible at the infrastructure level, not just in CI. Here's how to add it to a FastAPI inference server:

```python
from squash.middleware import SquashComplianceMiddleware

app = FastAPI()
app.add_middleware(
    SquashComplianceMiddleware,
    model_id="bert-base-v2",
    attestation_path="./attestation/cyclonedx.json",
    block_on_missing=True,  # Returns 503 if attestation missing
)
```

Every inference response now includes:

```
X-Squash-Compliant: true
X-Squash-Model: bert-base-v2
X-Squash-Policy: eu-ai-act
X-Squash-Attested-At: 2026-07-01T12:00:00Z
```

When a model's attestation expires or a new CVE is flagged, the middleware automatically switches to `X-Squash-Compliant: false` and optionally returns 503.

---

## Prometheus metrics

The REST API exposes a `/metrics` endpoint in Prometheus text format:

```bash
curl https://api.getsquash.dev/metrics
```

```
# HELP squash_attestations_total Total attestation runs
# TYPE squash_attestations_total counter
squash_attestations_total{result="passed",policy="eu-ai-act"} 142
squash_attestations_total{result="failed",policy="eu-ai-act"} 3

# HELP squash_models_compliant_ratio Ratio of compliant models
# TYPE squash_models_compliant_ratio gauge
squash_models_compliant_ratio 0.979

# HELP squash_api_latency_seconds HTTP response latency
# TYPE squash_api_latency_seconds histogram
squash_api_latency_seconds_bucket{le="0.1",method="POST",endpoint="/v1/attest"} 138
```

Wire this to Grafana and your compliance posture becomes a dashboard tile, not a separate login.

---

## How the Annex IV generator works

The interesting engineering challenge was generating structured Annex IV documentation from model artifacts — without hallucinating content.

The generator reads actual artifacts:
- `config.json` → model architecture, parameter count
- `training_config.json` → training data, hyperparameters, epochs
- `requirements.txt` → dependency graph
- `*.safetensors` / `*.bin` → model format, compression
- MLflow/W&B run metadata → experiment tracking, data lineage

Each Annex IV section maps to specific artifacts. Section 5 (risk management) is generated from the ModelScan results, CVE feed data, and a configurable risk matrix. Section 6 (data governance) pulls from training metadata and data lineage records. Section 7 (human oversight) is the only section that requires human input — squash scaffolds it with prompts.

The generator produces structured Markdown that can be reviewed by a human, signed off by a compliance officer, then stored alongside the model artifact. The whole cycle is 10–15 minutes versus 3–6 months.

---

## The drift detection

One capability I'm particularly proud of is the drift detector. EU AI Act Article 72 requires post-market monitoring — detecting when a model's actual behavior diverges from its documented performance.

```bash
# Establish baseline
squash attest ./model-v1 --policy eu-ai-act

# Later, check drift
squash drift-check ./model-v1 ./model-v2

# Or watch continuously
squash watch ./models --interval 60 --on-fail notify
```

When drift is detected, squash fires a Slack notification and auto-creates a JIRA ticket if configured. It's the difference between catching behavioral drift in development versus in production.

---

## Open-core: what's free, what's paid

Everything core is Apache 2.0:
- Full CLI (`squash attest`, `demo`, `init`, `watch`, `install-hook`)
- All policy checks (EU AI Act, NIST AI RMF, OWASP LLM, ISO 42001, FedRAMP)
- CycloneDX + SPDX generation
- Sigstore signing
- Annex IV generator
- Self-hosted REST API

Paid features ($299–$899/month):
- Cloud-hosted REST API with managed auth
- Multi-tenant dashboard
- Live VEX feed (CVE tracking per deployed model)
- SAML SSO
- SLA support

---

## The timeline

If you're building or deploying AI in Europe and haven't started Annex IV documentation:

- **Now:** `pip install squash-ai && squash demo`
- **Today:** `squash init ./my-model` — scaffold `.squash.yml`, dry-run attestation
- **This week:** `squash attest ./my-model --policy eu-ai-act` in CI/CD
- **August 2:** Enforcement day — squash users are compliant

The tool is at [github.com/konjoai/squash](https://github.com/konjoai/squash). I'm answering questions in the comments.

---

## About the author

I'm Wesley Scholl, founder of Konjo AI. We build developer tools for frontier AI teams. Squash is open-core, Apache 2.0. The cloud tier pays for the development.

---

*Post this the day after the HN Show HN for maximum cross-platform reach. Reference the HN discussion in the article.*
