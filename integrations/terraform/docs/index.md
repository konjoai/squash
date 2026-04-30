---
page_title: "Squash Provider"
description: |-
  Automated EU AI Act, NIST AI RMF, and ISO 42001 compliance attestation
  for ML models, as Terraform resources.
---

# Squash Provider

The `squash` provider turns AI model compliance into a Terraform resource.
Every `terraform apply` produces an attestation: a signed, auditable
record of which compliance frameworks the model satisfies, what its SBOM
looks like, and where the artefacts live on disk.

Squash is the Python CLI [`konjoai/squash`](https://github.com/konjoai/squash).
This provider wraps it — the CLI is the source of truth, the provider is
the declarative front-end.

## Why Terraform?

* **GitOps-native gating.** A regression in compliance score blocks the
  apply, which blocks every dependent deployment, image promotion, or
  API gateway rule. No external admission controller required.
* **Single source of truth.** The same SBOM/policy logic that runs in CI
  runs from `terraform apply` — no parallel implementation to keep in sync.
* **Multi-language reach.** This provider is the foundation for the
  Pulumi bridge — see [`pulumi/`](https://github.com/konjoai/squash/tree/main/integrations/terraform/pulumi).

## Example

```hcl
terraform {
  required_providers {
    squash = {
      source  = "konjoai/squash"
      version = "~> 0.1"
    }
  }
}

provider "squash" {
  policy = "eu-ai-act"
}

resource "squash_attestation" "phi3" {
  model_path        = "./models/phi-3"
  policies          = ["eu-ai-act", "iso-42001"]
  sign              = true
  fail_on_violation = true
}

resource "squash_policy_check" "gate" {
  attestation_id = squash_attestation.phi3.attestation_id
  score          = squash_attestation.phi3.overall_score
  passed         = squash_attestation.phi3.passed
  min_score      = 85
  require_passed = true
}
```

## Authentication

The provider shells out to the `squash` CLI. Authentication for the
optional Squash cloud API is forwarded via `SQUASH_API_KEY`:

```hcl
provider "squash" {
  api_key = var.squash_api_key  # or set $SQUASH_API_KEY in the environment
}
```

For air-gapped runs:

```hcl
provider "squash" {
  offline = true  # disables OIDC / network — uses local Ed25519 keypair for signing
}
```

## Schema

### Optional

* `cli_path` — path to the `squash` binary. Defaults to `squash` on
  `$PATH`. Env: `SQUASH_CLI_PATH`.
* `models_dir` — default directory for model lookups. Env:
  `SQUASH_MODELS_DIR`.
* `policy` — default policy applied when a resource omits its own.
* `api_key` — Squash cloud API key. Env: `SQUASH_API_KEY`. Sensitive.
* `offline` — air-gapped mode. Env: `SQUASH_OFFLINE=1`.
