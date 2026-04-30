# terraform-provider-squash

> **Compliance as infrastructure.** A Terraform provider that wraps the
> [`squash`](https://github.com/konjoai/squash) CLI to make EU AI Act,
> NIST AI RMF, and ISO 42001 attestation a first-class resource type.

[![Konjo](https://img.shields.io/badge/built-konjo-1e40af)](https://github.com/konjoai)

## What it does

```hcl
resource "squash_attestation" "phi3" {
  model_path = "./models/phi-3"
  policies   = ["eu-ai-act", "iso-42001"]
  sign       = true
}

resource "squash_policy_check" "gate" {
  attestation_id = squash_attestation.phi3.attestation_id
  score          = squash_attestation.phi3.overall_score
  passed         = squash_attestation.phi3.passed
  min_score      = 85
  require_passed = true
}
```

`terraform apply` runs `squash attest`, signs the SBOM, and stores the
attestation ID in state. A score regression fails the gate, which blocks
every downstream resource — model deployments, image promotions, API
gateway rules, anything that `depends_on` the gate.

The same primitives work via Pulumi today through
[`@pulumi/command`](./pulumi/) and via the official Pulumi Terraform
bridge once this provider is published to the Registry.

## Resources

| Type                       | Purpose                                              |
| -------------------------- | ---------------------------------------------------- |
| `squash_attestation`       | Run `squash attest`; track signed attestation state. |
| `squash_policy_check`      | Declarative compliance gate over score / pass-state. |

## Data Sources

| Type                       | Purpose                                              |
| -------------------------- | ---------------------------------------------------- |
| `squash_compliance_score`  | Read an existing `master_record.json`.               |

## Architecture

```
┌─────────────────────────┐
│  Terraform / Pulumi     │
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│  internal/provider      │  schema, plan, state — terraform-plugin-framework
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│  internal/squashcli     │  stdlib-only — argv builder, JSON parser, exec wrapper
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│  squash CLI (Python)    │  the single source of truth
└─────────────────────────┘
```

The provider is intentionally thin. All compliance logic lives in the
squash CLI so there is exactly one implementation to audit, one set of
policies to maintain, and one binary to ship to air-gapped sites.

The `internal/squashcli` package has zero external dependencies — it
builds and tests offline. This is what makes the provider safe to ship
to FedRAMP / CMMC environments.

## Build / Install

```bash
make build            # ./terraform-provider-squash
make install          # → ~/.terraform.d/plugins/registry.terraform.io/konjoai/squash/<ver>/<os_arch>
make test             # all tests (requires HashiCorp deps fetched)
make test-core        # stdlib-only tests (offline)
```

## Provider Configuration

| Field        | Env                     | Default              | Notes                                      |
| ------------ | ----------------------- | -------------------- | ------------------------------------------ |
| `cli_path`   | `SQUASH_CLI_PATH`       | `squash` on `$PATH`  |                                            |
| `models_dir` | `SQUASH_MODELS_DIR`     | unset                |                                            |
| `policy`     | —                       | unset                | Default per-resource policy.               |
| `api_key`    | `SQUASH_API_KEY`        | unset                | Forwarded to CLI; sensitive.               |
| `offline`    | `SQUASH_OFFLINE=1`      | `false`              | Air-gapped — no OIDC, no network.          |

## Examples

* [`examples/basic`](./examples/basic) — single model, signed, gated.
* [`examples/multi-model-gate`](./examples/multi-model-gate) — `for_each` over a registry.
* [`examples/data-source-gate`](./examples/data-source-gate) — gate on a CI-produced record.
* [`pulumi/examples/typescript`](./pulumi/examples/typescript) — Pulumi via `@pulumi/command`.
* [`pulumi/examples/python`](./pulumi/examples/python) — same, in Python.

## Konjo

This provider is small on purpose. Every line earns its keep:

* **건조 — strip to essence.** No reimplemented SBOM logic. The CLI is the
  source of truth; the provider is a typed declarative front-end.
* **ᨀᨚᨐᨚ — seaworthy.** Stdlib-only core; offline test target; tests run
  in <1s. Built to carry real workloads in air-gapped environments.
* **康宙 — health of the universe.** No goroutine sprawl, no
  background workers, no daemons. One process per `terraform apply`.
* **কুঞ্জ — the garden.** Schema, examples, and docs are written for the
  next person — auditor, platform engineer, or AI agent — to land here
  and ship.

## License

MIT — see the parent [`squash`](https://github.com/konjoai/squash) repo.
