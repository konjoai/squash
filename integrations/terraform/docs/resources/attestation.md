---
page_title: "squash_attestation Resource — squash"
description: |-
  Run squash attest against a model artefact and track the attestation
  as Terraform-managed state.
---

# squash_attestation (Resource)

Runs `squash attest` against a model directory or file. The resource ID
is the squash-issued attestation ID — a stable, audit-grade identifier.

A change to `model_path` triggers a replacement (a new attestation),
which preserves an immutable provenance trail. Squash attestations are
never deleted by `terraform destroy` — squash is a write-once provenance
ledger; removing from state is sufficient.

## Example

```hcl
resource "squash_attestation" "phi3" {
  model_path        = "./models/phi-3"
  policies          = ["eu-ai-act", "iso-42001"]
  hf_repo           = "microsoft/phi-3"
  quant_format      = "INT4"
  sign              = true
  fail_on_violation = true
}
```

## Argument Reference

### Required

* `model_path` (String) — path to the model directory or file. Forces
  replacement on change.

### Optional

* `model_id` (String) — override the model ID embedded in the SBOM.
* `policies` (List of String) — policy names to evaluate. E.g.
  `["eu-ai-act", "nist-ai-rmf", "iso-42001"]`.
* `output_dir` (String) — directory for SBOM/signature artefacts.
* `hf_repo` (String) — HuggingFace `org/name` repo ID for provenance.
* `quant_format` (String) — quantization label (e.g. `INT4`, `BF16`).
* `sign` (Bool) — sign the SBOM via Sigstore keyless (or offline
  Ed25519 if `provider.offline = true`).
* `fail_on_violation` (Bool) — fail `terraform apply` if any policy
  gate trips.
* `skip_scan` (Bool) — skip the security scanner stage.

## Attribute Reference

* `id` / `attestation_id` (String) — squash-issued attestation ID.
* `overall_score` (Number) — weighted compliance score 0-100.
* `passed` (Bool) — true if all gating policies passed.
* `generated_at` (String) — ISO-8601 timestamp.
* `squash_version` (String) — squash CLI version.
* `cyclonedx_path`, `spdx_json_path`, `master_record_path`,
  `signature_path` (String) — artefact paths.
* `framework_scores` (Map of Number) — per-framework breakdown.

## Import

Existing attestations can be imported by their master record path:

```bash
terraform import squash_attestation.phi3 /path/to/master_record.json
```
