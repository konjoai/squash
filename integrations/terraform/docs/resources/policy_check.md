---
page_title: "squash_policy_check Resource — squash"
description: |-
  Declarative compliance gate. Fails terraform apply when an attestation
  drops below a minimum score or fails a required pass-state.
---

# squash_policy_check (Resource)

A declarative gate over a `squash_attestation` (or
`squash_compliance_score` data source). The gate does no I/O of its own
— it consumes `score` and `passed` and fails the apply when thresholds
are not met. This makes compliance regressions block every dependent
resource in the same plan.

## Example

```hcl
resource "squash_policy_check" "gate" {
  attestation_id = squash_attestation.phi3.attestation_id
  score          = squash_attestation.phi3.overall_score
  passed         = squash_attestation.phi3.passed
  min_score      = 85
  require_passed = true
}

# Downstream resources reference the gate so a failure blocks them all.
resource "kubernetes_deployment" "inference" {
  depends_on = [squash_policy_check.gate]
  # ...
}
```

## Argument Reference

* `attestation_id` (String, required) — attestation being gated.
* `score` (Number, required) — score reported by the attestation.
* `passed` (Bool, required) — pass-state of the attestation.
* `min_score` (Number, optional) — minimum acceptable score (0-100).
* `require_passed` (Bool, optional) — if true, fail when `passed = false`.

## Attribute Reference

* `id` (String) — `gate-<attestation_id>`.
* `result` (String) — human-readable gate result.
