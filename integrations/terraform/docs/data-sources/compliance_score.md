---
page_title: "squash_compliance_score Data Source — squash"
description: |-
  Read an existing squash master attestation record without re-running
  the pipeline.
---

# squash_compliance_score (Data Source)

Read an existing `master_record.json` produced by `squash attest
--json-result <path>` and expose its scores. Use when an attestation was
produced outside Terraform (e.g. by CI) but a downstream Terraform
resource should refuse to apply if the latest score is below threshold.

## Example

```hcl
data "squash_compliance_score" "latest" {
  master_record_path = "/var/lib/ci/last-attestation.json"
}

resource "squash_policy_check" "deploy_gate" {
  attestation_id = data.squash_compliance_score.latest.attestation_id
  score          = data.squash_compliance_score.latest.overall_score
  passed         = data.squash_compliance_score.latest.passed
  min_score      = 90
  require_passed = true
}
```

## Argument Reference

* `master_record_path` (String, required) — path to a master attestation
  JSON file.

## Attribute Reference

* `attestation_id` (String).
* `overall_score` (Number).
* `passed` (Bool).
* `generated_at` (String).
* `framework_scores` (Map of Number) — per-framework breakdown.
* `top_frameworks` (List of String) — up to three highest-scoring
  frameworks, descending.
