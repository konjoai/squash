# Read-only gate.
#
# CI ran `squash attest` and wrote master_record.json into an artefact
# bucket. Terraform just reads the result and gates a deployment on it —
# no model files reach the Terraform host.

terraform {
  required_providers {
    squash = {
      source  = "konjoai/squash"
      version = "~> 0.1"
    }
  }
}

provider "squash" {}

data "squash_compliance_score" "latest" {
  master_record_path = var.master_record_path
}

resource "squash_policy_check" "deploy_gate" {
  attestation_id = data.squash_compliance_score.latest.attestation_id
  score          = data.squash_compliance_score.latest.overall_score
  passed         = data.squash_compliance_score.latest.passed
  min_score      = 90
  require_passed = true
}

variable "master_record_path" {
  type        = string
  description = "Path to the master_record.json produced by `squash attest --json-result ...`"
}

output "score" {
  value = data.squash_compliance_score.latest.overall_score
}

output "top_frameworks" {
  value = data.squash_compliance_score.latest.top_frameworks
}
