terraform {
  required_providers {
    squash = {
      source  = "konjoai/squash"
      version = "~> 0.1"
    }
  }
}

provider "squash" {
  # Defaults to `squash` on $PATH. Override per-environment if needed:
  # cli_path = "/usr/local/bin/squash"
  policy = "eu-ai-act"
}

resource "squash_attestation" "phi3" {
  model_path        = "${path.module}/../../models/phi-3"
  policies          = ["eu-ai-act", "iso-42001"]
  hf_repo           = "microsoft/phi-3"
  quant_format      = "INT4"
  sign              = true
  fail_on_violation = true
}

resource "squash_policy_check" "phi3_gate" {
  attestation_id = squash_attestation.phi3.attestation_id
  score          = squash_attestation.phi3.overall_score
  passed         = squash_attestation.phi3.passed
  min_score      = 80
  require_passed = true
}

output "phi3_score" {
  value = squash_attestation.phi3.overall_score
}

output "phi3_attestation_id" {
  value = squash_attestation.phi3.attestation_id
}
