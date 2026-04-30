# Multi-model deployment gate.
#
# A model registry where every promotion to production goes through the
# same compliance gate as code. The K8s deployment refuses to apply when
# any model in the bundle drops below threshold or fails its gating
# policies — blast radius is the apply, not production traffic.

terraform {
  required_providers {
    squash = {
      source  = "konjoai/squash"
      version = "~> 0.1"
    }
  }
}

provider "squash" {
  policy = "enterprise-strict"
}

locals {
  models = {
    phi3   = { path = "./models/phi-3",   hf = "microsoft/phi-3",          quant = "INT4" }
    llama  = { path = "./models/llama-3", hf = "meta-llama/Llama-3.1-8B",  quant = "INT4" }
    mistral = { path = "./models/mistral", hf = "mistralai/Mistral-7B-v0.3", quant = "BF16" }
  }
}

resource "squash_attestation" "model" {
  for_each = local.models

  model_path   = each.value.path
  hf_repo      = each.value.hf
  quant_format = each.value.quant
  policies     = ["eu-ai-act", "nist-ai-rmf", "iso-42001"]
  sign         = true
}

resource "squash_policy_check" "gate" {
  for_each = squash_attestation.model

  attestation_id = each.value.attestation_id
  score          = each.value.overall_score
  passed         = each.value.passed
  min_score      = 85
  require_passed = true
}

# Downstream resources depend on the gate.
# A score regression in any model → apply fails → no deploy.
output "all_attested" {
  value = {
    for k, v in squash_attestation.model :
    k => v.attestation_id
  }
}

output "gate_results" {
  value = {
    for k, v in squash_policy_check.gate :
    k => v.result
  }
}
