#!/usr/bin/env bash
# run_squash.sh — Squash attestation task for Azure Pipelines (Linux / macOS)
# Reads Azure DevOps task inputs via INPUT_* env vars and emits ##vso logging commands.
set -euo pipefail

MODEL_PATH="${INPUT_MODELPATH:?INPUT_MODELPATH is required}"
POLICIES="${INPUT_POLICIES:-eu-ai-act}"
SIGN="${INPUT_SIGN:-false}"
FAIL_ON_VIOLATION="${INPUT_FAILONVIOLATION:-true}"
OUTPUT_DIR="${INPUT_OUTPUTDIR:-}"

# Install squash-ai (the EU AI Act compliance toolkit)
# Optional companion: pip install squish  (Apple Silicon inference server)
pip install squash-ai --quiet

# Build CLI argument list
ARGS=("attest" "$MODEL_PATH")
IFS=',' read -ra POLICY_LIST <<< "$POLICIES"
for policy in "${POLICY_LIST[@]}"; do
  trimmed="${policy// /}"
  [[ -n "$trimmed" ]] && ARGS+=("--policy" "$trimmed")
done

if [[ "${SIGN,,}" == "true" ]]; then
  ARGS+=("--sign")
fi

if [[ -n "$OUTPUT_DIR" ]]; then
  ARGS+=("--output-dir" "$OUTPUT_DIR")
fi

ARGS+=("--json-result" "${OUTPUT_DIR:-.}/squash-result.json")

# Run attestation
set +e
squash "${ARGS[@]}"
EXIT_CODE=$?
set -e

PASSED="false"
[[ $EXIT_CODE -eq 0 ]] && PASSED="true"

# Parse artifact paths from result JSON
RESULT_JSON="${OUTPUT_DIR:-.}/squash-result.json"
SCAN_STATUS="unknown"
CYCLONEDX_PATH=""
SPDX_JSON_PATH=""
MASTER_RECORD_PATH=""

if [[ -f "$RESULT_JSON" ]]; then
  SCAN_STATUS=$(python3 -c "import json,sys; d=json.load(open('$RESULT_JSON')); print(d.get('scan_status','unknown'))" 2>/dev/null || echo "unknown")
  CYCLONEDX_PATH=$(python3 -c "import json,sys; d=json.load(open('$RESULT_JSON')); print(d.get('cyclonedx_path',''))" 2>/dev/null || echo "")
  SPDX_JSON_PATH=$(python3 -c "import json,sys; d=json.load(open('$RESULT_JSON')); print(d.get('spdx_json_path',''))" 2>/dev/null || echo "")
  MASTER_RECORD_PATH=$(python3 -c "import json,sys; d=json.load(open('$RESULT_JSON')); print(d.get('master_record_path',''))" 2>/dev/null || echo "")
fi

# Emit Azure DevOps output variables
echo "##vso[task.setvariable variable=SQUASH_PASSED;isOutput=true]${PASSED}"
echo "##vso[task.setvariable variable=SQUASH_SCAN_STATUS;isOutput=true]${SCAN_STATUS}"
echo "##vso[task.setvariable variable=SQUASH_CYCLONEDX_PATH;isOutput=true]${CYCLONEDX_PATH}"
echo "##vso[task.setvariable variable=SQUASH_SPDX_JSON_PATH;isOutput=true]${SPDX_JSON_PATH}"
echo "##vso[task.setvariable variable=SQUASH_MASTER_RECORD_PATH;isOutput=true]${MASTER_RECORD_PATH}"

# Complete the task
if [[ "${FAIL_ON_VIOLATION,,}" == "true" && "$PASSED" == "false" ]]; then
  echo "##vso[task.complete result=Failed;]Squash attestation failed — policy violations detected"
  exit 1
fi

echo "##vso[task.complete result=Succeeded;]Squash attestation passed (policies: ${POLICIES})"
