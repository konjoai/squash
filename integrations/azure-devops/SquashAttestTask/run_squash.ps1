# run_squash.ps1 — Squash attestation task for Azure Pipelines (Windows / Linux / macOS)
# Reads Azure DevOps task inputs and emits ##vso logging commands.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TaskInput {
    param([string]$Name, [string]$Default = "")
    $envName = "INPUT_$($Name.ToUpper())"
    $val = [System.Environment]::GetEnvironmentVariable($envName)
    if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
    return $val.Trim()
}

$ModelPath       = Get-TaskInput "modelPath"
$Policies        = Get-TaskInput "policies" "eu-ai-act"
$Sign            = Get-TaskInput "sign" "false"
$FailOnViolation = Get-TaskInput "failOnViolation" "true"
$OutputDir       = Get-TaskInput "outputDir" ""

if ([string]::IsNullOrWhiteSpace($ModelPath)) {
    Write-Error "modelPath input is required"
    exit 1
}

# Install squash-ai (the EU AI Act compliance toolkit)
# Optional companion: pip install squish  (Apple Silicon inference server)
pip install squash-ai --quiet

# Build CLI argument list
$Args = @("attest", $ModelPath)
foreach ($policy in ($Policies -split ',')) {
    $trimmed = $policy.Trim()
    if ($trimmed) { $Args += @("--policy", $trimmed) }
}

if ($Sign -eq "true") { $Args += "--sign" }
if ($OutputDir) { $Args += @("--output-dir", $OutputDir) }

$ResultFile = if ($OutputDir) { "$OutputDir/squash-result.json" } else { "squash-result.json" }
$Args += @("--json-result", $ResultFile)

# Run attestation
$ExitCode = 0
try {
    & squash @Args
    $ExitCode = $LASTEXITCODE
} catch {
    $ExitCode = 1
}

$Passed = if ($ExitCode -eq 0) { "true" } else { "false" }

# Parse artifact paths from result JSON
$ScanStatus      = "unknown"
$CyclonedxPath   = ""
$SpdxJsonPath    = ""
$MasterRecordPath = ""

if (Test-Path $ResultFile) {
    $result = Get-Content $ResultFile | ConvertFrom-Json
    $ScanStatus       = if ($result.scan_status)       { $result.scan_status }       else { "unknown" }
    $CyclonedxPath    = if ($result.cyclonedx_path)    { $result.cyclonedx_path }    else { "" }
    $SpdxJsonPath     = if ($result.spdx_json_path)    { $result.spdx_json_path }    else { "" }
    $MasterRecordPath = if ($result.master_record_path){ $result.master_record_path } else { "" }
}

# Emit Azure DevOps output variables
Write-Host "##vso[task.setvariable variable=SQUASH_PASSED;isOutput=true]$Passed"
Write-Host "##vso[task.setvariable variable=SQUASH_SCAN_STATUS;isOutput=true]$ScanStatus"
Write-Host "##vso[task.setvariable variable=SQUASH_CYCLONEDX_PATH;isOutput=true]$CyclonedxPath"
Write-Host "##vso[task.setvariable variable=SQUASH_SPDX_JSON_PATH;isOutput=true]$SpdxJsonPath"
Write-Host "##vso[task.setvariable variable=SQUASH_MASTER_RECORD_PATH;isOutput=true]$MasterRecordPath"

# Complete the task
if ($FailOnViolation -eq "true" -and $Passed -eq "false") {
    Write-Host "##vso[task.complete result=Failed;]Squash attestation failed — policy violations detected"
    exit 1
}

Write-Host "##vso[task.complete result=Succeeded;]Squash attestation passed (policies: $Policies)"
