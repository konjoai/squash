/**
 * squashAttest — Jenkins shared library step for EU AI Act compliance attestation.
 *
 * Usage in a Jenkinsfile:
 *
 *   @Library('squash') _
 *
 *   pipeline {
 *     agent any
 *     stages {
 *       stage('Attest') {
 *         steps {
 *           squashAttest modelPath: './models/llama-3-8b',
 *                        policies: 'eu-ai-act,nist-ai-rmf',
 *                        failOnViolation: true
 *         }
 *       }
 *     }
 *   }
 *
 * Parameters:
 *   modelPath        — (required) Path to the model directory or artifact.
 *   policies         — Comma-separated policy list. Default: 'eu-ai-act'.
 *   sign             — Enable Sigstore signing. Default: false.
 *   failOnViolation  — Fail the build on policy violation. Default: true.
 *   outputDir        — Override artifact output directory.
 *   annexIv          — Generate Annex IV documentation. Default: false.
 *   squashVersion    — Pin squash-ai version. Default: '' (latest).
 *   apiKey           — Squash Cloud API key credential ID (Jenkins credential ID).
 *
 * Outputs (stashed as 'squash-attestation'):
 *   squash_result.json, BOM files, policy reports, and optional Annex IV docs.
 */
def call(Map params = [:]) {
    def modelPath       = params.modelPath        ?: error('squashAttest: modelPath is required')
    def policies        = params.policies         ?: 'eu-ai-act'
    def sign            = params.sign             ?: false
    def failOnViolation = params.containsKey('failOnViolation') ? params.failOnViolation : true
    def outputDir       = params.outputDir        ?: ''
    def annexIv         = params.annexIv          ?: false
    def squashVersion   = params.squashVersion    ?: ''
    def apiKeyId        = params.apiKey           ?: ''

    def extraFlags = []
    if (sign)            extraFlags << '--sign'
    if (!failOnViolation) extraFlags << '--no-fail-on-violation'
    if (outputDir)       extraFlags << "--output-dir '${outputDir}'"

    policies.split(',').each { p ->
        extraFlags << "--policy ${p.trim()}"
    }

    def installCmd = squashVersion
        ? "pip install \"squash-ai==${squashVersion}\" --quiet"
        : "pip install squash-ai --quiet"

    def attestCmd = "squash attest '${modelPath}' ${extraFlags.join(' ')} --output-json squash_result.json"

    def annexCmd = "squash annex-iv generate --root '${modelPath}' --format md json --no-validate || true"

    if (apiKeyId) {
        withCredentials([string(credentialsId: apiKeyId, variable: 'SQUASH_API_KEY')]) {
            _runAttest(installCmd, attestCmd, annexCmd, annexIv, modelPath)
        }
    } else {
        _runAttest(installCmd, attestCmd, annexCmd, annexIv, modelPath)
    }
}

private def _runAttest(String installCmd, String attestCmd, String annexCmd, boolean annexIv, String modelPath) {
    stage('Install squash-ai') {
        sh installCmd
    }

    stage('Squash Attest') {
        sh attestCmd
    }

    if (annexIv) {
        stage('Squash Annex IV') {
            sh annexCmd
        }
    }

    // Parse and log result summary
    stage('Squash Report') {
        script {
            if (fileExists('squash_result.json')) {
                def result = readJSON file: 'squash_result.json'
                def passed = result.passed ?: false
                def score  = result.compliance_score ?: 0
                echo "[squash] passed=${passed}  compliance_score=${score}"
                if (!passed) {
                    unstable("[squash] Policy violations detected. compliance_score=${score}")
                }
            } else {
                echo "[squash] squash_result.json not found — attestation may have failed."
            }
        }
    }

    // Stash artifacts for downstream stages
    stash name: 'squash-attestation',
          includes: "squash_result.json,${modelPath}/squash/**,annex_iv*",
          allowEmpty: true
}
