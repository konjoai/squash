"""squish/squash/cli.py — Standalone ``squash`` CLI entry point.

Provides the ``squash attest`` sub-command that CI/CD integrations call:

    squash attest ./my-model --policy eu-ai-act --policy enterprise-strict

Exit codes (per project CLI standard):
    0  Success — attestation passed
    1  User / input error (bad path, unknown policy, missing flag)
    2  Runtime error (I/O failure, scan error, attestation violation)

Usage::

    squash attest MODEL_PATH [options]

Options::

    --policy, -p     Policy name to evaluate (repeatable, default: enterprise-strict)
    --output-dir     Artifact output directory (default: model dir)
    --sign           Sign the CycloneDX BOM via Sigstore keyless signing
    --fail-on-violation  Exit 2 if any policy error-severity finding is raised
    --skip-scan      Skip the security scanner
    --json-result    Path to write the master attestation record as JSON
    --model-id       Override the model ID in the SBOM
    --hf-repo        HuggingFace repository ID for provenance metadata
    --quant-format   Quantization format label (e.g. INT4, BF16)
    --quiet, -q      Suppress informational output (errors still go to stderr)
    --help           Show this message and exit

"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="squash",
        description="AI-SBOM attestation for ML models (Squish Squash)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  squash attest ./llama-3.1-8b-q4 --policy eu-ai-act\n"
            "  squash attest ./model --sign --fail-on-violation --json-result ./result.json\n"
            "  squash policies              # list available policy templates\n"
        ),
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress info output")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── squash attest ──────────────────────────────────────────────────────────
    attest = sub.add_parser("attest", help="Run full attestation pipeline on a model artifact")
    attest.add_argument(
        "model_path",
        help="Path to model directory or file (e.g. ./llama-3.1-8b-q4 or ./model.gguf)",
    )
    attest.add_argument(
        "--policy", "-p",
        dest="policies",
        action="append",
        default=[],
        metavar="POLICY",
        help="Policy name to evaluate (repeatable). Default: enterprise-strict. "
             "Also: eu-cra, fedramp, cmmc, eu-ai-act, nist-ai-rmf, owasp-llm-top10, iso-42001 "
             "(run 'squash policies' to list all)",
    )
    attest.add_argument("--output-dir", default=None, help="Artifact destination directory")
    attest.add_argument("--sign", action="store_true", help="Sign BOM via Sigstore keyless")
    attest.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 2 if any error-severity policy finding exists or scan is unsafe",
    )
    attest.add_argument("--skip-scan", action="store_true", help="Skip security scanner")
    attest.add_argument(
        "--json-result",
        default=None,
        metavar="PATH",
        help="Write master attestation record JSON to this path",
    )
    attest.add_argument("--model-id", default="", help="Override model ID in SBOM")
    attest.add_argument("--hf-repo", default="", help="HuggingFace repo ID for provenance")
    attest.add_argument(
        "--quant-format",
        default="unknown",
        help="Quantization format label (e.g. INT4, BF16)",
    )
    # ── SPDX AI Profile enrichment ────────────────────────────────────────────
    attest.add_argument(
        "--spdx-type",
        default=None,
        metavar="TYPE",
        dest="spdx_type",
        help="SPDX AI Profile: type_of_model (e.g. text-generation, text-classification, "
             "translation, summarization, question-answering). Default: text-generation",
    )
    attest.add_argument(
        "--spdx-safety-risk",
        default=None,
        choices=["high", "medium", "low", "unspecified"],
        dest="spdx_safety_risk",
        help="SPDX AI Profile: safetyRiskAssessment tier. Default: unspecified",
    )
    attest.add_argument(
        "--spdx-dataset",
        action="append",
        default=[],
        dest="spdx_datasets",
        metavar="DATASET_ID",
        help="Training dataset HF ID or URI (repeatable; e.g. --spdx-dataset wikipedia "
             "--spdx-dataset c4). Embedded in the SPDX AI Profile",
    )
    attest.add_argument(
        "--spdx-training-info",
        default=None,
        dest="spdx_training_info",
        metavar="TEXT",
        help="SPDX AI Profile: informationAboutTraining free-text. "
             "Default: see-model-card",
    )
    attest.add_argument(
        "--spdx-sensitive-data",
        default=None,
        choices=["absent", "present", "unknown"],
        dest="spdx_sensitive_data",
        help="SPDX AI Profile: sensitivePIIInTrainingData. Default: absent",
    )
    # ── W49: offline / air-gapped mode ────────────────────────────────────────
    attest.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="Air-gapped mode: disable all OIDC/network calls (also set by SQUASH_OFFLINE=1)",
    )
    attest.add_argument(
        "--offline-key",
        metavar="PATH",
        default=None,
        dest="offline_key",
        help="Path to Ed25519 .priv.pem for offline signing (requires --sign --offline)",
    )

    # ── squash keygen ─────────────────────────────────────────────────────────
    keygen_cmd = sub.add_parser(
        "keygen",
        help="Generate a local Ed25519 keypair for offline signing",
        description=(
            "Generate an Ed25519 keypair for offline BOM signing.\n\n"
            "Example: squash keygen mykey\n"
            "Example: squash keygen ci-key --key-dir ~/.squash/keys"
        ),
    )
    keygen_cmd.add_argument("name", help="Base filename for the keypair (no extension)")
    keygen_cmd.add_argument(
        "--key-dir",
        metavar="DIR",
        default=".",
        dest="key_dir",
        help="Directory to write <name>.priv.pem and <name>.pub.pem (default: current dir)",
    )
    keygen_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── squash verify-local ───────────────────────────────────────────────────
    verify_local_cmd = sub.add_parser(
        "verify-local",
        help="Verify a BOM's Ed25519 offline signature against a local public key",
        description=(
            "Verify the local Ed25519 signature for a CycloneDX BOM.\n\n"
            "Example: squash verify-local ./model/cyclonedx-mlbom.json "
            "--key mykey.pub.pem\n"
            "Example: squash verify-local bom.json --key ci-key.pub.pem --sig bom.sig"
        ),
    )
    verify_local_cmd.add_argument("bom_path", help="Path to the CycloneDX BOM file to verify")
    verify_local_cmd.add_argument(
        "--key",
        required=True,
        metavar="PATH",
        dest="pub_key",
        help="Path to the Ed25519 .pub.pem public key",
    )
    verify_local_cmd.add_argument(
        "--sig",
        default=None,
        metavar="PATH",
        dest="sig_file",
        help="Explicit .sig file path (default: <bom_path>.sig)",
    )
    verify_local_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── squash pack-offline ───────────────────────────────────────────────────
    pack_offline_cmd = sub.add_parser(
        "pack-offline",
        help="Bundle a model directory and squash artefacts into a .squash-bundle.tar.gz",
        description=(
            "Archive a model directory (weights + BOM + signatures + chain) into a "
            "portable, self-contained tarball for air-gapped deployment.\n\n"
            "Example: squash pack-offline ./llama-3.1-8b-q4\n"
            "Example: squash pack-offline ./model --output /tmp/bundle.squash-bundle.tar.gz"
        ),
    )
    pack_offline_cmd.add_argument("model_dir", help="Path to the model directory to bundle")
    pack_offline_cmd.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        dest="output_path",
        help="Output .squash-bundle.tar.gz path (default: <model_dir>-<timestamp>.squash-bundle.tar.gz)",
    )
    pack_offline_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── squash policies ────────────────────────────────────────────────────────
    policies_cmd = sub.add_parser("policies", help="List available built-in policy templates")
    policies_cmd.add_argument(
        "--validate",
        metavar="PATH",
        default=None,
        help="Validate a custom YAML rules file (exit 0 = valid, 1 = user error, 2 = invalid rules)",
    )

    # ── squash scan ────────────────────────────────────────────────────────────
    scan_cmd = sub.add_parser("scan", help="Run security scanner only (no SBOM generation)")
    scan_cmd.add_argument("model_path", help="Path to model directory or file")
    scan_cmd.add_argument("--json-result", default=None, metavar="PATH")
    scan_cmd.add_argument(
        "--sarif",
        default=None,
        metavar="PATH",
        help="Write SARIF 2.1.0 output to PATH",
    )
    scan_cmd.add_argument(
        "--exit-2-on-unsafe",
        action="store_true",
        default=False,
        help="Exit 2 on critical/high findings; exit 1 on other unsafe statuses",
    )

    # ── squash diff ───────────────────────────────────────────────────────────
    diff_cmd = sub.add_parser(
        "diff",
        help="Compare two CycloneDX SBOM snapshots and report differences",
    )
    diff_cmd.add_argument("sbom_a", metavar="SBOM_A", help="Older (baseline) SBOM JSON file")
    diff_cmd.add_argument("sbom_b", metavar="SBOM_B", help="Newer SBOM JSON file")
    diff_cmd.add_argument(
        "--exit-1-on-regression",
        action="store_true",
        default=False,
        help="Exit 1 when new vulnerabilities are introduced or policy status worsens",
    )

    # ── squash verify ──────────────────────────────────────────────────────────
    verify_cmd = sub.add_parser(
        "verify",
        help="Verify the Sigstore bundle for a model's CycloneDX BOM",
    )
    verify_cmd.add_argument(
        "model_path",
        help="Path to model directory (must contain cyclonedx-mlbom.json)",
    )
    verify_cmd.add_argument(
        "--bundle",
        default=None,
        metavar="PATH",
        help="Explicit path to the .sig.json bundle (default: <bom>.sig.json)",
    )
    verify_cmd.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Exit 2 when no bundle is found (treat unsigned BOMs as failures)",
    )

    # ── squash report ──────────────────────────────────────────────────────────
    report_cmd = sub.add_parser(
        "report",
        help="Generate an HTML or JSON compliance report from attestation artifacts",
        description="squash report MODEL_DIR  # writes squash-report.html into model dir",
    )
    report_cmd.add_argument(
        "model_path",
        help="Path to model directory containing attestation artifacts",
    )
    report_cmd.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help="Output file path (default: <model_dir>/squash-report.html)",
    )
    report_cmd.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="Output format (default: html)",
    )

    # ── squash vex ─────────────────────────────────────────────────────────────
    vex_cmd = sub.add_parser(
        "vex",
        help="VEX feed cache management",
    )
    vex_sub = vex_cmd.add_subparsers(dest="vex_command")
    vex_update = vex_sub.add_parser("update", help="Refresh the local VEX feed cache")
    vex_update.add_argument(
        "--url",
        default=None,
        help="Override VEX feed URL (default: SQUASH_VEX_URL env or built-in)",
    )
    vex_update.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10)",
    )
    vex_sub.add_parser("status", help="Show VEX cache status and freshness")

    # Wave 52 — subscribe / unsubscribe / list-subscriptions
    vex_subscribe = vex_sub.add_parser(
        "subscribe",
        help="Register a remote VEX feed URL for periodic polling",
        description=(
            "squash vex subscribe URL [--alias NAME] [--api-key-env VAR] [--polling-hours N]\n\n"
            "Example: squash vex subscribe https://vex.example.com/feed.json --alias corp-feed\n"
            "Example: squash vex subscribe https://api.example.com/vex --api-key-env CORP_VEX_KEY"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vex_subscribe.add_argument(
        "url",
        metavar="URL",
        help="HTTPS endpoint returning an OpenVEX JSON feed",
    )
    vex_subscribe.add_argument(
        "--alias",
        default="",
        metavar="NAME",
        help="Short human-readable name for this subscription (optional)",
    )
    vex_subscribe.add_argument(
        "--api-key-env",
        default="SQUASH_VEX_API_KEY",
        metavar="VAR",
        help="Environment variable name that holds the API key (default: SQUASH_VEX_API_KEY)",
    )
    vex_subscribe.add_argument(
        "--polling-hours",
        type=int,
        default=24,
        metavar="N",
        help="Refresh interval in hours used by 'squash vex update --all' (default: 24)",
    )
    vex_subscribe.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    vex_unsubscribe = vex_sub.add_parser(
        "unsubscribe",
        help="Remove a registered VEX feed subscription",
        description=(
            "squash vex unsubscribe URL_OR_ALIAS\n\n"
            "Example: squash vex unsubscribe corp-feed\n"
            "Example: squash vex unsubscribe https://vex.example.com/feed.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vex_unsubscribe.add_argument(
        "url_or_alias",
        metavar="URL_OR_ALIAS",
        help="URL or alias of the subscription to remove",
    )
    vex_unsubscribe.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    vex_sub.add_parser("list-subscriptions", help="List all registered VEX feed subscriptions")

    # ── squash attest-composed ────────────────────────────────────────────────
    ac_cmd = sub.add_parser(
        "attest-composed",
        help="Attest multiple models and produce a parent composite BOM",
        description="squash attest-composed MODEL_A MODEL_B ...  [--output-dir DIR]",
    )
    ac_cmd.add_argument(
        "model_paths",
        nargs="+",
        metavar="MODEL_PATH",
        help="Two or more model directories to attest",
    )
    ac_cmd.add_argument(
        "--output-dir",
        default=None,
        metavar="DIR",
        help="Write parent BOM and component results here (default: first model dir)",
    )
    ac_cmd.add_argument(
        "--policy",
        dest="policies",
        action="append",
        default=None,
        metavar="NAME",
        help="Policy name(s) to evaluate (repeatable; default: enterprise-strict; "
             "also: eu-cra, fedramp, cmmc — run 'squash policies' to list all)",
    )
    ac_cmd.add_argument(
        "--sign",
        action="store_true",
        default=False,
        help="Sign each component BOM with Sigstore after attestation",
    )

    # ── squash push ───────────────────────────────────────────────────────────
    push_cmd = sub.add_parser(
        "push",
        help="Push a CycloneDX SBOM to a supported registry (Dependency-Track, GUAC, Squash)",
        description="squash push MODEL_DIR --registry-url URL  [options]",
    )
    push_cmd.add_argument(
        "model_path",
        help="Model directory containing cyclonedx-mlbom.json",
    )
    push_cmd.add_argument(
        "--registry-url",
        required=True,
        metavar="URL",
        help="Registry endpoint URL",
    )
    push_cmd.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API key or token (or set SQUASH_REGISTRY_KEY env var)",
    )
    push_cmd.add_argument(
        "--registry-type",
        choices=["dtrack", "guac", "squash"],
        default="dtrack",
        help="Registry protocol (default: dtrack)",
    )

    # ── Wave 20 — NTIA minimum elements check ─────────────────────────────────
    ntia_cmd = sub.add_parser(
        "ntia-check",
        help="Validate NTIA minimum elements in a CycloneDX BOM",
        description=(
            "Check a CycloneDX BOM for the NTIA Minimum Elements for SBOM "
            "compliance (Nov 2021).\n\n"
            "Example: squash ntia-check model/cyclonedx-mlbom.json"
        ),
    )
    ntia_cmd.add_argument("bom_path", help="Path to the CycloneDX BOM JSON file")
    ntia_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Require non-empty dependsOn fields (stricter NTIA compliance)",
    )
    ntia_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 21 — SLSA provenance attestation ─────────────────────────────────
    slsa_cmd = sub.add_parser(
        "slsa-attest",
        help="Generate SLSA provenance statement for a model directory",
        description=(
            "Build a SLSA 1.0 Build Provenance statement for the artefacts in "
            "MODEL_DIR and (optionally) sign it.\n\n"
            "Example: squash slsa-attest ./my-model --level 2"
        ),
    )
    slsa_cmd.add_argument("model_dir", help="Path to the squash model directory")
    slsa_cmd.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="SLSA build track level (default: 1)",
    )
    slsa_cmd.add_argument(
        "--builder-id",
        default="https://squish.local/squash/builder",
        help="URI identifying the build system",
    )
    slsa_cmd.add_argument("--sign", action="store_true", help="Force signing even at L1")
    slsa_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 22 — BOM merge ────────────────────────────────────────────────────
    merge_cmd = sub.add_parser(
        "merge",
        help="Merge multiple CycloneDX BOMs into one canonical BOM",
        description=(
            "Deduplicate components by PURL and union vulnerabilities across "
            "multiple CycloneDX BOMs.\n\n"
            "Example: squash merge a/cyclonedx-mlbom.json b/cyclonedx-mlbom.json "
            "--output merged/cyclonedx-mlbom.json"
        ),
    )
    merge_cmd.add_argument(
        "bom_paths", nargs="+", help="Two or more CycloneDX BOM JSON files to merge"
    )
    merge_cmd.add_argument(
        "--output", required=True, help="Destination path for the merged BOM"
    )
    merge_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 23 — AI risk assessment ──────────────────────────────────────────
    risk_cmd = sub.add_parser(
        "risk-assess",
        help="Assess AI risk per EU AI Act and/or NIST AI RMF",
        description=(
            "Evaluate the BOM in MODEL_DIR against the EU AI Act (2024/1689) "
            "risk tiers and the NIST AI Risk Management Framework.\n\n"
            "Example: squash risk-assess ./my-model --framework eu-ai-act"
        ),
    )
    risk_cmd.add_argument("model_dir", help="Path to the squash model directory")
    risk_cmd.add_argument(
        "--framework",
        choices=["eu-ai-act", "nist-rmf", "both"],
        default="both",
        help="Risk framework to run (default: both)",
    )
    risk_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 24 — Drift monitoring ────────────────────────────────────────────
    monitor_cmd = sub.add_parser(
        "monitor",
        help="Detect drift in a squash model directory",
        description=(
            "Snapshot the attestation state of MODEL_DIR and compare against a "
            "previous snapshot to detect BOM changes, new CVEs, or policy "
            "regressions.\n\n"
            "Example: squash monitor ./my-model --once"
        ),
    )
    monitor_cmd.add_argument("model_dir", help="Path to the squash model directory")
    monitor_cmd.add_argument(
        "--baseline",
        default=None,
        help="SHA-256 baseline snapshot string to compare against (omit to just snapshot)",
    )
    monitor_cmd.add_argument(
        "--interval",
        type=float,
        default=3600.0,
        help="Poll interval in seconds for continuous monitoring (default: 3600)",
    )
    monitor_cmd.add_argument(
        "--once",
        action="store_true",
        help="Snapshot once (or compare against --baseline) then exit",
    )
    monitor_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 25 — CI/CD integration ───────────────────────────────────────────
    ci_cmd = sub.add_parser(
        "ci-run",
        help="Run the full squash check pipeline in CI",
        description=(
            "Execute NTIA validation, AI risk assessment, and drift detection "
            "for MODEL_DIR, then emit native CI annotations.\n\n"
            "Example: squash ci-run ./my-model --report-format github"
        ),
    )
    ci_cmd.add_argument("model_dir", help="Path to the squash model directory")
    ci_cmd.add_argument(
        "--report-format",
        choices=["github", "jenkins", "gitlab", "text"],
        default="text",
        help="CI annotation format (default: text; auto-detected if not set)",
    )
    ci_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 27 — Kubernetes admission webhook ─────────────────────────────────
    webhook_cmd = sub.add_parser(
        "webhook",
        help="Start the Kubernetes admission webhook server",
        description=(
            "Run an HTTPS validating admission webhook that enforces Squash BOM "
            "attestation policy.  Pods annotated with "
            "squash.ai/attestation-required=true must carry a valid "
            "squash.ai/bom-digest annotation whose digest is present in the "
            "configured policy store.\n\n"
            "Example: squash webhook --port 8443 --tls-cert /tls/tls.crt "
            "--tls-key /tls/tls.key --policy-store /var/squash/policy-store.json"
        ),
    )
    webhook_cmd.add_argument(
        "--port",
        type=int,
        default=8443,
        help="TCP port for the webhook server (default: 8443)",
    )
    webhook_cmd.add_argument(
        "--tls-cert",
        metavar="PATH",
        default=None,
        help="Path to PEM-encoded TLS certificate (omit for dev HTTP mode)",
    )
    webhook_cmd.add_argument(
        "--tls-key",
        metavar="PATH",
        default=None,
        help="Path to PEM-encoded TLS private key",
    )
    webhook_cmd.add_argument(
        "--policy-store",
        metavar="PATH",
        default=None,
        help="Path to JSON policy store file: {digest: bool}",
    )
    webhook_cmd.add_argument(
        "--default-deny",
        action="store_true",
        default=False,
        help="Deny pods that lack the attestation-required annotation (default: allow)",
    )
    webhook_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 50 — Shadow AI detection ─────────────────────────────────────────
    shadow_ai_cmd = sub.add_parser(
        "shadow-ai",
        help="Detect shadow AI model files running inside Kubernetes pods",
        description=(
            "Scan a Kubernetes pod list for shadow AI model file references "
            "(*.gguf, *.safetensors, *.bin, *.pt, etc.) in volume mounts, "
            "environment variables, and container arguments.\n\n"
            "Example: squash shadow-ai scan pods.json\n"
            "Example: kubectl get pods -o json | squash shadow-ai scan -\n"
            "Example: squash shadow-ai scan pods.json --fail-on-hits"
        ),
    )
    shadow_ai_sub = shadow_ai_cmd.add_subparsers(dest="shadow_ai_cmd", metavar="SUBCOMMAND")
    shadow_ai_sub.required = True
    shadow_ai_scan_cmd = shadow_ai_sub.add_parser(
        "scan",
        help="Scan a pod list JSON for shadow AI model file references",
        description=(
            "Read a Kubernetes pod list (kubectl get pods -o json) from a file or stdin "
            "and report any container that references shadow AI model files.\n\n"
            "Exit codes: 0 = clean, 1 = error, 2 = shadow AI hits found (with --fail-on-hits)"
        ),
    )
    shadow_ai_scan_cmd.add_argument(
        "pod_list",
        metavar="POD_LIST_JSON",
        help="Path to pod list JSON file, or '-' to read from stdin",
    )
    shadow_ai_scan_cmd.add_argument(
        "--namespace",
        metavar="NS",
        action="append",
        dest="namespaces",
        default=[],
        help="Only scan pods in this namespace (repeatable; default: all namespaces)",
    )
    shadow_ai_scan_cmd.add_argument(
        "--extensions",
        nargs="+",
        metavar="EXT",
        default=None,
        help="Override the set of file extensions to flag (e.g. --extensions .gguf .pt)",
    )
    shadow_ai_scan_cmd.add_argument(
        "--output-json",
        metavar="PATH",
        default=None,
        help="Write the full scan result as JSON to this path",
    )
    shadow_ai_scan_cmd.add_argument(
        "--fail-on-hits",
        action="store_true",
        default=False,
        help="Exit with code 2 if any shadow AI model files are detected",
    )
    shadow_ai_scan_cmd.add_argument(
        "--quiet", action="store_true", help="Suppress non-error output"
    )

    # ── Wave 51 — SBOM drift detection ────────────────────────────────────────
    drift_check_cmd = sub.add_parser(
        "drift-check",
        help="Verify a model directory against its CycloneDX BOM (SHA-256 digest check)",
        description=(
            "Compare the SHA-256 digests of every weight file in MODEL_DIR against "
            "the digests recorded in the squish CycloneDX BOM sidecar.  Reports "
            "missing or tampered files and optionally exits non-zero on drift.\n\n"
            "Example: squash drift-check ./my-model --bom ./my-model/cyclonedx-mlbom.json\n"
            "Example: squash drift-check ./my-model --bom bom.json --fail-on-drift\n"
            "Exit codes: 0 = clean, 1 = error, 2 = drift found (with --fail-on-drift)"
        ),
    )
    drift_check_cmd.add_argument(
        "model_dir",
        metavar="MODEL_DIR",
        help="Path to the squish compressed model directory",
    )
    drift_check_cmd.add_argument(
        "--bom",
        metavar="BOM_PATH",
        required=True,
        help="Path to the CycloneDX BOM JSON file (cyclonedx-mlbom.json)",
    )
    drift_check_cmd.add_argument(
        "--fail-on-drift",
        action="store_true",
        default=False,
        help="Exit with code 2 when drift is detected (default: exit 0 and report only)",
    )
    drift_check_cmd.add_argument(
        "--output-json",
        metavar="PATH",
        default=None,
        help="Write the full drift result as JSON to this path",
    )
    drift_check_cmd.add_argument(
        "--quiet", action="store_true", help="Suppress non-error output"
    )

    # ── Wave 29 — VEX publish + integration CLI shims ─────────────────────────
    vex_pub_cmd = sub.add_parser(
        "vex-publish",
        help="Generate and write a static OpenVEX 0.2.0 feed JSON file",
        description=(
            "Build an OpenVEX 0.2.0 document from a list of statement entries and "
            "write it to a configurable output path.  Entries are read from a JSON "
            "file, stdin ('-'), or an inline JSON string.\n\n"
            "Example: squash vex-publish --output feed.json --entries entries.json\n"
            "Example: squash vex-publish --output feed.json --entries '[]'"
        ),
    )
    vex_pub_cmd.add_argument(
        "--output",
        metavar="PATH",
        required=True,
        help="Destination path to write the OpenVEX JSON file",
    )
    vex_pub_cmd.add_argument(
        "--entries",
        metavar="PATH_OR_JSON",
        default="[]",
        help=(
            "Statement entries as a JSON file path, '-' for stdin, or inline JSON "
            "array string (default: '[]')"
        ),
    )
    vex_pub_cmd.add_argument(
        "--author",
        default="squash",
        help="Author field in the VEX document (default: squash)",
    )
    vex_pub_cmd.add_argument(
        "--doc-id",
        metavar="URL",
        default=None,
        help="Optional @id URI for the document; auto-generated if omitted",
    )
    vex_pub_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    attest_mlflow_cmd = sub.add_parser(
        "attest-mlflow",
        help="Run attestation pipeline and emit result as JSON (MLflow-compatible)",
        description=(
            "Execute the full Squash attestation pipeline on MODEL_PATH and write "
            "the result JSON to stdout (or --output-dir).  Designed for piping into "
            "MLflow artifact upload scripts or CI steps that wrap mlflow.log_artifact.\n\n"
            "Example: squash attest-mlflow ./my-model --policies enterprise-strict"
        ),
    )
    attest_mlflow_cmd.add_argument("model_path", help="Path to the model directory or file")
    attest_mlflow_cmd.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Directory to write attestation artifacts (default: <model_path>/../squash)",
    )
    attest_mlflow_cmd.add_argument(
        "--policies",
        nargs="*",
        metavar="POLICY",
        default=None,
        help="Policy templates to evaluate (default: enterprise-strict; "
             "also: eu-cra, fedramp, cmmc — run 'squash policies' for all)",
    )
    attest_mlflow_cmd.add_argument(
        "--sign", action="store_true", help="Sign BOM via Sigstore keyless"
    )
    attest_mlflow_cmd.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 1 if any policy violation is found",
    )
    attest_mlflow_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    attest_wandb_cmd = sub.add_parser(
        "attest-wandb",
        help="Run attestation pipeline and emit result as JSON (W&B-compatible)",
        description=(
            "Execute the full Squash attestation pipeline on MODEL_PATH and write "
            "the result JSON to stdout (or --output-dir).  Designed for piping into "
            "W&B artifact upload scripts or run-summary steps.\n\n"
            "Example: squash attest-wandb ./my-model --policies enterprise-strict"
        ),
    )
    attest_wandb_cmd.add_argument("model_path", help="Path to the model directory or file")
    attest_wandb_cmd.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Directory to write attestation artifacts (default: <model_path>/../squash)",
    )
    attest_wandb_cmd.add_argument(
        "--policies",
        nargs="*",
        metavar="POLICY",
        default=None,
        help="Policy templates to evaluate (default: enterprise-strict; "
             "also: eu-cra, fedramp, cmmc — run 'squash policies' for all)",
    )
    attest_wandb_cmd.add_argument(
        "--sign", action="store_true", help="Sign BOM via Sigstore keyless"
    )
    attest_wandb_cmd.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 1 if any policy violation is found",
    )
    attest_wandb_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    attest_hf_cmd = sub.add_parser(
        "attest-huggingface",
        help="Attest a model and push artifacts to a HuggingFace Hub repository",
        description=(
            "Run the Squash attestation pipeline on MODEL_PATH and upload the "
            "resulting artifacts to --repo-id on the HuggingFace Hub.\n\n"
            "Example: squash attest-huggingface ./my-model --repo-id myorg/llama-3-8b"
        ),
    )
    attest_hf_cmd.add_argument("model_path", help="Path to the local model directory")
    attest_hf_cmd.add_argument(
        "--repo-id",
        metavar="ORG/REPO",
        default=None,
        help="HuggingFace Hub repo ID to push artifacts to (skip push if omitted)",
    )
    attest_hf_cmd.add_argument(
        "--hf-token",
        metavar="TOKEN",
        default=None,
        help="HuggingFace API token; falls back to HF_TOKEN env var",
    )
    attest_hf_cmd.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Local artifact output directory (default: <model_path>/../squash)",
    )
    attest_hf_cmd.add_argument(
        "--policies",
        nargs="*",
        metavar="POLICY",
        default=None,
        help="Policy templates to evaluate (default: enterprise-strict; "
             "also: eu-cra, fedramp, cmmc — run 'squash policies' for all)",
    )
    attest_hf_cmd.add_argument(
        "--sign", action="store_true", help="Sign BOM via Sigstore keyless"
    )
    attest_hf_cmd.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 1 if any policy violation is found",
    )
    attest_hf_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    attest_lc_cmd = sub.add_parser(
        "attest-langchain",
        help="Run a one-shot attestation pass on a model (LangChain-compatible)",
        description=(
            "Run the Squash attestation pipeline on MODEL_PATH and write the "
            "result JSON to stdout.  Mirrors the behaviour of SquashCallback on "
            "first LLM invocation, allowing offline pre-validation before deploying "
            "a LangChain agent.\n\n"
            "Example: squash attest-langchain ./my-model --policies enterprise-strict"
        ),
    )
    attest_lc_cmd.add_argument("model_path", help="Path to the model directory or file")
    attest_lc_cmd.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Directory for attestation artifacts (default: <model_path>/../squash)",
    )
    attest_lc_cmd.add_argument(
        "--policies",
        nargs="*",
        metavar="POLICY",
        default=None,
        help="Policy templates to evaluate (default: enterprise-strict; "
             "also: eu-cra, fedramp, cmmc — run 'squash policies' for all)",
    )
    attest_lc_cmd.add_argument(
        "--sign", action="store_true", help="Sign BOM via Sigstore keyless"
    )
    attest_lc_cmd.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 1 if any policy violation is found",
    )
    attest_lc_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    attest_mcp_cmd = sub.add_parser(
        "attest-mcp",
        help="Scan an MCP tool manifest catalog for supply-chain threats",
        description=(
            "Scan a Model Context Protocol (MCP) tools/list JSON catalog for six "
            "threat classes: prompt injection, SSRF vectors, tool shadowing, "
            "integrity gaps, data exfiltration patterns, and permission over-reach.\n\n"
            "Addresses EU AI Act Art. 9(2)(d): adversarial input resilience for "
            "agentic AI systems that invoke MCP tools at runtime.\n\n"
            "Example: squash attest-mcp ./mcp_catalog.json --policy mcp-strict"
        ),
    )
    attest_mcp_cmd.add_argument("catalog_path", help="Path to the MCP tool catalog JSON file")
    attest_mcp_cmd.add_argument(
        "--policy",
        metavar="POLICY",
        default="mcp-strict",
        help="Policy template to apply (default: mcp-strict)",
    )
    attest_mcp_cmd.add_argument(
        "--sign",
        action="store_true",
        help="Sign the catalog with Sigstore keyless signing after attestation",
    )
    attest_mcp_cmd.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit 1 if any error-severity finding is present",
    )
    attest_mcp_cmd.add_argument(
        "--json-result",
        metavar="PATH",
        default=None,
        help="Write scan result JSON to this file (default: stdout only)",
    )
    attest_mcp_cmd.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Directory for attestation artifacts (default: catalog directory)",
    )
    attest_mcp_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 46 — Agent audit trail ───────────────────────────────────────────
    audit_cmd = sub.add_parser(
        "audit",
        help="Agent audit trail management (show / verify)",
        description=(
            "Manage the squash agent audit trail (append-only JSONL with hash chain).\n\n"
            "Examples:\n"
            "  squash audit show --n 20\n"
            "  squash audit verify --log /var/log/squash/audit.jsonl"
        ),
    )
    audit_sub = audit_cmd.add_subparsers(dest="audit_command")

    audit_show = audit_sub.add_parser(
        "show",
        help="Print the last N entries from the audit log",
    )
    audit_show.add_argument(
        "--n",
        type=int,
        default=20,
        help="Number of entries to show (default: 20)",
    )
    audit_show.add_argument(
        "--log",
        metavar="PATH",
        default=None,
        help="Audit log file path (default: $SQUASH_AUDIT_LOG or ~/.squash/audit.jsonl)",
    )
    audit_show.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output entries as a JSON array instead of pretty-printed lines",
    )
    audit_show.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    audit_verify = audit_sub.add_parser(
        "verify",
        help="Verify the hash chain integrity of the audit log (exit 0=intact, 2=tampered)",
    )
    audit_verify.add_argument(
        "--log",
        metavar="PATH",
        default=None,
        help="Audit log file path (default: $SQUASH_AUDIT_LOG or ~/.squash/audit.jsonl)",
    )
    audit_verify.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 47 — RAG knowledge base integrity ────────────────────────────────
    scan_rag_cmd = sub.add_parser(
        "scan-rag",
        help="RAG knowledge base integrity scanner — index a corpus and detect drift",
    )
    scan_rag_sub = scan_rag_cmd.add_subparsers(dest="scan_rag_command")

    scan_rag_index = scan_rag_sub.add_parser(
        "index", help="Hash every document in a corpus and write a signed manifest"
    )
    scan_rag_index.add_argument("corpus_dir", help="Corpus directory to index")
    scan_rag_index.add_argument(
        "--glob",
        default="**/*",
        metavar="PATTERN",
        help='File glob (default "**/*")',
    )
    scan_rag_index.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    scan_rag_verify = scan_rag_sub.add_parser(
        "verify",
        help="Verify live corpus against manifest (exit 0=intact, 2=drift detected)",
    )
    scan_rag_verify.add_argument("corpus_dir", help="Corpus directory to verify")
    scan_rag_verify.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Print drift report as JSON",
    )
    scan_rag_verify.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── Wave 48 — Model transformation lineage ────────────────────────────────────
    lineage_cmd = sub.add_parser(
        "lineage",
        help="Model transformation lineage chain — record, show, and verify (EU AI Act Annex IV)",
        description=(
            "Manage the Merkle-chained transformation ledger for a model artefact.\n\n"
            "Addresses EU AI Act Annex IV technical documentation requirements (Art. 11)\n"
            "and NIST AI RMF GOVERN 1.7 (supply-chain provenance).  The chain file\n"
            "(.lineage_chain.json) travels with the model so provenance is available\n"
            "after transfer or M&A.\n\n"
            "Examples:\n"
            "  squash lineage record ./my-model --operation compress --params format=INT4 awq=true\n"
            "  squash lineage show   ./my-model\n"
            "  squash lineage verify ./my-model"
        ),
    )
    lineage_sub = lineage_cmd.add_subparsers(dest="lineage_command")

    lineage_record = lineage_sub.add_parser(
        "record", help="Append a transformation event to the lineage chain"
    )
    lineage_record.add_argument("model_dir", help="Model artefact directory")
    lineage_record.add_argument(
        "--operation",
        required=True,
        metavar="OP",
        help="Operation label (e.g. compress, quantize, sign, verify, export)",
    )
    lineage_record.add_argument(
        "--model-id",
        default="",
        dest="model_id",
        help="Model identifier (default: directory name)",
    )
    lineage_record.add_argument(
        "--input-dir",
        default="",
        dest="input_dir",
        help="Source model directory (default: model_dir)",
    )
    lineage_record.add_argument(
        "--params",
        nargs="*",
        metavar="KEY=VALUE",
        default=[],
        help="Arbitrary key=value operation parameters (repeatable)",
    )
    lineage_record.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    lineage_show = lineage_sub.add_parser(
        "show", help="Print the transformation lineage chain for a model directory"
    )
    lineage_show.add_argument("model_dir", help="Model artefact directory")
    lineage_show.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output events as a JSON array",
    )
    lineage_show.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    lineage_verify = lineage_sub.add_parser(
        "verify",
        help="Verify the Merkle chain integrity (exit 0=intact, 2=tampered/missing)",
    )
    lineage_verify.add_argument("model_dir", help="Model artefact directory")
    lineage_verify.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── remediate ──────────────────────────────────────────────────────────
    remediate_cmd = sub.add_parser(
        "remediate",
        help="Convert unsafe .bin/.pt/.pth pickle files to .safetensors",
    )
    remediate_cmd.add_argument("model_path", help="Model directory or single file to remediate")
    remediate_cmd.add_argument(
        "--convert-to",
        default="safetensors",
        dest="target_format",
        choices=["safetensors"],
        help="Target format (default: safetensors)",
    )
    remediate_cmd.add_argument("--output-dir", default=None, dest="output_dir",
                                help="Where to write converted files (default: alongside originals)")
    remediate_cmd.add_argument("--dry-run", action="store_true",
                                help="Analyse files but do not write converted output")
    remediate_cmd.add_argument("--overwrite", action="store_true",
                                help="Overwrite existing .safetensors files at the destination")
    remediate_cmd.add_argument("--sbom", default=None,
                                help="CycloneDX BOM to update with new hashes after conversion")
    remediate_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── evaluate ───────────────────────────────────────────────────────────
    evaluate_cmd = sub.add_parser(
        "evaluate",
        help="Dynamic behavioural safety red-team evaluation against an inference endpoint",
    )
    evaluate_cmd.add_argument(
        "endpoint",
        help="OpenAI-compatible base URL (e.g. http://localhost:11434/v1) or 'auto' to use squish serve",
    )
    evaluate_cmd.add_argument("--model", default="llama3",
                               help="Model name to pass to the endpoint (default: llama3)")
    evaluate_cmd.add_argument("--api-key", default=None, dest="api_key",
                               help="Bearer API key (optional for local endpoints)")
    evaluate_cmd.add_argument("--output-dir", default=None, dest="output_dir",
                               help="Directory for squash-eval-report.json (default: cwd)")
    evaluate_cmd.add_argument("--bom", default=None,
                               help="CycloneDX BOM to annotate with evaluation metrics")
    evaluate_cmd.add_argument("--fail-on-critical", action="store_true", dest="fail_on_critical",
                               help="Exit 2 if any critical probe fails")
    evaluate_cmd.add_argument("--timeout", type=float, default=30.0,
                               help="Seconds to wait per probe request (default: 30)")
    evaluate_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── edge-scan ──────────────────────────────────────────────────────────
    edge_scan_cmd = sub.add_parser(
        "edge-scan",
        help="Parse and security-scan TFLite (.tflite) or CoreML (.mlpackage) edge AI models",
    )
    edge_scan_cmd.add_argument("model_path",
                                help="Path to a .tflite file or .mlpackage directory")
    edge_scan_cmd.add_argument("--json-result", default=None, dest="json_result",
                                help="Write structured scan result to this JSON file")
    edge_scan_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # ── chat ───────────────────────────────────────────────────────────────
    chat_cmd = sub.add_parser(
        "chat",
        help="Interactive RAG compliance auditor — ask plain-English questions about squash artifacts",
    )
    chat_cmd.add_argument("model_dir", help="Model directory containing squash attestation artifacts")
    chat_cmd.add_argument("--backend", choices=["ollama", "openai"], default="ollama",
                           help="LLM backend to use (default: ollama)")
    chat_cmd.add_argument("--model", default=None,
                           help="Model name (default: llama3 for ollama, gpt-4o-mini for openai)")
    chat_cmd.add_argument("--api-key", default=None, dest="api_key",
                           help="API key (required for openai backend)")
    chat_cmd.add_argument("--top-k", type=int, default=5, dest="top_k",
                           help="Number of chunks to retrieve per question (default: 5)")
    chat_cmd.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    mc_cmd = sub.add_parser(
        "model-card",
        help="Generate regulation-compliant model cards from squash attestation artifacts",
        description=(
            "Generate AI regulation–compliant model cards from squash attestation "
            "artifacts (ML-BOM, scan results, policy reports, VEX report).\n\n"
            "Example:\n"
            "  squash model-card ./my-model --format all"
        ),
    )
    mc_cmd.add_argument(
        "model_dir",
        help="Model directory containing squash attestation artifacts",
    )
    mc_cmd.add_argument(
        "--format",
        choices=["hf", "eu-ai-act", "iso-42001", "all"],
        default="hf",
        dest="mc_format",
        help="Output format: hf (HuggingFace), eu-ai-act (EU AI Act Art. 13), "
             "iso-42001 (ISO/IEC 42001:2023), all (write all three). Default: hf",
    )
    mc_cmd.add_argument(
        "--output-dir",
        default=None,
        dest="mc_output_dir",
        help="Directory to write model card file(s). Defaults to model_dir.",
    )
    mc_cmd.add_argument(
        "--model-id",
        default="",
        dest="mc_model_id",
        help="Override model identifier used in card metadata.",
    )
    mc_cmd.add_argument(
        "--license",
        default="apache-2.0",
        dest="mc_license",
        help="SPDX licence identifier for the card (default: apache-2.0).",
    )
    # W194 (Sprint 10) — first-class CLI: validate + push subflags
    mc_cmd.add_argument(
        "--validate",
        action="store_true",
        dest="mc_validate",
        help="Validate generated card(s) against the HuggingFace model-card schema. "
             "Exits non-zero on errors.",
    )
    mc_cmd.add_argument(
        "--validate-only",
        action="store_true",
        dest="mc_validate_only",
        help="Skip generation and validate an existing card file at "
             "model_dir/squash-model-card-hf.md.",
    )
    mc_cmd.add_argument(
        "--push-to-hub",
        default=None,
        dest="mc_push_repo",
        metavar="REPO_ID",
        help="After generating, push squash-model-card-hf.md to the given HF repo "
             "(e.g. user/model). Requires `huggingface_hub` to be installed.",
    )
    mc_cmd.add_argument(
        "--hub-token",
        default=None,
        dest="mc_hub_token",
        help="HuggingFace token for --push-to-hub. Falls back to HUGGING_FACE_HUB_TOKEN.",
    )
    mc_cmd.add_argument(
        "--json",
        action="store_true",
        dest="mc_json",
        help="With --validate or --validate-only, emit structured JSON report.",
    )
    mc_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    # ── Wave 77 — Cloud CLI commands ──────────────────────────────────────────
    cloud_status_cmd = sub.add_parser(
        "cloud-status",
        help="Show EU AI Act conformance status for a single tenant",
        description=(
            "Query the in-memory cloud dashboard for EU AI Act conformance status "
            "of the specified tenant.  Exits 0 if conformant, 2 if non-conformant.\n\n"
            "Example: squash cloud-status acme-tenant-id"
        ),
    )
    cloud_status_cmd.add_argument(
        "tenant_id",
        help="Tenant identifier to inspect",
    )
    cloud_status_cmd.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Also dump full conformance dict as JSON to stdout",
    )
    cloud_status_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    cloud_report_cmd = sub.add_parser(
        "cloud-report",
        help="Print a platform-wide EU AI Act conformance report",
        description=(
            "Print a summary table of EU AI Act conformance for all registered "
            "tenants.  Exits 0 if all tenants are conformant, 2 if any are not.\n\n"
            "Example: squash cloud-report"
        ),
    )
    cloud_report_cmd.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Dump full conformance report dict as JSON to stdout",
    )
    cloud_report_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    cloud_export_cmd = sub.add_parser(
        "cloud-export",
        help="Export a complete compliance audit bundle for a tenant",
        description=(
            "Compose and export a complete compliance audit bundle for the "
            "specified tenant.  Scope is gated by SQUASH_PLAN "
            "(community/professional/enterprise).\n\n"
            "Example: squash cloud-export acme-tenant-id --output report.json"
        ),
    )
    cloud_export_cmd.add_argument(
        "tenant_id",
        help="Tenant identifier to export",
    )
    cloud_export_cmd.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        dest="output_path",
        help="Write JSON to PATH (default: stdout; use - for stdout explicitly)",
    )
    cloud_export_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    # ── Wave 79 — Cloud Attestation + Cloud VEX CLI ───────────────────────────
    cloud_attest_cmd = sub.add_parser(
        "cloud-attest",
        help="Attest a model for a tenant and register it in the cloud inventory",
        description=(
            "Run the full attestation pipeline against MODEL_PATH and register"
            " the result in the cloud dashboard inventory for TENANT_ID.\n\n"
            "Example: squash cloud-attest acme-corp ./models/llama-3.1-8b"
        ),
    )
    cloud_attest_cmd.add_argument(
        "tenant_id",
        help="Tenant identifier that owns this model",
    )
    cloud_attest_cmd.add_argument(
        "model_path",
        help="Path to the model directory or file to attest",
    )
    cloud_attest_cmd.add_argument(
        "--policy",
        metavar="POLICY",
        default="enterprise-strict",
        dest="policy",
        help="Policy to evaluate (default: enterprise-strict)",
    )
    cloud_attest_cmd.add_argument(
        "--output-path",
        metavar="PATH",
        default=None,
        dest="output_path",
        help="Directory for attestation artifacts (default: model_path directory)",
    )
    cloud_attest_cmd.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Dump attestation result as JSON to stdout",
    )
    cloud_attest_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    cloud_vex_cmd = sub.add_parser(
        "cloud-vex",
        help="List open VEX/CVE alerts for a tenant",
        description=(
            "Retrieve VEX alerts from the cloud dashboard for TENANT_ID.\n\n"
            "Example: squash cloud-vex acme-corp --limit 20"
        ),
    )
    cloud_vex_cmd.add_argument(
        "tenant_id",
        help="Tenant identifier to inspect",
    )
    cloud_vex_cmd.add_argument(
        "--limit",
        metavar="N",
        type=int,
        default=50,
        dest="limit",
        help="Maximum number of alerts to return (default: 50)",
    )
    cloud_vex_cmd.add_argument(
        "--status",
        metavar="STATUS",
        default=None,
        dest="vex_status",
        help="Filter by alert status: open | acknowledged | resolved",
    )
    cloud_vex_cmd.add_argument(
        "--severity",
        metavar="SEVERITY",
        default=None,
        dest="severity",
        help="Filter by severity: critical | high | medium | low | unknown",
    )
    cloud_vex_cmd.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Dump alerts as JSON to stdout",
    )
    cloud_vex_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    # ── Wave 80 — Cloud Risk Profile CLI ─────────────────────────────────────
    cloud_risk_cmd = sub.add_parser(
        "cloud-risk",
        help="Show EU AI Act risk profile for a tenant or the entire platform",
        description=(
            "Compute and display the EU AI Act risk tier for each model in a tenant's "
            "inventory, or a platform-wide risk overview when --overview is used. "
            "Risk tiers: UNACCEPTABLE > HIGH > LIMITED > MINIMAL (Art. 6/9).\n\n"
            "Example: squash cloud-risk acme-corp\n"
            "Example: squash cloud-risk --overview"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    cloud_risk_cmd.add_argument(
        "tenant_id",
        nargs="?",
        default=None,
        help="Tenant ID to inspect (omit when using --overview)",
    )
    cloud_risk_cmd.add_argument(
        "--overview",
        action="store_true",
        help="Show platform-wide risk summary across all tenants",
    )
    cloud_risk_cmd.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Dump risk profile as JSON to stdout",
    )
    cloud_risk_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    # ── Wave 81 — Cloud Remediation Plan CLI ─────────────────────────────────
    cloud_remediate_cmd = sub.add_parser(
        "cloud-remediate",
        help="Generate a prioritised EU AI Act remediation plan for a tenant",
        description=(
            "Produce a step-by-step remediation plan for a cloud tenant based on "
            "its EU AI Act risk tier.  Steps are ordered by priority "
            "(1 = critical, 2 = high, 3 = medium).\n\n"
            "Example: squash cloud-remediate acme-corp\n"
            "Example: squash cloud-remediate acme-corp --json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    cloud_remediate_cmd.add_argument(
        "tenant_id",
        help="Tenant ID to generate a remediation plan for",
    )
    cloud_remediate_cmd.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Dump remediation plan as JSON to stdout",
    )
    cloud_remediate_cmd.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    # ── W170 — ISO 42001 Readiness Assessment ────────────────────────────────
    iso42001_cmd = sub.add_parser(
        "iso42001",
        help="ISO/IEC 42001:2023 AI Management System readiness assessment",
        description=(
            "Assess a model directory against the 38 controls of ISO/IEC 42001:2023 "
            "and generate a gap analysis with remediation roadmap.\n\n"
            "Example: squash iso42001 ./my-model\n"
            "Example: squash iso42001 ./my-model --output iso42001-report.json --format json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    iso42001_cmd.add_argument("model_path", help="Path to model directory")
    iso42001_cmd.add_argument("--output", "-o", default=None, help="Output file path (default: model_path/iso42001_report.json)")
    iso42001_cmd.add_argument("--format", default="text", choices=["text", "json"], help="Output format (default: text)")
    iso42001_cmd.add_argument("--fail-below", type=float, default=None, metavar="SCORE",
                              help="Exit 2 if readiness score below this percentage")

    # ── W171 — Trust Package ──────────────────────────────────────────────────
    trust_pkg_cmd = sub.add_parser(
        "trust-package",
        help="Export a signed vendor attestation bundle (eliminates questionnaire process)",
        description=(
            "Bundle all compliance artifacts into a signed, verifiable trust package ZIP. "
            "Buyers verify it in <10 seconds instead of reviewing a 40-page questionnaire.\n\n"
            "Example: squash trust-package ./my-model --output vendor-package.zip\n"
            "Example: squash trust-package ./my-model --sign --model-id acme-llm-v2\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    trust_pkg_cmd.add_argument("model_path", help="Path to model directory containing squash artifacts")
    trust_pkg_cmd.add_argument("--output", "-o", default=None, help="Output ZIP path (default: <model_id>-trust-package.zip)")
    trust_pkg_cmd.add_argument("--model-id", default=None, help="Override model ID in package")
    trust_pkg_cmd.add_argument("--sign", action="store_true", help="Sign manifest via Sigstore")
    trust_pkg_cmd.add_argument("--verification-url", default="", help="URL for online verification")

    verify_trust_cmd = sub.add_parser(
        "verify-trust-package",
        help="Verify integrity and compliance posture of a trust package ZIP",
        description=(
            "Verify a vendor trust package: check SHA-256 integrity of all artifacts, "
            "parse the compliance summary, and report pass/fail.\n\n"
            "Example: squash verify-trust-package vendor-package.zip\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify_trust_cmd.add_argument("package_path", help="Path to trust package ZIP file")
    verify_trust_cmd.add_argument("--json", dest="output_json", action="store_true", help="Output JSON result")
    verify_trust_cmd.add_argument("--fail-on-error", action="store_true", help="Exit 2 if verification fails")

    # ── W172 — Agent Audit (OWASP Agentic AI Top 10) ─────────────────────────
    agent_audit_cmd = sub.add_parser(
        "agent-audit",
        help="OWASP Agentic AI Top 10 compliance audit for AI agents",
        description=(
            "Audit an AI agent manifest against the OWASP Agentic AI Top 10 (December 2025): "
            "goal hijacking, unsafe tools, identity abuse, memory poisoning, cascading failure, "
            "rogue agents, auditability, excessive autonomy, data exfiltration, human oversight.\n\n"
            "Example: squash agent-audit ./agent.json\n"
            "Example: squash agent-audit ./agent.json --output agent_audit.json --fail-on-critical\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    agent_audit_cmd.add_argument("manifest_path", help="Path to agent manifest JSON file")
    agent_audit_cmd.add_argument("--output", "-o", default=None, help="Output path for audit report JSON")
    agent_audit_cmd.add_argument("--fail-on-critical", action="store_true", help="Exit 2 if any CRITICAL risk found")
    agent_audit_cmd.add_argument("--fail-on-high", action="store_true", help="Exit 2 if any HIGH risk found")
    agent_audit_cmd.add_argument("--format", default="text", choices=["text", "json"], help="Output format")

    # ── W173 — Incident Response ──────────────────────────────────────────────
    incident_cmd = sub.add_parser(
        "incident",
        help="Generate AI incident response package (EU AI Act Article 73 disclosure)",
        description=(
            "Generate a structured incident response package including the model attestation "
            "snapshot, EU AI Act Article 73 disclosure document, drift delta, and remediation plan.\n\n"
            "Example: squash incident ./my-model --description 'Model output exposed PII'\n"
            "Example: squash incident ./my-model --severity serious --affected-persons 150\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    incident_cmd.add_argument("model_path", help="Path to model directory")
    incident_cmd.add_argument("--description", "-d", required=True, help="Incident description")
    incident_cmd.add_argument("--timestamp", default=None, help="Incident timestamp (ISO8601, default: now)")
    incident_cmd.add_argument("--severity", default="serious",
                              choices=["critical", "serious", "moderate", "minor"],
                              help="Incident severity (default: serious)")
    incident_cmd.add_argument("--category", default="other",
                              choices=["bias_discrimination", "pii_exposure", "harmful_output",
                                       "model_failure", "security_breach", "accuracy_regression",
                                       "policy_violation", "data_poisoning", "prompt_injection", "other"],
                              help="Incident category")
    incident_cmd.add_argument("--affected-persons", type=int, default=0, dest="affected_persons",
                              help="Number of affected persons")
    incident_cmd.add_argument("--output-dir", default=None, dest="output_dir",
                              help="Output directory for incident package")
    incident_cmd.add_argument("--model-id", default=None, dest="model_id", help="Override model ID")

    # ── W174 — Board Report ───────────────────────────────────────────────────
    board_report_cmd = sub.add_parser(
        "board-report",
        help="Generate executive AI compliance board report",
        description=(
            "Generate a quarterly AI compliance board report: compliance scorecard, "
            "model portfolio status, violations, CVEs, regulatory deadlines, and remediation roadmap.\n\n"
            "Example: squash board-report --models-dir ./models --quarter Q2-2026\n"
            "Example: squash board-report --model ./my-model --output-dir ./reports\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    board_report_cmd.add_argument("--models-dir", default=None, dest="models_dir",
                                  help="Directory containing model subdirectories")
    board_report_cmd.add_argument("--model", default=None, dest="model_path",
                                  help="Single model directory path")
    board_report_cmd.add_argument("--quarter", "-q", default=None,
                                  help="Quarter identifier, e.g. Q2-2026 (default: current quarter)")
    board_report_cmd.add_argument("--output-dir", default=None, dest="output_dir",
                                  help="Output directory (default: ./board-report-<quarter>)")
    board_report_cmd.add_argument("--format", default="all", choices=["all", "json", "md", "text"],
                                  help="Output format (default: all)")
    board_report_cmd.add_argument("--json", dest="output_json", action="store_true",
                                  help="Print JSON summary to stdout")

    # ── W182 — Annual Review ──────────────────────────────────────────────────
    annual_review_cmd = sub.add_parser(
        "annual-review",
        help="Generate annual AI system compliance review",
        description=(
            "Generate a full annual AI compliance review: model portfolio audit, "
            "compliance score trend, incident log, regulatory changes, and next-year objectives.\n\n"
            "Examples:\n"
            "  squash annual-review --year 2025 --models-dir ./models\n"
            "  squash annual-review --model ./my-model --output-dir ./annual-review-2025\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    annual_review_cmd.add_argument("--year", type=int, default=None, help="Review year (default: last year)")
    annual_review_cmd.add_argument("--models-dir", default=None, dest="models_dir")
    annual_review_cmd.add_argument("--model", default=None, dest="model_path")
    annual_review_cmd.add_argument("--output-dir", default=None, dest="output_dir")
    annual_review_cmd.add_argument("--json", dest="output_json", action="store_true")

    # ── W183 — Attestation Registry ───────────────────────────────────────────
    pub_cmd = sub.add_parser(
        "publish",
        help="Publish attestation to the squash public registry",
        description=(
            "Publish a signed attestation to the squash attestation registry "
            "(att://attestations.getsquash.dev). Buyers can verify your compliance posture "
            "in <10 seconds without questionnaires.\n\n"
            "Examples:\n"
            "  squash publish ./my-model --org acme-corp\n"
            "  squash publish ./my-model --org acme-corp --private\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pub_cmd.add_argument("model_path", help="Path to model directory with squash artifacts")
    pub_cmd.add_argument("--org", default="default", help="Organization name")
    pub_cmd.add_argument("--model-id", default=None, dest="model_id")
    pub_cmd.add_argument("--private", action="store_true", help="Publish as private (not queryable)")
    pub_cmd.add_argument("--db", default=None)

    lookup_cmd = sub.add_parser(
        "lookup",
        help="Query the squash attestation registry",
        description="Look up published attestations by model ID or organization.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lookup_cmd.add_argument("--model-id", default=None, dest="model_id")
    lookup_cmd.add_argument("--org", default=None)
    lookup_cmd.add_argument("--entry-id", default=None, dest="entry_id")
    lookup_cmd.add_argument("--json", dest="output_json", action="store_true")
    lookup_cmd.add_argument("--db", default=None)

    reg_verify_cmd = sub.add_parser(
        "verify-entry",
        help="Verify integrity of a published registry entry",
    )
    reg_verify_cmd.add_argument("entry_id", help="Registry entry ID")
    reg_verify_cmd.add_argument("--db", default=None)

    # ── W184 — CISO Dashboard ─────────────────────────────────────────────────
    dashboard_cmd = sub.add_parser(
        "dashboard",
        help="CISO/Executive AI compliance dashboard",
        description=(
            "Render a terminal compliance dashboard: portfolio score, violations, CVEs, "
            "regulatory deadline countdown, and model risk heat-map.\n\n"
            "Examples:\n"
            "  squash dashboard --models-dir ./models\n"
            "  squash dashboard --model ./my-model --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dashboard_cmd.add_argument("--models-dir", default=None, dest="models_dir")
    dashboard_cmd.add_argument("--model", default=None, dest="model_path")
    dashboard_cmd.add_argument("--json", dest="output_json", action="store_true")
    dashboard_cmd.add_argument("--no-color", action="store_true", dest="no_color")

    # ── W185 — Regulatory Intelligence Feed ───────────────────────────────────
    regulatory_cmd = sub.add_parser(
        "regulatory",
        help="Regulatory intelligence feed — AI regulation tracking and deadline monitoring",
        description=(
            "Track AI regulations across all major jurisdictions, monitor enforcement deadlines, "
            "and check which regulations affect your AI portfolio.\n\n"
            "Examples:\n"
            "  squash regulatory status\n"
            "  squash regulatory list --jurisdiction eu\n"
            "  squash regulatory updates --since 2026-01-01\n"
            "  squash regulatory deadlines --days 180\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    reg_sub = regulatory_cmd.add_subparsers(dest="regulatory_command", metavar="SUBCOMMAND")

    reg_status = reg_sub.add_parser("status", help="Overall regulatory status summary")
    reg_status.add_argument("--json", dest="output_json", action="store_true")

    reg_list = reg_sub.add_parser("list", help="List all tracked regulations")
    reg_list.add_argument("--jurisdiction", default=None, help="Filter by jurisdiction (eu, us_federal, us_state, global)")
    reg_list.add_argument("--industry", default=None, help="Filter by industry")
    reg_list.add_argument("--json", dest="output_json", action="store_true")

    reg_updates = reg_sub.add_parser("updates", help="Show regulatory changes since a date")
    reg_updates.add_argument("--since", default=None, help="ISO date filter, e.g. 2026-01-01")
    reg_updates.add_argument("--json", dest="output_json", action="store_true")

    reg_deadlines = reg_sub.add_parser("deadlines", help="Upcoming enforcement deadlines")
    reg_deadlines.add_argument("--days", type=int, default=365, help="Look-ahead window in days")
    reg_deadlines.add_argument("--json", dest="output_json", action="store_true")

    # ── W186 — M&A Due Diligence ──────────────────────────────────────────────
    dd_cmd = sub.add_parser(
        "due-diligence",
        help="M&A / investment AI due diligence package",
        description=(
            "Generate a comprehensive AI compliance package for M&A review: model inventory, "
            "security exposure, regulatory compliance matrix, training data provenance, "
            "bias audit results, liability flags, and R&W guidance.\n\n"
            "Examples:\n"
            "  squash due-diligence --models-dir ./models --company AcmeCorp\n"
            "  squash due-diligence --model ./my-model --deal-type investment\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dd_cmd.add_argument("--models-dir", default=None, dest="models_dir")
    dd_cmd.add_argument("--model", default=None, dest="model_path")
    dd_cmd.add_argument("--company", default="Target Company", help="Target company name")
    dd_cmd.add_argument("--deal-type", default="acquisition", dest="deal_type",
                        choices=["acquisition", "investment", "partnership"])
    dd_cmd.add_argument("--output-dir", default=None, dest="output_dir")
    dd_cmd.add_argument("--json", dest="output_json", action="store_true")

    # ── W178 — AI Vendor Risk Register ───────────────────────────────────────
    vendor_cmd = sub.add_parser(
        "vendor",
        help="AI Vendor Risk Register — track and assess third-party AI vendors",
        description=(
            "Manage the AI vendor risk register: add vendors, generate due-diligence "
            "questionnaires, import Trust Packages, and monitor assessment status.\n\n"
            "Examples:\n"
            "  squash vendor add --name OpenAI --risk-tier high --use-case 'Customer chat'\n"
            "  squash vendor list\n"
            "  squash vendor questionnaire VENDOR_ID\n"
            "  squash vendor import-trust-package VENDOR_ID ./vendor.zip\n"
            "  squash vendor summary\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vendor_sub = vendor_cmd.add_subparsers(dest="vendor_command", metavar="SUBCOMMAND")

    vendor_add = vendor_sub.add_parser("add", help="Add a new AI vendor to the register")
    vendor_add.add_argument("--name", required=True, help="Vendor name")
    vendor_add.add_argument("--website", default="", help="Vendor website URL")
    vendor_add.add_argument("--risk-tier", default="medium",
                            choices=["critical","high","medium","low"], dest="risk_tier",
                            help="Risk tier (default: medium)")
    vendor_add.add_argument("--use-case", default="", dest="use_case", help="Use case description")
    vendor_add.add_argument("--data-access", default="none", dest="data_access",
                            help="Data accessed (e.g. PII, financial, none)")
    vendor_add.add_argument("--notes", default="", help="Additional notes")
    vendor_add.add_argument("--db", default=None, help="Registry database path")

    vendor_list = vendor_sub.add_parser("list", help="List registered vendors")
    vendor_list.add_argument("--tier", default=None, help="Filter by risk tier")
    vendor_list.add_argument("--json", dest="output_json", action="store_true")
    vendor_list.add_argument("--db", default=None)

    vendor_q = vendor_sub.add_parser("questionnaire", help="Generate due-diligence questionnaire for a vendor")
    vendor_q.add_argument("vendor_id", help="Vendor ID")
    vendor_q.add_argument("--output", "-o", default=None, help="Output file (.json or .txt)")
    vendor_q.add_argument("--db", default=None)

    vendor_import = vendor_sub.add_parser("import-trust-package", help="Import and verify a vendor Trust Package")
    vendor_import.add_argument("vendor_id", help="Vendor ID")
    vendor_import.add_argument("package_path", help="Path to trust package ZIP")
    vendor_import.add_argument("--db", default=None)

    vendor_summary = vendor_sub.add_parser("summary", help="Show vendor risk register summary")
    vendor_summary.add_argument("--json", dest="output_json", action="store_true")
    vendor_summary.add_argument("--db", default=None)

    # ── W179 — AI Asset Registry ──────────────────────────────────────────────
    registry_cmd = sub.add_parser(
        "registry",
        help="AI Asset Registry — inventory of all AI models in the organization",
        description=(
            "Maintain a continuously updated inventory of every AI model the organization owns.\n\n"
            "Examples:\n"
            "  squash registry add --model-id gpt4-ft-v2 --environment production\n"
            "  squash registry sync ./my-model\n"
            "  squash registry list\n"
            "  squash registry summary\n"
            "  squash registry export --format md\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    registry_sub = registry_cmd.add_subparsers(dest="registry_command", metavar="SUBCOMMAND")

    registry_add = registry_sub.add_parser("add", help="Register an AI asset")
    registry_add.add_argument("--model-id", required=True, dest="model_id")
    registry_add.add_argument("--model-path", default="", dest="model_path")
    registry_add.add_argument("--environment", default="development",
                              choices=["production","staging","development","research","retired"])
    registry_add.add_argument("--owner", default="")
    registry_add.add_argument("--team", default="")
    registry_add.add_argument("--risk-tier", default="unknown", dest="risk_tier")
    registry_add.add_argument("--notes", default="")
    registry_add.add_argument("--shadow", action="store_true", help="Flag as shadow AI")
    registry_add.add_argument("--db", default=None)

    registry_sync = registry_sub.add_parser("sync", help="Sync an asset from squash attestation artifacts")
    registry_sync.add_argument("model_path", help="Path to model directory with squash artifacts")
    registry_sync.add_argument("--db", default=None)

    registry_list = registry_sub.add_parser("list", help="List all registered assets")
    registry_list.add_argument("--environment", default=None)
    registry_list.add_argument("--risk-tier", default=None, dest="risk_tier")
    registry_list.add_argument("--shadow-only", action="store_true", dest="shadow_only")
    registry_list.add_argument("--json", dest="output_json", action="store_true")
    registry_list.add_argument("--db", default=None)

    registry_summary = registry_sub.add_parser("summary", help="Show asset registry summary")
    registry_summary.add_argument("--json", dest="output_json", action="store_true")
    registry_summary.add_argument("--db", default=None)

    registry_export = registry_sub.add_parser("export", help="Export registry to JSON or Markdown")
    registry_export.add_argument("--format", default="json", choices=["json","md"])
    registry_export.add_argument("--output", "-o", default=None)
    registry_export.add_argument("--db", default=None)

    # ── W180 — Training Data Lineage ──────────────────────────────────────────
    data_lineage_cmd = sub.add_parser(
        "data-lineage",
        help="Training Data Lineage Certificate — license check, PII risk, GDPR assessment",
        description=(
            "Trace training datasets from a model directory, check licenses against the "
            "SPDX database, flag PII risks, and generate a signed lineage certificate.\n\n"
            "Examples:\n"
            "  squash data-lineage ./my-model\n"
            "  squash data-lineage ./my-model --config train_config.json\n"
            "  squash data-lineage ./my-model --datasets wikipedia,common_crawl\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    data_lineage_cmd.add_argument("model_path", help="Path to model directory")
    data_lineage_cmd.add_argument("--config", default=None, dest="config_path",
                                  help="Training config file path")
    data_lineage_cmd.add_argument("--datasets", default=None,
                                  help="Comma-separated list of dataset names (supplements auto-detection)")
    data_lineage_cmd.add_argument("--model-id", default=None, dest="model_id")
    data_lineage_cmd.add_argument("--output", "-o", default=None,
                                  help="Output path (default: model_path/data_lineage_certificate.json)")
    data_lineage_cmd.add_argument("--format", default="text", choices=["text", "json"])
    data_lineage_cmd.add_argument("--fail-on-pii", action="store_true", dest="fail_on_pii",
                                  help="Exit 2 if HIGH or CRITICAL PII risk detected")
    data_lineage_cmd.add_argument("--fail-on-license", action="store_true", dest="fail_on_license",
                                  help="Exit 2 if any license issues detected")

    # ── W181 — Bias Audit ─────────────────────────────────────────────────────
    bias_audit_cmd = sub.add_parser(
        "bias-audit",
        help="Algorithmic bias audit (NYC Local Law 144, EU AI Act Annex III, ECOA)",
        description=(
            "Audit model predictions for bias across protected attributes.\n"
            "Metrics: Demographic Parity Difference, Disparate Impact Ratio (4/5ths rule), "
            "Equalized Odds Difference, Predictive Equality Difference.\n\n"
            "Examples:\n"
            "  squash bias-audit --predictions pred.csv --protected age_group,gender\n"
            "  squash bias-audit --predictions pred.csv --standard nyc_local_law_144 "
            "--label-col hired --pred-col model_output --fail-on-fail\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bias_audit_cmd.add_argument("--predictions", required=True, dest="predictions_path",
                                help="Path to CSV with predictions and protected attributes")
    bias_audit_cmd.add_argument("--protected", required=True,
                                help="Comma-separated protected attribute column names")
    bias_audit_cmd.add_argument("--label-col", default="label", dest="label_col",
                                help="Ground truth label column name (default: label)")
    bias_audit_cmd.add_argument("--pred-col", default="prediction", dest="pred_col",
                                help="Prediction column name (default: prediction)")
    bias_audit_cmd.add_argument("--standard", default="generic", dest="standard",
                                choices=["nyc_local_law_144","eu_ai_act_annex_iii",
                                         "ecoa_4_5ths_rule","fair_housing","generic"],
                                help="Regulatory standard for thresholds (default: generic)")
    bias_audit_cmd.add_argument("--model-id", default="model", dest="model_id")
    bias_audit_cmd.add_argument("--output", "-o", default=None,
                                help="Output path for audit report JSON")
    bias_audit_cmd.add_argument("--format", default="text", choices=["text","json"])
    bias_audit_cmd.add_argument("--fail-on-fail", action="store_true", dest="fail_on_fail",
                                help="Exit 2 if overall verdict is FAIL")
    bias_audit_cmd.add_argument("--fail-on-warn", action="store_true", dest="fail_on_warn",
                                help="Exit 2 if overall verdict is WARN or FAIL")

    # ── W191 — SBOM diff ──────────────────────────────────────────────────────
    diff_cmd = sub.add_parser(
        "diff",
        help="Compare two squash attestation files and show compliance delta",
        description=(
            "Compare two squash attestation JSON files. Shows compliance score movement,\n"
            "component changes, policy drift, and vulnerability lifecycle.\n\n"
            "Examples:\n"
            "  squash diff v1.json v2.json\n"
            "  squash diff v1.json v2.json --format json\n"
            "  squash diff v1.json v2.json --format html --output delta.html\n"
            "  squash diff v1.json v2.json --fail-on-regression\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    diff_cmd.add_argument("before", help="Path to the older (before) attestation JSON")
    diff_cmd.add_argument("after", help="Path to the newer (after) attestation JSON")
    diff_cmd.add_argument(
        "--format", default="table",
        choices=["table", "json", "html", "summary"],
        help="Output format (default: table)",
    )
    diff_cmd.add_argument("--output", "-o", default=None, help="Write output to file instead of stdout")
    diff_cmd.add_argument(
        "--fail-on-regression", action="store_true", dest="fail_on_regression",
        help="Exit 2 if compliance regression is detected",
    )

    # ── W190 — Webhook management ─────────────────────────────────────────────
    webhook_cmd = sub.add_parser(
        "webhook",
        help="Manage outbound webhook endpoints for squash compliance events",
        description=(
            "Register, list, test, and remove outbound webhook endpoints.\n"
            "Squash POSTs signed JSON events to registered endpoints on attestation,\n"
            "violation, drift, and VEX alert events.\n\n"
            "Examples:\n"
            "  squash webhook add --url https://hooks.example.com/squash --events attestation.complete\n"
            "  squash webhook list\n"
            "  squash webhook test --url https://hooks.example.com/squash\n"
            "  squash webhook remove <id>\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    webhook_sub = webhook_cmd.add_subparsers(dest="webhook_command")
    wh_add = webhook_sub.add_parser("add", help="Register a new webhook endpoint")
    wh_add.add_argument("--url", required=True, help="HTTPS endpoint URL")
    wh_add.add_argument(
        "--events", default=None,
        help="Comma-separated event types (default: all). Options: attestation.complete,violation.detected,drift.detected,vex.alert,score.changed",
    )
    wh_add.add_argument("--secret", default=None, help="HMAC-SHA256 signing secret (auto-generated if omitted)")
    wh_list = webhook_sub.add_parser("list", help="List registered webhook endpoints")
    wh_list.add_argument("--all", action="store_true", dest="show_all", help="Include inactive endpoints")
    wh_test = webhook_sub.add_parser("test", help="Send a test event to a URL")
    wh_test.add_argument("--url", required=True, help="URL to test")
    wh_rm = webhook_sub.add_parser("remove", help="Deactivate a webhook endpoint")
    wh_rm.add_argument("id", help="Endpoint ID to remove")

    # ── W188 — Telemetry ──────────────────────────────────────────────────────
    telemetry_cmd = sub.add_parser(
        "telemetry",
        help="Configure and test OpenTelemetry integration",
        description=(
            "Configure squash to emit OpenTelemetry spans for every attestation run.\n"
            "Integrates with Datadog, Honeycomb, Jaeger, and any OTLP-compatible backend.\n\n"
            "Examples:\n"
            "  squash telemetry status\n"
            "  squash telemetry test --endpoint http://localhost:4317\n"
            "  squash telemetry configure --endpoint http://otelcollector:4317 --service squash-prod\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    telemetry_sub = telemetry_cmd.add_subparsers(dest="telemetry_command")
    tel_status = telemetry_sub.add_parser("status", help="Show current telemetry configuration")
    tel_test = telemetry_sub.add_parser("test", help="Send a test span to verify connectivity")
    tel_test.add_argument("--endpoint", default=None, help="OTLP gRPC endpoint (overrides env var)")
    tel_test.add_argument("--http-endpoint", default=None, dest="http_endpoint", help="OTLP HTTP endpoint")
    tel_configure = telemetry_sub.add_parser("configure", help="Show configuration instructions")
    tel_configure.add_argument("--endpoint", default=None, help="OTLP gRPC endpoint")
    tel_configure.add_argument("--service", default="squash", help="Service name (default: squash)")

    # ── W189 — GitOps ─────────────────────────────────────────────────────────
    gitops_cmd = sub.add_parser(
        "gitops",
        help="ArgoCD / Flux GitOps enforcement gate for Kubernetes deployments",
        description=(
            "Enforce squash compliance in Kubernetes GitOps pipelines.\n"
            "Blocks deployment of AI models that lack valid attestations or\n"
            "fall below the minimum compliance score.\n\n"
            "Examples:\n"
            "  squash gitops check --manifest deployment.yaml --min-score 80\n"
            "  squash gitops webhook-manifest --url https://squash.example.com\n"
            "  squash gitops annotate --deployment my-model --attestation att://myorg/v1 --score 87.5\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    gitops_sub = gitops_cmd.add_subparsers(dest="gitops_command")
    go_check = gitops_sub.add_parser("check", help="Check a K8s manifest for squash compliance annotations")
    go_check.add_argument("--manifest", required=True, dest="manifest_path", help="Path to K8s manifest YAML")
    go_check.add_argument("--min-score", type=float, default=80.0, dest="min_score", help="Minimum compliance score (default: 80)")
    go_check.add_argument("--require-attestation", action="store_true", default=True, dest="require_attestation")
    go_check.add_argument("--json", action="store_true", dest="output_json", help="Output JSON")
    go_manifest = gitops_sub.add_parser("webhook-manifest", help="Generate K8s ValidatingWebhookConfiguration YAML")
    go_manifest.add_argument("--url", required=True, help="HTTPS URL where squash webhook is hosted")
    go_manifest.add_argument("--namespace", default="squash-system", help="Kubernetes namespace (default: squash-system)")
    go_manifest.add_argument("--failure-policy", default="Fail", choices=["Fail", "Ignore"], dest="failure_policy")
    go_annotate = gitops_sub.add_parser("annotate", help="Print kubectl annotate command for a deployment")
    go_annotate.add_argument("--deployment", required=True, help="Deployment name")
    go_annotate.add_argument("--attestation", required=True, dest="attestation_id", help="Attestation ID (att:// URI)")
    go_annotate.add_argument("--score", type=float, required=True, dest="compliance_score", help="Compliance score")
    go_annotate.add_argument("--policy", default="eu-ai-act", help="Policy name (default: eu-ai-act)")
    go_annotate.add_argument("--passed", action="store_true", default=True)

    # ── W135 / W136 — Annex IV generate + validate ────────────────────────────
    annex_iv_cmd = sub.add_parser(
        "annex-iv",
        help="EU AI Act Annex IV technical documentation (generate / validate)",
        description=(
            "Generate or validate EU AI Act Annex IV technical documentation.\n\n"
            "Examples:\n"
            "  squash annex-iv generate --root ./my-training-run --system-name \"BERT Classifier\"\n"
            "  squash annex-iv generate --root . --format md html json pdf --output-dir ./docs\n"
            "  squash annex-iv validate ./docs/annex_iv.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    annex_iv_sub = annex_iv_cmd.add_subparsers(dest="annex_iv_command", metavar="SUBCOMMAND")
    annex_iv_sub.required = True

    # squash annex-iv generate
    aiv_gen = annex_iv_sub.add_parser(
        "generate",
        help="Generate Annex IV documentation from a training run directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    aiv_gen.add_argument(
        "--root", "-r",
        required=True,
        metavar="DIR",
        help="Training run directory to scan (TensorBoard logs, configs, .py files)",
    )
    aiv_gen.add_argument(
        "--output-dir", "-o",
        default=None,
        metavar="DIR",
        help="Directory to write Annex IV artifacts. Defaults to --root.",
    )
    aiv_gen.add_argument(
        "--format", "-f",
        dest="formats",
        nargs="+",
        default=["md", "json"],
        choices=["md", "html", "json", "pdf"],
        metavar="FMT",
        help="Output formats: md html json pdf (default: md json)",
    )
    aiv_gen.add_argument("--system-name",    default="AI System",  help="Human-readable AI system name (§1(a))")
    aiv_gen.add_argument("--version",        default="1.0.0",      help="System version string (§1(a))")
    aiv_gen.add_argument("--intended-purpose", default=None,        help="§1(b) — what this system is designed to do")
    aiv_gen.add_argument("--risk-level",     default=None,
                         choices=["minimal", "limited", "high", "unacceptable"],
                         help="EU AI Act risk classification (§4)")
    aiv_gen.add_argument("--general-description", default=None,    help="§1(a) — free-text system overview")
    aiv_gen.add_argument("--hardware",       dest="hardware_requirements", default=None,
                         help="§1(a) — compute / hardware requirements")
    aiv_gen.add_argument("--deployment-context", default=None,     help="§1(b) — production environment description")
    aiv_gen.add_argument("--risk-management", default=None,        help="§4 — risk management system description")
    aiv_gen.add_argument("--oversight",      dest="oversight_description", default=None,
                         help="§5 — human oversight description")
    aiv_gen.add_argument("--model-type",     default=None,         help="§3(a) — architecture family (e.g. transformer)")
    aiv_gen.add_argument("--lifecycle-plan", default=None,         help="§7 — lifecycle management description")
    aiv_gen.add_argument("--monitoring-plan", default=None,        help="§7 — post-deployment monitoring")
    aiv_gen.add_argument(
        "--mlflow-run",
        default=None,
        metavar="RUN_ID",
        help="Augment with MLflow run metrics and params (requires mlflow)",
    )
    aiv_gen.add_argument(
        "--mlflow-uri",
        default="http://localhost:5000",
        metavar="URI",
        help="MLflow tracking URI (default: http://localhost:5000)",
    )
    aiv_gen.add_argument(
        "--wandb-run",
        default=None,
        metavar="ENTITY/PROJECT/RUN_ID",
        help="Augment with Weights & Biases run (requires wandb)",
    )
    aiv_gen.add_argument(
        "--hf-dataset",
        dest="hf_datasets",
        action="append",
        default=[],
        metavar="DATASET_ID",
        help="Augment with HuggingFace dataset provenance (repeatable)",
    )
    aiv_gen.add_argument(
        "--hf-token",
        default=None,
        metavar="TOKEN",
        help="HuggingFace API token for private datasets",
    )
    aiv_gen.add_argument(
        "--stem",
        default="annex_iv",
        metavar="NAME",
        help="Output filename stem (default: annex_iv → annex_iv.md, annex_iv.json, …)",
    )
    aiv_gen.add_argument("--no-validate", action="store_true", help="Skip post-generation validation report")
    aiv_gen.add_argument("--fail-on-warning", action="store_true", help="Exit 1 if validation produces warnings")
    aiv_gen.add_argument("--quiet", action="store_true", help="Suppress informational output")

    # squash annex-iv validate
    aiv_val = annex_iv_sub.add_parser(
        "validate",
        help="Validate an existing Annex IV JSON document against EU AI Act requirements",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    aiv_val.add_argument(
        "document",
        metavar="PATH",
        help="Path to an annex_iv.json file produced by 'squash annex-iv generate'",
    )
    aiv_val.add_argument("--fail-on-warning", action="store_true", help="Exit 1 if validation produces warnings")
    aiv_val.add_argument("--quiet", action="store_true", help="Suppress informational output")

    # ── W160 — squash demo ────────────────────────────────────────────────────
    demo_cmd = sub.add_parser(
        "demo",
        help="Run a zero-setup attestation demo against a bundled sample model.",
        description=(
            "Runs a complete squash attestation pipeline on a bundled sample AI model "
            "artifact — no setup, no credentials, no model download required. "
            "Produces a CycloneDX ML-BOM, SPDX SBOM, EU AI Act policy report, "
            "SLSA provenance record, and a signed audit trail — all in under 10 seconds.\n\n"
            "Examples:\n"
            "  squash demo\n"
            "  squash demo --output-dir ./demo-output\n"
            "  squash demo --policy nist-ai-rmf\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    demo_cmd.add_argument(
        "--output-dir",
        metavar="DIR",
        default="",
        help="Write artifacts here instead of a temp directory.",
    )
    demo_cmd.add_argument(
        "--policy",
        metavar="POLICY",
        default="eu-ai-act",
        help="Policy to evaluate (default: eu-ai-act).",
    )
    demo_cmd.add_argument("--quiet", action="store_true", help="Suppress output")

    # ── W162 — squash init ────────────────────────────────────────────────────
    init_cmd = sub.add_parser(
        "init",
        help="Scaffold a .squash.yml config for the current project.",
        description=(
            "Auto-detects the ML framework in the current directory, generates a "
            ".squash.yml configuration scaffold with sensible policy defaults, and "
            "runs a first dry-run attestation to show what will be produced.\n\n"
            "Examples:\n"
            "  squash init\n"
            "  squash init --dir ./models/llama-3\n"
            "  squash init --framework pytorch --policy eu-ai-act nist-ai-rmf\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init_cmd.add_argument(
        "--dir",
        metavar="DIR",
        default=".",
        help="Project directory to inspect (default: current directory).",
    )
    init_cmd.add_argument(
        "--framework",
        metavar="FRAMEWORK",
        default="",
        help="Override framework detection (pytorch, tensorflow, jax, mlx, huggingface).",
    )
    init_cmd.add_argument(
        "--policy",
        metavar="POLICY",
        nargs="*",
        default=None,
        help="Policy templates to include in the scaffold (default: eu-ai-act).",
    )
    init_cmd.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Run a dry-run attestation after scaffolding (default: true).",
    )
    init_cmd.add_argument("--no-dry-run", action="store_false", dest="dry_run")
    init_cmd.add_argument("--quiet", action="store_true", help="Suppress output")

    # ── W167 — squash watch ───────────────────────────────────────────────────
    watch_cmd = sub.add_parser(
        "watch",
        help="Watch a model directory and re-attest on file changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Watch a model directory for changes and automatically re-run\n"
            "attestation whenever model files are modified. Press Ctrl+C to stop.\n\n"
            "Examples::\n\n"
            "  squash watch ./models\n"
            "  squash watch ./models --policy eu-ai-act --interval 10\n"
            "  squash watch ./models --on-fail notify\n"
        ),
    )
    watch_cmd.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Model directory to watch (default: current directory).",
    )
    watch_cmd.add_argument(
        "--policy",
        nargs="+",
        default=["eu-ai-act"],
        metavar="POLICY",
        help="Policy framework(s) to enforce (default: eu-ai-act).",
    )
    watch_cmd.add_argument(
        "--interval",
        type=int,
        default=5,
        metavar="SECONDS",
        help="Polling interval in seconds (default: 5).",
    )
    watch_cmd.add_argument(
        "--on-fail",
        choices=["log", "notify", "exit"],
        default="log",
        dest="on_fail",
        help="Action on attestation failure (default: log).",
    )
    watch_cmd.add_argument(
        "--output-dir",
        default=None,
        metavar="DIR",
        help="Directory to write attestation artifacts (default: <path>/attestation).",
    )
    watch_cmd.add_argument("--quiet", action="store_true", help="Suppress output")

    # ── W168 — squash install-hook ────────────────────────────────────────────
    hook_cmd = sub.add_parser(
        "install-hook",
        help="Install squash as a git pre-push hook.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Install a git pre-push hook that runs squash attest before every push.\n"
            "Blocks the push if attestation fails.\n\n"
            "Examples::\n\n"
            "  squash install-hook\n"
            "  squash install-hook --dir ./my-repo\n"
            "  squash install-hook --hook-type pre-commit\n"
        ),
    )
    hook_cmd.add_argument(
        "--dir",
        default=".",
        metavar="DIR",
        help="Git repository root (default: current directory).",
    )
    hook_cmd.add_argument(
        "--hook-type",
        choices=["pre-push", "pre-commit"],
        default="pre-push",
        dest="hook_type",
        help="Git hook type to install (default: pre-push).",
    )
    hook_cmd.add_argument(
        "--policy",
        nargs="+",
        default=["eu-ai-act"],
        metavar="POLICY",
        help="Policy framework(s) to enforce in the hook.",
    )
    hook_cmd.add_argument("--quiet", action="store_true", help="Suppress output")

    return parser


def _cmd_policies(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.policy import AVAILABLE_POLICIES, PolicyRegistry
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    validate_path: str | None = getattr(args, "validate", None)

    if validate_path is not None:
        rules_path = Path(validate_path)
        if not rules_path.exists():
            print(f"error: path does not exist: {rules_path}", file=sys.stderr)
            return 1
        try:
            rules = PolicyRegistry.load_rules_from_yaml(rules_path)
        except ImportError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        except (OSError, ValueError) as e:
            print(f"error loading rules: {e}", file=sys.stderr)
            return 1

        raw_errors = PolicyRegistry.validate_rules(rules)
        if raw_errors:
            if not quiet:
                print(f"✗ {len(raw_errors)} validation error(s):", file=sys.stderr)
                for err in raw_errors:
                    print(f"  {err}", file=sys.stderr)
            return 2

        if not quiet:
            print(f"✓ {len(rules)} rule(s) valid: {rules_path}")
        return 0

    if not quiet:
        print("Available policy templates:")
    for name in sorted(AVAILABLE_POLICIES):
        print(f"  {name}")
    return 0


def _cmd_scan(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.scanner import ModelScanner
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: path does not exist: {model_path}", file=sys.stderr)
        return 1

    scan_dir = model_path if model_path.is_dir() else model_path.parent
    result = ModelScanner.scan_directory(scan_dir)

    if not quiet:
        icon = "✓" if result.is_safe else "✗"
        print(f"{icon} Scan {result.status}: {scan_dir}")
        for f in result.findings:
            print(f"  [{f.severity.upper()}] {f.title} — {f.detail}")

    if args.json_result:
        data = {
            "status": result.status,
            "is_safe": result.is_safe,
            "critical": result.critical_count,
            "high": result.high_count,
            "findings": [
                {"severity": f.severity, "title": f.title, "file": f.file_path}
                for f in result.findings
            ],
        }
        Path(args.json_result).write_text(json.dumps(data, indent=2))

    if args.sarif:
        try:
            from squash.sarif import SarifBuilder
        except ImportError as e:  # pragma: no cover
            print(f"sarif export unavailable: {e}", file=sys.stderr)
            return 2
        SarifBuilder.write(result, Path(args.sarif))
        if not quiet:
            print(f"SARIF written to {args.sarif}")

    if getattr(args, "exit_2_on_unsafe", False):
        if result.critical_count > 0 or result.high_count > 0:
            return 2
        if not result.is_safe:
            return 1
        return 0

    return 0 if result.is_safe else 2


def _cmd_diff(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.sbom_builder import SbomDiff
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    path_a = Path(args.sbom_a)
    path_b = Path(args.sbom_b)
    for p in (path_a, path_b):
        if not p.exists():
            print(f"error: path does not exist: {p}", file=sys.stderr)
            return 1

    try:
        bom_a = json.loads(path_a.read_text(encoding="utf-8"))
        bom_b = json.loads(path_b.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error reading SBOM: {e}", file=sys.stderr)
        return 1

    diff = SbomDiff.compare(bom_a, bom_b)

    if not quiet:
        print(f"hash changed:          {diff.hash_changed}")
        print(f"score delta:           {diff.score_delta}")
        print(f"policy status changed: {diff.policy_status_changed}")
        if diff.new_findings:
            print(f"new findings ({len(diff.new_findings)}):")
            for fid in diff.new_findings:
                print(f"  + {fid}")
        if diff.resolved_findings:
            print(f"resolved findings ({len(diff.resolved_findings)}):")
            for fid in diff.resolved_findings:
                print(f"  - {fid}")
        if diff.metadata_changes:
            print("metadata changes:")
            for key, (old, new) in diff.metadata_changes.items():
                print(f"  {key}: {old!r} → {new!r}")

    if getattr(args, "exit_1_on_regression", False) and diff.has_regressions:
        return 1
    return 0


def _cmd_verify(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.oms_signer import OmsVerifier
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: path does not exist: {model_path}", file=sys.stderr)
        return 1

    bom_path = model_path / "cyclonedx-mlbom.json" if model_path.is_dir() else model_path
    if not bom_path.exists():
        print(f"error: CycloneDX BOM not found: {bom_path}", file=sys.stderr)
        return 1

    bundle_path = Path(args.bundle) if args.bundle else None
    result = OmsVerifier.verify(bom_path, bundle_path)

    if result is None:
        if args.strict:
            if not quiet:
                print("✗ no bundle found (strict mode)", file=sys.stderr)
            return 2
        if not quiet:
            print("— verification skipped (no bundle)")
        return 0

    if result:
        if not quiet:
            print(f"✓ verified: {bom_path}")
        return 0

    print(f"✗ verification FAILED: {bom_path}", file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────────
# Wave 49 — air-gapped / offline signing helpers
# ────────────────────────────────────────────────────────────────────────────

def _cmd_keygen(args: argparse.Namespace, quiet: bool) -> int:
    """Generate an Ed25519 keypair for offline BOM signing."""
    try:
        from squash.oms_signer import OmsSigner
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    try:
        priv_path, pub_path = OmsSigner.keygen(args.name, args.key_dir)
    except ImportError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"runtime error: {e}", file=sys.stderr)
        return 2

    if not quiet:
        print(f"✓ keypair generated:")
        print(f"  Private : {priv_path}")
        print(f"  Public  : {pub_path}")
        print()
        print("Keep the private key secret.  Share the public key for verification.")
        print(f"  Sign  : squash attest <model> --sign --offline --offline-key {priv_path}")
        print(f"  Verify: squash verify-local <bom> --key {pub_path}")
    return 0


def _cmd_verify_local(args: argparse.Namespace, quiet: bool) -> int:
    """Verify a BOM's Ed25519 offline signature against a local public key."""
    try:
        from squash.oms_signer import OmsVerifier
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    bom_path = Path(args.bom_path)
    if not bom_path.exists():
        print(f"error: BOM not found: {bom_path}", file=sys.stderr)
        return 1

    pub_key_path = Path(args.pub_key)
    if not pub_key_path.exists():
        print(f"error: public key not found: {pub_key_path}", file=sys.stderr)
        return 1

    sig_path = Path(args.sig_file) if args.sig_file else None

    try:
        ok = OmsVerifier.verify_local(bom_path, pub_key_path, sig_path)
    except ImportError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"runtime error: {e}", file=sys.stderr)
        return 2

    if ok:
        if not quiet:
            print(f"✓ verified (offline): {bom_path}")
        return 0

    print(f"✗ verification FAILED (offline): {bom_path}", file=sys.stderr)
    return 2


def _cmd_pack_offline(args: argparse.Namespace, quiet: bool) -> int:
    """Bundle a model directory into a portable .squash-bundle.tar.gz archive."""
    try:
        from squash.oms_signer import OmsSigner
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        print(f"error: model_dir not found: {model_dir}", file=sys.stderr)
        return 1

    output_path = Path(args.output_path) if args.output_path else None

    try:
        bundle_path = OmsSigner.pack_offline(model_dir, output_path)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"runtime error: {e}", file=sys.stderr)
        return 2

    size_mb = bundle_path.stat().st_size / (1024 * 1024)
    if not quiet:
        print(f"✓ bundle created: {bundle_path} ({size_mb:.1f} MB)")
    return 0


def _cmd_attest(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.attest import (
            AttestConfig,
            AttestPipeline,
            AttestationViolationError,
        )
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: path does not exist: {model_path}", file=sys.stderr)
        return 1

    policies = args.policies if args.policies else ["enterprise-strict"]

    # Build SpdxOptions only when the user supplied at least one SPDX flag.
    spdx_options = None
    if any([
        args.spdx_type,
        args.spdx_safety_risk,
        args.spdx_datasets,
        args.spdx_training_info,
        args.spdx_sensitive_data,
    ]):
        from squash.spdx_builder import SpdxOptions
        spdx_options = SpdxOptions(
            type_of_model=args.spdx_type or "text-generation",
            safety_risk_assessment=args.spdx_safety_risk or "unspecified",
            dataset_ids=list(args.spdx_datasets),
            information_about_training=args.spdx_training_info or "see-model-card",
            sensitive_personal_information=args.spdx_sensitive_data or "absent",
        )

    config = AttestConfig(
        model_path=model_path,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        model_id=args.model_id,
        hf_repo=args.hf_repo,
        quant_format=args.quant_format,
        policies=policies,
        sign=args.sign,
        offline=args.offline,
        local_signing_key=Path(args.offline_key) if args.offline_key else None,
        fail_on_violation=False,  # handle ourselves below for clean exit codes
        skip_scan=args.skip_scan,
        spdx_options=spdx_options,
    )

    try:
        result = AttestPipeline.run(config)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"runtime error: {e}", file=sys.stderr)
        return 2

    if not quiet:
        icon = "✓" if result.passed else "✗"
        print(f"{icon} {result.summary()}")
        if result.cyclonedx_path:
            print(f"   CycloneDX : {result.cyclonedx_path}")
        if result.spdx_json_path:
            print(f"   SPDX JSON : {result.spdx_json_path}")
        if result.master_record_path:
            print(f"   Master    : {result.master_record_path}")
        if result.signature_path:
            print(f"   Signature : {result.signature_path}")

    if args.json_result and result.master_record_path and result.master_record_path.exists():
        import shutil
        shutil.copy2(result.master_record_path, args.json_result)

    if args.fail_on_violation and not result.passed:
        if not quiet:
            print("error: attestation failed (fail-on-violation set)", file=sys.stderr)
        return 2

    return 0 if result.passed else 2


# ────────────────────────────────────────────────────────────────────────────
# Wave 15  — HTML / JSON compliance report
# ────────────────────────────────────────────────────────────────────────────

def _cmd_report(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.report import ComplianceReporter
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: path does not exist: {model_path}", file=sys.stderr)
        return 1

    output = Path(args.output) if args.output else None
    fmt: str = getattr(args, "format", "html")

    if fmt == "json":
        # Emit a raw JSON summary of all artifacts (no HTML rendering)
        import json as _json
        from squash.report import _load_artifacts  # type: ignore[attr-defined]
        ctx = _load_artifacts(model_path)
        payload = {
            "model_dir": str(ctx["model_dir"]),
            "has_attest": ctx.get("attest") is not None,
            "has_cdx": ctx.get("cdx") is not None,
            "has_scan": ctx.get("scan") is not None,
            "has_vex": ctx.get("vex") is not None,
            "policy_count": len(ctx.get("policies", {})),
            "bundle_present": ctx.get("bundle_present", False),
        }
        dest = output or (model_path / "squash-report.json")
        dest.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
        if not quiet:
            print(f"Report written to {dest}")
        return 0

    try:
        dest = ComplianceReporter.write(model_path, output)
    except Exception as e:
        print(f"error generating report: {e}", file=sys.stderr)
        return 2

    if not quiet:
        print(f"Report written to {dest}")
    return 0


# ────────────────────────────────────────────────────────────────────────────
# Wave 16  — VEX feed cache management
# ────────────────────────────────────────────────────────────────────────────

def _cmd_vex(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.vex import VexCache
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    vex_cmd = getattr(args, "vex_command", None)
    if vex_cmd == "update":
        import os
        url = args.url or os.environ.get("SQUASH_VEX_URL", VexCache.DEFAULT_URL)
        timeout = float(args.timeout)
        api_key = os.environ.get("SQUASH_VEX_API_KEY") or None
        try:
            cache = VexCache()
            feed = cache.load_or_fetch(url, timeout=timeout, force=True, api_key=api_key)
            if not quiet:
                print(f"VEX cache updated: {len(feed.statements)} statements from {url}")
        except Exception as e:
            print(f"error updating VEX cache: {e}", file=sys.stderr)
            return 2
        return 0

    if vex_cmd == "status":
        cache = VexCache()
        manifest = cache.manifest()
        if not manifest:
            if not quiet:
                print("VEX cache: empty (run 'squash vex update' to populate)")
            return 0
        if not quiet:
            print(f"URL         : {manifest.get('url', 'unknown')}")
            print(f"Fetched at  : {manifest.get('last_fetched', 'unknown')}")
            print(f"Statements  : {manifest.get('statement_count', 'unknown')}")
            stale = cache.is_stale()
            print(f"Stale       : {'yes' if stale else 'no'}")
        return 0

    # ── Wave 52: subscribe  ───────────────────────────────────────────────────
    if vex_cmd == "subscribe":
        from squash.vex import VexSubscription, VexSubscriptionStore
        import os
        url = args.url
        if not url.startswith("http"):
            print(f"error: URL must begin with http(s)://: {url!r}", file=sys.stderr)
            return 1
        sub = VexSubscription(
            url=url,
            alias=args.alias or "",
            api_key_env_var=args.api_key_env,
            polling_hours=args.polling_hours,
        )
        _store_dir = os.environ.get("SQUISH_SQUASH_STORE_DIR")
        store = VexSubscriptionStore(Path(_store_dir) if _store_dir else None)
        store.add(sub)
        _q = getattr(args, "quiet", False) or quiet
        if not _q:
            label = f" (alias: {sub.alias})" if sub.alias else ""
            print(f"Subscribed to {url}{label}")
            print(f"  API key env : {sub.api_key_env_var}")
            print(f"  Polling     : every {sub.polling_hours}h")
        return 0

    if vex_cmd == "unsubscribe":
        from squash.vex import VexSubscriptionStore
        import os as _os
        _store_dir = _os.environ.get("SQUISH_SQUASH_STORE_DIR")
        store = VexSubscriptionStore(Path(_store_dir) if _store_dir else None)
        removed = store.remove(args.url_or_alias)
        _q = getattr(args, "quiet", False) or quiet
        if not removed:
            print(f"error: no subscription found for {args.url_or_alias!r}", file=sys.stderr)
            return 1
        if not _q:
            print(f"Unsubscribed from {args.url_or_alias}")
        return 0

    if vex_cmd == "list-subscriptions":
        from squash.vex import VexSubscriptionStore
        import os as _os
        _store_dir = _os.environ.get("SQUISH_SQUASH_STORE_DIR")
        store = VexSubscriptionStore(Path(_store_dir) if _store_dir else None)
        subs = store.list()
        if not subs:
            if not quiet:
                print("No VEX feed subscriptions registered.")
            return 0
        if not quiet:
            for sub in subs:
                alias_part = f" [{sub.alias}]" if sub.alias else ""
                polled = sub.last_polled or "never"
                print(f"  {sub.url}{alias_part}")
                print(f"    api-key-env={sub.api_key_env_var}  polling={sub.polling_hours}h  last-polled={polled}")
        return 0

    # No sub-command — print help
    print("usage: squash vex {update,status,subscribe,unsubscribe,list-subscriptions} [options]", file=sys.stderr)
    return 1


# ────────────────────────────────────────────────────────────────────────────
# Wave 18  — Composite multi-model attestation
# ────────────────────────────────────────────────────────────────────────────

def _cmd_attest_composed(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.attest import CompositeAttestConfig, CompositeAttestPipeline
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_paths = [Path(p) for p in args.model_paths]
    for mp in model_paths:
        if not mp.exists():
            print(f"error: path does not exist: {mp}", file=sys.stderr)
            return 1

    if len(model_paths) < 2:
        print("error: attest-composed requires at least two model paths", file=sys.stderr)
        return 1

    config = CompositeAttestConfig(
        model_paths=model_paths,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        policies=args.policies or ["enterprise-strict"],
        sign=args.sign,
    )

    try:
        result = CompositeAttestPipeline.run(config)
    except Exception as e:
        print(f"runtime error: {e}", file=sys.stderr)
        return 2

    if not quiet:
        icon = "✓" if result.passed else "✗"
        print(f"{icon} composite attestation {'passed' if result.passed else 'FAILED'}")
        for cr in result.component_results:
            sub_icon = "✓" if cr.passed else "✗"
            print(f"  {sub_icon} {cr.model_path}")
        if result.parent_bom_path:
            print(f"  parent BOM: {result.parent_bom_path}")

    return 0 if result.passed else 2


# ────────────────────────────────────────────────────────────────────────────
# Wave 19  — SBOM registry push
# ────────────────────────────────────────────────────────────────────────────

def _cmd_push(args: argparse.Namespace, quiet: bool) -> int:
    import os

    try:
        from squash.sbom_builder import SbomRegistry
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: path does not exist: {model_path}", file=sys.stderr)
        return 1

    bom_path = model_path / "cyclonedx-mlbom.json"
    if not bom_path.exists():
        print(f"error: CycloneDX BOM not found: {bom_path}", file=sys.stderr)
        return 1

    api_key = args.api_key or os.environ.get("SQUASH_REGISTRY_KEY", "")
    registry_url: str = args.registry_url
    registry_type: str = getattr(args, "registry_type", "dtrack")

    try:
        if registry_type == "dtrack":
            pushed_url = SbomRegistry.push_dtrack(bom_path, registry_url, api_key)
        elif registry_type == "guac":
            pushed_url = SbomRegistry.push_guac(bom_path, registry_url)
        else:
            pushed_url = SbomRegistry.push_squash(bom_path, registry_url, api_key)
    except Exception as e:
        print(f"error pushing SBOM: {e}", file=sys.stderr)
        return 2

    if not quiet:
        print(f"✓ SBOM pushed to {pushed_url}")
    return 0


# ── Wave 20 — NTIA check handler ───────────────────────────────────────────────

def _cmd_ntia_check(args: argparse.Namespace, quiet: bool) -> int:
    from squash.policy import NtiaValidator

    bom_path = Path(args.bom_path)
    if not bom_path.exists():
        print(f"error: BOM file not found: {bom_path}", file=sys.stderr)
        return 1
    try:
        result = NtiaValidator.check(bom_path, strict=getattr(args, "strict", False))
    except Exception as e:
        print(f"error: NTIA check failed: {e}", file=sys.stderr)
        return 2
    if not quiet:
        status = "PASS" if result.passed else "FAIL"
        print(f"NTIA minimum elements: {status}")
        print(f"  completeness: {result.completeness_score:.1%}  "
              f"({len(result.present_fields)}/{len(result.present_fields) + len(result.missing_fields)} fields)")
        if result.missing_fields:
            print(f"  missing: {', '.join(result.missing_fields)}")
    return 0 if result.passed else 1


# ── Wave 21 — SLSA attest handler ─────────────────────────────────────────────

def _cmd_slsa_attest(args: argparse.Namespace, quiet: bool) -> int:
    from squash.slsa import SlsaLevel, SlsaProvenanceBuilder

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        print(f"error: model directory not found: {model_dir}", file=sys.stderr)
        return 1
    level_int = getattr(args, "level", 1)
    level = SlsaLevel(level_int)
    builder_id = getattr(args, "builder_id", "https://squish.local/squash/builder")
    try:
        attest = SlsaProvenanceBuilder.build(
            model_dir,
            level=level,
            builder_id=builder_id,
        )
    except Exception as e:
        print(f"error: SLSA attestation failed: {e}", file=sys.stderr)
        return 2
    if not quiet:
        print(f"✓ SLSA L{level.value} provenance written to {attest.output_path}")
        print(f"  subject: {attest.subject_name}")
        print(f"  digest:  sha256:{attest.subject_sha256}")
    return 0


# ── Wave 22 — BOM merge handler ───────────────────────────────────────────────

def _cmd_merge(args: argparse.Namespace, quiet: bool) -> int:
    from squash.sbom_builder import BomMerger

    bom_paths = [Path(p) for p in args.bom_paths]
    output_path = Path(args.output)
    for p in bom_paths:
        if not p.exists():
            print(f"error: BOM file not found: {p}", file=sys.stderr)
            return 1
    try:
        merged = BomMerger.merge(bom_paths, output_path)
    except Exception as e:
        print(f"error: BOM merge failed: {e}", file=sys.stderr)
        return 2
    if not quiet:
        n_comp = len(merged.get("components", []))
        print(f"✓ Merged {len(bom_paths)} BOMs → {output_path}  ({n_comp} components)")
    return 0


# ── Wave 23 — Risk assess handler ─────────────────────────────────────────────

def _cmd_risk_assess(args: argparse.Namespace, quiet: bool) -> int:
    from squash.risk import AiRiskAssessor

    model_dir = Path(args.model_dir)
    bom_path = model_dir / "cyclonedx-mlbom.json"
    if not bom_path.exists():
        print(f"error: CycloneDX BOM not found: {bom_path}", file=sys.stderr)
        return 1
    framework = getattr(args, "framework", "both")
    overall_passed = True
    try:
        if framework in ("eu-ai-act", "both"):
            eu = AiRiskAssessor.assess_eu_ai_act(bom_path)
            if not quiet:
                print(f"EU AI Act: {eu.category.value.upper()}  "
                      f"({'PASS' if eu.passed else 'FAIL'})")
                for r in eu.rationale:
                    print(f"  • {r}")
            if not eu.passed:
                overall_passed = False
        if framework in ("nist-rmf", "both"):
            rmf = AiRiskAssessor.assess_nist_rmf(bom_path)
            if not quiet:
                print(f"NIST RMF:  {rmf.category.value.upper()}  "
                      f"({'PASS' if rmf.passed else 'FAIL'})")
                for r in rmf.rationale:
                    print(f"  • {r}")
            if not rmf.passed:
                overall_passed = False
    except Exception as e:
        print(f"error: risk assessment failed: {e}", file=sys.stderr)
        return 2
    return 0 if overall_passed else 1


# ── Wave 24 — Drift monitor handler ───────────────────────────────────────────

def _cmd_monitor(args: argparse.Namespace, quiet: bool) -> int:
    from squash.governor import DriftMonitor

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        print(f"error: model directory not found: {model_dir}", file=sys.stderr)
        return 1
    baseline = getattr(args, "baseline", None)
    once = getattr(args, "once", False)

    try:
        if baseline is None:
            snap = DriftMonitor.snapshot(model_dir)
            if not quiet:
                print(f"✓ Snapshot: {snap}")
            return 0
        events = DriftMonitor.compare(model_dir, baseline)
    except Exception as e:
        print(f"error: drift monitor failed: {e}", file=sys.stderr)
        return 2

    if not events:
        if not quiet:
            print("✓ No drift detected")
        return 0

    for evt in events:
        print(f"[{evt.event_type}] {evt.component}: {evt.old_value!r} → {evt.new_value!r}")
    return 1


# ── Wave 25 — CI run handler ───────────────────────────────────────────────────

def _cmd_ci_run(args: argparse.Namespace, quiet: bool) -> int:
    from squash.cicd import CicdAdapter

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        print(f"error: model directory not found: {model_dir}", file=sys.stderr)
        return 1
    report_format = getattr(args, "report_format", "text")
    try:
        report = CicdAdapter.run_pipeline(model_dir, report_format=report_format)
    except Exception as e:
        print(f"error: CI pipeline failed: {e}", file=sys.stderr)
        return 2
    if not quiet and report_format in ("github", "text"):
        print(CicdAdapter.job_summary(report))
    return 0 if report.passed else 1


# ── Wave 27 — Kubernetes admission webhook handler ─────────────────────────────

def _cmd_webhook(args: argparse.Namespace, quiet: bool) -> int:
    from squash.integrations.kubernetes import (
        KubernetesWebhookHandler,
        WebhookConfig,
        serve_webhook,
    )

    policy_store_path = Path(args.policy_store) if getattr(args, "policy_store", None) else None
    config = WebhookConfig(
        policy_store_path=policy_store_path,
        default_allow=not getattr(args, "default_deny", False),
    )
    handler = KubernetesWebhookHandler(config)
    port: int = getattr(args, "port", 8443)
    tls_cert: str | None = getattr(args, "tls_cert", None)
    tls_key: str | None = getattr(args, "tls_key", None)

    if not quiet:
        mode = "HTTPS" if tls_cert else "HTTP (dev)"
        print(f"squash webhook: starting {mode} server on port {port}")
        if policy_store_path:
            print(f"squash webhook: policy store → {policy_store_path}")

    try:
        serve_webhook(handler, port=port, tls_cert=tls_cert, tls_key=tls_key)
    except Exception as e:
        print(f"error: webhook server failed: {e}", file=sys.stderr)
        return 2
    return 0


# ── Wave 50 — Shadow AI detection ─────────────────────────────────────────────

def _cmd_shadow_ai(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """Run the shadow-ai scan subcommand."""
    import json as _json

    from squash.integrations.kubernetes import (
        ShadowAiConfig,
        ShadowAiScanner,
        SHADOW_AI_MODEL_EXTENSIONS,
    )

    subcommand = getattr(args, "shadow_ai_cmd", None)
    if subcommand != "scan":
        print("error: unknown shadow-ai subcommand", file=sys.stderr)
        return 1

    # ─ Load pod list JSON ──────────────────────────────────────────────────────
    pod_list_path: str = args.pod_list
    try:
        if pod_list_path == "-":
            raw = sys.stdin.read()
        else:
            raw = Path(pod_list_path).read_text(encoding="utf-8")
        pod_list = _json.loads(raw)
    except (OSError, _json.JSONDecodeError) as exc:
        print(f"error: could not read pod list: {exc}", file=sys.stderr)
        return 1

    # ─ Build config ───────────────────────────────────────────────────────────
    extensions: frozenset[str] | None = None
    raw_exts: list[str] | None = getattr(args, "extensions", None)
    if raw_exts:
        extensions = frozenset(e if e.startswith(".") else f".{e}" for e in raw_exts)

    cfg = ShadowAiConfig(
        scan_extensions=extensions if extensions is not None else SHADOW_AI_MODEL_EXTENSIONS,
        namespaces_include=list(getattr(args, "namespaces", None) or []),
    )

    # ─ Scan ───────────────────────────────────────────────────────────────────
    scanner = ShadowAiScanner(cfg)
    result = scanner.scan_pod_list(pod_list)

    # ─ Output ─────────────────────────────────────────────────────────────────
    if not quiet:
        print(result.summary)
        for hit in result.hits:
            print(
                f"  [{hit.location_type}] {hit.namespace}/{hit.pod_name}"
                f" container={hit.container_name!r}"
                f" value={hit.matched_value!r} ({hit.extension})"
            )

    output_json_path: str | None = getattr(args, "output_json", None)
    if output_json_path:
        import dataclasses
        try:
            Path(output_json_path).write_text(
                _json.dumps(
                    {
                        "ok": result.ok,
                        "pods_scanned": result.pods_scanned,
                        "summary": result.summary,
                        "hits": [dataclasses.asdict(h) for h in result.hits],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"error: could not write output JSON: {exc}", file=sys.stderr)
            return 1

    fail_on_hits: bool = getattr(args, "fail_on_hits", False)
    if not result.ok and fail_on_hits:
        return 2
    return 0


# ── Wave 51 — SBOM drift detection handler ───────────────────────────────────

def _cmd_drift_check(args: argparse.Namespace, quiet: bool) -> int:
    """Run the drift-check subcommand (W51)."""
    import json as _json
    import dataclasses
    from squash.drift import DriftConfig, check_drift

    bom_path = Path(getattr(args, "bom", "") or "")
    model_dir = Path(args.model_dir)

    if not bom_path or not bom_path.exists():
        print(f"error: BOM file not found: {bom_path}", file=sys.stderr)
        return 1

    if not model_dir.exists():
        print(f"error: model directory not found: {model_dir}", file=sys.stderr)
        return 1

    try:
        config = DriftConfig(bom_path=bom_path, model_dir=model_dir)
        result = check_drift(config)
    except (OSError, _json.JSONDecodeError, ValueError) as exc:
        print(f"error: drift check failed: {exc}", file=sys.stderr)
        return 1

    if not quiet:
        print(result.summary)
        for hit in result.hits:
            if hit.missing:
                print(f"  [MISSING]  {hit.path}")
            else:
                print(f"  [TAMPERED] {hit.path}")
                print(f"             expected: {hit.expected_digest}")
                print(f"             actual:   {hit.actual_digest}")

    output_json_path: str | None = getattr(args, "output_json", None)
    if output_json_path:
        try:
            Path(output_json_path).write_text(
                _json.dumps(
                    {
                        "ok": result.ok,
                        "files_checked": result.files_checked,
                        "summary": result.summary,
                        "hits": [dataclasses.asdict(h) for h in result.hits],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"error: could not write output JSON: {exc}", file=sys.stderr)
            return 1

    fail_on_drift: bool = getattr(args, "fail_on_drift", False)
    if not result.ok and fail_on_drift:
        return 2
    return 0


# ── Wave 29 — VEX publish + integration CLI shims ─────────────────────────────

def _cmd_vex_publish(args: argparse.Namespace, quiet: bool) -> int:
    """Generate an OpenVEX 0.2.0 feed JSON file from statement entries."""
    import json as _json
    import sys as _sys

    from squash.vex import VexFeedManifest

    # Resolve entries: inline JSON string, '-' for stdin, or file path
    entries_raw: str = args.entries
    if entries_raw == "-":
        entries_raw = _sys.stdin.read()

    try:
        p = Path(entries_raw)
        if p.exists():
            entries_raw = p.read_text()
    except (OSError, ValueError):
        pass  # not a valid path — treat as inline JSON

    try:
        entries: list[dict] = _json.loads(entries_raw)
    except _json.JSONDecodeError as e:
        print(f"error: could not parse entries JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(entries, list):
        print("error: --entries must be a JSON array", file=sys.stderr)
        return 1

    doc = VexFeedManifest.generate(
        entries,
        author=args.author,
        doc_id=getattr(args, "doc_id", None),
    )

    errors = VexFeedManifest.validate(doc)
    if errors:
        for err in errors:
            print(f"validation error: {err}", file=sys.stderr)
        return 1

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_json.dumps(doc, indent=2))

    if not quiet:
        print(
            f"✓ VEX feed written to {output_path} "
            f"({len(entries)} statement(s), spec {VexFeedManifest.SPEC_VERSION})"
        )
    return 0


def _cmd_attest_mlflow(args: argparse.Namespace, quiet: bool) -> int:
    """Run the attestation pipeline and emit result JSON (MLflow-compatible offline shim)."""
    import json as _json

    from squash.attest import AttestConfig, AttestPipeline

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: model path not found: {model_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else None
    config = AttestConfig(
        model_path=model_path,
        output_dir=out_dir or (model_path.parent / "squash"),
        policies=args.policies or ["enterprise-strict"],
        sign=getattr(args, "sign", False),
        fail_on_violation=getattr(args, "fail_on_violation", False),
    )

    try:
        result = AttestPipeline.run(config)
    except Exception as e:
        print(f"error: attestation failed: {e}", file=sys.stderr)
        return 2

    if not quiet:
        icon = "✓" if result.passed else "✗"
        print(f"{icon} mlflow attestation {'passed' if result.passed else 'FAILED'}: {model_path}")
        print(f"  artifacts  : {result.output_dir}")
        print(f"  bom_path   : {result.bom_path}")

    # Emit JSON to stdout for pipe-friendly consumption
    print(_json.dumps(result.to_dict() if hasattr(result, "to_dict") else {
        "passed": result.passed,
        "bom_path": str(result.bom_path) if result.bom_path else None,
        "output_dir": str(result.output_dir) if result.output_dir else None,
    }))
    return 0 if result.passed else 1


def _cmd_attest_wandb(args: argparse.Namespace, quiet: bool) -> int:
    """Run the attestation pipeline and emit result JSON (W&B-compatible offline shim)."""
    import json as _json

    from squash.attest import AttestConfig, AttestPipeline

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: model path not found: {model_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else None
    config = AttestConfig(
        model_path=model_path,
        output_dir=out_dir or (model_path.parent / "squash"),
        policies=args.policies or ["enterprise-strict"],
        sign=getattr(args, "sign", False),
        fail_on_violation=getattr(args, "fail_on_violation", False),
    )

    try:
        result = AttestPipeline.run(config)
    except Exception as e:
        print(f"error: attestation failed: {e}", file=sys.stderr)
        return 2

    if not quiet:
        icon = "✓" if result.passed else "✗"
        print(f"{icon} wandb attestation {'passed' if result.passed else 'FAILED'}: {model_path}")
        print(f"  artifacts  : {result.output_dir}")
        print(f"  bom_path   : {result.bom_path}")

    print(_json.dumps(result.to_dict() if hasattr(result, "to_dict") else {
        "passed": result.passed,
        "bom_path": str(result.bom_path) if result.bom_path else None,
        "output_dir": str(result.output_dir) if result.output_dir else None,
    }))
    return 0 if result.passed else 1


def _cmd_attest_huggingface(args: argparse.Namespace, quiet: bool) -> int:
    """Attest a model and optionally push artifacts to HuggingFace Hub."""
    import os

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: model path not found: {model_path}", file=sys.stderr)
        return 1

    repo_id: str | None = getattr(args, "repo_id", None)
    hf_token: str | None = getattr(args, "hf_token", None) or os.environ.get("HF_TOKEN")
    policies = getattr(args, "policies", None) or ["enterprise-strict"]
    sign = getattr(args, "sign", False)
    fail_on_violation = getattr(args, "fail_on_violation", False)
    out_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else None

    if repo_id:
        # Full push via HFSquash
        try:
            from squash.integrations.huggingface import HFSquash
        except ImportError as e:
            print(f"error: HFSquash not available: {e}", file=sys.stderr)
            return 2
        try:
            result = HFSquash.attest_and_push(
                repo_id,
                model_path,
                hf_token=hf_token or "",
                policies=policies,
                sign=sign,
                fail_on_violation=fail_on_violation,
            )
        except Exception as e:
            print(f"error: HuggingFace attestation failed: {e}", file=sys.stderr)
            return 2
    else:
        # Offline attestation only (no push)
        from squash.attest import AttestConfig, AttestPipeline

        config = AttestConfig(
            model_path=model_path,
            output_dir=out_dir or (model_path.parent / "squash"),
            policies=policies,
            sign=sign,
            fail_on_violation=fail_on_violation,
        )
        try:
            result = AttestPipeline.run(config)
        except Exception as e:
            print(f"error: attestation failed: {e}", file=sys.stderr)
            return 2

    if not quiet:
        icon = "✓" if result.passed else "✗"
        label = f"→ {repo_id}" if repo_id else "(local only)"
        print(f"{icon} huggingface attestation {'passed' if result.passed else 'FAILED'} {label}")
        print(f"  bom_path   : {result.bom_path}")

    return 0 if result.passed else 1


def _cmd_attest_langchain(args: argparse.Namespace, quiet: bool) -> int:
    """Run a one-shot attestation pass on a model (matches SquashCallback first-run behaviour)."""
    import json as _json

    from squash.attest import AttestConfig, AttestPipeline

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"error: model path not found: {model_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else None
    config = AttestConfig(
        model_path=model_path,
        output_dir=out_dir or (model_path.parent / "squash"),
        policies=getattr(args, "policies", None) or ["enterprise-strict"],
        sign=getattr(args, "sign", False),
        fail_on_violation=getattr(args, "fail_on_violation", False),
    )

    try:
        result = AttestPipeline.run(config)
    except Exception as e:
        print(f"error: attestation failed: {e}", file=sys.stderr)
        return 2

    if not quiet:
        icon = "✓" if result.passed else "✗"
        print(f"{icon} langchain attestation {'passed' if result.passed else 'FAILED'}: {model_path}")
        print(f"  artifacts  : {result.output_dir}")
        print(f"  bom_path   : {result.bom_path}")

    print(_json.dumps(result.to_dict() if hasattr(result, "to_dict") else {
        "passed": result.passed,
        "bom_path": str(result.bom_path) if result.bom_path else None,
        "output_dir": str(result.output_dir) if result.output_dir else None,
    }))
    return 0 if result.passed else 1


def _cmd_attest_mcp(args: argparse.Namespace, quiet: bool) -> int:
    """Scan an MCP tool manifest catalog for supply-chain threats."""
    import json as _json

    from squash.mcp import McpScanner, McpSigner

    catalog_path = Path(args.catalog_path)
    if not catalog_path.exists():
        print(f"error: catalog not found: {catalog_path}", file=sys.stderr)
        return 1

    result = McpScanner.scan_file(catalog_path, getattr(args, "policy", "mcp-strict"))

    if not quiet:
        icon = "✓" if result.status == "safe" else ("⚠" if result.status == "warn" else "✗")
        label = {"safe": "SAFE", "warn": "WARNINGS", "unsafe": "UNSAFE"}.get(result.status, result.status.upper())
        print(f"{icon} MCP attestation {label}: {catalog_path}")
        print(f"  tools      : {result.tool_count}")
        print(f"  catalog_sha: {result.catalog_hash[:16]}…")
        errors = sum(1 for f in result.findings if f.severity == "error")
        warnings = sum(1 for f in result.findings if f.severity == "warning")
        if errors or warnings:
            print(f"  findings   : {errors} error(s), {warnings} warning(s)")
            for finding in result.findings:
                prefix = "  ✗" if finding.severity == "error" else "  ⚠"
                print(f"{prefix} [{finding.rule_id}] {finding.tool_name}: {finding.detail}")

    result_dict = result.to_dict()

    json_result_path = getattr(args, "json_result", None)
    if json_result_path:
        try:
            out_path = Path(json_result_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(_json.dumps(result_dict, indent=2), encoding="utf-8")
            if not quiet:
                print(f"  result     : {out_path}")
        except Exception as exc:
            print(f"error: could not write result file: {exc}", file=sys.stderr)
            return 2

    sign = getattr(args, "sign", False)
    if sign:
        sig_path = McpSigner.sign(catalog_path)
        if sig_path and not quiet:
            print(f"  signed     : {sig_path}")
        elif not sig_path and not quiet:
            print("  signing    : unavailable (sigstore not installed)", file=sys.stderr)

    fail_on_violation = getattr(args, "fail_on_violation", False)
    if fail_on_violation and result.status == "unsafe":
        return 1
    return 0


def _cmd_audit(args: argparse.Namespace, quiet: bool) -> int:
    """Handler for ``squash audit show`` and ``squash audit verify``."""
    audit_command = getattr(args, "audit_command", None)
    if not audit_command:
        print("usage: squash audit <show|verify>", file=sys.stderr)
        return 1

    try:
        from squash.governor import AgentAuditLogger
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    log_path = getattr(args, "log", None)
    logger = AgentAuditLogger(log_path=log_path)

    if audit_command == "show":
        n = getattr(args, "n", 20)
        entries = logger.read_tail(n)
        if not entries:
            if not quiet:
                print("(audit log is empty or does not exist)")
            return 0
        json_output = getattr(args, "json_output", False)
        if json_output:
            print(json.dumps(entries, indent=2))
        else:
            for e in entries:
                ts = e.get("ts", "?")
                seq = e.get("seq", "?")
                etype = e.get("event_type", "?")
                model = e.get("model_id", "")
                session = e.get("session_id", "")
                latency = e.get("latency_ms", -1)
                lat_str = f" {latency:.1f}ms" if latency >= 0 else ""
                sid_str = f" [{session}]" if session else ""
                mod_str = f" model={model}" if model else ""
                print(f"#{seq} {ts} {etype}{sid_str}{mod_str}{lat_str}")
        return 0

    if audit_command == "verify":
        ok, msg = logger.verify_chain()
        if ok:
            if not quiet:
                path_str = str(logger.path)
                print(f"✓ audit chain intact: {path_str}")
            return 0
        print(f"✗ audit chain TAMPERED: {msg}", file=sys.stderr)
        return 2

    print(f"unknown audit subcommand: {audit_command}", file=sys.stderr)
    return 1


def _cmd_lineage(args: argparse.Namespace, quiet: bool) -> int:
    """Handler for ``squash lineage record``, ``show``, and ``verify``."""
    lineage_command = getattr(args, "lineage_command", None)
    if not lineage_command:
        print("usage: squash lineage {record,show,verify} -- use --help for details", file=sys.stderr)
        return 1

    try:
        from squash.lineage import LineageChain  # lazy — keeps cli.py import-fast
    except ImportError as e:
        print(f"squash is not installed: {e}", file=sys.stderr)
        return 2

    model_dir = Path(args.model_dir)

    if lineage_command == "record":
        operation = args.operation
        model_id = getattr(args, "model_id", "") or model_dir.name
        input_dir = getattr(args, "input_dir", "") or str(model_dir)
        raw_params = getattr(args, "params", []) or []
        params: dict = {}
        for kv in raw_params:
            if "=" in kv:
                k, _, v = kv.partition("=")
                params[k.strip()] = v.strip()
        try:
            model_dir.mkdir(parents=True, exist_ok=True)
            evt = LineageChain.create_event(
                operation=operation,
                model_id=model_id,
                input_dir=input_dir,
                output_dir=str(model_dir),
                params=params,
            )
            event_hash = LineageChain.record(model_dir, evt)
        except Exception as exc:
            print(f"error recording lineage event: {exc}", file=sys.stderr)
            return 2
        if not quiet:
            print(
                f"✓ lineage event recorded\n"
                f"  model_dir  : {model_dir}\n"
                f"  operation  : {operation}\n"
                f"  event_hash : {event_hash}"
            )
        return 0

    if lineage_command == "show":
        if not model_dir.exists():
            print(f"error: directory not found: {model_dir}", file=sys.stderr)
            return 1
        try:
            events = LineageChain.load(model_dir)
        except Exception as exc:
            print(f"error loading lineage: {exc}", file=sys.stderr)
            return 2
        json_output = getattr(args, "json_output", False)
        if json_output:
            print(json.dumps([e.to_dict() for e in events], indent=2))
        else:
            if not events:
                if not quiet:
                    print("(no lineage events recorded)")
                return 0
            for i, e in enumerate(events):
                prev = e.prev_hash[:32] + "\u2026" if e.prev_hash else "(genesis)"
                print(f"#{i + 1} {e.timestamp}  [{e.operation}]  {e.model_id}")
                print(f"     operator  : {e.operator}")
                print(f"     input_dir : {e.input_dir}")
                print(f"     output_dir: {e.output_dir}")
                if e.params:
                    pstr = "  ".join(f"{k}={v}" for k, v in e.params.items())
                    print(f"     params    : {pstr}")
                print(f"     event_hash: {e.event_hash[:32]}\u2026")
                print(f"     prev_hash : {prev}")
        return 0

    if lineage_command == "verify":
        if not model_dir.exists():
            print(f"error: directory not found: {model_dir}", file=sys.stderr)
            return 1
        try:
            result = LineageChain.verify(model_dir)
        except Exception as exc:
            print(f"error verifying chain: {exc}", file=sys.stderr)
            return 2
        if not quiet:
            icon = "\u2713" if result.ok else "\u2717"
            print(f"{icon} lineage chain: {result.message}")
            print(f"   model_dir  : {result.model_dir}")
            print(f"   event_count: {result.event_count}")
            if result.broken_at is not None:
                print(f"   broken_at  : event index {result.broken_at}", file=sys.stderr)
        return 0 if result.ok else 2

    print(f"unknown lineage subcommand: {lineage_command}", file=sys.stderr)
    return 1


def _cmd_scan_rag(args: argparse.Namespace, quiet: bool) -> int:
    """Handler for ``squash scan-rag index`` and ``squash scan-rag verify``."""
    from squash.rag import RagScanner  # lazy — keeps cli.py import-fast

    sub = getattr(args, "scan_rag_command", None)
    if sub is None:
        print("usage: squash scan-rag {index,verify} -- use --help for details", file=sys.stderr)
        return 1

    if sub == "index":
        corpus_dir = args.corpus_dir
        try:
            manifest = RagScanner.index(corpus_dir, glob=args.glob)
        except NotADirectoryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"error indexing corpus: {exc}", file=sys.stderr)
            return 2
        if not quiet:
            print(
                f"✓ indexed {manifest.file_count} files\n"
                f"  corpus:        {manifest.corpus_dir}\n"
                f"  manifest_hash: {manifest.manifest_hash}\n"
                f"  indexed_at:    {manifest.indexed_at}"
            )
        return 0

    if sub == "verify":
        corpus_dir = args.corpus_dir
        try:
            result = RagScanner.verify(corpus_dir)
        except Exception as exc:  # noqa: BLE001
            print(f"error verifying corpus: {exc}", file=sys.stderr)
            return 2
        if getattr(args, "json_output", False):
            import json as _json
            print(_json.dumps(result.to_dict(), indent=2))
        elif not quiet:
            if result.ok:
                print(f"✓ corpus intact — {result.total_files} files, no drift")
            else:
                print(
                    f"✗ drift detected — {result.drift_count} change(s) in {result.corpus_dir}",
                    file=sys.stderr,
                )
                for item in result.drift:
                    print(f"  [{item.status:8s}] {item.path}", file=sys.stderr)
        return 0 if result.ok else 2

    print(f"unknown scan-rag subcommand: {sub}", file=sys.stderr)
    return 1


# ── Wave 54–56: remediate / evaluate / edge-scan / chat ──────────────────────


def _cmd_remediate(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.remediate import Remediator
    except ImportError as exc:
        print(f"squash remediate requires torch and safetensors: {exc}", file=sys.stderr)
        return 2

    model_path = Path(args.model_path)
    output_dir = Path(args.output_dir) if args.output_dir else None

    result = Remediator.convert(
        model_path,
        target_format=args.target_format,
        output_dir=output_dir,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
    )

    if not quiet:
        print(result.summary())

    if args.sbom and result.sbom_patch:
        sbom_path = Path(args.sbom)
        patched = Remediator.patch_sbom(sbom_path, result.sbom_patch)
        if not quiet:
            if patched:
                print(f"✓ Updated hashes in {sbom_path}")
            else:
                print(f"! Could not patch {sbom_path} (not found or invalid JSON)", file=sys.stderr)

    if result.failed and not args.dry_run:
        for f in result.failed:
            print(f"  ✗ {f.source.name}: {f.reason}", file=sys.stderr)
        return 1

    return 0


def _cmd_evaluate(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.evaluator import EvalEngine
    except ImportError as exc:
        print(f"squash evaluate unavailable: {exc}", file=sys.stderr)
        return 2

    engine = EvalEngine(
        endpoint=args.endpoint,
        model=args.model,
        api_key=args.api_key,
        timeout_s=args.timeout,
    )

    if not quiet:
        print(f"Running {len(engine._extra_probes or []) + 8} probes against {args.endpoint} …")

    report = engine.run()

    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "squash-eval-report.json"
    report.save(report_path)

    if not quiet:
        print(report.summary_text())
        print(f"Report saved → {report_path}")

    if args.bom:
        patched = engine.patch_bom(Path(args.bom), report)
        if not quiet:
            if patched:
                print(f"✓ BOM annotated → {args.bom}")
            else:
                print(f"! Could not patch BOM {args.bom}", file=sys.stderr)

    if args.fail_on_critical and report.critical_failures:
        print(f"✗ {report.critical_failures} critical probe(s) failed", file=sys.stderr)
        return 2

    return 0


def _cmd_edge_scan(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.edge_formats import (
            TFLiteParser,
            CoreMLParser,
            EdgeSecurityScanner,
        )
    except ImportError as exc:
        print(f"squash edge-scan unavailable: {exc}", file=sys.stderr)
        return 2

    target = Path(args.model_path)
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 1

    suffix = target.suffix.lower()
    if suffix == ".tflite":
        meta = TFLiteParser.parse(target)
        findings = EdgeSecurityScanner.scan(target)
        result_dict: dict = {
            "format": "tflite",
            "file": str(target),
            "sha256": meta.sha256,
            "schema_version": meta.schema_version,
            "operator_count": meta.operator_count,
            "subgraph_count": meta.subgraph_count,
            "quant_level": meta.quant_level,
            "custom_ops": meta.custom_ops,
            "parse_error": meta.parse_error,
            "findings": [
                {
                    "severity": f.severity,
                    "id": f.finding_id,
                    "title": f.title,
                    "detail": f.detail,
                }
                for f in findings
            ],
        }
        if not quiet:
            print(f"TFLite model: {target.name}")
            print(f"  Schema version : {meta.schema_version}")
            print(f"  Operators      : {meta.operator_count}")
            print(f"  Quantisation   : {meta.quant_level}")
            if meta.custom_ops:
                print(f"  Custom ops     : {', '.join(meta.custom_ops)}")
            if meta.parse_error:
                print(f"  ⚠ parse error  : {meta.parse_error}", file=sys.stderr)
    elif target.is_dir() and target.name.endswith(".mlpackage"):
        meta = CoreMLParser.parse(target)
        findings = EdgeSecurityScanner.scan(target)
        result_dict = {
            "format": "coreml",
            "package": str(target),
            "sha256": meta.sha256,
            "model_version": meta.model_version,
            "spec_version": meta.spec_version,
            "short_description": meta.short_description,
            "quant_level": meta.quant_level,
            "pipeline_stages": meta.pipeline_stages,
            "findings": [
                {
                    "severity": f.severity,
                    "id": f.finding_id,
                    "title": f.title,
                    "detail": f.detail,
                }
                for f in findings
            ],
        }
        if not quiet:
            print(f"CoreML package: {target.name}")
            print(f"  Spec version   : {meta.spec_version}")
            print(f"  Quantisation   : {meta.quant_level}")
    else:
        print(
            "Unsupported format. Provide a .tflite file or a .mlpackage directory.",
            file=sys.stderr,
        )
        return 1

    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    if not quiet:
        if findings:
            print(f"\n{len(findings)} finding(s): {len(critical)} critical, {len(high)} high")
            for f in findings:
                print(f"  [{f.severity.upper():8s}] {f.finding_id} — {f.title}")
        else:
            print("✓ No security findings")

    if args.json_result:
        import json as _json
        json_path = Path(args.json_result)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(_json.dumps(result_dict, indent=2))
        if not quiet:
            print(f"Result saved → {json_path}")

    return 2 if critical else (1 if high else 0)


def _cmd_chat(args: argparse.Namespace, quiet: bool) -> int:
    try:
        from squash.chat import ChatSession
    except ImportError as exc:
        print(f"squash chat unavailable: {exc}", file=sys.stderr)
        return 2

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        print(f"Model directory not found: {model_dir}", file=sys.stderr)
        return 1

    backend_defaults = {
        "ollama": ("http://localhost:11434/v1", "llama3"),
        "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
    }
    base_url, default_model = backend_defaults[args.backend]
    model_name = args.model or default_model

    session = ChatSession.from_model_dir(
        model_dir,
        endpoint=base_url,
        model=model_name,
        api_key=args.api_key,
        top_k=args.top_k,
    )

    if not quiet:
        print(f"squash chat — {model_name} via {args.backend} ({base_url})")
        print(f"Loaded {len(session._retriever._chunks)} document chunks from {model_dir.name}")

    session.repl()
    return 0


def _cmd_model_card(args: argparse.Namespace, quiet: bool) -> int:
    """Generate regulation-compliant model cards from squash attestation artifacts.

    W194 (Sprint 10): added --validate, --validate-only, and --push-to-hub flows.
    """
    try:
        from squash.model_card import ModelCardConfig, ModelCardGenerator
    except ImportError as exc:
        print(f"squash model-card unavailable: {exc}", file=sys.stderr)
        return 2

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        print(f"Model directory not found: {model_dir}", file=sys.stderr)
        return 1

    output_dir = Path(args.mc_output_dir) if args.mc_output_dir else None

    # ── Validate-only short-circuit ──────────────────────────────────────────
    if getattr(args, "mc_validate_only", False):
        return _model_card_validate(
            card_path=(output_dir or model_dir) / "squash-model-card-hf.md",
            json_out=getattr(args, "mc_json", False),
            quiet=quiet,
        )

    config = ModelCardConfig(
        model_dir=model_dir,
        model_id=args.mc_model_id or "",
        license=args.mc_license or "apache-2.0",
        output_dir=output_dir,
    )
    gen = ModelCardGenerator(model_dir=model_dir, config=config)

    try:
        paths = gen.generate(fmt=args.mc_format, output_dir=output_dir)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if not quiet:
        for p in paths:
            print(f"✓ {p}")

    # ── Optional validate after generation ───────────────────────────────────
    if getattr(args, "mc_validate", False):
        hf_card = next(
            (p for p in paths if p.name == "squash-model-card-hf.md"),
            (output_dir or model_dir) / "squash-model-card-hf.md",
        )
        rc = _model_card_validate(
            card_path=hf_card,
            json_out=getattr(args, "mc_json", False),
            quiet=quiet,
        )
        if rc != 0:
            return rc

    # ── Optional push to HuggingFace Hub ─────────────────────────────────────
    push_repo = getattr(args, "mc_push_repo", None)
    if push_repo:
        hf_card = next(
            (p for p in paths if p.name == "squash-model-card-hf.md"), None
        )
        if hf_card is None:
            print(
                "--push-to-hub requires --format hf or --format all to produce "
                "squash-model-card-hf.md",
                file=sys.stderr,
            )
            return 1
        return _model_card_push(
            card_path=hf_card,
            repo_id=push_repo,
            token=getattr(args, "mc_hub_token", None),
            quiet=quiet,
        )

    return 0


def _model_card_validate(card_path: Path, json_out: bool, quiet: bool) -> int:
    """Validate an HF model card; print report. Exit non-zero on errors."""
    try:
        from squash.model_card_validator import ModelCardValidator
    except ImportError as exc:
        print(f"squash model-card validator unavailable: {exc}", file=sys.stderr)
        return 2

    report = ModelCardValidator().validate(card_path)

    if json_out:
        print(json.dumps(report.to_dict(), indent=2))
    elif not quiet:
        print(report.summary())
        for f in report.errors + report.warnings + report.infos:
            print(f"  {f.render()}")

    return 0 if report.is_valid else 1


def _model_card_push(
    card_path: Path, repo_id: str, token: str | None, quiet: bool,
) -> int:
    """Upload squash-model-card-hf.md to a HuggingFace repo. Optional dep."""
    if not card_path.exists():
        print(f"Model card not found: {card_path}", file=sys.stderr)
        return 1
    try:
        from huggingface_hub import HfApi  # type: ignore
    except ImportError:
        print(
            "--push-to-hub requires `huggingface_hub`. Install with: "
            "pip install huggingface_hub",
            file=sys.stderr,
        )
        return 2

    import os as _os
    hub_token = token or _os.environ.get("HUGGING_FACE_HUB_TOKEN") \
        or _os.environ.get("HF_TOKEN")
    if not hub_token:
        print(
            "--push-to-hub requires a token. Pass --hub-token or set "
            "HUGGING_FACE_HUB_TOKEN.",
            file=sys.stderr,
        )
        return 1

    api = HfApi(token=hub_token)
    try:
        api.upload_file(
            path_or_fileobj=str(card_path),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="model",
            commit_message="Squash: model card auto-generated by squash model-card",
        )
    except Exception as exc:  # noqa: BLE001 — surface any HF error verbatim
        print(f"HuggingFace upload failed: {exc}", file=sys.stderr)
        return 1

    if not quiet:
        print(f"✓ pushed {card_path.name} to https://huggingface.co/{repo_id}")
    return 0


# ── Wave 77 — Cloud CLI command implementations ───────────────────────────────

def _cmd_cloud_status(args: argparse.Namespace, quiet: bool) -> int:
    """Show EU AI Act conformance status for a single tenant. Exit 0=conformant, 2=non-conformant."""
    try:
        from squash import api as _api
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    if args.tenant_id not in _api._tenants:
        print(f"squash cloud-status: tenant not found: {args.tenant_id}", file=sys.stderr)
        return 1

    status = _api._db_read_tenant_conformance(args.tenant_id)

    conformant: bool = status.get("conformant", False)
    score: float = float(status.get("compliance_score", 0.0))
    risk: str = status.get("enforcement_risk_level", "UNKNOWN")
    days: int = int(status.get("days_until_enforcement", 0))
    reasons: list = status.get("reasons", [])

    status_label = "CONFORMANT" if conformant else "NON-CONFORMANT"
    icon = "✓" if conformant else "✗"

    if not quiet:
        print(
            f"{icon} {args.tenant_id} | {status_label} | score: {score:.1f} | "
            f"{risk} | {days} days until enforcement"
        )
        for reason in reasons:
            print(f"  • {reason}")

    if getattr(args, "output_json", False):
        import json as _json
        print(_json.dumps(status, indent=2))

    return 0 if conformant else 2


def _cmd_cloud_report(args: argparse.Namespace, quiet: bool) -> int:
    """Print platform-wide EU AI Act conformance report. Exit 0=all conformant, 2=any non-conformant."""
    try:
        from squash import api as _api
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    if not _api._tenants:
        if not quiet:
            print("no tenants registered")
        return 0

    report = _api._db_read_conformance_report()
    total: int = report.get("total_tenants", 0)
    conformant_count: int = report.get("conformant_tenants", 0)
    non_conformant_count: int = report.get("non_conformant_tenants", 0)
    risk: str = report.get("enforcement_risk_level", "UNKNOWN")
    days: int = int(report.get("days_until_enforcement", 0))

    if not quiet:
        print(
            f"Platform Report | {total} tenant(s) | {conformant_count} conformant | "
            f"{non_conformant_count} non-conformant | {risk} | {days} days until enforcement"
        )
        print(f"{'Tenant':<30} {'Score':>7} {'Status':<16} {'Risk':<10} {'Days':>5}")
        print("-" * 72)
        for tid in _api._tenants:
            row = _api._db_read_tenant_conformance(tid)
            row_score: float = float(row.get("compliance_score", 0.0))
            row_status = "CONFORMANT" if row.get("conformant") else "NON-CONFORMANT"
            row_risk: str = row.get("enforcement_risk_level", "UNKNOWN")
            row_days: int = int(row.get("days_until_enforcement", 0))
            print(f"{tid:<30} {row_score:>7.1f} {row_status:<16} {row_risk:<10} {row_days:>5}")

    if getattr(args, "output_json", False):
        import json as _json
        print(_json.dumps(report, indent=2))

    return 0 if non_conformant_count == 0 else 2


def _cmd_cloud_export(args: argparse.Namespace, quiet: bool) -> int:
    """Export a complete compliance audit bundle for a tenant. Always exits 0 on success."""
    try:
        from squash import api as _api
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    if args.tenant_id not in _api._tenants:
        print(f"squash cloud-export: tenant not found: {args.tenant_id}", file=sys.stderr)
        return 1

    import json as _json

    bundle = _api._db_build_tenant_export(args.tenant_id)

    output_path = getattr(args, "output_path", None)
    if output_path and output_path != "-":
        path = Path(output_path)
        path.write_text(_json.dumps(bundle, indent=2), encoding="utf-8")
        if not quiet:
            print(f"✓ export written to {path}")
    else:
        print(_json.dumps(bundle, indent=2))

    return 0


# ── Wave 79 — Cloud CLI command implementations ──────────────────────────────

def _cmd_cloud_attest(args: argparse.Namespace, quiet: bool) -> int:
    """Attest a model for a tenant and register the result in the cloud inventory.

    Exit codes: 0=attested+passed+registered, 1=bad-args/tenant-not-found, 2=attest-failed.
    """
    try:
        from squash import api as _api
        from squash.attest import AttestConfig, AttestPipeline
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    if args.tenant_id not in _api._tenants:
        print(
            f"squash cloud-attest: tenant not found: {args.tenant_id}",
            file=sys.stderr,
        )
        return 1

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(
            f"squash cloud-attest: model path does not exist: {model_path}",
            file=sys.stderr,
        )
        return 1

    output_dir = Path(args.output_path) if getattr(args, "output_path", None) else None

    config = AttestConfig(
        model_path=model_path,
        output_dir=output_dir,
        model_id=model_path.stem,
        policies=[args.policy],
        fail_on_violation=False,
        sign=False,
    )

    try:
        result = AttestPipeline.run(config)
    except FileNotFoundError as exc:
        print(f"squash cloud-attest: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"squash cloud-attest: attestation error: {exc}", file=sys.stderr)
        return 2

    # Serialize policy results to a plain dict for storage
    policy_dict: dict = {
        name: {
            "passed": pr.passed if hasattr(pr, "passed") else bool(pr),
            "error_count": getattr(pr, "error_count", 0),
            "warning_count": getattr(pr, "warning_count", 0),
        }
        for name, pr in result.policy_results.items()
    }

    bom_path_str = str(result.cyclonedx_path) if result.cyclonedx_path else ""

    record: dict = {
        "model_id": result.model_id,
        "model_path": str(model_path),
        "bom_path": bom_path_str,
        "attestation_passed": result.passed,
        "policy_results": policy_dict,
        "vex_cves": [],
        "timestamp": "",
        "record_id": "",
    }
    import uuid as _uuid
    import datetime as _dt
    record["timestamp"] = _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    record["record_id"] = str(_uuid.uuid4())

    _api._db_write_inventory(args.tenant_id, record)

    status_label = "PASS" if result.passed else "FAIL"
    icon = "\u2713" if result.passed else "\u2717"

    if not quiet:
        print(
            f"{icon} cloud-attest | {args.tenant_id} | {result.model_id} | {status_label}"
            f" | policy: {args.policy} | registered"
        )

    if getattr(args, "output_json", False):
        import json as _json
        print(_json.dumps(record, indent=2))

    return 0 if result.passed else 2


def _cmd_cloud_vex(args: argparse.Namespace, quiet: bool) -> int:
    """List VEX/CVE alerts for a tenant. Exit 0=success, 1=tenant-not-found, 2=server-error."""
    try:
        from squash import api as _api
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    if args.tenant_id not in _api._tenants:
        print(
            f"squash cloud-vex: tenant not found: {args.tenant_id}",
            file=sys.stderr,
        )
        return 1

    try:
        alerts: list = _api._db_read_vex_alerts(args.tenant_id)
    except Exception as exc:  # noqa: BLE001
        print(f"squash cloud-vex: error reading alerts: {exc}", file=sys.stderr)
        return 2

    # Apply filters
    vex_status = getattr(args, "vex_status", None)
    severity = getattr(args, "severity", None)
    limit: int = max(1, min(getattr(args, "limit", 50), 500))

    if vex_status:
        alerts = [a for a in alerts if a.get("status") == vex_status]
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    alerts = alerts[-limit:]

    if getattr(args, "output_json", False):
        import json as _json
        print(_json.dumps({"tenant_id": args.tenant_id, "count": len(alerts), "alerts": alerts}, indent=2))
        return 0

    if not quiet:
        if not alerts:
            print(f"No VEX alerts for tenant: {args.tenant_id}")
        else:
            print(f"VEX Alerts | {args.tenant_id} | {len(alerts)} alert(s)")
            print(f"{'CVE':<20} {'Severity':<10} {'Status':<14} {'Model':<30} {'Date'}")
            print("-" * 90)
            for alert in alerts:
                cve = alert.get("cve_id", "-")
                sev = alert.get("severity", "-")
                stat = alert.get("status", "-")
                model = alert.get("model_id", "-")
                ts = alert.get("timestamp", "-")[:10] if alert.get("timestamp") else "-"
                print(f"{cve:<20} {sev:<10} {stat:<14} {model:<30} {ts}")

    return 0


def _cmd_cloud_risk(args: argparse.Namespace, quiet: bool) -> int:
    """Show EU AI Act risk profile for a tenant or platform.

    Exit codes:
        0 = tenant found and overall tier is MINIMAL or LIMITED (conformant-ish)
        1 = tenant not found (or missing positional arg without --overview)
        2 = overall tier is HIGH or UNACCEPTABLE (non-conformant)
    """
    try:
        from squash import api as _api
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    overview: bool = getattr(args, "overview", False)
    tenant_id: str | None = getattr(args, "tenant_id", None)
    output_json: bool = getattr(args, "output_json", False)

    if overview:
        # ── Platform overview ──────────────────────────────────────────────
        summary: dict[str, int] = {
            "UNACCEPTABLE": 0,
            "HIGH": 0,
            "LIMITED": 0,
            "MINIMAL": 0,
        }
        tier_order = ["UNACCEPTABLE", "HIGH", "LIMITED", "MINIMAL"]
        tenant_rows: list[dict] = []

        for tid in list(_api._tenants.keys()):
            inventory = _api._db_read_inventory(tid)
            vex = _api._db_read_vex_alerts(tid)
            open_vex = len(vex)
            if inventory:
                tiers = [_api._compute_model_risk_tier(rec, open_vex) for rec in inventory]
                overall_tier = min(
                    tiers,
                    key=lambda t: tier_order.index(t) if t in tier_order else len(tier_order),
                )
            else:
                overall_tier = "MINIMAL"
            summary[overall_tier] += 1
            tenant_rows.append(
                {
                    "tenant_id": tid,
                    "overall_risk_tier": overall_tier,
                    "model_count": len(inventory),
                }
            )

        if output_json:
            import json as _json
            print(
                _json.dumps(
                    {
                        "total_tenants": len(tenant_rows),
                        "risk_summary": summary,
                        "tenants": tenant_rows,
                    },
                    indent=2,
                )
            )
            return 0

        if not quiet:
            print(f"Risk Overview | {len(tenant_rows)} tenant(s)")
            print(
                f"  UNACCEPTABLE: {summary['UNACCEPTABLE']}  "
                f"HIGH: {summary['HIGH']}  "
                f"LIMITED: {summary['LIMITED']}  "
                f"MINIMAL: {summary['MINIMAL']}"
            )
            for row in tenant_rows:
                tier_icon = "\u2715" if row["overall_risk_tier"] in ("UNACCEPTABLE", "HIGH") else "\u2713"
                print(
                    f"  {tier_icon} {row['tenant_id']:<30} "
                    f"{row['overall_risk_tier']:<15} {row['model_count']} model(s)"
                )

        worst = "MINIMAL"
        if summary["UNACCEPTABLE"] > 0 or summary["HIGH"] > 0:
            worst = "HIGH"
        return 2 if worst in ("UNACCEPTABLE", "HIGH") else 0

    # ── Per-tenant profile ─────────────────────────────────────────────────
    if not tenant_id:
        print(
            "squash cloud-risk: specify a tenant_id or use --overview",
            file=sys.stderr,
        )
        return 1

    if tenant_id not in _api._tenants:
        print(
            f"squash cloud-risk: tenant not found: {tenant_id}",
            file=sys.stderr,
        )
        return 1

    inventory = _api._db_read_inventory(tenant_id)
    vex = _api._db_read_vex_alerts(tenant_id)
    open_vex = len(vex)

    tier_order = ["UNACCEPTABLE", "HIGH", "LIMITED", "MINIMAL"]
    model_profiles: list[dict] = []
    for rec in inventory:
        tier = _api._compute_model_risk_tier(rec, open_vex)
        policy_results = rec.get("policy_results", {})
        total = len(policy_results)
        failed = sum(1 for pr in policy_results.values() if not pr.get("passed", True))
        failure_rate = round(failed / total, 4) if total > 0 else 0.0
        model_profiles.append(
            {
                "model_id": rec.get("model_id", ""),
                "risk_tier": tier,
                "attestation_passed": bool(rec.get("attestation_passed", False)),
                "open_vex_alerts": open_vex,
                "policy_failure_rate": failure_rate,
            }
        )

    if model_profiles:
        overall_tier = min(
            (p["risk_tier"] for p in model_profiles),
            key=lambda t: tier_order.index(t) if t in tier_order else len(tier_order),
        )
    else:
        overall_tier = "MINIMAL"

    if output_json:
        import json as _json
        print(
            _json.dumps(
                {
                    "tenant_id": tenant_id,
                    "overall_risk_tier": overall_tier,
                    "model_count": len(model_profiles),
                    "models": model_profiles,
                },
                indent=2,
            )
        )
        return 0 if overall_tier in ("MINIMAL", "LIMITED") else 2

    if not quiet:
        icon = "\u2713" if overall_tier in ("MINIMAL", "LIMITED") else "\u2715"
        print(
            f"{icon} cloud-risk | {tenant_id} | {overall_tier} | {len(model_profiles)} model(s)"
        )
        if model_profiles:
            print(f"  {'Model':<35} {'Risk Tier':<15} {'Attested':<10} {'VEX Alerts'}")
            print("  " + "-" * 72)
            for mp in model_profiles:
                attest_mark = "PASS" if mp["attestation_passed"] else "FAIL"
                print(
                    f"  {mp['model_id']:<35} {mp['risk_tier']:<15} "
                    f"{attest_mark:<10} {mp['open_vex_alerts']}"
                )

    return 0 if overall_tier in ("MINIMAL", "LIMITED") else 2


def _cmd_cloud_risk(args: argparse.Namespace, quiet: bool) -> int:
    """Show EU AI Act risk profile for a tenant or platform.

    Exit codes:
        0 = tenant found and overall tier is MINIMAL or LIMITED (conformant-ish)
        1 = tenant not found (or missing positional arg without --overview)
        2 = overall tier is HIGH or UNACCEPTABLE (non-conformant)
    """
    try:
        from squash import api as _api
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    overview: bool = getattr(args, "overview", False)
    tenant_id: str | None = getattr(args, "tenant_id", None)
    output_json: bool = getattr(args, "output_json", False)

    if overview:
        # ── Platform overview ──────────────────────────────────────────────
        summary: dict[str, int] = {
            "UNACCEPTABLE": 0,
            "HIGH": 0,
            "LIMITED": 0,
            "MINIMAL": 0,
        }
        tier_order = ["UNACCEPTABLE", "HIGH", "LIMITED", "MINIMAL"]
        tenant_rows: list[dict] = []

        for tid in list(_api._tenants.keys()):
            inventory = _api._db_read_inventory(tid)
            vex = _api._db_read_vex_alerts(tid)
            open_vex = len(vex)
            if inventory:
                tiers = [_api._compute_model_risk_tier(rec, open_vex) for rec in inventory]
                overall_tier = min(
                    tiers,
                    key=lambda t: tier_order.index(t) if t in tier_order else len(tier_order),
                )
            else:
                overall_tier = "MINIMAL"
            summary[overall_tier] += 1
            tenant_rows.append(
                {
                    "tenant_id": tid,
                    "overall_risk_tier": overall_tier,
                    "model_count": len(inventory),
                }
            )

        if output_json:
            import json as _json
            print(
                _json.dumps(
                    {
                        "total_tenants": len(tenant_rows),
                        "risk_summary": summary,
                        "tenants": tenant_rows,
                    },
                    indent=2,
                )
            )
            return 0

        if not quiet:
            print(f"Risk Overview | {len(tenant_rows)} tenant(s)")
            print(
                f"  UNACCEPTABLE: {summary['UNACCEPTABLE']}  "
                f"HIGH: {summary['HIGH']}  "
                f"LIMITED: {summary['LIMITED']}  "
                f"MINIMAL: {summary['MINIMAL']}"
            )
            for row in tenant_rows:
                tier_icon = "\u2715" if row["overall_risk_tier"] in ("UNACCEPTABLE", "HIGH") else "\u2713"
                print(
                    f"  {tier_icon} {row['tenant_id']:<30} "
                    f"{row['overall_risk_tier']:<15} {row['model_count']} model(s)"
                )

        worst = "MINIMAL"
        if summary["UNACCEPTABLE"] > 0 or summary["HIGH"] > 0:
            worst = "HIGH"
        return 2 if worst in ("UNACCEPTABLE", "HIGH") else 0

    # ── Per-tenant profile ─────────────────────────────────────────────────
    if not tenant_id:
        print(
            "squash cloud-risk: specify a tenant_id or use --overview",
            file=sys.stderr,
        )
        return 1

    if tenant_id not in _api._tenants:
        print(
            f"squash cloud-risk: tenant not found: {tenant_id}",
            file=sys.stderr,
        )
        return 1

    inventory = _api._db_read_inventory(tenant_id)
    vex = _api._db_read_vex_alerts(tenant_id)
    open_vex = len(vex)

    tier_order = ["UNACCEPTABLE", "HIGH", "LIMITED", "MINIMAL"]
    model_profiles: list[dict] = []
    for rec in inventory:
        tier = _api._compute_model_risk_tier(rec, open_vex)
        policy_results = rec.get("policy_results", {})
        total = len(policy_results)
        failed = sum(1 for pr in policy_results.values() if not pr.get("passed", True))
        failure_rate = round(failed / total, 4) if total > 0 else 0.0
        model_profiles.append(
            {
                "model_id": rec.get("model_id", ""),
                "risk_tier": tier,
                "attestation_passed": bool(rec.get("attestation_passed", False)),
                "open_vex_alerts": open_vex,
                "policy_failure_rate": failure_rate,
            }
        )

    if model_profiles:
        overall_tier = min(
            (p["risk_tier"] for p in model_profiles),
            key=lambda t: tier_order.index(t) if t in tier_order else len(tier_order),
        )
    else:
        overall_tier = "MINIMAL"

    if output_json:
        import json as _json
        print(
            _json.dumps(
                {
                    "tenant_id": tenant_id,
                    "overall_risk_tier": overall_tier,
                    "model_count": len(model_profiles),
                    "models": model_profiles,
                },
                indent=2,
            )
        )
        return 0 if overall_tier in ("MINIMAL", "LIMITED") else 2

    if not quiet:
        icon = "\u2713" if overall_tier in ("MINIMAL", "LIMITED") else "\u2715"
        print(
            f"{icon} cloud-risk | {tenant_id} | {overall_tier} | {len(model_profiles)} model(s)"
        )
        if model_profiles:
            print(f"  {'Model':<35} {'Risk Tier':<15} {'Attested':<10} {'VEX Alerts'}")
            print("  " + "-" * 72)
            for mp in model_profiles:
                attest_mark = "PASS" if mp["attestation_passed"] else "FAIL"
                print(
                    f"  {mp['model_id']:<35} {mp['risk_tier']:<15} "
                    f"{attest_mark:<10} {mp['open_vex_alerts']}"
                )

    return 0 if overall_tier in ("MINIMAL", "LIMITED") else 2


def _cmd_cloud_remediate(args: argparse.Namespace, quiet: bool) -> int:
    """Generate a prioritised EU AI Act remediation plan for a tenant.

    Exit codes:
        0 = plan generated with zero critical steps (tenant is on track)
        1 = tenant not found
        2 = plan contains one or more priority-1 (critical) steps
    """
    try:
        from squash import api as _api
        from squash.risk import generate_remediation_plan
    except ImportError as exc:
        print(f"squash is not installed: {exc}", file=sys.stderr)
        return 2

    tenant_id: str = args.tenant_id
    output_json: bool = getattr(args, "output_json", False)

    if tenant_id not in _api._tenants:
        print(
            f"squash cloud-remediate: tenant not found: {tenant_id}",
            file=sys.stderr,
        )
        return 1

    inventory = _api._db_read_inventory(tenant_id)
    vex = _api._db_read_vex_alerts(tenant_id)
    open_vex = len(vex)

    tier_order = ["UNACCEPTABLE", "HIGH", "LIMITED", "MINIMAL"]
    if inventory:
        tiers = [_api._compute_model_risk_tier(rec, open_vex) for rec in inventory]
        overall_tier = min(
            tiers,
            key=lambda t: tier_order.index(t) if t in tier_order else len(tier_order),
        )
    else:
        overall_tier = "MINIMAL"

    # Aggregate worst-case policy results + attestation state
    all_policy_results: dict = {}
    all_attested = True
    for rec in inventory:
        if not rec.get("attestation_passed", True):
            all_attested = False
        for pname, presult in rec.get("policy_results", {}).items():
            if pname not in all_policy_results or not presult.get("passed", True):
                all_policy_results[pname] = presult

    steps = generate_remediation_plan(
        risk_tier=overall_tier,
        policy_results=all_policy_results,
        open_vex=open_vex,
        attestation_passed=all_attested,
    )
    critical_count = sum(1 for s in steps if s.priority == 1)

    if output_json:
        import json as _json
        print(
            _json.dumps(
                {
                    "tenant_id": tenant_id,
                    "risk_tier": overall_tier,
                    "total_steps": len(steps),
                    "critical_count": critical_count,
                    "steps": [
                        {
                            "id": s.id,
                            "priority": s.priority,
                            "action": s.action,
                            "description": s.description,
                            "evidence_required": s.evidence_required,
                            "estimated_effort": s.estimated_effort,
                        }
                        for s in steps
                    ],
                },
                indent=2,
            )
        )
        return 2 if critical_count > 0 else 0

    if not quiet:
        icon = "\u2713" if critical_count == 0 else "\u2715"
        print(
            f"{icon} cloud-remediate | {tenant_id} | {overall_tier} | "
            f"{len(steps)} step(s), {critical_count} critical"
        )
        for s in steps:
            pri_label = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(s.priority, str(s.priority))
            print(f"  [{pri_label}] {s.action} ({s.estimated_effort})")
            print(f"         {s.description[:100]}")
            print(f"         Evidence: {s.evidence_required}")

    return 2 if critical_count > 0 else 0


# ---------------------------------------------------------------------------
# W135 / W136 — annex-iv generate + validate
# ---------------------------------------------------------------------------

def _cmd_annex_iv(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """Dispatch annex-iv subcommands (generate / validate)."""
    subcmd = args.annex_iv_command

    if subcmd == "generate":
        return _cmd_annex_iv_generate(args, quiet)
    elif subcmd == "validate":
        return _cmd_annex_iv_validate(args, quiet)
    else:
        print("squash annex-iv: unknown subcommand", file=sys.stderr)
        return 1


def _cmd_annex_iv_generate(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """W135 — generate Annex IV documentation from a training run directory."""
    from pathlib import Path as _Path

    try:
        from squash.artifact_extractor import ArtifactExtractor
        from squash.annex_iv_generator import AnnexIVGenerator, AnnexIVValidator
    except ImportError as exc:
        print(f"squash modules not available: {exc}", file=sys.stderr)
        return 2

    root = _Path(args.root).expanduser().resolve()
    if not root.exists():
        print(f"error: --root directory not found: {root}", file=sys.stderr)
        return 1

    output_dir = _Path(args.output_dir).expanduser().resolve() if args.output_dir else root
    output_dir.mkdir(parents=True, exist_ok=True)

    if not quiet:
        print(f"squash annex-iv generate | scanning {root}")

    # ── Phase 1: extract artifacts from run directory ─────────────────────────
    result = ArtifactExtractor.from_run_dir(root)

    if result.warnings and not quiet:
        for w in result.warnings:
            print(f"  [warn] {w}")

    # ── Phase 2: optional MLflow augmentation ─────────────────────────────────
    if args.mlflow_run:
        if not quiet:
            print(f"  [mlflow] fetching run {args.mlflow_run} from {args.mlflow_uri}")
        try:
            full = ArtifactExtractor.from_mlflow_run_full(
                args.mlflow_run, tracking_uri=args.mlflow_uri
            )
            if result.metrics is None:
                result.metrics = full.metrics
            if result.config is None:
                result.config = full.config
        except Exception as exc:
            print(f"  [warn] mlflow augmentation failed: {exc}", file=sys.stderr)

    # ── Phase 3: optional W&B augmentation ───────────────────────────────────
    if args.wandb_run:
        if not quiet:
            print(f"  [wandb] fetching run {args.wandb_run}")
        try:
            parts = args.wandb_run.split("/")
            run_id = parts[-1]
            project = parts[-2] if len(parts) >= 2 else None
            entity = parts[-3] if len(parts) >= 3 else None
            full = ArtifactExtractor.from_wandb_run_full(
                run_id, project=project, entity=entity
            )
            if result.metrics is None:
                result.metrics = full.metrics
            if result.config is None:
                result.config = full.config
        except Exception as exc:
            print(f"  [warn] wandb augmentation failed: {exc}", file=sys.stderr)

    # ── Phase 4: optional HuggingFace dataset provenance ─────────────────────
    if args.hf_datasets:
        if not quiet:
            print(f"  [hf] fetching provenance for: {', '.join(args.hf_datasets)}")
        try:
            datasets = ArtifactExtractor.from_huggingface_dataset_list(
                args.hf_datasets, token=args.hf_token
            )
            result.datasets.extend(datasets)
        except Exception as exc:
            print(f"  [warn] huggingface augmentation failed: {exc}", file=sys.stderr)

    # ── Phase 5: generate Annex IV document ──────────────────────────────────
    if not quiet:
        print("  [generate] building Annex IV document …")

    doc = AnnexIVGenerator().generate(
        result,
        system_name=args.system_name,
        version=args.version,
        intended_purpose=args.intended_purpose,
        risk_level=args.risk_level,
        general_description=args.general_description,
        hardware_requirements=args.hardware_requirements,
        deployment_context=args.deployment_context,
        risk_management=args.risk_management,
        oversight_description=args.oversight_description,
        model_type=args.model_type,
        lifecycle_plan=args.lifecycle_plan,
        monitoring_plan=args.monitoring_plan,
    )

    # ── Phase 6: save to disk ─────────────────────────────────────────────────
    written = doc.save(output_dir, formats=list(args.formats), stem=args.stem)

    if not quiet:
        score_icon = "✅" if doc.overall_score >= 80 else ("⚠️" if doc.overall_score >= 40 else "❌")
        print(f"\n{score_icon}  Annex IV score: {doc.overall_score}/100 "
              f"({len(doc.complete_sections)}/12 sections complete)")
        for fmt, path in written.items():
            print(f"  [{fmt}] {path}")

    # ── Phase 7: validate ─────────────────────────────────────────────────────
    if args.no_validate:
        return 0

    report = AnnexIVValidator().validate(doc)

    if not quiet:
        print(f"\n{'Hard fails' if report.hard_fails else 'No hard fails'} | "
              f"{len(report.warnings)} warning(s) | "
              f"{len(report.info)} info")
        for f in report.hard_fails:
            print(f"  [FAIL] {f.section}: {f.message}")
        for w in report.warnings:
            print(f"  [WARN] {w.section}: {w.message}")

    if report.hard_fails:
        return 2
    if args.fail_on_warning and report.warnings:
        return 1
    return 0


def _cmd_annex_iv_validate(args: argparse.Namespace, quiet: bool) -> int:
    """W136 — validate an existing Annex IV JSON document."""
    from pathlib import Path as _Path
    import json as _json

    try:
        from squash.annex_iv_generator import AnnexIVDocument, AnnexIVValidator, AnnexIVSection
    except ImportError as exc:
        print(f"squash modules not available: {exc}", file=sys.stderr)
        return 2

    doc_path = _Path(args.document).expanduser().resolve()
    if not doc_path.exists():
        print(f"error: file not found: {doc_path}", file=sys.stderr)
        return 1

    try:
        raw = _json.loads(doc_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"error: could not parse JSON: {exc}", file=sys.stderr)
        return 1

    try:
        # Reconstruct AnnexIVDocument from saved JSON
        sections = []
        for s in raw.get("sections", []):
            sections.append(AnnexIVSection(
                key=s["key"],
                title=s["title"],
                article=s.get("article", ""),
                content=s.get("content", ""),
                completeness=s.get("completeness", 0),
                gaps=s.get("gaps", []),
            ))
        doc = AnnexIVDocument(
            system_name=raw.get("system_name", ""),
            version=raw.get("version", ""),
            generated_at=raw.get("generated_at", ""),
            sections=sections,
            overall_score=raw.get("overall_score", 0),
            metadata=raw.get("metadata", {}),
        )
    except Exception as exc:
        print(f"error: could not reconstruct AnnexIVDocument: {exc}", file=sys.stderr)
        return 1

    report = AnnexIVValidator().validate(doc)

    if not quiet:
        score_icon = "✅" if doc.overall_score >= 80 else ("⚠️" if doc.overall_score >= 40 else "❌")
        print(f"{score_icon}  {doc.system_name} v{doc.version} — score {doc.overall_score}/100")
        print(f"   Hard fails: {len(report.hard_fails)}  Warnings: {len(report.warnings)}  Info: {len(report.info)}")
        for f in report.hard_fails:
            print(f"  [FAIL] {f.section}: {f.message}")
        for w in report.warnings:
            print(f"  [WARN] {w.section}: {w.message}")
        for i in report.info:
            print(f"  [INFO] {i.section}: {i.message}")

    if report.hard_fails:
        return 2
    if args.fail_on_warning and report.warnings:
        return 1
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# W160 — squash demo
# ─────────────────────────────────────────────────────────────────────────────

_DEMO_MODEL_CONFIG = """{
  "model_type": "bert",
  "hidden_size": 768,
  "num_attention_heads": 12,
  "num_hidden_layers": 12,
  "vocab_size": 30522,
  "architectures": ["BertForSequenceClassification"],
  "task_type": "text-classification"
}"""

_DEMO_TRAIN_CONFIG = """{
  "optimizer": {"type": "AdamW", "lr": 2e-5, "weight_decay": 0.01},
  "scheduler": "linear_warmup",
  "num_epochs": 3,
  "batch_size": 32,
  "max_seq_length": 128,
  "framework": "pytorch",
  "dataset": "imdb",
  "seed": 42
}"""

_DEMO_TRAIN_PY = '''"""Sample training script for squash demo."""
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from transformers import BertForSequenceClassification

model = BertForSequenceClassification.from_pretrained("bert-base-uncased")
optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
criterion = nn.CrossEntropyLoss()

for epoch in range(3):
    for batch in DataLoader([]):
        outputs = model(**batch)
        loss = criterion(outputs.logits, batch["labels"])
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

torch.save(model.state_dict(), "model.pt")
'''


def _cmd_demo(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """W160 — zero-friction first-value demo attestation."""
    import tempfile
    import struct

    from pathlib import Path as _Path

    try:
        from squash.attest import AttestConfig, AttestPipeline
    except ImportError as exc:
        print(f"squash modules not available: {exc}", file=sys.stderr)
        return 2

    if not quiet:
        print("\n" + "─" * 60)
        print("  Squash violations, not velocity.")
        print("  Running demo attestation on sample BERT model…")
        print("─" * 60)

    with tempfile.TemporaryDirectory(prefix="squash_demo_") as tmp:
        model_dir = _Path(tmp) / "bert-base-demo"
        model_dir.mkdir()

        # Write a minimal but realistic model artifact structure
        (model_dir / "config.json").write_text(_DEMO_MODEL_CONFIG)
        (model_dir / "training_config.json").write_text(_DEMO_TRAIN_CONFIG)
        (model_dir / "train.py").write_text(_DEMO_TRAIN_PY)

        # Tiny synthetic safetensors-style binary (just enough for the scanner)
        header = b'{"weight": {"dtype": "F32", "shape": [768, 768], "data_offsets": [0, 2359296]}}'
        header_padded = header + b" " * (8 - len(header) % 8 if len(header) % 8 else 0)
        weights = model_dir / "model.safetensors"
        weights.write_bytes(struct.pack("<Q", len(header_padded)) + header_padded + b"\x00" * 64)

        out_dir = _Path(args.output_dir).expanduser().resolve() if args.output_dir else _Path(tmp) / "output"
        out_dir.mkdir(parents=True, exist_ok=True)

        config = AttestConfig(
            model_path=model_dir,
            output_dir=out_dir,
            model_id="bert-base-demo",
            policies=[args.policy] if args.policy else ["eu-ai-act"],
            sign=False,
            fail_on_violation=False,
        )

        if not quiet:
            print(f"\n  Model:   bert-base-uncased (sample)")
            print(f"  Policy:  {args.policy or 'eu-ai-act'}")
            print(f"  Output:  {out_dir}\n")

        result = AttestPipeline.run(config)

        if not quiet:
            passed_icon = "✅" if result.passed else "❌"
            print(f"\n{passed_icon} Attestation {'PASSED' if result.passed else 'FAILED'}")

            if result.cyclonedx_path:
                print(f"\n  Artifacts generated:")
                for f in sorted(out_dir.rglob("*")):
                    if f.is_file():
                        size = f.stat().st_size
                        print(f"    {f.name:<40} {size:>8,} bytes")

            print("\n" + "─" * 60)
            print("  This is squash. It runs in CI in <10 seconds.")
            print("  pip install squash-ai && squash attest ./your-model")
            print("─" * 60 + "\n")

        return 0 if result.passed else 1


# ─────────────────────────────────────────────────────────────────────────────
# W162 — squash init
# ─────────────────────────────────────────────────────────────────────────────

_SQUASH_YML_TEMPLATE = """\
# .squash.yml — Squash AI compliance configuration
# Generated by: squash init
# Docs: https://github.com/konjoai/squash

project:
  name: "{project_name}"
  version: "1.0.0"
  risk_level: "limited"       # minimal | limited | high | unacceptable

attestation:
  model_path: "./models"      # path to model directory or file
  output_dir: "./attestation" # where artifacts are written

  # Compliance policy frameworks to evaluate
  policies:{policies_block}

  # Enable Sigstore keyless signing (requires internet)
  sign: false

  # Fail the CI job on policy violation
  fail_on_violation: true

  # Generate EU AI Act Annex IV technical documentation
  annex_iv: false

# MLframework detection: {framework}
framework:
  detected: "{framework}"

# CI/CD integration: add this to your pipeline
# GitHub Actions:  uses: konjoai/squash@v1
# GitLab CI:       include: integrations/gitlab-ci/squash.gitlab-ci.yml
# Jenkins:         squashAttest modelPath: "./models"
"""

_FRAMEWORK_INDICATORS = {
    "pytorch": ["torch", "pytorch", "*.pt", "*.pth", "*.bin"],
    "tensorflow": ["tensorflow", "keras", "saved_model", "*.pb", "*.h5"],
    "huggingface": ["transformers", "config.json", "tokenizer_config.json", "*.safetensors"],
    "mlflow": ["mlruns", "MLproject", "conda.yaml"],
    "wandb": ["wandb", ".wandb"],
    "jax": ["jax", "flax", "orbax"],
    "mlx": ["mlx"],
}


def _detect_framework(directory: "Path") -> str:
    """Detect ML framework from directory contents."""
    from pathlib import Path as _Path
    d = _Path(directory)

    # Check requirements files
    for req_file in ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"]:
        req_path = d / req_file
        if req_path.exists():
            try:
                content = req_path.read_text(encoding="utf-8", errors="ignore").lower()
                for framework, indicators in _FRAMEWORK_INDICATORS.items():
                    if any(ind.lower() in content for ind in indicators if not ind.startswith("*")):
                        return framework
            except OSError:
                pass

    # Check for model files and directories
    for framework, indicators in _FRAMEWORK_INDICATORS.items():
        for pattern in indicators:
            if pattern.startswith("*"):
                if list(d.rglob(pattern)):
                    return framework
            elif (d / pattern).exists():
                return framework

    # Check Python imports in .py files
    for py_file in list(d.rglob("*.py"))[:20]:  # limit scan
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for framework in ["torch", "tensorflow", "jax", "mlx", "transformers"]:
                if f"import {framework}" in content or f"from {framework}" in content:
                    fw_map = {"torch": "pytorch", "tensorflow": "tensorflow",
                              "jax": "jax", "mlx": "mlx", "transformers": "huggingface"}
                    return fw_map.get(framework, framework)
        except OSError:
            pass

    return "unknown"


def _cmd_init(args: argparse.Namespace, quiet: bool) -> int:
    """W162 — scaffold .squash.yml and run a dry-run attestation."""
    from pathlib import Path as _Path

    project_dir = _Path(getattr(args, "dir", ".")).expanduser().resolve()
    if not project_dir.exists():
        print(f"error: directory not found: {project_dir}", file=sys.stderr)
        return 1

    squash_yml = project_dir / ".squash.yml"
    if squash_yml.exists() and not quiet:
        print(f"[squash init] .squash.yml already exists at {squash_yml}")
        print("  Delete it and re-run to regenerate.\n")
        return 0

    # Detect framework
    framework = getattr(args, "framework", "") or _detect_framework(project_dir)

    # Policies
    policies = getattr(args, "policy", None) or ["eu-ai-act"]
    policies_block = "\n" + "".join(f"    - {p}\n" for p in policies)

    project_name = project_dir.name

    yml_content = _SQUASH_YML_TEMPLATE.format(
        project_name=project_name,
        framework=framework,
        policies_block=policies_block.rstrip("\n"),
    )
    squash_yml.write_text(yml_content, encoding="utf-8")

    if not quiet:
        fw_display = f" [{framework}]" if framework != "unknown" else ""
        print(f"\n[squash init]{fw_display}")
        print(f"  ✅ Created {squash_yml}")
        print(f"  Framework detected: {framework}")
        print(f"  Policies: {', '.join(policies)}")

    # Dry run
    dry_run = getattr(args, "dry_run", True)
    if dry_run:
        if not quiet:
            print("\n  Running dry-run attestation to validate configuration…\n")
        try:
            from squash.attest import AttestConfig, AttestPipeline
            import tempfile

            config = AttestConfig(
                model_path=project_dir,
                output_dir=_Path(tempfile.mkdtemp(prefix="squash_init_")),
                policies=policies,
                sign=False,
                fail_on_violation=False,
            )
            result = AttestPipeline.run(config)
            if not quiet:
                icon = "✅" if result.passed else "⚠️"
                print(f"  {icon} Dry-run complete — passed: {result.passed}")
                print("\n  Next steps:")
                print("    1. Edit .squash.yml to match your model path")
                print("    2. Run: squash attest .")
                print("    3. Add to CI: uses: konjoai/squash@v1")
                print()
        except Exception as exc:  # noqa: BLE001
            if not quiet:
                print(f"  ⚠️  Dry-run skipped ({exc})")
                print("  Edit .squash.yml and run: squash attest .")

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# W167 — squash watch
# ─────────────────────────────────────────────────────────────────────────────

_WATCH_EXTENSIONS = frozenset({
    ".safetensors", ".bin", ".pt", ".pth", ".pb", ".h5", ".onnx",
    ".pkl", ".joblib", ".json", ".yaml", ".yml",
})


def _snapshot_dir(directory: "Path") -> dict[str, float]:
    """Return a {relative_path: mtime} snapshot of watched files."""
    from pathlib import Path as _Path
    snap = {}
    for f in _Path(directory).rglob("*"):
        if f.is_file() and f.suffix in _WATCH_EXTENSIONS:
            try:
                snap[str(f.relative_to(directory))] = f.stat().st_mtime
            except (OSError, ValueError):
                pass
    return snap


def _cmd_watch(args: argparse.Namespace, quiet: bool) -> int:
    """W167 — watch a model directory and re-attest on file changes."""
    import time
    from pathlib import Path as _Path

    try:
        from squash.attest import AttestConfig, AttestPipeline
    except ImportError as exc:
        print(f"squash modules not available: {exc}", file=sys.stderr)
        return 2

    watch_path = _Path(getattr(args, "path", ".")).expanduser().resolve()
    if not watch_path.exists():
        print(f"error: path not found: {watch_path}", file=sys.stderr)
        return 1

    policies = getattr(args, "policy", ["eu-ai-act"])
    interval = max(1, getattr(args, "interval", 5))
    on_fail = getattr(args, "on_fail", "log")
    out_dir = _Path(args.output_dir).expanduser().resolve() if args.output_dir else watch_path / "attestation"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not quiet:
        print(f"\n[squash watch] Watching {watch_path}")
        print(f"  Policies: {', '.join(policies)}")
        print(f"  Interval: {interval}s  |  On-fail: {on_fail}")
        print(f"  Press Ctrl+C to stop.\n")

    last_snap = _snapshot_dir(watch_path)
    run_count = 0

    def _run_attestation() -> bool:
        nonlocal run_count
        run_count += 1
        if not quiet:
            print(f"[squash watch] Run #{run_count} — {time.strftime('%H:%M:%S')}")
        config = AttestConfig(
            model_path=watch_path,
            output_dir=out_dir,
            policies=policies,
            sign=False,
            fail_on_violation=False,
        )
        try:
            result = AttestPipeline.run(config)
            icon = "✅" if result.passed else "❌"
            if not quiet:
                print(f"  {icon} {'PASSED' if result.passed else 'FAILED'}")
            return result.passed
        except Exception as exc:  # noqa: BLE001
            if not quiet:
                print(f"  ⚠️  Attestation error: {exc}")
            return False

    # Initial run
    passed = _run_attestation()
    if not passed and on_fail == "exit":
        return 1

    try:
        while True:
            time.sleep(interval)
            snap = _snapshot_dir(watch_path)
            if snap != last_snap:
                changed = set(snap) - set(last_snap) | {k for k in snap if snap[k] != last_snap.get(k)}
                if not quiet and changed:
                    print(f"[squash watch] Changed: {', '.join(sorted(changed)[:5])}")
                last_snap = snap
                passed = _run_attestation()
                if not passed:
                    if on_fail == "exit":
                        return 1
                    if on_fail == "notify":
                        try:
                            from squash.notifications import notify, ATTESTATION_FAILED
                            notify(ATTESTATION_FAILED, model_id=watch_path.name)
                        except Exception:  # noqa: BLE001
                            pass
    except KeyboardInterrupt:
        if not quiet:
            print(f"\n[squash watch] Stopped after {run_count} run(s).")

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# W168 — squash install-hook
# ─────────────────────────────────────────────────────────────────────────────

_PRE_PUSH_HOOK = """\
#!/bin/sh
# squash pre-push hook — installed by: squash install-hook
set -e
echo "[squash] Running attestation before push…"
squash attest . {policy_flags} --fail-on-violation
echo "[squash] Attestation passed."
"""

_PRE_COMMIT_HOOK = """\
#!/bin/sh
# squash pre-commit hook — installed by: squash install-hook
set -e
echo "[squash] Running attestation before commit…"
squash attest . {policy_flags} --fail-on-violation
echo "[squash] Attestation passed."
"""


def _cmd_install_hook(args: argparse.Namespace, quiet: bool) -> int:
    """W168 — install squash as a git pre-push / pre-commit hook."""
    from pathlib import Path as _Path
    import stat

    repo_dir = _Path(getattr(args, "dir", ".")).expanduser().resolve()
    git_dir = repo_dir / ".git"
    if not git_dir.exists():
        print(f"error: not a git repository: {repo_dir}", file=sys.stderr)
        return 1

    hook_type = getattr(args, "hook_type", "pre-push")
    policies = getattr(args, "policy", ["eu-ai-act"])
    policy_flags = " ".join(f"--policy {p}" for p in policies) if policies else ""

    hook_path = git_dir / "hooks" / hook_type
    (git_dir / "hooks").mkdir(exist_ok=True)

    template = _PRE_PUSH_HOOK if hook_type == "pre-push" else _PRE_COMMIT_HOOK
    hook_content = template.format(policy_flags=policy_flags)

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        if "squash" in existing:
            if not quiet:
                print(f"[squash install-hook] Hook already installed at {hook_path}")
            return 0
        backup = hook_path.with_suffix(".bak")
        hook_path.rename(backup)
        if not quiet:
            print(f"[squash install-hook] Backed up existing hook to {backup}")
        hook_content = existing.rstrip("\n") + "\n\n" + hook_content

    hook_path.write_text(hook_content, encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    if not quiet:
        print(f"\n[squash install-hook]")
        print(f"  ✅ Installed {hook_type} hook at {hook_path}")
        print(f"  Policies: {', '.join(policies)}")
        print(f"  Remove with: rm {hook_path}\n")

    return 0


def _cmd_iso42001(args: argparse.Namespace, quiet: bool) -> int:
    """W170 — ISO 42001 readiness assessment."""
    from squash.iso42001 import Iso42001Assessor

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"[squash iso42001] ERROR: path not found: {model_path}", file=sys.stderr)
        return 1

    report = Iso42001Assessor.assess(model_path)

    output_path = args.output
    if output_path is None:
        output_path = model_path / "iso42001_report.json" if model_path.is_dir() else Path("iso42001_report.json")
    else:
        output_path = Path(output_path)

    report.save(output_path)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        if not quiet:
            print(report.summary())
            print(f"\n[squash iso42001] Report written to {output_path}")
            print(f"  Readiness: {report.readiness_level.value}  Score: {report.overall_score:.1f}%")

    if args.fail_below is not None and report.overall_score < args.fail_below:
        print(f"[squash iso42001] FAIL: score {report.overall_score:.1f}% < threshold {args.fail_below}%",
              file=sys.stderr)
        return 2
    return 0


def _cmd_trust_package(args: argparse.Namespace, quiet: bool) -> int:
    """W171 — Trust Package export."""
    from squash.trust_package import TrustPackageBuilder

    model_path = Path(args.model_path)
    model_id = args.model_id or model_path.name
    output_path = Path(args.output) if args.output else Path(f"{model_id}-trust-package.zip")

    pkg = TrustPackageBuilder.build(
        model_path=model_path,
        output_path=output_path,
        model_id=model_id,
        sign=args.sign,
        verification_url=args.verification_url,
    )

    if not quiet:
        print(pkg.summary())
        print(f"\n[squash trust-package] Package written to {output_path}")
        print(f"  Artifacts: {len(pkg.artifacts_included)}")
        print(f"  Verify with: squash verify-trust-package {output_path}")
    return 0


def _cmd_verify_trust_package(args: argparse.Namespace, quiet: bool) -> int:
    """W171 — Trust Package verification."""
    from squash.trust_package import TrustPackageVerifier

    result = TrustPackageVerifier.verify(Path(args.package_path))

    if args.output_json:
        print(json.dumps({
            "passed": result.passed,
            "package_path": result.package_path,
            "integrity_errors": result.integrity_errors,
            "missing_artifacts": result.missing_artifacts,
            "compliance_summary": result.compliance_summary,
        }, indent=2))
    elif not quiet:
        print(result.summary())

    if args.fail_on_error and not result.passed:
        return 2
    return 0 if result.passed else 1


def _cmd_agent_audit(args: argparse.Namespace, quiet: bool) -> int:
    """W172 — OWASP Agentic AI Top 10 agent audit."""
    from squash.agent_audit import AgentAuditor, RiskLevel

    manifest_path = Path(args.manifest_path)
    if not manifest_path.exists():
        print(f"[squash agent-audit] ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    report = AgentAuditor.audit(manifest_path)

    if args.output:
        report.save(Path(args.output))

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        if not quiet:
            print(report.summary())
            if args.output:
                print(f"\n[squash agent-audit] Report written to {args.output}")
            print(f"\n[squash agent-audit] Overall Risk: {report.overall_risk.value}  Score: {report.risk_score}/100")

    if args.fail_on_critical and report.critical_count > 0:
        return 2
    if args.fail_on_high and (report.critical_count > 0 or report.high_count > 0):
        return 2
    return 0


def _cmd_incident(args: argparse.Namespace, quiet: bool) -> int:
    """W173 — Incident response package generation."""
    from squash.incident import IncidentResponder

    model_path = Path(args.model_path)
    pkg = IncidentResponder.respond(
        model_path=model_path,
        description=args.description,
        timestamp=args.timestamp,
        severity=args.severity,
        category=args.category,
        affected_persons=args.affected_persons,
        model_id=args.model_id,
    )

    output_dir = Path(args.output_dir) if args.output_dir else Path(f"incident-{pkg.incident_id}")
    pkg.save(output_dir)

    if not quiet:
        print(pkg.summary())
        print(f"\n[squash incident] Incident package written to {output_dir}/")

    return 0


def _cmd_annual_review(args: argparse.Namespace, quiet: bool) -> int:
    """W182 — Annual review generator."""
    from squash.annual_review import AnnualReviewGenerator
    model_paths = [Path(args.model_path)] if getattr(args, "model_path", None) else None
    models_dir = Path(args.models_dir) if getattr(args, "models_dir", None) else None
    review = AnnualReviewGenerator.generate(
        year=getattr(args, "year", None),
        models_dir=models_dir,
        model_paths=model_paths,
    )
    if getattr(args, "output_json", False):
        print(json.dumps(review.to_dict(), indent=2))
        return 0
    if not quiet:
        print(review.executive_summary())
    output_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else Path(f"annual-review-{review.year}")
    written = review.save(output_dir)
    if not quiet:
        print(f"\n[squash annual-review] Written to {output_dir}/")
        for f in written:
            print(f"  {f}")
    return 0


def _cmd_publish(args: argparse.Namespace, quiet: bool) -> int:
    """W183 — Publish attestation to registry."""
    from squash.attestation_registry import AttestationRegistry
    model_path = Path(args.model_path)
    db = Path(args.db) if getattr(args, "db", None) else None
    attest_path = None
    for candidate in [
        model_path / "squash_attestation.json",
        model_path / "squash-attest.json",
    ]:
        if candidate.exists():
            attest_path = candidate
            break
    with AttestationRegistry(db) as reg:
        entry = reg.publish(
            model_id=getattr(args, "model_id", None) or model_path.name,
            attestation_path=attest_path,
            org=args.org,
            is_public=not getattr(args, "private", False),
        )
    if not quiet:
        print(f"[squash publish] Published: {entry.uri}")
        print(f"  Verify: {entry.verify_url}")
        print(f"  Entry ID: {entry.entry_id}")
    return 0


def _cmd_lookup(args: argparse.Namespace, quiet: bool) -> int:
    """W183 — Lookup attestation registry."""
    from squash.attestation_registry import AttestationRegistry
    db = Path(args.db) if getattr(args, "db", None) else None
    with AttestationRegistry(db) as reg:
        entries = reg.lookup(
            model_id=getattr(args, "model_id", None),
            org=getattr(args, "org", None),
            entry_id=getattr(args, "entry_id", None),
        )
    if getattr(args, "output_json", False):
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        if not entries:
            print("[squash lookup] No entries found.")
        for e in entries:
            print(f"  {e.uri}  score={e.compliance_score}  published={e.published_at[:10]}")
    return 0


def _cmd_verify_entry(args: argparse.Namespace, quiet: bool) -> int:
    """W183 — Verify registry entry."""
    from squash.attestation_registry import AttestationRegistry
    db = Path(args.db) if getattr(args, "db", None) else None
    with AttestationRegistry(db) as reg:
        result = reg.verify(args.entry_id)
    status = "VALID" if result.valid else "INVALID"
    if not quiet:
        print(f"[squash verify-entry] {status}  {args.entry_id}")
        if result.error:
            print(f"  Error: {result.error}")
    return 0 if result.valid else 2


def _cmd_dashboard(args: argparse.Namespace, quiet: bool) -> int:
    """W184 — CISO dashboard."""
    from squash.dashboard import Dashboard
    model_paths = [Path(args.model_path)] if getattr(args, "model_path", None) else None
    models_dir = Path(args.models_dir) if getattr(args, "models_dir", None) else None
    d = Dashboard.build(models_dir=models_dir, model_paths=model_paths)
    if getattr(args, "output_json", False):
        print(json.dumps(d.to_dict(), indent=2))
    else:
        print(d.render_text(color=not getattr(args, "no_color", False)))
    return 0


def _cmd_regulatory(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """W185 — Regulatory intelligence feed."""
    from squash.regulatory_feed import RegulatoryFeed
    feed = RegulatoryFeed()
    cmd = getattr(args, "regulatory_command", None)

    if cmd == "status" or cmd is None:
        s = feed.status()
        if getattr(args, "output_json", False):
            print(json.dumps({
                "total": s.total_regulations, "active": s.active_enforcement,
                "pending": s.pending_enforcement, "nearest_deadline": s.nearest_deadline,
                "days": s.nearest_deadline_days, "squash_coverage": s.squash_coverage,
            }, indent=2))
        else:
            print(s.compliance_impact_summary())
        return 0

    elif cmd == "list":
        jurisdiction = getattr(args, "jurisdiction", None)
        industry = getattr(args, "industry", None)
        if jurisdiction:
            regs = feed.regulations_by_jurisdiction(jurisdiction)
        elif industry:
            regs = feed.regulations_affecting_industry(industry)
        else:
            regs = feed.all_regulations()
        if getattr(args, "output_json", False):
            print(json.dumps(feed.export(), indent=2))
        else:
            for r in regs:
                print(r.summary())
        return 0

    elif cmd == "updates":
        since = getattr(args, "since", None)
        updates = feed.check_updates(since=since)
        if getattr(args, "output_json", False):
            print(json.dumps([{
                "reg_id": u.reg_id, "change_date": u.change_date,
                "impact": u.impact_level, "summary": u.change_summary,
            } for u in updates], indent=2))
        else:
            for u in updates:
                print(u.summary())
                print()
        return 0

    elif cmd == "deadlines":
        days = getattr(args, "days", 365)
        deadlines = feed.upcoming_deadlines(days=days)
        if getattr(args, "output_json", False):
            print(json.dumps([{
                "regulation": r.short_name, "deadline": r.enforcement_date,
                "days_remaining": d,
            } for r, d in deadlines], indent=2))
        else:
            if not deadlines:
                print(f"[squash regulatory] No enforcement deadlines in next {days} days.")
            for r, d in deadlines:
                print(f"  {d:4d} days — {r.short_name} ({r.enforcement_date})")
        return 0

    else:
        print(f"[squash regulatory] Unknown subcommand: {cmd}")
        return 1


def _cmd_due_diligence(args: argparse.Namespace, quiet: bool) -> int:
    """W186 — M&A due diligence package."""
    from squash.due_diligence import DueDiligenceGenerator
    model_paths = [Path(args.model_path)] if getattr(args, "model_path", None) else None
    models_dir = Path(args.models_dir) if getattr(args, "models_dir", None) else None
    pkg = DueDiligenceGenerator.generate(
        company_name=args.company,
        deal_type=args.deal_type,
        models_dir=models_dir,
        model_paths=model_paths,
    )
    if getattr(args, "output_json", False):
        print(json.dumps(pkg.to_dict(), indent=2))
        return 0
    if not quiet:
        print(pkg.executive_risk_summary())
    output_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else Path(f"dd-{pkg.package_id}")
    written = pkg.save(output_dir)
    if not quiet:
        print(f"\n[squash due-diligence] Package written to {output_dir}/")
        for f in written:
            print(f"  {f}")
    return 0


def _cmd_vendor(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """W178 — AI Vendor Risk Register."""
    from squash.vendor_registry import VendorRegistry
    from pathlib import Path as _Path

    db = _Path(args.db) if getattr(args, "db", None) else None

    with VendorRegistry(db) as reg:
        cmd = getattr(args, "vendor_command", None)

        if cmd == "add":
            vid = reg.add_vendor(
                name=args.name, website=args.website, risk_tier=args.risk_tier,
                use_case=args.use_case, data_access=args.data_access, notes=args.notes,
            )
            if not quiet:
                print(f"[squash vendor] Added vendor '{args.name}' ID={vid}")
            return 0

        elif cmd == "list":
            vendors = reg.list_vendors(tier=getattr(args, "tier", None))
            if getattr(args, "output_json", False):
                print(json.dumps([v.to_dict() for v in vendors], indent=2))
            else:
                if not vendors:
                    print("[squash vendor] No vendors registered.")
                for v in vendors:
                    print(f"  [{v.risk_tier.value.upper():8s}] {v.name:30s} {v.vendor_id}  "
                          f"status={v.assessment_status.value}")
            return 0

        elif cmd == "questionnaire":
            q = reg.generate_questionnaire(args.vendor_id)
            output = getattr(args, "output", None)
            if output:
                from pathlib import Path as _P
                _P(output).write_text(
                    json.dumps(q.to_dict(), indent=2) if output.endswith(".json")
                    else q.to_text()
                )
                if not quiet:
                    print(f"[squash vendor] Questionnaire written to {output}")
            else:
                print(q.to_text())
            return 0

        elif cmd == "import-trust-package":
            result = reg.import_trust_package(args.vendor_id, Path(args.package_path))
            if not quiet:
                status = "PASS" if result["passed"] else "FAIL"
                print(f"[squash vendor] Trust Package import: {status}  "
                      f"score={result.get('score', 'N/A')}")
            return 0 if result["passed"] else 1

        elif cmd == "summary":
            s = reg.risk_summary()
            if getattr(args, "output_json", False):
                print(json.dumps(s, indent=2))
            else:
                print(f"[squash vendor] Registry: {s['total_vendors']} vendors")
                for tier, count in s["by_risk_tier"].items():
                    if count:
                        print(f"  {tier.upper()}: {count}")
                if s["high_or_critical_unreviewed"] > 0:
                    print(f"  ⚠  {s['high_or_critical_unreviewed']} HIGH/CRITICAL vendors not reviewed")
            return 0

        else:
            print("[squash vendor] Specify a subcommand: add | list | questionnaire | import-trust-package | summary")
            return 1


def _cmd_registry(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    """W179 — AI Asset Registry."""
    from squash.asset_registry import AssetRegistry

    db = Path(args.db) if getattr(args, "db", None) else None

    with AssetRegistry(db) as reg:
        cmd = getattr(args, "registry_command", None)

        if cmd == "add":
            aid = reg.register(
                model_id=args.model_id, model_path=args.model_path,
                environment=args.environment, owner=args.owner, team=args.team,
                risk_tier=args.risk_tier, notes=args.notes,
                is_shadow_ai=getattr(args, "shadow", False),
            )
            if not quiet:
                print(f"[squash registry] Registered '{args.model_id}' ID={aid}")
            return 0

        elif cmd == "sync":
            aid = reg.sync_from_attestation(Path(args.model_path))
            if not quiet:
                if aid:
                    print(f"[squash registry] Synced from {args.model_path} → ID={aid}")
                else:
                    print(f"[squash registry] No attestation found in {args.model_path}")
            return 0

        elif cmd == "list":
            assets = reg.list_assets(
                environment=getattr(args, "environment", None),
                risk_tier=getattr(args, "risk_tier", None),
                shadow_only=getattr(args, "shadow_only", False),
            )
            if getattr(args, "output_json", False):
                print(json.dumps([a.to_dict() for a in assets], indent=2))
            else:
                if not assets:
                    print("[squash registry] No assets registered.")
                for a in assets:
                    score = f"{a.compliance_score:.0f}%" if a.compliance_score else "N/A"
                    print(f"  [{a.environment.value:12s}] {a.model_id:30s} "
                          f"score={score:5s} viol={a.open_violations} cve={a.open_cves}")
            return 0

        elif cmd == "summary":
            s = reg.summary()
            if getattr(args, "output_json", False):
                print(json.dumps({
                    "total": s.total_assets,
                    "by_environment": s.by_environment,
                    "by_risk_tier": s.by_risk_tier,
                    "compliant": s.compliant, "non_compliant": s.non_compliant,
                    "unattested": s.unattested, "stale": s.stale,
                    "shadow_ai": s.shadow_ai_count, "violations": s.total_violations,
                    "cves": s.total_cves, "drift": s.drift_count,
                }, indent=2))
            else:
                print(s.to_text())
            return 0

        elif cmd == "export":
            output_str = reg.export(format=getattr(args, "format", "json"))
            output_path = getattr(args, "output", None)
            if output_path:
                Path(output_path).write_text(output_str)
                if not quiet:
                    print(f"[squash registry] Exported to {output_path}")
            else:
                print(output_str)
            return 0

        else:
            print("[squash registry] Specify a subcommand: add | sync | list | summary | export")
            return 1


def _cmd_data_lineage(args: argparse.Namespace, quiet: bool) -> int:
    """W180 — Training Data Lineage Certificate."""
    from squash.data_lineage import DataLineageTracer, PIIRiskLevel

    model_path = Path(args.model_path)
    datasets = [d.strip() for d in args.datasets.split(",")] if args.datasets else None
    config_path = Path(args.config_path) if args.config_path else None

    cert = DataLineageTracer.trace(
        model_path=model_path,
        config_path=config_path,
        model_id=args.model_id,
        datasets=datasets,
    )

    output_path = Path(args.output) if args.output else model_path / "data_lineage_certificate.json"
    cert.save(output_path)

    if args.format == "json":
        print(json.dumps(cert.to_dict(), indent=2))
    elif not quiet:
        print(cert.summary())
        print(f"\n[squash data-lineage] Certificate written to {output_path}")

    if args.fail_on_pii and cert.overall_risk.value in ("high", "critical"):
        print(f"[squash data-lineage] FAIL: PII risk is {cert.overall_risk.value}", file=sys.stderr)
        return 2
    if args.fail_on_license and cert.license_issues:
        print(f"[squash data-lineage] FAIL: {len(cert.license_issues)} license issue(s)", file=sys.stderr)
        return 2
    return 0


def _cmd_bias_audit(args: argparse.Namespace, quiet: bool) -> int:
    """W181 — Bias Audit."""
    from squash.bias_audit import BiasAuditor, FairnessVerdict

    predictions_path = Path(args.predictions_path)
    if not predictions_path.exists():
        print(f"[squash bias-audit] ERROR: predictions file not found: {predictions_path}", file=sys.stderr)
        return 1

    protected = [a.strip() for a in args.protected.split(",")]

    report = BiasAuditor.audit_from_csv(
        predictions_path=predictions_path,
        protected_attributes=protected,
        label_col=args.label_col,
        pred_col=args.pred_col,
        model_id=args.model_id,
        standard=args.standard,
    )

    if args.output:
        report.save(Path(args.output))

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif not quiet:
        print(report.summary())
        if args.output and not quiet:
            print(f"\n[squash bias-audit] Report written to {args.output}")

    if args.fail_on_fail and report.overall_verdict == FairnessVerdict.FAIL:
        return 2
    if args.fail_on_warn and report.overall_verdict in (FairnessVerdict.FAIL, FairnessVerdict.WARN):
        return 2
    return 0


def _cmd_diff(args: argparse.Namespace, quiet: bool) -> int:
    """Compare two squash attestation JSON files."""
    from squash.sbom_diff import diff_attestations

    before_path = Path(args.before)
    after_path = Path(getattr(args, "after"))

    try:
        delta = diff_attestations(before_path, after_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[squash diff] Error: {exc}", file=sys.stderr)
        return 1

    fmt = getattr(args, "format", "table")
    output_path = getattr(args, "output", None)

    if fmt == "json":
        text = json.dumps(delta.to_dict(), indent=2)
    elif fmt == "html":
        text = delta.to_html()
    elif fmt == "summary":
        text = delta.summary_line()
    else:
        text = delta.to_table()

    if output_path:
        Path(output_path).write_text(text)
        if not quiet:
            print(f"[squash diff] Written to {output_path}")
    else:
        print(text)

    if getattr(args, "fail_on_regression", False) and delta.is_regression:
        if not quiet:
            print("[squash diff] Regression detected — exiting 2", file=sys.stderr)
        return 2

    return 0


def _cmd_webhook(args: argparse.Namespace, quiet: bool) -> int:
    """Manage outbound webhook endpoints."""
    from squash.webhook_delivery import WebhookDelivery, WebhookEvent

    db_path = os.environ.get("SQUASH_WEBHOOK_DB", "squash_webhooks.db")
    wh = WebhookDelivery(db_path=db_path)
    cmd = getattr(args, "webhook_command", None)

    if cmd == "add":
        events_str = getattr(args, "events", None)
        if events_str:
            event_list = [WebhookEvent.from_str(e.strip()) for e in events_str.split(",")]
        else:
            event_list = WebhookEvent.all()
        secret = getattr(args, "secret", None)
        ep = wh.register(url=args.url, events=event_list, secret=secret)
        if not quiet:
            print(f"[squash webhook] Registered endpoint {ep.id}")
            print(f"  URL:    {ep.url}")
            print(f"  Events: {', '.join(e.value for e in ep.events)}")
            print(f"  Secret: {ep.secret}")
        return 0

    elif cmd == "list":
        show_all = getattr(args, "show_all", False)
        endpoints = wh.list_endpoints(active_only=not show_all)
        if not endpoints:
            print("[squash webhook] No endpoints registered.")
            return 0
        for ep in endpoints:
            status = "active" if ep.active else "inactive"
            print(f"  {ep.id}  [{status}]  {ep.url}")
            print(f"    events: {', '.join(e.value for e in ep.events)}")
            print(f"    deliveries: {ep.delivery_count}  last_status: {ep.last_status_code}")
        return 0

    elif cmd == "test":
        result = wh.test_endpoint(args.url)
        if result.success:
            print(f"[squash webhook] Test delivery succeeded ({result.status_code}) in {result.duration_ms:.0f}ms")
            return 0
        else:
            print(f"[squash webhook] Test delivery failed: {result.error or result.status_code}", file=sys.stderr)
            return 1

    elif cmd == "remove":
        removed = wh.remove(args.id)
        if removed:
            print(f"[squash webhook] Endpoint {args.id} deactivated.")
        else:
            print(f"[squash webhook] Endpoint {args.id} not found.", file=sys.stderr)
            return 1
        return 0

    else:
        print("squash webhook: specify a subcommand — add | list | test | remove")
        return 1


def _cmd_telemetry(args: argparse.Namespace, quiet: bool) -> int:
    """Configure and test OpenTelemetry integration."""
    from squash.telemetry import SquashTelemetry

    cmd = getattr(args, "telemetry_command", None)

    if cmd == "status":
        tel = SquashTelemetry.from_env()
        status = tel.status()
        print("[squash telemetry] Status")
        print(f"  Enabled:            {status.enabled}")
        print(f"  OTel available:     {status.otel_available}")
        print(f"  Exporter available: {status.exporter_available}")
        print(f"  Endpoint:           {status.endpoint or '(not configured)'}")
        print(f"  Service name:       {status.service_name}")
        print(f"  Spans emitted:      {status.spans_emitted}")
        if status.last_error:
            print(f"  Last error:         {status.last_error}")
        if not status.otel_available:
            print("\n  Install OTel: pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc")
        return 0

    elif cmd == "test":
        endpoint = getattr(args, "endpoint", None)
        http_endpoint = getattr(args, "http_endpoint", None)
        tel = SquashTelemetry(
            endpoint=endpoint or os.environ.get("SQUASH_OTEL_ENDPOINT"),
            http_endpoint=http_endpoint or os.environ.get("SQUASH_OTEL_HTTP_ENDPOINT"),
        )
        result = tel.test_connection()
        if result.emitted:
            print(f"[squash telemetry] Test span emitted — trace_id={result.trace_id}")
            return 0
        elif not result.otel_available:
            print("[squash telemetry] opentelemetry-api not installed. Install with:")
            print("  pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc")
            return 1
        else:
            print(f"[squash telemetry] Test span not emitted: {result.error or 'no endpoint configured'}")
            return 1

    elif cmd == "configure":
        endpoint = getattr(args, "endpoint", None)
        service = getattr(args, "service", "squash")
        print("[squash telemetry] Set these environment variables to enable telemetry:")
        if endpoint:
            print(f"  export SQUASH_OTEL_ENDPOINT={endpoint}")
        else:
            print("  export SQUASH_OTEL_ENDPOINT=http://localhost:4317")
        print(f"  export SQUASH_OTEL_SERVICE_NAME={service}")
        print("  export SQUASH_OTEL_ENABLED=true")
        return 0

    else:
        print("squash telemetry: specify a subcommand — status | test | configure")
        return 1


def _cmd_gitops(args: argparse.Namespace, quiet: bool) -> int:
    """ArgoCD / Flux GitOps enforcement gate."""
    from squash.integrations.gitops import (
        check_manifest_compliance,
        generate_webhook_manifest,
        annotate_deployment_command,
    )

    cmd = getattr(args, "gitops_command", None)

    if cmd == "check":
        manifest_path = Path(args.manifest_path)
        result = check_manifest_compliance(
            manifest_path=manifest_path,
            min_score=getattr(args, "min_score", 80.0),
            require_attestation=getattr(args, "require_attestation", True),
        )
        if getattr(args, "output_json", False):
            print(json.dumps(result.to_dict(), indent=2))
        else:
            icon = "✓" if result.passed else "✗"
            print(f"[squash gitops] {icon} {result.resource_kind}/{result.resource_name}")
            print(f"  Passed:     {result.passed}")
            print(f"  Reason:     {result.reason}")
            if result.attestation_id:
                print(f"  Attestation: {result.attestation_id}")
            if result.compliance_score is not None:
                print(f"  Score:      {result.compliance_score:.1f}")
        return 0 if result.passed else 2

    elif cmd == "webhook-manifest":
        yaml_str = generate_webhook_manifest(
            webhook_url=args.url,
            namespace=getattr(args, "namespace", "squash-system"),
            failure_policy=getattr(args, "failure_policy", "Fail"),
        )
        output = getattr(args, "output", None)
        if output:
            Path(output).write_text(yaml_str)
            print(f"[squash gitops] Written to {output}")
        else:
            print(yaml_str)
        return 0

    elif cmd == "annotate":
        cmd_str = annotate_deployment_command(
            deployment_name=args.deployment,
            attestation_id=args.attestation_id,
            compliance_score=args.compliance_score,
            policy=getattr(args, "policy", "eu-ai-act"),
            passed=getattr(args, "passed", True),
        )
        print(cmd_str)
        return 0

    else:
        print("squash gitops: specify a subcommand — check | webhook-manifest | annotate")
        return 1


def _cmd_board_report(args: argparse.Namespace, quiet: bool) -> int:
    """W174 — Board report generation."""
    from squash.board_report import BoardReportGenerator

    model_paths = None
    models_dir = Path(args.models_dir) if args.models_dir else None
    if args.model_path:
        model_paths = [Path(args.model_path)]

    report = BoardReportGenerator.generate(
        models_dir=models_dir,
        model_paths=model_paths,
        quarter=args.quarter,
    )

    if args.output_json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    if not quiet:
        print(report.executive_summary())

    output_dir = Path(args.output_dir) if args.output_dir else Path(f"board-report-{report.quarter}")
    written = report.save(output_dir)

    if not quiet:
        print(f"\n[squash board-report] Report written to {output_dir}/")
        for f in written:
            print(f"  {f}")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    quiet: bool = getattr(args, "quiet", False)

    if not quiet:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s %(name)s: %(message)s",
        )

    if args.command == "policies":
        sys.exit(_cmd_policies(args, quiet))
    elif args.command == "scan":
        sys.exit(_cmd_scan(args, quiet))
    elif args.command == "diff":
        sys.exit(_cmd_diff(args, quiet))
    elif args.command == "verify":
        sys.exit(_cmd_verify(args, quiet))
    elif args.command == "keygen":
        sys.exit(_cmd_keygen(args, quiet))
    elif args.command == "verify-local":
        sys.exit(_cmd_verify_local(args, quiet))
    elif args.command == "pack-offline":
        sys.exit(_cmd_pack_offline(args, quiet))
    elif args.command == "report":
        sys.exit(_cmd_report(args, quiet))
    elif args.command == "vex":
        sys.exit(_cmd_vex(args, quiet))
    elif args.command == "attest-composed":
        sys.exit(_cmd_attest_composed(args, quiet))
    elif args.command == "push":
        sys.exit(_cmd_push(args, quiet))
    elif args.command == "attest":
        sys.exit(_cmd_attest(args, quiet))
    elif args.command == "ntia-check":
        sys.exit(_cmd_ntia_check(args, quiet))
    elif args.command == "slsa-attest":
        sys.exit(_cmd_slsa_attest(args, quiet))
    elif args.command == "merge":
        sys.exit(_cmd_merge(args, quiet))
    elif args.command == "risk-assess":
        sys.exit(_cmd_risk_assess(args, quiet))
    elif args.command == "monitor":
        sys.exit(_cmd_monitor(args, quiet))
    elif args.command == "ci-run":
        sys.exit(_cmd_ci_run(args, quiet))
    elif args.command == "webhook":
        sys.exit(_cmd_webhook(args, quiet))
    elif args.command == "shadow-ai":
        sys.exit(_cmd_shadow_ai(args, quiet))
    elif args.command == "vex-publish":
        sys.exit(_cmd_vex_publish(args, quiet))
    elif args.command == "attest-mlflow":
        sys.exit(_cmd_attest_mlflow(args, quiet))
    elif args.command == "attest-wandb":
        sys.exit(_cmd_attest_wandb(args, quiet))
    elif args.command == "attest-huggingface":
        sys.exit(_cmd_attest_huggingface(args, quiet))
    elif args.command == "attest-langchain":
        sys.exit(_cmd_attest_langchain(args, quiet))
    elif args.command == "attest-mcp":
        sys.exit(_cmd_attest_mcp(args, quiet))
    elif args.command == "audit":
        sys.exit(_cmd_audit(args, quiet))
    elif args.command == "scan-rag":
        sys.exit(_cmd_scan_rag(args, quiet))
    elif args.command == "lineage":
        sys.exit(_cmd_lineage(args, quiet))
    elif args.command == "drift-check":
        sys.exit(_cmd_drift_check(args, quiet))
    elif args.command == "remediate":
        sys.exit(_cmd_remediate(args, quiet))
    elif args.command == "evaluate":
        sys.exit(_cmd_evaluate(args, quiet))
    elif args.command == "edge-scan":
        sys.exit(_cmd_edge_scan(args, quiet))
    elif args.command == "chat":
        sys.exit(_cmd_chat(args, quiet))
    elif args.command == "model-card":
        sys.exit(_cmd_model_card(args, quiet))
    elif args.command == "cloud-status":
        sys.exit(_cmd_cloud_status(args, quiet))
    elif args.command == "cloud-report":
        sys.exit(_cmd_cloud_report(args, quiet))
    elif args.command == "cloud-export":
        sys.exit(_cmd_cloud_export(args, quiet))
    elif args.command == "cloud-attest":
        sys.exit(_cmd_cloud_attest(args, quiet))
    elif args.command == "cloud-vex":
        sys.exit(_cmd_cloud_vex(args, quiet))
    elif args.command == "cloud-risk":
        sys.exit(_cmd_cloud_risk(args, quiet))
    elif args.command == "cloud-remediate":
        sys.exit(_cmd_cloud_remediate(args, quiet))
    elif args.command == "annex-iv":
        sys.exit(_cmd_annex_iv(args, quiet))
    elif args.command == "demo":
        sys.exit(_cmd_demo(args, quiet))
    elif args.command == "init":
        sys.exit(_cmd_init(args, quiet))
    elif args.command == "watch":
        sys.exit(_cmd_watch(args, quiet))
    elif args.command == "install-hook":
        sys.exit(_cmd_install_hook(args, quiet))
    elif args.command == "annual-review":
        sys.exit(_cmd_annual_review(args, quiet))
    elif args.command == "publish":
        sys.exit(_cmd_publish(args, quiet))
    elif args.command == "lookup":
        sys.exit(_cmd_lookup(args, quiet))
    elif args.command == "verify-entry":
        sys.exit(_cmd_verify_entry(args, quiet))
    elif args.command == "dashboard":
        sys.exit(_cmd_dashboard(args, quiet))
    elif args.command == "regulatory":
        sys.exit(_cmd_regulatory(args, quiet))
    elif args.command == "due-diligence":
        sys.exit(_cmd_due_diligence(args, quiet))
    elif args.command == "vendor":
        sys.exit(_cmd_vendor(args, quiet))
    elif args.command == "registry":
        sys.exit(_cmd_registry(args, quiet))
    elif args.command == "data-lineage":
        sys.exit(_cmd_data_lineage(args, quiet))
    elif args.command == "bias-audit":
        sys.exit(_cmd_bias_audit(args, quiet))
    elif args.command == "iso42001":
        sys.exit(_cmd_iso42001(args, quiet))
    elif args.command == "trust-package":
        sys.exit(_cmd_trust_package(args, quiet))
    elif args.command == "verify-trust-package":
        sys.exit(_cmd_verify_trust_package(args, quiet))
    elif args.command == "agent-audit":
        sys.exit(_cmd_agent_audit(args, quiet))
    elif args.command == "incident":
        sys.exit(_cmd_incident(args, quiet))
    elif args.command == "board-report":
        sys.exit(_cmd_board_report(args, quiet))
    elif args.command == "diff":
        sys.exit(_cmd_diff(args, quiet))
    elif args.command == "webhook":
        sys.exit(_cmd_webhook(args, quiet))
    elif args.command == "telemetry":
        sys.exit(_cmd_telemetry(args, quiet))
    elif args.command == "gitops":
        sys.exit(_cmd_gitops(args, quiet))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
