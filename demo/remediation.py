"""demo/remediation.py — Detailed remediation engine for the demo.

Translates squash signals (missing SPDX, no model card, oversized
weights, undisclosed training data, …) into actionable, regulator-aware
remediation entries. Each entry includes:

    - ``code``           — stable machine-readable ID
    - ``severity``       — info / warn / error / critical
    - ``title``          — one-line plain English
    - ``why``            — the regulatory or technical rationale
    - ``how_to_fix``     — concrete 3-line action plan
    - ``framework``      — EU AI Act / NIST AI RMF / ISO 42001 / OWASP LLM
    - ``article``        — exact article or control reference
    - ``citation_url``   — link to the live source (regulator or NIST)

Sources:
    - EU AI Act (Regulation (EU) 2024/1689) — eur-lex.europa.eu
    - NIST AI Risk Management Framework 1.0 — nist.gov/itl/ai-risk-management-framework
    - ISO/IEC 42001:2023 — iso.org/standard/81230.html
    - OWASP LLM Top 10 (2025) — owasp.org/www-project-top-10-for-large-language-model-applications
    - SLSA — slsa.dev/spec/v1.0/levels

Make it Konjo.
"""

from __future__ import annotations

from typing import Any


CATALOG: dict[str, dict[str, Any]] = {
    "no-spdx": {
        "severity": "warn",
        "title": "No SPDX SBOM emitted alongside attestation",
        "why": (
            "EU AI Act Article 11 requires technical documentation that "
            "accompanies a high-risk AI system, and Annex IV §2(c) "
            "explicitly calls for a description of components and their "
            "provenance — the SBOM is the canonical machine-readable form."
        ),
        "how_to_fix": [
            "Add `cyclonedx-bom` to your project (pip install cyclonedx-bom).",
            "Re-run `squash attest --emit-spdx --emit-cyclonedx ./model-dir`.",
            "Verify with `squash diff <baseline.json> <new.json>` before each release.",
        ],
        "framework": "EU AI Act",
        "article": "Annex IV §2(c) · Article 11",
        "citation_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
    },
    "no-model-card": {
        "severity": "warn",
        "title": "No model card — capabilities, limits, and intended use undeclared",
        "why": (
            "Article 13 of the EU AI Act mandates 'Transparency and "
            "provision of information to deployers'. Without a model "
            "card, downstream operators cannot perform their fundamental-"
            "rights impact assessment (Article 27) or meet their "
            "Article 26 obligations as a deployer."
        ),
        "how_to_fix": [
            "Run `squash model-card --validate ./model-dir` to scaffold a HF-schema-compliant card.",
            "Fill in: intended_use, limitations, training_data summary, evaluation_results.",
            "Push to the Hub or attach to your release: `squash model-card --push-to-hub`.",
        ],
        "framework": "EU AI Act",
        "article": "Article 13 · Article 26",
        "citation_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
    },
    "missing-data-governance": {
        "severity": "error",
        "title": "Training-data lineage is undisclosed",
        "why": (
            "Article 10 of the EU AI Act demands data and data governance "
            "for high-risk systems — provenance, examination for biases, "
            "and documentation of relevant design choices. NIST AI RMF "
            "GOVERN 1.4 + MAP 2.3 reinforce the same: 'AI actors document "
            "the data used for training, validation, and testing.'"
        ),
        "how_to_fix": [
            "Run `squash lineage trace ./model-dir` to materialise the training-data certificate.",
            "Cross-reference the discovered datasets against the Hugging Face Datasets index.",
            "If proprietary, attach a signed `data_governance.json` with `squash chain-attest`.",
        ],
        "framework": "EU AI Act + NIST AI RMF",
        "article": "Article 10 · NIST AI RMF GOVERN 1.4 / MAP 2.3",
        "citation_url": "https://www.nist.gov/itl/ai-risk-management-framework",
    },
    "no-bias-audit": {
        "severity": "error",
        "title": "No bias / fairness audit on file",
        "why": (
            "EU AI Act Article 10(2)(f-g) requires examination of "
            "possible biases and appropriate measures. NYC Local Law 144 "
            "additionally requires an independent bias audit for AEDTs "
            "before commercial deployment. ECOA and the EEOC 4/5ths rule "
            "are also load-bearing in the US lending and HR contexts."
        ),
        "how_to_fix": [
            "Prepare a labelled outcome dataset (pred + ground truth + protected attributes).",
            "Run `squash bias-audit --csv predictions.csv --protected race,gender,age`.",
            "Fix any DPD/DIR/EOD/PED ratios that fall outside the 4/5ths tolerance.",
        ],
        "framework": "EU AI Act + NYC Local Law 144 + ECOA",
        "article": "Article 10(2)(f-g) · NYC LL 144 · ECOA Reg B",
        "citation_url": "https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page",
    },
    "large-binary": {
        "severity": "info",
        "title": "Single-file weight blob exceeds 4 GiB — chunked attestation recommended",
        "why": (
            "Single-file weight blobs over 4 GiB are uncomfortable for "
            "supply-chain tooling: GitHub LFS hits its 5 GB ceiling, "
            "OCI registries require multi-part uploads, and SLSA "
            "verifiers stream-hash incrementally. Chunking to "
            "≤ 2 GiB shards keeps the BOM portable."
        ),
        "how_to_fix": [
            "Re-export weights as safetensors with `max_shard_size='2GB'`.",
            "Re-attest with `squash attest`; the BOM picks up the shard digests automatically.",
            "Verify shard order is stable across builds (Phase G reproducibility test).",
        ],
        "framework": "SLSA",
        "article": "SLSA v1.0 Build L3 — provenance.subject",
        "citation_url": "https://slsa.dev/spec/v1.0/levels",
    },
    "unknown-family": {
        "severity": "warn",
        "title": "Model family not recognised by the genealogy registry",
        "why": (
            "When the model family is unknown to squash.genealogy, the "
            "deployed weights cannot be traced back to a known training "
            "data corpus. EU AI Act Article 10 (data governance) and "
            "Article 11 (technical documentation) both implicitly assume "
            "the deployer can answer 'what was this trained on?'."
        ),
        "how_to_fix": [
            "Open a PR adding the family to `squash/genealogy.py::_BASE_MODEL_REGISTRY`.",
            "Include the published training corpus, copyright_risk, and known restrictions.",
            "Re-run `squash genealogy build ./model-dir` to confirm the chain resolves.",
        ],
        "framework": "EU AI Act",
        "article": "Article 10 · Article 11",
        "citation_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
    },
    "no-signature": {
        "severity": "error",
        "title": "Attestation not cryptographically signed",
        "why": (
            "Without a signature, the attestation provides no integrity "
            "guarantee — any process with write access can mutate the "
            "JSON file. NIST AI RMF GOVERN 1.7 requires 'Mechanisms to "
            "preserve the integrity of AI system documentation', and "
            "EU AI Act Article 12 demands automatic logging that is "
            "tamper-evident."
        ),
        "how_to_fix": [
            "Generate an Ed25519 keypair: `squash keygen --name release-2026`.",
            "Re-attest with `--sign --offline` (or use Sigstore keyless in CI).",
            "Verify on consumer side with `squash verify ./model-dir`.",
        ],
        "framework": "EU AI Act + NIST AI RMF",
        "article": "Article 12 · NIST AI RMF GOVERN 1.7",
        "citation_url": "https://www.nist.gov/itl/ai-risk-management-framework",
    },
    "no-runtime-monitor": {
        "severity": "warn",
        "title": "No runtime hallucination / drift monitor wired",
        "why": (
            "Article 9 (risk management) and Article 72 (post-market "
            "monitoring) of the EU AI Act require ongoing observation "
            "of deployed AI systems. Static attestation at release is "
            "necessary but not sufficient — drift, hallucination rate, "
            "and behavioural changes must be tracked in production."
        ),
        "how_to_fix": [
            "Wire `squash hallucination-monitor` into your serving layer (one-line decorator).",
            "Set domain-aware thresholds (legal: 2%, medical: 2%, financial: 3%, code: 5%).",
            "Forward breach events to your incident pipeline (PagerDuty / Slack / JIRA).",
        ],
        "framework": "EU AI Act",
        "article": "Article 9 · Article 72",
        "citation_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
    },
    "no-prompt-injection-test": {
        "severity": "warn",
        "title": "No OWASP LLM01 (prompt injection) test surface",
        "why": (
            "OWASP LLM Top 10 — LLM01:2025 (Prompt Injection) is the "
            "single most-exploited LLM vulnerability class today. Without "
            "a documented red-team surface, deployers cannot demonstrate "
            "the 'appropriate cybersecurity measures' required by EU AI "
            "Act Article 15(5)."
        ),
        "how_to_fix": [
            "Run `squash audit ./model-dir --owasp-llm-top10` for the baseline scan.",
            "Add the OWASP-published indirect-injection probes to your eval harness.",
            "Re-run on every release; surface the rate in your model card.",
        ],
        "framework": "OWASP LLM Top 10 + EU AI Act",
        "article": "LLM01:2025 · Article 15(5)",
        "citation_url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "no-iso-42001-mapping": {
        "severity": "info",
        "title": "ISO/IEC 42001 readiness not yet mapped",
        "why": (
            "ISO/IEC 42001:2023 is the primary management-system standard "
            "for AI. Procurement teams in the EU and Canada increasingly "
            "require evidence of 42001 alignment as a prerequisite to "
            "vendor onboarding (especially where an AI Act FRIA is also "
            "in scope)."
        ),
        "how_to_fix": [
            "Run `squash iso-42001 readiness ./model-dir` for the 38-control gap analysis.",
            "Tackle the top three RED controls first (typically AI.4.x lifecycle).",
            "Re-export the readiness matrix on each quarterly review.",
        ],
        "framework": "ISO/IEC 42001",
        "article": "ISO/IEC 42001:2023 §7.5 · §8.2",
        "citation_url": "https://www.iso.org/standard/81230.html",
    },
}


def _entry(code: str) -> dict[str, Any] | None:
    e = CATALOG.get(code)
    if not e:
        return None
    return {"code": code, **e}


def build_findings_for_model(model, scan_result) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], int
]:
    """Inspect a freshly-scanned Ollama model and emit findings + remediations.

    Scoring rubric: critical = -25, error = -12, warn = -5, info = -1.
    Score floors at 0; ceiling 100.
    """
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []

    if not scan_result.spdx_emitted:
        findings.append({"code": "no-spdx", "severity": "warn",
                         "title": CATALOG["no-spdx"]["title"]})
        remediations.append(_entry("no-spdx"))

    findings.append({"code": "no-model-card", "severity": "warn",
                     "title": CATALOG["no-model-card"]["title"]})
    remediations.append(_entry("no-model-card"))

    if model.family == "unknown":
        findings.append({"code": "unknown-family", "severity": "warn",
                         "title": CATALOG["unknown-family"]["title"]})
        remediations.append(_entry("unknown-family"))
    elif model.family in ("mistral", "mixtral"):
        findings.append({"code": "missing-data-governance", "severity": "error",
                         "title": CATALOG["missing-data-governance"]["title"]})
        remediations.append(_entry("missing-data-governance"))

    if model.size_bytes >= 4 * 1024**3:
        findings.append({"code": "large-binary", "severity": "info",
                         "title": CATALOG["large-binary"]["title"]})
        remediations.append(_entry("large-binary"))

    findings.append({"code": "no-signature", "severity": "error",
                     "title": CATALOG["no-signature"]["title"]})
    remediations.append(_entry("no-signature"))

    findings.append({"code": "no-bias-audit", "severity": "error",
                     "title": CATALOG["no-bias-audit"]["title"]})
    remediations.append(_entry("no-bias-audit"))

    findings.append({"code": "no-runtime-monitor", "severity": "warn",
                     "title": CATALOG["no-runtime-monitor"]["title"]})
    remediations.append(_entry("no-runtime-monitor"))

    findings.append({"code": "no-prompt-injection-test", "severity": "warn",
                     "title": CATALOG["no-prompt-injection-test"]["title"]})
    remediations.append(_entry("no-prompt-injection-test"))

    findings.append({"code": "no-iso-42001-mapping", "severity": "info",
                     "title": CATALOG["no-iso-42001-mapping"]["title"]})
    remediations.append(_entry("no-iso-42001-mapping"))

    sev_weights = {"critical": -25, "error": -12, "warn": -5, "info": -1}
    score = 100
    for f in findings:
        score += sev_weights.get(f["severity"], 0)
    score = max(0, min(100, score))

    remediations = [r for r in remediations if r is not None]
    return findings, remediations, score


def all_codes() -> list[str]:
    return sorted(CATALOG.keys())
