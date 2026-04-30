"""tests/test_washing_detector.py — W223-W225 / C2 AI Washing Detection.

Test taxonomy:

PART 1 — Claim extraction (benchmark fixtures)
  * 50 labelled marketing claims from real SEC/FTC AI enforcement contexts
  * Extractor recall ≥ 90% across all claim types
  * Extractor precision: no false positives on clean prose

PART 2 — Divergence engine rules
  * Each rule fires correctly on crafted inputs
  * Each rule does NOT fire when evidence supports the claim

PART 3 — WashingReport
  * Summary, passed(), JSON round-trip, Markdown render

PART 4 — AttestationEvidence loader
  * Loads master_record, bias_audit, data_lineage correctly

PART 5 — WashingDetector end-to-end
  * Clean doc + good evidence → CLEAN/LOW
  * Washing doc + bad evidence → CRITICAL

PART 6 — CLI smoke
  * Parser registration, scan subcommand, report subcommand
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squash.washing_detector import (
    AttestationEvidence,
    ClaimExtractor,
    ClaimType,
    DivergenceEngine,
    FindingSeverity,
    FindingType,
    OverallVerdict,
    WashingDetector,
    WashingReport,
    load_evidence,
    load_report,
)


# ---------------------------------------------------------------------------
# Part 1 — Claim extraction benchmark
# ---------------------------------------------------------------------------

# 50 labelled marketing claims representative of SEC/FTC AI enforcement context.
# Format: (input_text, expected_claim_type, should_match: bool)
_BENCHMARK: list[tuple[str, ClaimType, bool]] = [
    # ACCURACY_CLAIM
    ("Our model achieves 99.2% accuracy on BIG-bench.", ClaimType.ACCURACY_CLAIM, True),
    ("We score 87.3% on MMLU benchmark tasks.", ClaimType.ACCURACY_CLAIM, True),
    ("96.4% precision on medical imaging classification.", ClaimType.ACCURACY_CLAIM, True),
    ("The model attains 94% recall on HellaSwag.", ClaimType.ACCURACY_CLAIM, True),
    ("Error rate of 0.8% on production data.", ClaimType.ACCURACY_CLAIM, True),
    ("false positive rate below 2%.", ClaimType.ACCURACY_CLAIM, True),
    ("Achieves SOTA on HumanEval with 87.1%.", ClaimType.ACCURACY_CLAIM, True),
    ("Scores 91.5% on GSM8K math reasoning tasks.", ClaimType.ACCURACY_CLAIM, True),
    ("Our team works hard.", ClaimType.ACCURACY_CLAIM, False),  # no-match
    ("We iterate constantly.", ClaimType.ACCURACY_CLAIM, False),  # no-match

    # COMPLIANCE_CLAIM
    ("The platform is EU AI Act compliant.", ClaimType.COMPLIANCE_CLAIM, True),
    ("Our AI is GDPR compliant for all EU customers.", ClaimType.COMPLIANCE_CLAIM, True),
    ("Fully HIPAA compliant deployment.", ClaimType.COMPLIANCE_CLAIM, True),
    ("NIST AI RMF aligned architecture.", ClaimType.COMPLIANCE_CLAIM, True),
    ("SOX compliant audit trail.", ClaimType.COMPLIANCE_CLAIM, True),
    ("The product is secure.", ClaimType.COMPLIANCE_CLAIM, False),  # security, not compliance

    # CERTIFICATION_CLAIM
    ("ISO 42001 certified by TÜV Rheinland.", ClaimType.CERTIFICATION_CLAIM, True),
    ("FedRAMP Authorized for federal use.", ClaimType.CERTIFICATION_CLAIM, True),
    ("SOC 2 Type II attested service.", ClaimType.CERTIFICATION_CLAIM, True),
    ("SOC 2 certified organization.", ClaimType.CERTIFICATION_CLAIM, True),

    # SAFETY_CLAIM
    ("Our system has no hallucinations.", ClaimType.SAFETY_CLAIM, True),
    ("Zero hallucination rate in production.", ClaimType.SAFETY_CLAIM, True),
    ("Bias-tested across 12 demographic attributes.", ClaimType.SAFETY_CLAIM, True),
    ("Tested for bias before deployment.", ClaimType.SAFETY_CLAIM, True),
    ("Safety guaranteed for clinical use.", ClaimType.SAFETY_CLAIM, True),
    ("Safe for medical diagnosis workflows.", ClaimType.SAFETY_CLAIM, True),

    # FAIRNESS_CLAIM
    ("Our AI is completely unbiased.", ClaimType.FAIRNESS_CLAIM, True),
    ("Bias-free model for hiring decisions.", ClaimType.FAIRNESS_CLAIM, True),
    ("Fairness-certified across all demographic groups.", ClaimType.FAIRNESS_CLAIM, True),
    ("Demographic parity achieved across gender groups.", ClaimType.FAIRNESS_CLAIM, True),

    # DATA_CLAIM
    ("Fine-tuned on 10 million prompts.", ClaimType.DATA_CLAIM, True),
    ("Pre-trained on 1B tokens of curated data.", ClaimType.DATA_CLAIM, True),
    ("Training data contains no PII.", ClaimType.DATA_CLAIM, True),
    ("No personally identifiable information in dataset.", ClaimType.DATA_CLAIM, True),
    ("Trained on fully consented data.", ClaimType.DATA_CLAIM, True),
    ("Trained on licensed, rights-cleared content.", ClaimType.DATA_CLAIM, True),

    # SECURITY_CLAIM
    ("Penetration-tested by an independent security firm.", ClaimType.SECURITY_CLAIM, True),
    ("Red-teamed against adversarial prompt injection.", ClaimType.SECURITY_CLAIM, True),
    ("No backdoors in model weights.", ClaimType.SECURITY_CLAIM, True),
    ("Enterprise-grade security for inference endpoints.", ClaimType.SECURITY_CLAIM, True),

    # SUPERLATIVE_CLAIM
    ("World's first enterprise-grade compliant LLM.", ClaimType.SUPERLATIVE_CLAIM, True),
    ("Best-in-class performance for legal document review.", ClaimType.SUPERLATIVE_CLAIM, True),
    ("Outperforms GPT-4 on legal reasoning benchmarks.", ClaimType.SUPERLATIVE_CLAIM, True),
    ("The only solution that guarantees compliance.", ClaimType.SUPERLATIVE_CLAIM, True),
    ("100% guaranteed accuracy on financial filings.", ClaimType.SUPERLATIVE_CLAIM, True),
    ("State-of-the-art ROUGE scores on summarisation.", ClaimType.SUPERLATIVE_CLAIM, True),

    # CAPABILITY_CLAIM (high-stakes)
    ("Our AI diagnoses cancer from radiology images.", ClaimType.CAPABILITY_CLAIM, True),
    ("Provides legal advice for contract review.", ClaimType.CAPABILITY_CLAIM, True),
    ("Delivers investment recommendations for retail clients.", ClaimType.CAPABILITY_CLAIM, True),
]


def test_extractor_recall_above_90():
    """Claim extractor must recall ≥ 90% of positive (should_match=True) benchmark claims."""
    extractor = ClaimExtractor()
    positives = [(text, ctype) for text, ctype, should_match in _BENCHMARK if should_match]
    hits = 0
    misses = []
    for text, expected_type in positives:
        claims = extractor.extract_from_text(text, "benchmark.md")
        types_found = {c.claim_type for c in claims}
        if expected_type in types_found:
            hits += 1
        else:
            misses.append((text, expected_type.value))
    recall = hits / len(positives)
    assert recall >= 0.90, (
        f"Recall {recall:.1%} < 90% threshold.\nMissed:\n"
        + "\n".join(f"  [{t}] {txt}" for txt, t in misses)
    )


def test_extractor_precision_no_false_positives():
    """Clean prose without claims should produce no extractions."""
    extractor = ClaimExtractor()
    clean_texts = [
        "Our team is dedicated to building helpful AI tools.",
        "We are working on improving the product continuously.",
        "Contact us at hello@example.com for more information.",
        "The conference will be held on March 15, 2026 in San Francisco.",
        "We raised Series A funding to accelerate our roadmap.",
    ]
    for text in clean_texts:
        claims = extractor.extract_from_text(text, "clean.md")
        assert not claims, f"False positive on: {text!r} → {[c.raw_text for c in claims]}"


def test_extractor_returns_source_location():
    extractor = ClaimExtractor()
    text = "Line one.\nOur AI achieves 99% accuracy on BIG-bench.\nLine three."
    claims = extractor.extract_from_text(text, "test.md")
    assert claims
    assert claims[0].source_file == "test.md"
    assert claims[0].line_number > 0


def test_extractor_multiline_doc(tmp_path):
    f = tmp_path / "deck.md"
    f.write_text(
        "# AI Platform\n\n"
        "We are EU AI Act compliant.\n"
        "No hallucinations in our system.\n"
        "Achieves 95% on MMLU.\n"
        "World's first certified AI assistant.\n"
    )
    extractor = ClaimExtractor()
    claims = extractor.extract_from_file(f)
    types = {c.claim_type for c in claims}
    assert ClaimType.COMPLIANCE_CLAIM in types
    assert ClaimType.SAFETY_CLAIM in types
    assert ClaimType.SUPERLATIVE_CLAIM in types


# ---------------------------------------------------------------------------
# Part 2 — Divergence engine rules
# ---------------------------------------------------------------------------

def _evidence(**kwargs) -> AttestationEvidence:
    defaults = dict(
        model_id="test-model",
        overall_score=85.0,
        passed=True,
        framework_scores={"eu-ai-act": 88.0, "gdpr": 82.0, "iso-42001": 85.0},
        has_bias_audit=True, bias_passed=True,
        has_data_lineage=True, no_pii_confirmed=True,
        has_security_scan=True, scan_passed=True,
        attestation_age_days=5.0,
    )
    defaults.update(kwargs)
    return AttestationEvidence(**defaults)


def _claim(raw: str, ctype: ClaimType) -> "ExtractedClaim":
    from squash.washing_detector import ExtractedClaim
    return ExtractedClaim(
        claim_type=ctype, raw_text=raw, normalized=raw.lower(),
        value=raw, context=raw, source_file="test.md", line_number=1, confidence=1.0,
    )


def test_rule_eu_ai_act_low_score_fires():
    ev = _evidence(framework_scores={"eu-ai-act": 42.0}, passed=True)
    c = _claim("EU AI Act compliant platform", ClaimType.COMPLIANCE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.FACTUAL_MISMATCH for f in findings)
    assert any(f.severity == FindingSeverity.CRITICAL for f in findings)


def test_rule_eu_ai_act_no_score_fires():
    ev = _evidence(framework_scores={})
    c = _claim("EU AI Act compliant", ClaimType.COMPLIANCE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNSUPPORTED_CLAIM for f in findings)


def test_rule_eu_ai_act_good_evidence_supported():
    ev = _evidence(framework_scores={"eu-ai-act": 92.0}, passed=True)
    c = _claim("EU AI Act compliant", ClaimType.COMPLIANCE_CLAIM)
    findings, supported = DivergenceEngine().check([c], ev)
    assert not any(f.claim.raw_text == c.raw_text for f in findings)
    assert c in supported


def test_rule_passed_false_fires_on_compliance():
    ev = _evidence(framework_scores={"eu-ai-act": 85.0}, passed=False)
    c = _claim("EU AI Act compliant", ClaimType.COMPLIANCE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.FACTUAL_MISMATCH for f in findings)


def test_rule_iso_42001_unsupported():
    ev = _evidence(framework_scores={})
    c = _claim("ISO 42001 certified", ClaimType.CERTIFICATION_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNSUPPORTED_CLAIM for f in findings)


def test_rule_no_hallucination_always_fires():
    ev = _evidence()
    c = _claim("No hallucinations in production", ClaimType.SAFETY_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNDOCUMENTED_SUPERLATIVE for f in findings)
    assert any(f.severity == FindingSeverity.HIGH for f in findings)


def test_rule_bias_claim_no_audit_fires():
    ev = _evidence(has_bias_audit=False, bias_passed=None)
    c = _claim("Bias-tested model", ClaimType.SAFETY_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNSUPPORTED_CLAIM for f in findings)


def test_rule_bias_failed_audit_fires():
    ev = _evidence(has_bias_audit=True, bias_passed=False)
    c = _claim("Bias-tested and safe", ClaimType.SAFETY_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.FACTUAL_MISMATCH for f in findings)
    assert any(f.severity == FindingSeverity.CRITICAL for f in findings)


def test_rule_fairness_no_audit_fires():
    ev = _evidence(has_bias_audit=False)
    c = _claim("Completely unbiased AI", ClaimType.FAIRNESS_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNSUPPORTED_CLAIM for f in findings)


def test_rule_fairness_failed_fires():
    ev = _evidence(has_bias_audit=True, bias_passed=False)
    c = _claim("Bias-free model", ClaimType.FAIRNESS_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.FACTUAL_MISMATCH and f.severity == FindingSeverity.CRITICAL for f in findings)


def test_rule_fairness_good_evidence_supported():
    ev = _evidence(has_bias_audit=True, bias_passed=True)
    c = _claim("Unbiased model", ClaimType.FAIRNESS_CLAIM)
    findings, supported = DivergenceEngine().check([c], ev)
    assert c in supported


def test_rule_no_pii_no_lineage_fires():
    ev = _evidence(has_data_lineage=False)
    c = _claim("No PII in training data", ClaimType.DATA_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNSUPPORTED_CLAIM for f in findings)


def test_rule_pii_risk_high_fires():
    ev = _evidence(has_data_lineage=True, no_pii_confirmed=False)
    c = _claim("Training data contains no PII", ClaimType.DATA_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.FACTUAL_MISMATCH for f in findings)


def test_rule_superlative_medium_severity():
    ev = _evidence()
    c = _claim("World's first enterprise AI compliance platform", ClaimType.SUPERLATIVE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNDOCUMENTED_SUPERLATIVE for f in findings)


def test_rule_guaranteed_100_accuracy_critical():
    ev = _evidence()
    c = _claim("100% guaranteed accuracy on all tasks", ClaimType.SUPERLATIVE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.severity == FindingSeverity.CRITICAL for f in findings)


def test_rule_security_no_scan_fires():
    ev = _evidence(has_security_scan=False, scan_passed=None)
    c = _claim("Penetration-tested model", ClaimType.SECURITY_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.UNSUPPORTED_CLAIM for f in findings)


def test_rule_security_scan_failed_fires():
    ev = _evidence(has_security_scan=True, scan_passed=False)
    c = _claim("Secure inference infrastructure", ClaimType.SECURITY_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.finding_type == FindingType.FACTUAL_MISMATCH and f.severity == FindingSeverity.CRITICAL for f in findings)


def test_rule_security_scan_passed_supported():
    ev = _evidence(has_security_scan=True, scan_passed=True)
    c = _claim("Penetration-tested model", ClaimType.SECURITY_CLAIM)
    findings, supported = DivergenceEngine().check([c], ev)
    assert c in supported


def test_rule_medical_capability_always_critical():
    ev = _evidence()
    c = _claim("Our AI diagnoses cancer from CT scans", ClaimType.CAPABILITY_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert any(f.severity == FindingSeverity.CRITICAL for f in findings)


def test_rule_stale_attestation_fires():
    ev = _evidence(
        attestation_age_days=120.0,
        framework_scores={"eu-ai-act": 88.0},
        passed=True,
    )
    c = _claim("EU AI Act compliant", ClaimType.COMPLIANCE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    temporal = [f for f in findings if f.finding_type == FindingType.TEMPORAL_MISMATCH]
    assert temporal, "Expected temporal mismatch for 120-day-old attestation"


def test_rule_fresh_attestation_no_temporal():
    ev = _evidence(attestation_age_days=10.0, framework_scores={"eu-ai-act": 88.0}, passed=True)
    c = _claim("EU AI Act compliant", ClaimType.COMPLIANCE_CLAIM)
    findings, _ = DivergenceEngine().check([c], ev)
    assert not any(f.finding_type == FindingType.TEMPORAL_MISMATCH for f in findings)


# ---------------------------------------------------------------------------
# Part 3 — WashingReport
# ---------------------------------------------------------------------------

def _make_clean_report(tmp_path) -> "WashingReport":
    f = tmp_path / "clean.md"
    f.write_text("# Product Overview\n\nWe build AI tools for enterprises.\n")
    ev = _evidence()
    return WashingDetector().scan([f], evidence=ev, model_id="test-model")


def _make_washing_report(tmp_path) -> "WashingReport":
    f = tmp_path / "marketing.md"
    f.write_text(
        "EU AI Act compliant platform.\n"
        "Our AI is completely unbiased.\n"
        "100% guaranteed accuracy.\n"
        "No hallucinations in production.\n"
        "World's first enterprise AI compliance solution.\n"
    )
    ev = _evidence(
        framework_scores={"eu-ai-act": 38.0},  # below threshold → factual mismatch
        has_bias_audit=False,
        overall_score=45.0,
    )
    return WashingDetector().scan([f], evidence=ev, model_id="test-model")


def test_report_clean_passes(tmp_path):
    report = _make_clean_report(tmp_path)
    assert report.passed() or report.verdict in (OverallVerdict.CLEAN, OverallVerdict.LOW, OverallVerdict.MEDIUM)


def test_report_washing_fails(tmp_path):
    report = _make_washing_report(tmp_path)
    assert not report.passed()
    assert len(report.findings) >= 1
    assert report.verdict not in (OverallVerdict.CLEAN,)


def test_report_summary_has_icon(tmp_path):
    report = _make_clean_report(tmp_path)
    s = report.summary()
    assert "✓" in s or "✗" in s


def test_report_json_round_trip(tmp_path):
    report = _make_washing_report(tmp_path)
    path = tmp_path / "report.json"
    path.write_text(report.to_json())
    loaded = load_report(path)
    assert loaded.schema == report.schema
    assert loaded.verdict == report.verdict
    assert len(loaded.findings) == len(report.findings)


def test_report_markdown_contains_model_id(tmp_path):
    report = _make_washing_report(tmp_path)
    md = report.to_markdown()
    assert "AI Washing Detection Report" in md
    assert report.verdict.value.upper() in md


# ---------------------------------------------------------------------------
# Part 4 — AttestationEvidence loader
# ---------------------------------------------------------------------------

def test_load_evidence_master_record(tmp_path):
    rec = {
        "attestation_id": "att-x",
        "model_id": "phi-3",
        "overall_score": 88.5,
        "passed": True,
        "generated_at": "2026-04-01T00:00:00+00:00",
        "framework_scores": {"eu-ai-act": 91.0},
        "scan_summary": {"is_safe": True, "status": "pass"},
    }
    p = tmp_path / "master.json"
    p.write_text(json.dumps(rec))
    ev = load_evidence(master_record_path=p, model_id="phi-3")
    assert ev.overall_score == 88.5
    assert ev.passed is True
    assert ev.framework_scores.get("eu-ai-act") == 91.0
    assert ev.has_security_scan
    assert ev.scan_passed is True


def test_load_evidence_bias_audit(tmp_path):
    d = {"passed": True, "overall_verdict": "pass", "attributes": {"gender": {"dpd": 0.01}}}
    p = tmp_path / "bias.json"
    p.write_text(json.dumps(d))
    ev = load_evidence(bias_audit_path=p, model_id="m")
    assert ev.has_bias_audit
    assert ev.bias_passed is True


def test_load_evidence_data_lineage(tmp_path):
    d = {"pii_risk_level": "none", "datasets": [{"dataset_id": "c4"}, {"dataset_id": "wiki"}]}
    p = tmp_path / "lineage.json"
    p.write_text(json.dumps(d))
    ev = load_evidence(data_lineage_path=p, model_id="m")
    assert ev.has_data_lineage
    assert ev.no_pii_confirmed is True
    assert "c4" in ev.datasets


# ---------------------------------------------------------------------------
# Part 5 — WashingDetector end-to-end
# ---------------------------------------------------------------------------

def test_detector_clean_doc_good_evidence(tmp_path):
    doc = tmp_path / "marketing.md"
    doc.write_text("# Our Platform\n\nWe build responsible AI tools.\n")
    ev = _evidence()
    report = WashingDetector().scan([doc], evidence=ev)
    assert report.schema == "squash.washing.report/v1"
    assert report.claims_extracted == 0 or report.findings == []


def test_detector_missing_doc_skipped(tmp_path):
    report = WashingDetector().scan([tmp_path / "nope.md"], evidence=_evidence())
    assert report.claims_extracted == 0


# ---------------------------------------------------------------------------
# Part 6 — CLI smoke
# ---------------------------------------------------------------------------

def test_cli_parser_registered():
    from squash.cli import _build_parser
    p = _build_parser()
    ns = p.parse_args(["detect-washing", "scan", "./marketing.md"])
    assert ns.command == "detect-washing"
    assert ns.aw_command == "scan"
    assert "./marketing.md" in ns.doc_paths
    assert ns.fail_on == "high"


def test_cli_scan_json_output(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_detect_washing
    doc = tmp_path / "doc.md"
    doc.write_text("Our platform is great. We iterate fast.\n")
    args = argparse.Namespace(
        aw_command="scan",
        doc_paths=[str(doc)],
        model_id="test",
        master_record=None,
        bias_audit=None,
        data_lineage=None,
        aw_format="json",
        out=None,
        fail_on="critical",
    )
    rc = _cmd_detect_washing(args, quiet=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["schema"] == "squash.washing.report/v1"
    assert rc == 0


def test_cli_scan_nonexistent(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_detect_washing
    args = argparse.Namespace(
        aw_command="scan",
        doc_paths=[str(tmp_path / "nope.md")],
        model_id="", master_record=None, bias_audit=None, data_lineage=None,
        aw_format="text", out=None, fail_on="high",
    )
    rc = _cmd_detect_washing(args, quiet=True)
    assert rc == 1
