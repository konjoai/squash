"""tests/test_squash_policy.py — Unit tests for squish.squash.policy.

Test taxonomy: Pure unit — no I/O, deterministic, tests policy evaluation
logic against synthetic SBOM dicts.

Covers:
  - All 5 policy templates (eu-ai-act, nist-ai-rmf, owasp-llm-top10,
    iso-42001, enterprise-strict) and the 'strict' alias
  - Field resolution (dot-path, array index, squash: key)
  - Check types: present, non_empty, equals, min_value, not_equals
  - Severity classification: error vs warning
  - PolicyResult summary string format
  - unknown policy name handling
"""

from __future__ import annotations

import pytest

from squash.policy import (
    AVAILABLE_POLICIES,
    OWASP_LLM_TOP10_2025,
    PolicyEngine,
    PolicyFinding,
    PolicyResult,
)

# ── Minimal valid CycloneDX BOM dict ─────────────────────────────────────────


def _minimal_bom(
    *,
    include_hashes: bool = True,
    include_description: bool = True,
    include_properties: bool = True,
    include_license: bool = True,
    include_version: bool = True,
    include_purl: bool = True,
    scan_result: str = "clean",
) -> dict:
    """Build a synthetic CycloneDX 1.7 BOM dict that should pass most policies."""
    props = [
        {"name": "squash:quantFormat", "value": "INT4"},
        {"name": "squash:modelFamily", "value": "llama"},
        {"name": "squash:awqAlpha", "value": "0.10"},
        {"name": "squash:evaluationScore", "value": "0.72"},
    ]
    comp: dict = {
        "type": "ml-model",
        "name": "llama-3.1-8b",
        "hashes": [
            {"alg": "SHA-256", "content": "abc123"},
            {"alg": "SHA-512", "content": "def456"},
        ]
        if include_hashes
        else [],
        "description": "Quantized Llama 3.1 8B INT4" if include_description else "",
        "licenses": [{"license": {"id": "META-LLAMA-3"}}] if include_license else [],
        "version": "3.1.0" if include_version else "",
        "purl": "pkg:mlmodel/llama-3.1-8b@3.1.0" if include_purl else "",
        "properties": props if include_properties else [],
        "modelCard": {
            "modelParameters": {
                "quantizationLevel": "INT4",
            }
        },
    }
    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
        "components": [comp],
        "squash:scan_result": scan_result,
    }
    return bom


# ── Shape / dtype contracts ───────────────────────────────────────────────────


class TestPolicyResultShape:
    def test_returns_policy_result(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "eu-ai-act")
        assert isinstance(result, PolicyResult)

    def test_findings_are_policy_finding_instances(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "eu-ai-act")
        for f in result.findings:
            assert isinstance(f, PolicyFinding)

    def test_counts_sum_correctly(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "enterprise-strict")
        total = result.error_count + result.warning_count + result.pass_count
        assert total == len(result.findings)

    def test_policy_name_stored_on_result(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "nist-ai-rmf")
        assert result.policy_name == "nist-ai-rmf"


# ── All 5 templates + alias can evaluate without error ───────────────────────


class TestAllPoliciesLoad:
    @pytest.mark.parametrize("policy", sorted(AVAILABLE_POLICIES))
    def test_policy_evaluates(self, policy):
        result = PolicyEngine.evaluate(_minimal_bom(), policy)
        assert isinstance(result, PolicyResult)

    def test_strict_is_alias_for_enterprise_strict(self):
        if "strict" not in AVAILABLE_POLICIES:
            pytest.skip("'strict' alias not defined")
        r_strict = PolicyEngine.evaluate(_minimal_bom(), "strict")
        r_ent = PolicyEngine.evaluate(_minimal_bom(), "enterprise-strict")
        # Same rules → same finding count
        assert len(r_strict.findings) == len(r_ent.findings)


# ── Passes on minimal valid BOM ───────────────────────────────────────────────


class TestPassingBOM:
    def test_eu_ai_act_passes_minimal_bom(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "eu-ai-act")
        error_findings = [f for f in result.findings if f.severity == "error" and not f.passed]
        assert error_findings == [], f"Unexpected errors: {error_findings}"

    def test_nist_ai_rmf_passes_minimal_bom(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "nist-ai-rmf")
        error_findings = [f for f in result.findings if f.severity == "error" and not f.passed]
        assert error_findings == [], f"Unexpected errors: {error_findings}"


# ── Fails correctly on broken BOM ────────────────────────────────────────────


class TestFailingBOM:
    def test_missing_hashes_fails_eu_ai_act(self):
        bom = _minimal_bom(include_hashes=False)
        result = PolicyEngine.evaluate(bom, "eu-ai-act")
        # The hash-presence rule should fire
        hash_rule_failures = [
            f for f in result.findings if not f.passed and "hash" in (f.field + f.rationale).lower()
        ]
        assert hash_rule_failures, "Expected a hash-presence failure"

    def test_unsafe_scan_fails_owasp(self):
        bom = _minimal_bom(scan_result="unsafe")
        result = PolicyEngine.evaluate(bom, "owasp-llm-top10")
        scan_failures = [f for f in result.findings if not f.passed and "scan" in f.field]
        assert scan_failures, "Expected scan_result failure in owasp policy"

    def test_missing_name_fails_iso_42001(self):
        bom = _minimal_bom()
        bom["components"][0]["name"] = ""
        result = PolicyEngine.evaluate(bom, "iso-42001")
        name_failures = [f for f in result.findings if not f.passed and "name" in f.field]
        assert name_failures, "Expected name non_empty failure"


# ── PolicyResult summary string ───────────────────────────────────────────────


class TestPolicyResultSummary:
    def test_summary_contains_policy_name(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "eu-ai-act")
        assert "eu-ai-act" in result.summary()

    def test_summary_contains_pass_or_fail(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "eu-ai-act")
        s = result.summary().upper()
        assert "PASS" in s or "FAIL" in s


# ── Unknown policy handling ───────────────────────────────────────────────────


class TestUnknownPolicy:
    def test_unknown_policy_raises_or_returns_error(self):
        """Unknown policy should either raise KeyError or return a failed result."""
        try:
            result = PolicyEngine.evaluate(_minimal_bom(), "nonexistent-policy-xyz")
            # If it returns rather than raising, it should indicate failure
            assert not result.passed
        except (KeyError, ValueError):
            pass  # Acceptable — explicit error on unknown policy


# ── AVAILABLE_POLICIES registry ──────────────────────────────────────────────


class TestAvailablePolicies:
    def test_at_least_five_policies(self):
        policy_keys = {k for k in AVAILABLE_POLICIES if k != "strict"}
        assert len(policy_keys) >= 5

    def test_required_policies_present(self):
        for name in (
            "eu-ai-act",
            "nist-ai-rmf",
            "owasp-llm-top10",
            "iso-42001",
            "enterprise-strict",
        ):
            assert name in AVAILABLE_POLICIES, f"Missing policy: {name}"


# ── OWASP Top 10 for LLM Applications (2025) alignment ────────────────────────


class TestOwaspLlm2025Catalogue:
    """The OWASP_LLM_TOP10_2025 constant must mirror the official list."""

    EXPECTED = {
        "LLM01:2025": "Prompt Injection",
        "LLM02:2025": "Sensitive Information Disclosure",
        "LLM03:2025": "Supply Chain",
        "LLM04:2025": "Data and Model Poisoning",
        "LLM05:2025": "Improper Output Handling",
        "LLM06:2025": "Excessive Agency",
        "LLM07:2025": "System Prompt Leakage",
        "LLM08:2025": "Vector and Embedding Weaknesses",
        "LLM09:2025": "Misinformation",
        "LLM10:2025": "Unbounded Consumption",
    }

    def test_has_all_ten_categories(self):
        assert set(OWASP_LLM_TOP10_2025) == set(self.EXPECTED)

    def test_official_names_match(self):
        for code, name in self.EXPECTED.items():
            assert OWASP_LLM_TOP10_2025[code]["name"] == name

    def test_no_legacy_overreliance_name(self):
        """'Overreliance' is a 2023-era name OWASP retired — it must not reappear."""
        names = {v["name"].lower() for v in OWASP_LLM_TOP10_2025.values()}
        assert "overreliance" not in names

    def test_llm09_is_misinformation_not_overreliance(self):
        assert OWASP_LLM_TOP10_2025["LLM09:2025"]["name"] == "Misinformation"

    def test_only_supply_chain_and_poisoning_are_attestable(self):
        attestable = {c for c, v in OWASP_LLM_TOP10_2025.items() if v["attestable"]}
        assert attestable == {"LLM03:2025", "LLM04:2025"}


class TestOwaspLlmPolicyRules:
    """The owasp-llm-top10 policy must cite only current 2025 categories."""

    def _owasp_findings(self, bom: dict) -> list[PolicyFinding]:
        return PolicyEngine.evaluate(bom, "owasp-llm-top10").findings

    def test_clean_minimal_bom_passes(self):
        result = PolicyEngine.evaluate(_minimal_bom(), "owasp-llm-top10")
        assert result.passed, [f.rule_id for f in result.findings if not f.passed]

    def test_no_rationale_references_overreliance(self):
        for f in self._owasp_findings(_minimal_bom()):
            assert "overreliance" not in f.rationale.lower()

    def test_every_rationale_uses_2025_versioned_codes(self):
        for f in self._owasp_findings(_minimal_bom()):
            assert ":2025" in f.rationale, f"{f.rule_id} cites a non-2025 OWASP code"

    def test_only_attestable_categories_are_cited(self):
        cited = {
            code
            for f in self._owasp_findings(_minimal_bom())
            for code in OWASP_LLM_TOP10_2025
            if code in f.rationale
        }
        assert cited <= {"LLM03:2025", "LLM04:2025"}

    def test_missing_version_warns_not_errors(self):
        bom = _minimal_bom(include_version=False)
        result = PolicyEngine.evaluate(bom, "owasp-llm-top10")
        version_findings = [f for f in result.findings if f.field == "components[0].version"]
        assert version_findings and all(
            f.severity == "warning" and not f.passed for f in version_findings
        )

    def test_missing_model_card_warns(self):
        bom = _minimal_bom()
        del bom["components"][0]["modelCard"]
        result = PolicyEngine.evaluate(bom, "owasp-llm-top10")
        card_findings = [f for f in result.findings if f.field == "components[0].modelCard"]
        assert card_findings and all(
            f.severity == "warning" and not f.passed for f in card_findings
        )
        # A missing model card is non-fatal — errors still pass.
        assert result.passed
