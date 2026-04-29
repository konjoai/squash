"""tests/test_squash_w191.py — W191: SBOM diff engine tests.

Coverage:
  - ComponentDiff: added/removed/unchanged/changed, to_dict()
  - PolicyDiff: regression/improvement, to_dict()
  - VulnerabilityDiff: net_change, to_dict()
  - AttestationDiff.score_delta — arithmetic
  - AttestationDiff.is_regression — score drop / newly_failed / vuln added
  - AttestationDiff.is_improvement — score rise / newly_passed / vuln resolved
  - AttestationDiff.summary_line() — all delta fields represented
  - AttestationDiff.to_dict() — has expected keys
  - AttestationDiff.to_table() — ANSI output, no exception
  - AttestationDiff.to_html() — valid HTML table
  - diff_from_dicts() — no-change scenario, score delta, policy change
  - diff_attestations() — file not found raises FileNotFoundError
  - diff_attestations() — invalid JSON raises ValueError
  - Internal helpers: _extract_score, _extract_passed, _component_names,
    _policy_results, _vuln_ids
  - CycloneDX format parsing: components list, properties score
  - Squash native format: policy_results list
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from squash.sbom_diff import (
    AttestationDiff,
    ComponentDiff,
    PolicyDiff,
    VulnerabilityDiff,
    diff_attestations,
    diff_from_dicts,
    _extract_score,
    _extract_passed,
    _component_names,
    _policy_results,
    _vuln_ids,
)


# ---------------------------------------------------------------------------
# ComponentDiff
# ---------------------------------------------------------------------------

class TestComponentDiff:
    def test_changed_when_added(self):
        c = ComponentDiff(added=["new-comp"], removed=[], unchanged=[])
        assert c.changed is True

    def test_changed_when_removed(self):
        c = ComponentDiff(added=[], removed=["old-comp"], unchanged=[])
        assert c.changed is True

    def test_not_changed_when_only_unchanged(self):
        c = ComponentDiff(added=[], removed=[], unchanged=["comp-a"])
        assert c.changed is False

    def test_to_dict_has_required_keys(self):
        c = ComponentDiff(added=["a"], removed=["b"], unchanged=["c"])
        d = c.to_dict()
        for key in ("added", "removed", "unchanged_count"):
            assert key in d

    def test_unchanged_count_in_dict(self):
        c = ComponentDiff(added=[], removed=[], unchanged=["a", "b", "c"])
        assert c.to_dict()["unchanged_count"] == 3


# ---------------------------------------------------------------------------
# PolicyDiff
# ---------------------------------------------------------------------------

class TestPolicyDiff:
    def test_regression_when_newly_failed(self):
        p = PolicyDiff(newly_failed=["eu-ai-act"])
        assert p.regression is True

    def test_no_regression_when_empty(self):
        p = PolicyDiff()
        assert p.regression is False

    def test_improvement_when_newly_passed(self):
        p = PolicyDiff(newly_passed=["nist-rmf"])
        assert p.improvement is True

    def test_no_improvement_when_empty(self):
        p = PolicyDiff()
        assert p.improvement is False

    def test_to_dict_has_required_keys(self):
        p = PolicyDiff(newly_passed=["p1"], newly_failed=["p2"])
        d = p.to_dict()
        for key in ("newly_passed", "newly_failed", "unchanged_pass_count", "unchanged_fail_count"):
            assert key in d


# ---------------------------------------------------------------------------
# VulnerabilityDiff
# ---------------------------------------------------------------------------

class TestVulnerabilityDiff:
    def test_net_change_positive_when_added(self):
        v = VulnerabilityDiff(added=["CVE-2026-001", "CVE-2026-002"], resolved=[])
        assert v.net_change == 2

    def test_net_change_negative_when_resolved(self):
        v = VulnerabilityDiff(added=[], resolved=["CVE-2025-999"])
        assert v.net_change == -1

    def test_net_change_zero_when_balanced(self):
        v = VulnerabilityDiff(added=["CVE-2026-001"], resolved=["CVE-2025-999"])
        assert v.net_change == 0

    def test_to_dict_has_required_keys(self):
        v = VulnerabilityDiff(added=["CVE-2026-001"], resolved=["CVE-2025-999"])
        d = v.to_dict()
        for key in ("added", "resolved", "unchanged_count", "net_change"):
            assert key in d


# ---------------------------------------------------------------------------
# AttestationDiff — derived properties
# ---------------------------------------------------------------------------

class TestAttestationDiffProperties:
    def _make_diff(self, score_before=None, score_after=None,
                   newly_failed=None, newly_passed=None,
                   vuln_added=None, vuln_resolved=None) -> AttestationDiff:
        return AttestationDiff(
            before_path="a.json",
            after_path="b.json",
            score_before=score_before,
            score_after=score_after,
            passed_before=None,
            passed_after=None,
            components=ComponentDiff(),
            policies=PolicyDiff(newly_failed=newly_failed or [], newly_passed=newly_passed or []),
            vulnerabilities=VulnerabilityDiff(added=vuln_added or [], resolved=vuln_resolved or []),
        )

    def test_score_delta_arithmetic(self):
        d = self._make_diff(score_before=75.0, score_after=82.5)
        assert d.score_delta == 7.5

    def test_score_delta_negative(self):
        d = self._make_diff(score_before=90.0, score_after=70.0)
        assert d.score_delta == -20.0

    def test_score_delta_none_when_before_missing(self):
        d = self._make_diff(score_before=None, score_after=80.0)
        assert d.score_delta is None

    def test_score_delta_none_when_after_missing(self):
        d = self._make_diff(score_before=80.0, score_after=None)
        assert d.score_delta is None

    def test_is_regression_on_score_drop(self):
        d = self._make_diff(score_before=85.0, score_after=70.0)
        assert d.is_regression is True

    def test_is_regression_on_newly_failed(self):
        d = self._make_diff(score_before=80.0, score_after=80.0, newly_failed=["eu-ai-act"])
        assert d.is_regression is True

    def test_is_regression_on_vuln_added(self):
        d = self._make_diff(score_before=80.0, score_after=80.0, vuln_added=["CVE-2026-001"])
        assert d.is_regression is True

    def test_no_regression_when_score_improves(self):
        d = self._make_diff(score_before=70.0, score_after=85.0)
        assert d.is_regression is False

    def test_is_improvement_on_score_rise(self):
        d = self._make_diff(score_before=70.0, score_after=85.0)
        assert d.is_improvement is True

    def test_is_improvement_on_newly_passed(self):
        d = self._make_diff(score_before=75.0, score_after=75.0, newly_passed=["nist-rmf"])
        assert d.is_improvement is True

    def test_is_improvement_on_vuln_resolved(self):
        d = self._make_diff(score_before=75.0, score_after=75.0, vuln_resolved=["CVE-2025-001"])
        assert d.is_improvement is True


# ---------------------------------------------------------------------------
# AttestationDiff.summary_line()
# ---------------------------------------------------------------------------

class TestAttestationDiffSummaryLine:
    def _diff(self, **kwargs) -> AttestationDiff:
        return AttestationDiff(
            before_path="a.json",
            after_path="b.json",
            score_before=kwargs.get("score_before"),
            score_after=kwargs.get("score_after"),
            passed_before=kwargs.get("passed_before"),
            passed_after=kwargs.get("passed_after"),
            components=ComponentDiff(
                added=kwargs.get("comp_added", []),
                removed=kwargs.get("comp_removed", []),
            ),
            policies=PolicyDiff(
                newly_passed=kwargs.get("newly_passed", []),
                newly_failed=kwargs.get("newly_failed", []),
            ),
            vulnerabilities=VulnerabilityDiff(
                added=kwargs.get("vuln_added", []),
                resolved=kwargs.get("vuln_resolved", []),
            ),
        )

    def test_returns_string(self):
        d = self._diff(score_before=75.0, score_after=82.0)
        assert isinstance(d.summary_line(), str)

    def test_score_included(self):
        d = self._diff(score_before=75.0, score_after=82.5)
        s = d.summary_line()
        assert "75.0" in s
        assert "82.5" in s

    def test_positive_delta_shown(self):
        d = self._diff(score_before=75.0, score_after=82.5)
        assert "+" in d.summary_line()

    def test_components_added_shown(self):
        d = self._diff(comp_added=["comp-a", "comp-b"])
        assert "2 component" in d.summary_line()

    def test_components_removed_shown(self):
        d = self._diff(comp_removed=["old-comp"])
        assert "1 component" in d.summary_line()

    def test_policy_newly_failed_shown(self):
        d = self._diff(newly_failed=["eu-ai-act", "nist-rmf"])
        assert "policy" in d.summary_line().lower()

    def test_vuln_resolved_shown(self):
        d = self._diff(vuln_resolved=["CVE-2025-001"])
        assert "vulnerability resolved" in d.summary_line()

    def test_vuln_added_shown(self):
        d = self._diff(vuln_added=["CVE-2026-001"])
        assert "vulnerability added" in d.summary_line()

    def test_no_changes_message(self):
        d = self._diff()
        assert "no changes" in d.summary_line().lower()


# ---------------------------------------------------------------------------
# AttestationDiff.to_dict()
# ---------------------------------------------------------------------------

class TestAttestationDiffToDict:
    def test_has_required_keys(self):
        d = AttestationDiff(
            before_path="a.json", after_path="b.json",
            score_before=75.0, score_after=80.0,
            passed_before=True, passed_after=True,
            components=ComponentDiff(),
            policies=PolicyDiff(),
            vulnerabilities=VulnerabilityDiff(),
        )
        result = d.to_dict()
        for key in ("before", "after", "score", "passed", "components", "policies", "vulnerabilities", "is_regression", "is_improvement", "summary"):
            assert key in result

    def test_score_delta_in_dict(self):
        d = AttestationDiff(
            before_path="a.json", after_path="b.json",
            score_before=70.0, score_after=80.0,
            passed_before=None, passed_after=None,
            components=ComponentDiff(), policies=PolicyDiff(), vulnerabilities=VulnerabilityDiff(),
        )
        result = d.to_dict()
        assert result["score"]["delta"] == 10.0


# ---------------------------------------------------------------------------
# AttestationDiff.to_table()
# ---------------------------------------------------------------------------

class TestAttestationDiffToTable:
    def test_returns_string(self):
        d = AttestationDiff(
            before_path="a.json", after_path="b.json",
            score_before=70.0, score_after=80.0,
            passed_before=False, passed_after=True,
            components=ComponentDiff(added=["new-model"]),
            policies=PolicyDiff(newly_passed=["nist-rmf"], newly_failed=["eu-ai-act"]),
            vulnerabilities=VulnerabilityDiff(resolved=["CVE-2025-001"]),
        )
        table = d.to_table()
        assert isinstance(table, str)
        assert len(table) > 50

    def test_contains_paths(self):
        d = AttestationDiff(
            before_path="old.json", after_path="new.json",
            score_before=None, score_after=None,
            passed_before=None, passed_after=None,
            components=ComponentDiff(), policies=PolicyDiff(), vulnerabilities=VulnerabilityDiff(),
        )
        table = d.to_table()
        assert "old.json" in table
        assert "new.json" in table


# ---------------------------------------------------------------------------
# AttestationDiff.to_html()
# ---------------------------------------------------------------------------

class TestAttestationDiffToHtml:
    def test_returns_string_with_table(self):
        d = AttestationDiff(
            before_path="a.json", after_path="b.json",
            score_before=75.0, score_after=82.0,
            passed_before=True, passed_after=True,
            components=ComponentDiff(), policies=PolicyDiff(), vulnerabilities=VulnerabilityDiff(),
        )
        html = d.to_html()
        assert "<table" in html
        assert "</table>" in html

    def test_html_contains_score(self):
        d = AttestationDiff(
            before_path="a.json", after_path="b.json",
            score_before=75.0, score_after=82.0,
            passed_before=None, passed_after=None,
            components=ComponentDiff(), policies=PolicyDiff(), vulnerabilities=VulnerabilityDiff(),
        )
        html = d.to_html()
        assert "75.0" in html
        assert "82.0" in html


# ---------------------------------------------------------------------------
# diff_from_dicts()
# ---------------------------------------------------------------------------

class TestDiffFromDicts:
    def test_no_change_scenario(self):
        doc = {
            "compliance_score": 80.0,
            "passed": True,
            "components": [{"name": "bert-base"}],
            "policy_results": [{"policy": "eu-ai-act", "passed": True}],
        }
        delta = diff_from_dicts(doc, doc)
        assert delta.score_delta == 0.0
        assert delta.components.added == []
        assert delta.components.removed == []
        assert delta.policies.newly_failed == []
        assert delta.policies.newly_passed == []

    def test_score_improvement(self):
        before = {"compliance_score": 70.0, "passed": False}
        after = {"compliance_score": 85.0, "passed": True}
        delta = diff_from_dicts(before, after)
        assert delta.score_delta == 15.0
        assert delta.is_improvement is True

    def test_score_regression(self):
        before = {"compliance_score": 90.0, "passed": True}
        after = {"compliance_score": 65.0, "passed": False}
        delta = diff_from_dicts(before, after)
        assert delta.is_regression is True

    def test_component_added(self):
        before = {"components": [{"name": "bert-base"}]}
        after = {"components": [{"name": "bert-base"}, {"name": "tokenizer-v2"}]}
        delta = diff_from_dicts(before, after)
        assert "tokenizer-v2" in delta.components.added

    def test_component_removed(self):
        before = {"components": [{"name": "bert-base"}, {"name": "old-model"}]}
        after = {"components": [{"name": "bert-base"}]}
        delta = diff_from_dicts(before, after)
        assert "old-model" in delta.components.removed

    def test_policy_drift_newly_failed(self):
        before = {"policy_results": [{"policy": "eu-ai-act", "passed": True}]}
        after = {"policy_results": [{"policy": "eu-ai-act", "passed": False}]}
        delta = diff_from_dicts(before, after)
        assert "eu-ai-act" in delta.policies.newly_failed
        assert delta.is_regression is True

    def test_policy_drift_newly_passed(self):
        before = {"policy_results": [{"policy": "nist-rmf", "passed": False}]}
        after = {"policy_results": [{"policy": "nist-rmf", "passed": True}]}
        delta = diff_from_dicts(before, after)
        assert "nist-rmf" in delta.policies.newly_passed
        assert delta.is_improvement is True

    def test_vulnerability_added(self):
        before = {"vulnerabilities": []}
        after = {"vulnerabilities": [{"id": "CVE-2026-001"}]}
        delta = diff_from_dicts(before, after)
        assert "CVE-2026-001" in delta.vulnerabilities.added

    def test_vulnerability_resolved(self):
        before = {"vulnerabilities": [{"id": "CVE-2025-999"}]}
        after = {"vulnerabilities": []}
        delta = diff_from_dicts(before, after)
        assert "CVE-2025-999" in delta.vulnerabilities.resolved

    def test_empty_docs_no_crash(self):
        delta = diff_from_dicts({}, {})
        assert isinstance(delta, AttestationDiff)


# ---------------------------------------------------------------------------
# diff_attestations() — file I/O
# ---------------------------------------------------------------------------

class TestDiffAttestations:
    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            diff_attestations(tmp_path / "before.json", tmp_path / "after.json")

    def test_invalid_json_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        good = tmp_path / "good.json"
        good.write_text('{"compliance_score": 80.0}')
        with pytest.raises(Exception):
            diff_attestations(bad, good)

    def test_non_object_json_raises(self, tmp_path):
        arr = tmp_path / "arr.json"
        arr.write_text("[1, 2, 3]")
        obj = tmp_path / "obj.json"
        obj.write_text('{"score": 80.0}')
        with pytest.raises(ValueError):
            diff_attestations(arr, obj)

    def test_valid_files_produce_diff(self, tmp_path):
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        before.write_text(json.dumps({
            "compliance_score": 70.0,
            "passed": False,
            "components": [{"name": "bert-base"}],
        }))
        after.write_text(json.dumps({
            "compliance_score": 85.0,
            "passed": True,
            "components": [{"name": "bert-base"}, {"name": "roberta"}],
        }))
        delta = diff_attestations(before, after)
        assert delta.score_delta == 15.0
        assert "roberta" in delta.components.added
        assert delta.is_improvement is True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class TestExtractScore:
    def test_compliance_score_key(self):
        assert _extract_score({"compliance_score": 87.5}) == 87.5

    def test_score_key(self):
        assert _extract_score({"score": 75.0}) == 75.0

    def test_camel_case_key(self):
        assert _extract_score({"complianceScore": 90.0}) == 90.0

    def test_cyclonedx_property(self):
        doc = {"properties": [{"name": "squash:compliance_score", "value": "82.5"}]}
        assert _extract_score(doc) == 82.5

    def test_nested_metadata(self):
        doc = {"metadata": {"compliance_score": 78.0}}
        assert _extract_score(doc) == 78.0

    def test_missing_returns_none(self):
        assert _extract_score({}) is None

    def test_non_numeric_returns_none(self):
        assert _extract_score({"score": "not-a-number"}) is None


class TestExtractPassed:
    def test_bool_true(self):
        assert _extract_passed({"passed": True}) is True

    def test_bool_false(self):
        assert _extract_passed({"passed": False}) is False

    def test_string_true(self):
        assert _extract_passed({"passed": "true"}) is True

    def test_string_pass(self):
        assert _extract_passed({"passed": "pass"}) is True

    def test_string_false(self):
        assert _extract_passed({"passed": "false"}) is False

    def test_missing_returns_none(self):
        assert _extract_passed({}) is None

    def test_policy_passed_key(self):
        assert _extract_passed({"policy_passed": True}) is True


class TestComponentNames:
    def test_cyclonedx_components(self):
        doc = {"components": [{"name": "bert"}, {"name": "roberta"}]}
        names = _component_names(doc)
        assert "bert" in names
        assert "roberta" in names

    def test_native_artifacts(self):
        doc = {"artifacts": [{"name": "weights.pt"}, {"name": "tokenizer.json"}]}
        names = _component_names(doc)
        assert "weights.pt" in names

    def test_empty_doc_returns_empty_set(self):
        assert _component_names({}) == set()

    def test_component_with_purl(self):
        doc = {"components": [{"purl": "pkg:pypi/bert@1.0", "name": None}]}
        names = _component_names(doc)
        assert "pkg:pypi/bert@1.0" in names


class TestPolicyResults:
    def test_list_format(self):
        doc = {"policy_results": [
            {"policy": "eu-ai-act", "passed": True},
            {"policy": "nist-rmf", "passed": False},
        ]}
        results = _policy_results(doc)
        assert results["eu-ai-act"] is True
        assert results["nist-rmf"] is False

    def test_dict_format(self):
        doc = {"policy_results": {"eu-ai-act": True, "nist-rmf": False}}
        results = _policy_results(doc)
        assert results["eu-ai-act"] is True

    def test_empty_doc(self):
        assert _policy_results({}) == {}


class TestVulnIds:
    def test_vulnerability_list(self):
        doc = {"vulnerabilities": [{"id": "CVE-2025-001"}, {"id": "CVE-2025-002"}]}
        ids = _vuln_ids(doc)
        assert "CVE-2025-001" in ids
        assert "CVE-2025-002" in ids

    def test_vex_alerts(self):
        doc = {"vex_alerts": [{"cve": "CVE-2025-999"}]}
        ids = _vuln_ids(doc)
        assert "CVE-2025-999" in ids

    def test_empty_doc(self):
        assert _vuln_ids({}) == set()
