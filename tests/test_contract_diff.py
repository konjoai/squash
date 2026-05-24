"""tests/test_contract_diff.py — contract redline diff with risk delta."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from squash.contracts.diff import (
    ChangeKind,
    ContractDiff,
    ContractDiffer,
    diff_contracts,
)


OLD = [
    "Vendor shall deliver Services within thirty (30) days.",
    "Customer shall pay all invoices within fifteen (15) days of receipt.",
    "Either Party may terminate this Agreement upon ninety (90) days written notice.",
    "Confidentiality survives termination for five (5) years.",
]

NEW = [
    "Vendor shall deliver Services within forty-five (45) days.",   # modified
    "Customer shall pay all invoices within fifteen (15) days of receipt.",
    # termination removed
    "Confidentiality survives termination for five (5) years.",
    "Each Party shall maintain cyber-insurance of at least $5 million during the Term.",
]


class TestDiffShape(unittest.TestCase):
    def test_summary_counts_match(self):
        d = ContractDiffer().diff(OLD, NEW)
        s = d.summary()
        self.assertEqual(s["old_clause_count"], 4)
        self.assertEqual(s["new_clause_count"], 4)
        self.assertEqual(s["added"], 1)
        self.assertEqual(s["removed"], 1)
        self.assertEqual(s["modified"], 1)
        self.assertEqual(s["unchanged"], 2)

    def test_to_dict_round_trip(self):
        d = ContractDiffer().diff(OLD, NEW)
        body = d.to_dict()
        self.assertIn("summary", body)
        self.assertIn("added", body)
        self.assertIn("removed", body)
        self.assertIn("modified", body)
        self.assertIn("unchanged", body)
        # added/removed/modified/unchanged each carry ClauseChange dicts
        for c in body["modified"]:
            self.assertIn("similarity", c)
            self.assertIn("diff_terms_added", c)
            self.assertIn("diff_terms_removed", c)


class TestDiffSemantics(unittest.TestCase):
    def test_modified_clause_records_changed_terms(self):
        d = ContractDiffer().diff(OLD, NEW)
        self.assertEqual(len(d.modified), 1)
        change = d.modified[0]
        # numeric deadlines were "thirty (30) days" vs "forty-five (45) days"
        # at minimum '30' is removed and '45' is added
        self.assertIn("30", change.diff_terms_removed)
        self.assertIn("45", change.diff_terms_added)
        self.assertLess(change.similarity, 1.0)
        self.assertGreater(change.similarity, 0.4)

    def test_unchanged_clauses_marked_correctly(self):
        d = ContractDiffer().diff(OLD, NEW)
        self.assertEqual(len(d.unchanged), 2)
        for change in d.unchanged:
            self.assertEqual(change.kind, ChangeKind.UNCHANGED)
            # similarity is from cosine on TF-IDF, so identical strings → ~1.0
            self.assertGreaterEqual(change.similarity, 0.95)

    def test_removed_clause(self):
        d = ContractDiffer().diff(OLD, NEW)
        self.assertEqual(len(d.removed), 1)
        self.assertIn("terminate", d.removed[0].old_text.lower())

    def test_added_clause(self):
        d = ContractDiffer().diff(OLD, NEW)
        self.assertEqual(len(d.added), 1)
        self.assertIn("cyber-insurance", d.added[0].new_text)

    def test_swapped_clause_order_still_matches(self):
        d = ContractDiffer().diff(OLD, list(reversed(NEW)))
        s = d.summary()
        # Invariant: every old clause is accounted for as either removed,
        # modified (matched-but-changed), or unchanged.
        self.assertEqual(
            s["removed"] + s["modified"] + s["unchanged"],
            s["old_clause_count"],
        )
        # Every new clause is accounted for as either added, modified, or unchanged.
        self.assertEqual(
            s["added"] + s["modified"] + s["unchanged"],
            s["new_clause_count"],
        )

    def test_empty_old(self):
        d = ContractDiffer().diff([], NEW)
        self.assertEqual(len(d.removed), 0)
        self.assertEqual(len(d.added), len(NEW))

    def test_empty_new(self):
        d = ContractDiffer().diff(OLD, [])
        self.assertEqual(len(d.removed), len(OLD))
        self.assertEqual(len(d.added), 0)


class TestRiskDelta(unittest.TestCase):
    def _report(self, overall: float, per_fw: dict[str, float]):
        # duck-typed compliance report
        results = {
            fw: SimpleNamespace(coverage_pct=cov)
            for fw, cov in per_fw.items()
        }
        return SimpleNamespace(
            overall_coverage_pct=lambda: overall,
            framework_results=results,
        )

    def test_delta_positive_means_improving(self):
        d = ContractDiffer().diff(OLD, NEW)
        old_r = self._report(40.0, {"SOC2": 30.0, "HIPAA": 50.0})
        new_r = self._report(70.0, {"SOC2": 75.0, "HIPAA": 65.0})
        d.with_risk_delta(old_r, new_r)
        self.assertIsNotNone(d.risk_delta)
        self.assertEqual(d.risk_delta["delta_pct"], 30.0)
        self.assertEqual(d.risk_delta["direction"], "improving")
        self.assertIn("SOC2", d.risk_delta["per_framework"])
        self.assertEqual(d.risk_delta["per_framework"]["SOC2"]["delta_pct"], 45.0)

    def test_delta_negative_means_degrading(self):
        d = ContractDiffer().diff(OLD, NEW)
        old_r = self._report(80.0, {"SOC2": 80.0})
        new_r = self._report(50.0, {"SOC2": 50.0})
        d.with_risk_delta(old_r, new_r)
        self.assertEqual(d.risk_delta["direction"], "degrading")

    def test_no_reports_leaves_risk_delta_none(self):
        d = ContractDiffer().diff(OLD, NEW)
        d.with_risk_delta(None, None)
        self.assertIsNone(d.risk_delta)


class TestValidation(unittest.TestCase):
    def test_old_must_be_list(self):
        with self.assertRaises(TypeError):
            ContractDiffer().diff("foo", ["bar"])  # type: ignore[arg-type]

    def test_bad_threshold_ordering_raises(self):
        with self.assertRaises(ValueError):
            ContractDiffer(match_threshold=0.5, modified_threshold=0.6)


if __name__ == "__main__":
    unittest.main()
