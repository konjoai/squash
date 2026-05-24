"""tests/test_contract_obligations.py — regex obligation extraction."""

from __future__ import annotations

import unittest

from squash.contracts.obligations import (
    MODAL_WEIGHTS,
    Obligation,
    ObligationExtractor,
    extract_obligations,
)


class TestObligationDataclass(unittest.TestCase):
    def test_to_dict_round_trip(self):
        o = Obligation(
            party="Vendor", obligation="deliver Services",
            modal="shall", strength=1.0,
            deadline="within 30 days", condition="upon written notice",
            source_clause="full text", source_index=2,
        )
        d = o.to_dict()
        self.assertEqual(d["party"], "Vendor")
        self.assertEqual(d["strength"], 1.0)
        self.assertEqual(d["deadline"], "within 30 days")

    def test_is_binding_threshold(self):
        weak = Obligation("X", "do thing", modal="may", strength=0.40)
        strong = Obligation("X", "do thing", modal="shall", strength=1.00)
        self.assertFalse(weak.is_binding)
        self.assertTrue(strong.is_binding)


class TestExtractionBasics(unittest.TestCase):
    def test_simple_shall_clause(self):
        ex = ObligationExtractor()
        out = ex.extract_from_text(
            "The Vendor shall deliver Services within thirty (30) days."
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].party, "Vendor")
        self.assertEqual(out[0].modal, "shall")
        self.assertIn("deliver Services", out[0].obligation)
        self.assertEqual(out[0].deadline, "within thirty (30) days")
        self.assertTrue(out[0].is_binding)

    def test_multiple_obligations_in_text(self):
        text = (
            "The Vendor shall deliver Services within thirty (30) days. "
            "The Client agrees to pay all invoices within fifteen (15) days. "
            "Customer must maintain insurance during the Term."
        )
        out = extract_obligations(text)
        self.assertEqual(len(out), 3)
        parties = {o.party for o in out}
        self.assertEqual(parties, {"Vendor", "Client", "Customer"})

    def test_clauses_list_path(self):
        clauses = [
            "Provider shall provide 99.9% uptime measured monthly.",
            "Receiving Party undertakes to maintain confidentiality.",
        ]
        out = ObligationExtractor().extract_from_clauses(clauses)
        self.assertEqual(len(out), 2)
        # Verifies the source_index round-trips
        self.assertEqual(out[0].source_index, 0)
        self.assertEqual(out[1].source_index, 1)
        # Decimal "99.9%" must NOT cut the predicate at the period
        self.assertIn("99.9%", out[0].obligation)


class TestModalSemantics(unittest.TestCase):
    def test_modal_weights_known(self):
        ex = ObligationExtractor()
        binding_text = "Vendor shall provide the deliverables."
        weak_text = "Customer may renew the subscription."
        binding = ex.extract_from_text(binding_text)
        weak = ex.extract_from_text(weak_text)
        self.assertEqual(binding[0].strength, MODAL_WEIGHTS["shall"])
        self.assertEqual(weak[0].strength, MODAL_WEIGHTS["may"])
        self.assertTrue(binding[0].is_binding)
        self.assertFalse(weak[0].is_binding)

    def test_agrees_to_modal(self):
        out = extract_obligations(
            "The Buyer agrees to pay all amounts when due."
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].modal, "agrees to")


class TestPartyHandling(unittest.TestCase):
    def test_connector_at_sentence_start_skipped(self):
        """`If a breach occurs, Vendor shall …` → party MUST be Vendor."""
        out = extract_obligations(
            "If a breach occurs, Vendor shall remediate within 24 hours."
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].party, "Vendor")
        self.assertEqual(out[0].deadline, "within 24 hours")

    def test_either_party_role_label(self):
        out = extract_obligations(
            "Either Party may terminate this Agreement upon thirty (30) "
            "days written notice."
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].party, "Either Party")
        # weak modal — discretionary, not binding
        self.assertFalse(out[0].is_binding)

    def test_all_caps_party_label(self):
        out = extract_obligations("ACME CORP shall indemnify the Buyer.")
        self.assertGreaterEqual(len(out), 1)
        self.assertEqual(out[0].party, "ACME CORP")

    def test_whereas_recital_skipped(self):
        out = extract_obligations(
            "WHEREAS the parties wish to enter into this Agreement, "
            "the Vendor shall provide the Services."
        )
        # the WHEREAS prefix should suppress the whole clause being treated
        # as an obligation, but the *second* sentence is still picked up
        # from the same input.
        parties = {o.party for o in out}
        self.assertNotIn("WHEREAS", parties)


class TestConditionsAndDeadlines(unittest.TestCase):
    def test_deadline_calendar_date(self):
        out = extract_obligations(
            "Vendor shall complete the audit by December 31, 2026."
        )
        self.assertEqual(len(out), 1)
        self.assertIn("December", out[0].deadline)

    def test_deadline_recurrent(self):
        out = extract_obligations(
            "Provider shall report uptime on a monthly basis."
        )
        self.assertEqual(len(out), 1)
        self.assertIn("monthly", out[0].deadline)

    def test_condition_upon_notice(self):
        out = extract_obligations(
            "Each Party may terminate upon written notice of sixty (60) days."
        )
        self.assertEqual(len(out), 1)
        self.assertIn("upon written notice", out[0].condition)

    def test_condition_if_clause(self):
        out = extract_obligations(
            "If a breach occurs, the Vendor shall remediate within 24 hours."
        )
        self.assertEqual(len(out), 1)
        self.assertIn("breach", out[0].condition)


class TestValidation(unittest.TestCase):
    def test_text_must_be_str(self):
        with self.assertRaises(TypeError):
            ObligationExtractor().extract_from_text(123)  # type: ignore[arg-type]

    def test_clauses_must_be_strs(self):
        with self.assertRaises(TypeError):
            ObligationExtractor().extract_from_clauses(["ok", 5])  # type: ignore[list-item]

    def test_empty_text_returns_empty_list(self):
        self.assertEqual(extract_obligations(""), [])


if __name__ == "__main__":
    unittest.main()
