"""tests/test_compliance_scanner.py — multi-framework clause scanner."""

from __future__ import annotations

import unittest

from squash.compliance import (
    ComplianceFramework,
    ComplianceReport,
    ComplianceScanner,
    FrameworkResult,
    RequirementMatch,
    builtin_requirements,
)


_HIPAA_CLAUSES = [
    "Business associates shall execute a BAA before any PHI is disclosed.",
    "Administrative safeguards include security awareness training for all workforce members.",
    "Technical safeguards include audit controls and automatic logoff.",
    "We follow the minimum necessary standard for all uses of PHI.",
    "Breach notification to affected individuals occurs within 60 days.",
]

_PCI_CLAUSES = [
    "Cardholder data is protected with tokenization; the primary account number is never stored.",
    "Sensitive authentication data including CVV is not retained after authorization.",
    "Encryption in transit uses TLS 1.3 with strong cryptography.",
    "Multi-factor authentication is required for all administrative access.",
    "Penetration testing is performed at least annually.",
]

_SOC2_CLAUSES = [
    "Role-based access control with least privilege governs all system access.",
    "Continuous monitoring with SIEM detects security events in real time.",
    "Incident response procedures include escalation procedures and breach response.",
    "Disaster recovery and business continuity programs include RTO and RPO commitments.",
    "Confidentiality is enforced through encryption at rest with AES-256 and key management.",
]


# ── Enum + parse ─────────────────────────────────────────────────────────────


class TestFrameworkEnum(unittest.TestCase):
    def test_three_frameworks_exist(self):
        names = {m.value for m in ComplianceFramework}
        self.assertEqual(names, {"SOC2", "HIPAA", "PCI_DSS"})

    def test_parse_canonical(self):
        self.assertIs(
            ComplianceFramework.parse("SOC2"), ComplianceFramework.SOC2,
        )
        self.assertIs(
            ComplianceFramework.parse("hipaa"), ComplianceFramework.HIPAA,
        )

    def test_parse_aliases(self):
        # PCI-DSS / pci_dss / PCI DSS all resolve
        for v in ("PCI-DSS", "pci_dss", "PCI DSS"):
            self.assertIs(
                ComplianceFramework.parse(v), ComplianceFramework.PCI_DSS,
            )

    def test_parse_unknown_raises(self):
        with self.assertRaises(ValueError):
            ComplianceFramework.parse("ISO-27001")


# ── Builtin catalogues ───────────────────────────────────────────────────────


class TestBuiltinCatalogues(unittest.TestCase):
    def test_each_framework_has_requirements(self):
        for fw in ComplianceFramework:
            reqs = builtin_requirements(fw)
            self.assertGreaterEqual(len(reqs), 8, msg=fw)

    def test_every_requirement_has_patterns_and_severity(self):
        for fw in ComplianceFramework:
            for req in builtin_requirements(fw):
                self.assertTrue(req.requirement_id.startswith(fw.value)
                                or fw.value.replace("_", "-") in req.requirement_id,
                                msg=req.requirement_id)
                self.assertGreater(len(req.patterns), 0)
                self.assertIn(req.severity,
                              {"critical", "high", "medium", "low"})

    def test_pattern_weights_in_range(self):
        for fw in ComplianceFramework:
            for req in builtin_requirements(fw):
                for _, w in req.patterns:
                    self.assertGreater(w, 0.0)
                    self.assertLessEqual(w, 1.0)


# ── Scanner core ─────────────────────────────────────────────────────────────


class TestScannerCore(unittest.TestCase):
    def test_report_returns_per_framework_results(self):
        s = ComplianceScanner()
        r = s.scan(
            _SOC2_CLAUSES + _HIPAA_CLAUSES + _PCI_CLAUSES,
            [ComplianceFramework.SOC2, ComplianceFramework.HIPAA,
             ComplianceFramework.PCI_DSS],
        )
        self.assertIsInstance(r, ComplianceReport)
        self.assertEqual(len(r.framework_results), 3)
        for fw in r.framework_results:
            self.assertIsInstance(r.framework_results[fw], FrameworkResult)

    def test_soc2_clauses_match_soc2_requirements(self):
        s = ComplianceScanner()
        r = s.scan(_SOC2_CLAUSES, [ComplianceFramework.SOC2])
        result = r.framework_results[ComplianceFramework.SOC2]
        ids = {m.requirement_id for m in result.matched_requirements}
        # Expect at least the access-control, monitoring, incident-response,
        # availability, and confidentiality cores to match
        for needle in ("SOC2-CC6.1", "SOC2-CC7.2", "SOC2-CC7.3",
                       "SOC2-A1.2", "SOC2-C1.1"):
            self.assertIn(needle, ids, msg=needle)

    def test_hipaa_clauses_match_hipaa_requirements(self):
        s = ComplianceScanner()
        r = s.scan(_HIPAA_CLAUSES, [ComplianceFramework.HIPAA])
        result = r.framework_results[ComplianceFramework.HIPAA]
        ids = {m.requirement_id for m in result.matched_requirements}
        for needle in ("HIPAA-160.103-BA", "HIPAA-164.308",
                       "HIPAA-164.312", "HIPAA-164.502(b)",
                       "HIPAA-164.404"):
            self.assertIn(needle, ids, msg=needle)

    def test_pci_clauses_match_pci_requirements(self):
        s = ComplianceScanner()
        r = s.scan(_PCI_CLAUSES, [ComplianceFramework.PCI_DSS])
        result = r.framework_results[ComplianceFramework.PCI_DSS]
        ids = {m.requirement_id for m in result.matched_requirements}
        for needle in ("PCI-DSS-3", "PCI-DSS-3.2", "PCI-DSS-4",
                       "PCI-DSS-8", "PCI-DSS-11"):
            self.assertIn(needle, ids, msg=needle)

    def test_match_includes_clause_text_and_phrase(self):
        s = ComplianceScanner()
        r = s.scan(_PCI_CLAUSES, [ComplianceFramework.PCI_DSS])
        for m in r.framework_results[ComplianceFramework.PCI_DSS].matched_requirements:
            self.assertIsInstance(m, RequirementMatch)
            self.assertIn(m.matched_clause, _PCI_CLAUSES)
            self.assertTrue(m.matched_phrase)
            self.assertGreaterEqual(m.confidence, 0.5)

    def test_min_confidence_filters_low_signal_matches(self):
        s = ComplianceScanner()
        loose = "general security information about the system"
        # high threshold: no requirement should fire on a vague clause
        r = s.scan([loose], [ComplianceFramework.SOC2], min_confidence=0.95)
        self.assertEqual(
            len(r.framework_results[ComplianceFramework.SOC2].matched_requirements),
            0,
        )

    def test_overall_risk_critical_when_empty(self):
        s = ComplianceScanner()
        r = s.scan(["this contract does not say anything about security"],
                   [ComplianceFramework.SOC2])
        self.assertEqual(r.overall_risk, "critical")

    def test_overall_risk_low_when_fully_covered(self):
        s = ComplianceScanner()
        clauses = _SOC2_CLAUSES + _HIPAA_CLAUSES + _PCI_CLAUSES + [
            "Code of conduct describes our ethical values.",
            "Encryption in transit uses TLS and DLP.",
            "Privacy notice obtains consent for processing personal information.",
            "Processing integrity is verified with input validation and integrity check.",
            "Change management uses CAB and change approval workflows.",
            "Covered entity acknowledges its obligations under the privacy rule.",
            "Physical safeguards include facility access controls and workstation security.",
            "Right of access lets individuals access their medical record.",
            "Notice of privacy practices is provided to all clients.",
            "Firewall rules and DMZ network segmentation are in place.",
            "Hardening standards follow CIS Benchmarks; default passwords are changed.",
            "Secure development lifecycle includes SAST and DAST tooling.",
            "Need-to-know access is enforced via role-based access control.",
            "Centralized log management with NTP time synchronization.",
            "Information security policy and risk assessment refreshed annually.",
        ]
        r = s.scan(clauses, list(ComplianceFramework))
        self.assertIn(r.overall_risk, ("low", "medium"))
        self.assertGreaterEqual(r.overall_coverage_pct(), 50.0)

    def test_to_dict_round_trip(self):
        s = ComplianceScanner()
        r = s.scan(_SOC2_CLAUSES, [ComplianceFramework.SOC2])
        d = r.to_dict()
        self.assertIn("framework_results", d)
        self.assertIn("SOC2", d["framework_results"])
        self.assertIn("matched_requirements", d["framework_results"]["SOC2"])
        self.assertEqual(d["clause_count"], len(_SOC2_CLAUSES))

    def test_scan_validates_clauses(self):
        s = ComplianceScanner()
        with self.assertRaises(TypeError):
            s.scan(["ok", 5])  # type: ignore[list-item]

    def test_scan_validates_min_confidence(self):
        s = ComplianceScanner()
        with self.assertRaises(ValueError):
            s.scan(_SOC2_CLAUSES, min_confidence=1.5)

    def test_default_frameworks_scans_all(self):
        s = ComplianceScanner()
        r = s.scan(_HIPAA_CLAUSES)  # no framework filter
        self.assertEqual(len(r.framework_results), 3)


if __name__ == "__main__":
    unittest.main()
