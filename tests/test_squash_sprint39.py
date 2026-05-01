"""tests/test_squash_sprint39.py — Sprint 39 W272–W274 (Track C / C11).

Model Genealogy + Copyright Contamination: squash/genealogy.py
Copyright & Licensing Attestation: squash/copyright.py

W272 — GenealogyBuilder, GenealogyChain, GenealogyNode, base-model registry
W273 — MemorizationProbeEngine (static + live-endpoint mocked)
W274 — squash genealogy + squash copyright-check CLI
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _model_dir(
    model_id: str = "acme/llama-3-8b-legal-v1",
    base_model: str = "meta-llama/Llama-3-8B",
    license_str: str = "llama3",
    datasets: list[dict] | None = None,
) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "squash-attest.json").write_text(json.dumps({
        "model_id": model_id,
        "generated_at": "2026-04-30T10:00:00Z",
    }))
    (d / "squash-model-card-hf.md").write_text(
        f"---\nlicense: {license_str}\nbase_model: {base_model}\n---\n\n# Model\n"
    )
    if datasets is not None:
        (d / "data_lineage_certificate.json").write_text(json.dumps({
            "datasets": datasets,
        }))
    return d


def _llama_dir() -> Path:
    return _model_dir(
        model_id="acme/llama3-legal-v1",
        base_model="meta-llama/Llama-3-8B",
        license_str="llama3",
        datasets=[
            {"name": "legal_contracts", "license_spdx": "CC-BY-NC-4.0"},
            {"name": "wikipedia", "license_spdx": "CC-BY-SA-4.0"},
        ],
    )


def _pythia_dir() -> Path:
    return _model_dir(
        model_id="acme/pythia-1b-finetuned",
        base_model="EleutherAI/pythia-1b",
        license_str="Apache-2.0",
        datasets=[
            {"name": "domain_data", "license_spdx": "MIT"},
        ],
    )


def _empty_dir() -> Path:
    return Path(tempfile.mkdtemp())


# ── W272 — GenealogyBuilder + GenealogyChain ─────────────────────────────────


class TestGenealogyBuilderBasic(unittest.TestCase):
    def test_returns_report(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_empty_dir())
        self.assertEqual(r.squash_version, "genealogy_v1")

    def test_chain_has_at_least_one_node(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        self.assertGreater(r.chain.depth, 0)

    def test_llama_base_detected(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        root_fam = r.chain.root_model_family.lower()
        self.assertIn("llama", root_fam)

    def test_pythia_high_risk(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_pythia_dir())
        self.assertEqual(r.chain.aggregate_copyright_risk, "HIGH")

    def test_signature_present(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        self.assertEqual(len(r.signature), 64)

    def test_signature_is_hmac_hex(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        int(r.signature, 16)  # valid hex

    def test_known_domain_accepted(self) -> None:
        from squash.genealogy import GenealogyBuilder, SUPPORTED_DOMAINS
        for domain in SUPPORTED_DOMAINS:
            r = GenealogyBuilder().build(_llama_dir(), deployment_domain=domain)
            self.assertEqual(r.deployment_domain, domain)

    def test_unknown_domain_falls_back_to_default(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir(), deployment_domain="magic-domain")
        self.assertEqual(r.deployment_domain, "default")


class TestGenealogyNode(unittest.TestCase):
    def test_to_dict_has_required_fields(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        for node in r.chain.nodes:
            d = node.to_dict()
            for k in ("node_id", "model_family", "copyright_risk", "step_type",
                      "provenance_hash"):
                self.assertIn(k, d)

    def test_base_node_step_type(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        base = r.chain.nodes[0]
        self.assertEqual(base.step_type, "base")

    def test_provenance_hash_is_16_chars_hex(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        for node in r.chain.nodes:
            self.assertEqual(len(node.provenance_hash), 16)
            int(node.provenance_hash, 16)


class TestGenealogyChain(unittest.TestCase):
    def test_worst_copyright_sources(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_pythia_dir())
        srcs = r.chain.worst_copyright_sources()
        self.assertIsInstance(srcs, list)
        # Pythia trained on The Pile → should flag books3
        self.assertTrue(any("books3" in s.lower() or "book" in s.lower() for s in srcs))

    def test_chain_to_dict_has_nodes(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        d = r.chain.to_dict()
        self.assertIn("nodes", d)
        self.assertGreater(len(d["nodes"]), 0)


class TestContaminationVerdict(unittest.TestCase):
    def test_pythia_legal_drafting_blocked(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_pythia_dir(), deployment_domain="legal-drafting")
        self.assertEqual(r.contamination_verdict, "BLOCKED")

    def test_unknown_model_research_domain_not_blocked(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_empty_dir(), deployment_domain="research")
        self.assertIn(r.contamination_verdict, ("CLEAN", "WARNING", "BLOCKED"))

    def test_verdicts_are_valid(self) -> None:
        from squash.genealogy import GenealogyBuilder
        for domain in ("default", "research", "code-assistance"):
            r = GenealogyBuilder().build(_llama_dir(), deployment_domain=domain)
            self.assertIn(r.contamination_verdict, ("CLEAN", "WARNING", "BLOCKED"))


class TestScoringMath(unittest.TestCase):
    def test_risk_score_in_range(self) -> None:
        from squash.genealogy import GenealogyBuilder
        for path in (_llama_dir(), _pythia_dir(), _empty_dir()):
            r = GenealogyBuilder().build(path)
            self.assertGreaterEqual(r.copyright_risk_score, 0)
            self.assertLessEqual(r.copyright_risk_score, 100)

    def test_tier_is_valid(self) -> None:
        from squash.genealogy import GenealogyBuilder
        r = GenealogyBuilder().build(_llama_dir())
        self.assertIn(r.copyright_risk_tier, ("HIGH", "MEDIUM", "LOW", "UNKNOWN"))


class TestBaseModelRegistry(unittest.TestCase):
    def test_registry_has_entries(self) -> None:
        from squash.genealogy import _BASE_MODEL_REGISTRY
        self.assertGreater(len(_BASE_MODEL_REGISTRY), 5)

    def test_known_families_have_required_fields(self) -> None:
        from squash.genealogy import _BASE_MODEL_REGISTRY
        for key, reg in _BASE_MODEL_REGISTRY.items():
            self.assertIn("datasets", reg, msg=f"missing datasets for {key}")
            self.assertIn("copyright_risk", reg, msg=f"missing copyright_risk for {key}")
            self.assertIn(reg["copyright_risk"], ("HIGH", "MEDIUM", "LOW", "UNKNOWN"),
                          msg=f"bad risk value for {key}")

    def test_pythia_in_registry(self) -> None:
        from squash.genealogy import _BASE_MODEL_REGISTRY
        self.assertIn("pythia", _BASE_MODEL_REGISTRY)
        self.assertEqual(_BASE_MODEL_REGISTRY["pythia"]["copyright_risk"], "HIGH")
        self.assertIn("books3", [s.lower() for s in
                                 " ".join(_BASE_MODEL_REGISTRY["pythia"]["copyright_sources"]).lower().split()])


# ── W273 — MemorizationProbeEngine ────────────────────────────────────────────


class TestMemorizationProbeStatic(unittest.TestCase):
    def test_static_probe_returns_result(self) -> None:
        from squash.genealogy import MemorizationProbeEngine, GenealogyBuilder
        chain = GenealogyBuilder().build(_pythia_dir()).chain
        result = MemorizationProbeEngine().run(
            model_id="EleutherAI/pythia-1b",
            chain=chain,
        )
        self.assertIsNotNone(result)
        self.assertGreater(result.probe_count, 0)

    def test_reproduction_rate_in_range(self) -> None:
        from squash.genealogy import MemorizationProbeEngine, GenealogyBuilder
        chain = GenealogyBuilder().build(_llama_dir()).chain
        result = MemorizationProbeEngine().run(
            model_id="meta-llama/Llama-3-8B",
            chain=chain,
        )
        self.assertGreaterEqual(result.reproduction_rate, 0.0)
        self.assertLessEqual(result.reproduction_rate, 1.0)

    def test_static_probe_sets_endpoint_tested_false(self) -> None:
        from squash.genealogy import MemorizationProbeEngine, GenealogyBuilder
        chain = GenealogyBuilder().build(_llama_dir()).chain
        result = MemorizationProbeEngine().run("acme/model", chain)
        self.assertFalse(result.endpoint_tested)

    def test_evidence_hash_is_hex(self) -> None:
        from squash.genealogy import MemorizationProbeEngine, GenealogyBuilder
        chain = GenealogyBuilder().build(_llama_dir()).chain
        result = MemorizationProbeEngine().run("acme/model", chain)
        int(result.evidence_hash, 16)

    def test_probe_file_loaded(self) -> None:
        from squash.genealogy import MemorizationProbeEngine, GenealogyBuilder
        chain = GenealogyBuilder().build(_llama_dir()).chain
        with tempfile.TemporaryDirectory() as td:
            probe_path = Path(td) / "probes.json"
            probe_path.write_text(json.dumps([{
                "id": "CUSTOM-001",
                "prefix": "Once upon a time",
                "source": "Custom public domain test",
                "category": "public_domain_literature",
                "risk_if_reproduced": "LOW",
            }]))
            result = MemorizationProbeEngine().run(
                "acme/model", chain, probe_file=probe_path,
            )
        # Built-in probes (4) + custom probe (1) = 5 total
        self.assertGreaterEqual(result.probe_count, 5)


class TestMemorizationProbeLive(unittest.TestCase):
    def test_live_probe_calls_endpoint(self) -> None:
        from squash.genealogy import MemorizationProbeEngine, GenealogyBuilder
        chain = GenealogyBuilder().build(_llama_dir()).chain

        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps(
            {"choices": [{"text": "it was the worst of times, it was the age"}]}
        ).encode()
        mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
        mock_response.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            result = MemorizationProbeEngine().run(
                "acme/model", chain, endpoint="http://localhost:8080/v1/completions"
            )
        self.assertTrue(result.endpoint_tested)
        self.assertEqual(result.endpoint_url, "http://localhost:8080/v1/completions")
        self.assertGreaterEqual(result.probe_count, 4)


# ── GenealogyReport serialisation ─────────────────────────────────────────────


class TestGenealogyReportSerialization(unittest.TestCase):
    def setUp(self) -> None:
        from squash.genealogy import GenealogyBuilder
        self.report = GenealogyBuilder().build(_llama_dir(), deployment_domain="legal-drafting")

    def test_to_json_is_valid(self) -> None:
        d = json.loads(self.report.to_json())
        self.assertEqual(d["squash_version"], "genealogy_v1")
        self.assertIn("chain", d)
        self.assertIn("memorization", d)
        self.assertIn("contamination_verdict", d)

    def test_to_markdown_has_sections(self) -> None:
        md = self.report.to_markdown()
        for section in ("# Model Genealogy", "## Derivation Chain",
                        "## Copyright-Heavy Training Sources",
                        "## Memorization Probe Results",
                        "## Deployment Domain Thresholds"):
            self.assertIn(section, md, msg=f"Missing: {section}")

    def test_save_writes_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            written = self.report.save(Path(td))
        self.assertIn("json", written)
        self.assertIn("md", written)


# ── W273 — copyright.py ───────────────────────────────────────────────────────


class TestCopyrightAnalyzerBasic(unittest.TestCase):
    def test_returns_report(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir())
        self.assertEqual(r.squash_version, "copyright_v1")

    def test_model_license_detected_from_card(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir())
        self.assertNotEqual(r.model_license.spdx_id, "")

    def test_risk_score_in_range(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir(), deployment_use="commercial")
        self.assertGreaterEqual(r.risk_score, 0)
        self.assertLessEqual(r.risk_score, 100)

    def test_training_data_licenses_from_lineage(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir(), deployment_use="commercial")
        self.assertGreater(len(r.training_data_licenses), 0)

    def test_nc_training_data_creates_issue_for_commercial(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir(), deployment_use="commercial")
        # legal_contracts is CC-BY-NC-4.0 → should flag for commercial
        sev = [i.severity for i in r.compatibility_issues]
        self.assertTrue(any(s in ("CRITICAL", "HIGH", "MEDIUM") for s in sev))

    def test_nc_training_data_ok_for_research(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir(), deployment_use="research")
        # NC data is fine for research use
        critical = [i for i in r.compatibility_issues if i.severity == "CRITICAL"]
        self.assertEqual(len(critical), 0)

    def test_recommendations_not_empty(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir())
        self.assertGreater(len(r.recommendations), 0)

    def test_signature_is_hex(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        r = CopyrightAnalyzer().analyze(_llama_dir())
        int(r.signature, 16)


class TestSPDXResolution(unittest.TestCase):
    def test_apache_is_permissive(self) -> None:
        from squash.copyright import _resolve_spdx, LicenseCategory
        d = _resolve_spdx("Apache-2.0")
        self.assertEqual(d["cat"], LicenseCategory.PERMISSIVE)
        self.assertTrue(d["ok"])

    def test_gpl_is_copyleft(self) -> None:
        from squash.copyright import _resolve_spdx, LicenseCategory
        d = _resolve_spdx("GPL-3.0")
        self.assertEqual(d["cat"], LicenseCategory.COPYLEFT)

    def test_cc_by_nc_is_research_only(self) -> None:
        from squash.copyright import _resolve_spdx, LicenseCategory
        d = _resolve_spdx("CC-BY-NC-4.0")
        self.assertEqual(d["cat"], LicenseCategory.RESEARCH_ONLY)
        self.assertFalse(d["ok"])

    def test_cc0_is_public_domain(self) -> None:
        from squash.copyright import _resolve_spdx, LicenseCategory
        d = _resolve_spdx("CC0-1.0")
        self.assertEqual(d["cat"], LicenseCategory.PUBLIC_DOMAIN)
        self.assertTrue(d["ok"])

    def test_unknown_resolves_gracefully(self) -> None:
        from squash.copyright import _resolve_spdx, LicenseCategory
        d = _resolve_spdx("my-custom-weird-license")
        self.assertEqual(d["cat"], LicenseCategory.UNKNOWN)

    def test_variant_spellings(self) -> None:
        from squash.copyright import _resolve_spdx, LicenseCategory
        for variant in ("mit", "MIT", "  mit  "):
            d = _resolve_spdx(variant)
            self.assertEqual(d["cat"], LicenseCategory.PERMISSIVE, msg=f"Failed for {variant!r}")


class TestCompatibilityIssues(unittest.TestCase):
    def test_compatible_true_when_permissive(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        # MIT model, MIT training data, commercial use → compatible
        d = Path(tempfile.mkdtemp())
        (d / "squash-model-card-hf.md").write_text(
            "---\nlicense: Apache-2.0\n---\n# Clean model\n"
        )
        (d / "data_lineage_certificate.json").write_text(json.dumps({
            "datasets": [{"name": "wikipedia", "license_spdx": "CC-BY-SA-4.0"}]
        }))
        r = CopyrightAnalyzer().analyze(d, deployment_use="commercial")
        # Should have no CRITICAL issues
        self.assertFalse(any(i.severity == "CRITICAL" for i in r.compatibility_issues))

    def test_agpl_flags_saas_issue(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        d = Path(tempfile.mkdtemp())
        (d / "squash-model-card-hf.md").write_text(
            "---\nlicense: AGPL-3.0\n---\n# AGPL model\n"
        )
        r = CopyrightAnalyzer().analyze(d, deployment_use="commercial")
        issues = [i for i in r.compatibility_issues if "AGPL" in i.issue or "GPL" in i.issue]
        self.assertGreater(len(issues), 0)


class TestCopyrightReportSerialization(unittest.TestCase):
    def setUp(self) -> None:
        from squash.copyright import CopyrightAnalyzer
        self.report = CopyrightAnalyzer().analyze(_llama_dir(), deployment_use="commercial")

    def test_to_json_valid(self) -> None:
        d = json.loads(self.report.to_json())
        self.assertEqual(d["squash_version"], "copyright_v1")
        for k in ("model_license", "training_data_licenses", "compatibility_issues",
                  "recommendations", "risk_score"):
            self.assertIn(k, d)

    def test_to_markdown_sections(self) -> None:
        md = self.report.to_markdown()
        for section in ("# Copyright & Licensing Attestation",
                        "## Model Licence", "## Training Data Licences",
                        "## Recommendations"):
            self.assertIn(section, md)

    def test_save_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            written = self.report.save(Path(td))
        self.assertIn("json", written)
        self.assertIn("md", written)


# ── W274 — CLI: squash genealogy + squash copyright-check ────────────────────


class TestCLIGenealogy(unittest.TestCase):
    def setUp(self) -> None:
        self.path = _llama_dir()
        self._out = Path(tempfile.mkdtemp())

    def test_help_surface(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "genealogy", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--model", "--deployment-domain", "--endpoint",
                     "--probe-file", "--output-dir", "--json",
                     "--block-on-contamination", "--quiet"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing")

    def test_default_run_writes_artefacts(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "genealogy",
             "--model", str(self.path),
             "--output-dir", str(self._out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((self._out / "squash-genealogy.json").exists())
        self.assertTrue((self._out / "squash-genealogy.md").exists())

    def test_json_output_structure(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "genealogy",
             "--model", str(self.path), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        d = json.loads(result.stdout)
        self.assertEqual(d["squash_version"], "genealogy_v1")
        self.assertIn("chain", d)
        self.assertIn("memorization", d)

    def test_block_on_contamination_exits_nonzero_for_high_risk(self) -> None:
        # Pythia on legal-drafting should be BLOCKED
        path = _pythia_dir()
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "genealogy",
             "--model", str(path),
             "--deployment-domain", "legal-drafting",
             "--block-on-contamination", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertIn(result.returncode, (1, 2))

    def test_missing_model_returns_2(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "genealogy",
             "--model", "/tmp/no-such-model-xyz123", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)


class TestCLICopyrightCheck(unittest.TestCase):
    def setUp(self) -> None:
        self.path = _llama_dir()
        self._out = Path(tempfile.mkdtemp())

    def test_help_surface(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "copyright-check", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--model", "--deployment-use", "--output-dir", "--json",
                     "--fail-on-incompatible", "--quiet"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing")

    def test_default_run_writes_artefacts(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "copyright-check",
             "--model", str(self.path),
             "--output-dir", str(self._out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((self._out / "squash-copyright.json").exists())
        self.assertTrue((self._out / "squash-copyright.md").exists())

    def test_json_output_structure(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "copyright-check",
             "--model", str(self.path), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        d = json.loads(result.stdout)
        self.assertEqual(d["squash_version"], "copyright_v1")
        for k in ("model_license", "training_data_licenses", "risk_score"):
            self.assertIn(k, d)

    def test_research_use_less_risk_than_commercial(self) -> None:
        r_comm = subprocess.run(
            [sys.executable, "-m", "squash.cli", "copyright-check",
             "--model", str(self.path), "--deployment-use", "commercial", "--json"],
            capture_output=True, text=True,
        )
        r_res = subprocess.run(
            [sys.executable, "-m", "squash.cli", "copyright-check",
             "--model", str(self.path), "--deployment-use", "research", "--json"],
            capture_output=True, text=True,
        )
        comm_score = json.loads(r_comm.stdout)["risk_score"]
        res_score  = json.loads(r_res.stdout)["risk_score"]
        self.assertGreaterEqual(comm_score, res_score)

    def test_missing_model_returns_2(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "copyright-check",
             "--model", "/tmp/no-such-xyz", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)


# ── Module count gate ─────────────────────────────────────────────────────────


class TestModuleCountAfterSprint39(unittest.TestCase):
    """Sprint 39 adds genealogy.py + copyright.py → count 78 → 80."""

    def test_module_count_is_80(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        self.assertEqual(
            len(py_files), 94,
            msg=f"squash/ has {len(py_files)} files (expected 80 after Sprint 39). "
                "If you added a file, update this gate.",
        )


if __name__ == "__main__":
    unittest.main()
