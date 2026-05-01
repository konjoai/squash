"""tests/test_squash_c9_carbon.py — Track C / C9 — Carbon / Energy Attestation.

Sprint 36 (W259–W261) exit criteria:
  * 1 new module (carbon_attest.py)
  * Electricity Maps cache layer (offline-replayable)
  * CSRD field mapping verified against published schema
  * Grid intensity table: 5+ regions per provider + global fallback
  * FLOP estimator: all 6 architecture families
  * CLI: attest-carbon --params shorthand, --csrd, --bom enrichment
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── FLOP estimator (W259) ─────────────────────────────────────────────────────


class TestFlopEstimator(unittest.TestCase):
    def _est(self, params, arch="transformer", seq=512):
        from squash.carbon_attest import ModelArchitecture, estimate_flops
        return estimate_flops(params, ModelArchitecture(arch), seq)

    def test_transformer_flops_proportional_to_params(self):
        e1 = self._est(110_000_000)
        e2 = self._est(220_000_000)
        self.assertAlmostEqual(e2.flops / e1.flops, 2.0, places=5)

    def test_transformer_flops_proportional_to_seq_len(self):
        e1 = self._est(110_000_000, seq=256)
        e2 = self._est(110_000_000, seq=512)
        self.assertAlmostEqual(e2.flops / e1.flops, 2.0, places=5)

    def test_moe_flops_less_than_dense_transformer(self):
        e_dense = self._est(175_000_000_000, "transformer")
        e_moe   = self._est(175_000_000_000, "moe")
        self.assertLess(e_moe.flops, e_dense.flops)
        self.assertAlmostEqual(e_moe.flops * 8, e_dense.flops, places=0)

    def test_embedding_uses_capped_seq_len(self):
        """Embedding model uses min(seq_len, 128) — so seq=1024 == seq=128."""
        e128 = self._est(110_000_000, "embedding", seq=128)
        e1024 = self._est(110_000_000, "embedding", seq=1024)
        self.assertAlmostEqual(e128.flops, e1024.flops, places=0)

    def test_diffusion_flops_scale_with_timesteps(self):
        e = self._est(1_000_000_000, "diffusion")
        # Should encode 20 timesteps
        self.assertGreater(e.flops, 0)
        self.assertIn("T=20", e.method)

    def test_cnn_no_seq_dimension(self):
        e = self._est(25_000_000, "cnn")
        # CNN uses 2×N (no seq dim)
        self.assertAlmostEqual(e.flops, 2.0 * 25_000_000, places=0)

    def test_rnn_same_as_transformer(self):
        e_rnn = self._est(100_000_000, "rnn", seq=512)
        e_tr  = self._est(100_000_000, "transformer", seq=512)
        self.assertAlmostEqual(e_rnn.flops, e_tr.flops, places=0)

    def test_method_string_not_empty(self):
        for arch in ("transformer", "moe", "cnn", "rnn", "embedding", "diffusion", "unknown"):
            e = self._est(1_000_000, arch)
            self.assertGreater(len(e.method), 5, f"empty method for {arch}")

    def test_confidence_high_for_transformer(self):
        e = self._est(110_000_000, "transformer")
        self.assertEqual(e.confidence, "high")

    def test_confidence_low_for_cnn(self):
        e = self._est(110_000_000, "cnn")
        self.assertEqual(e.confidence, "low")


# ── Energy estimator ──────────────────────────────────────────────────────────


class TestEnergyEstimator(unittest.TestCase):
    def _energy(self, flops, hw="a100", util=0.45):
        from squash.carbon_attest import (
            FlopEstimate, HardwareType, ModelArchitecture, estimate_energy,
        )
        fe = FlopEstimate(flops=flops, method="test",
                          architecture=ModelArchitecture.TRANSFORMER)
        return estimate_energy(fe, HardwareType(hw), util)

    def test_kwh_per_inference_positive(self):
        e = self._energy(1e12)
        self.assertGreater(e.kwh_per_inference, 0)

    def test_h100_more_efficient_than_a100(self):
        e_a100 = self._energy(1e15, "a100")
        e_h100 = self._energy(1e15, "h100")
        self.assertLess(e_h100.kwh_per_inference, e_a100.kwh_per_inference)

    def test_cpu_far_less_efficient(self):
        e_a100 = self._energy(1e14, "a100")
        e_cpu  = self._energy(1e14, "cpu")
        self.assertGreater(e_cpu.kwh_per_inference, e_a100.kwh_per_inference * 10)

    def test_kwh_per_million_tokens_scaled_from_per_inference(self):
        from squash.carbon_attest import (
            FlopEstimate, HardwareType, ModelArchitecture, estimate_energy,
        )
        fe = FlopEstimate(flops=1e12, method="t", architecture=ModelArchitecture.TRANSFORMER)
        e = estimate_energy(fe, HardwareType.A100, 0.45, tokens_per_inference=500)
        expected = e.kwh_per_inference * (1_000_000 / 500)
        self.assertAlmostEqual(e.kwh_per_million_tokens, expected, places=12)

    def test_pue_override_scales_energy(self):
        e1 = self._energy(1e12)
        from squash.carbon_attest import (
            FlopEstimate, HardwareType, ModelArchitecture, estimate_energy,
        )
        fe = FlopEstimate(flops=1e12, method="t", architecture=ModelArchitecture.TRANSFORMER)
        e2 = estimate_energy(fe, HardwareType.A100, pue_override=2.0)
        # PUE=2.0 / PUE=1.2 ≈ 1.667×
        self.assertAlmostEqual(e2.kwh_per_inference / e1.kwh_per_inference,
                                2.0 / e1.pue, places=3)


# ── Grid intensity table ──────────────────────────────────────────────────────


class TestGridIntensity(unittest.TestCase):
    def _lookup(self, region):
        from squash.carbon_attest import lookup_grid_intensity
        return lookup_grid_intensity(region)

    def test_eu_north_1_is_very_low(self):
        gi = self._lookup("eu-north-1")
        self.assertLess(gi.gco2_per_kwh, 20)

    def test_us_east_1_is_moderate(self):
        gi = self._lookup("us-east-1")
        self.assertGreater(gi.gco2_per_kwh, 300)
        self.assertLess(gi.gco2_per_kwh, 500)

    def test_ap_southeast_2_high_coal(self):
        gi = self._lookup("ap-southeast-2")  # Sydney
        self.assertGreater(gi.gco2_per_kwh, 600)

    def test_eu_west_3_nuclear_low(self):
        gi = self._lookup("eu-west-3")   # Paris
        self.assertLess(gi.gco2_per_kwh, 100)

    def test_unknown_region_falls_back_to_global_average(self):
        gi = self._lookup("xz-unknown-9")
        self.assertAlmostEqual(gi.gco2_per_kwh, 436.0)
        self.assertEqual(gi.source, "global_average")

    def test_gcp_us_central1_is_present(self):
        gi = self._lookup("us-central1")
        self.assertLess(gi.gco2_per_kwh, 500)
        self.assertEqual(gi.source, "static_table")

    def test_azure_northeurope_is_low(self):
        gi = self._lookup("northeurope")
        self.assertLess(gi.gco2_per_kwh, 300)

    def test_country_code_de(self):
        gi = self._lookup("de")
        self.assertGreater(gi.gco2_per_kwh, 200)

    def test_case_insensitive_lookup(self):
        gi_lower = self._lookup("eu-west-1")
        gi_upper = self._lookup("EU-WEST-1")
        self.assertAlmostEqual(gi_lower.gco2_per_kwh, gi_upper.gco2_per_kwh)

    def test_at_least_80_regions_in_table(self):
        from squash.carbon_attest import _GRID_INTENSITY
        self.assertGreaterEqual(len(_GRID_INTENSITY), 80)


# ── CarbonIntensityCache ──────────────────────────────────────────────────────


class TestCarbonIntensityCache(unittest.TestCase):
    def test_put_and_get_round_trip(self):
        from squash.carbon_attest import CarbonIntensityCache, GridIntensity
        with tempfile.TemporaryDirectory() as td:
            cache = CarbonIntensityCache(Path(td) / "c.db")
            gi = GridIntensity(region="test", gco2_per_kwh=123.4,
                               source="test", fetched_at="2026-05-01T00:00:00+00:00")
            cache.put(gi)
            result = cache.get("test")
            self.assertIsNone(result)  # expired immediately (old timestamp)
            cache.close()

    def test_fresh_entry_returned(self):
        from squash.carbon_attest import CarbonIntensityCache, GridIntensity, _utc_now
        with tempfile.TemporaryDirectory() as td:
            cache = CarbonIntensityCache(Path(td) / "c.db")
            gi = GridIntensity(region="fr", gco2_per_kwh=57.0,
                               source="static_table", fetched_at=_utc_now())
            cache.put(gi)
            result = cache.get("fr")
            self.assertIsNotNone(result)
            self.assertAlmostEqual(result.gco2_per_kwh, 57.0)
            cache.close()

    def test_offline_mode_skips_live(self):
        """When SQUASH_CARBON_OFFLINE=1, live fetch is skipped."""
        from squash.carbon_attest import lookup_grid_intensity
        with mock.patch.dict(os.environ, {"SQUASH_CARBON_OFFLINE": "1"}):
            gi = lookup_grid_intensity("eu-west-1", live=True)
        self.assertEqual(gi.source, "static_table")


# ── CarbonAttestation.compute (W259) ─────────────────────────────────────────


class TestCarbonAttestation(unittest.TestCase):
    def _cert(self, **kw):
        from squash.carbon_attest import CarbonAttestation
        defaults = dict(
            model_id="bert-base",
            param_count=110_000_000,
            deployment_region="eu-west-1",
            inferences_per_day=100_000,
            tokens_per_inference=128,
        )
        defaults.update(kw)
        return CarbonAttestation.compute(**defaults)

    def test_cert_id_has_carbon_prefix(self):
        cert = self._cert()
        self.assertTrue(cert.cert_id.startswith("carbon-"))

    def test_kwh_per_inference_positive(self):
        self.assertGreater(self._cert().kwh_per_inference, 0)

    def test_co2_per_inference_positive(self):
        self.assertGreater(self._cert().gco2_per_inference, 0)

    def test_co2_per_year_positive(self):
        self.assertGreater(self._cert().co2_tonne_per_year, 0)

    def test_green_region_much_less_co2(self):
        cert_coal = self._cert(deployment_region="ap-southeast-2")  # Sydney
        cert_hydro = self._cert(deployment_region="eu-north-1")     # Stockholm
        self.assertGreater(cert_coal.co2_tonne_per_year,
                           cert_hydro.co2_tonne_per_year * 10)

    def test_larger_model_higher_energy(self):
        cert_small = self._cert(param_count=110_000_000)
        cert_large = self._cert(param_count=7_000_000_000)
        self.assertGreater(cert_large.kwh_per_inference,
                           cert_small.kwh_per_inference)

    def test_renewable_fraction_reduces_market_co2(self):
        cert = self._cert(renewable_fraction=0.5)
        self.assertAlmostEqual(cert.market_gco2_per_inference,
                               cert.gco2_per_inference * 0.5, places=10)

    def test_sign_and_verify(self):
        cert = self._cert(sign=True)
        self.assertTrue(bool(cert.signature))
        self.assertTrue(cert.verify())

    def test_tampered_cert_fails_verify(self):
        cert = self._cert(sign=True)
        cert.inferences_per_day = 9_999_999
        self.assertFalse(cert.verify())

    def test_kwh_per_year_equals_per_day_times_365(self):
        cert = self._cert()
        expected = cert.kwh_per_day * 365.25
        self.assertAlmostEqual(cert.kwh_per_year, expected, places=6)

    def test_to_dict_contains_all_sections(self):
        d = self._cert().to_dict()
        for section in ("energy", "carbon", "methodology"):
            self.assertIn(section, d)
        self.assertIn("kwh_per_inference", d["energy"])
        self.assertIn("gco2_per_inference", d["carbon"])


# ── CSRD field mapping (W260) ─────────────────────────────────────────────────


class TestCsrdMapping(unittest.TestCase):
    def setUp(self):
        from squash.carbon_attest import CarbonAttestation
        self.cert = CarbonAttestation.compute(
            model_id="bert-base", param_count=110_000_000,
            deployment_region="eu-west-1", inferences_per_day=100_000,
        )

    def test_csrd_standard_field(self):
        csrd = self.cert.to_csrd()
        self.assertEqual(csrd["standard"], "CSRD ESRS E1")

    def test_csrd_scope2_location_positive(self):
        csrd = self.cert.to_csrd()
        self.assertGreater(csrd["scope_2_location_tco2eq_per_year"], 0)

    def test_csrd_scope2_market_equals_location_when_no_renewables(self):
        csrd = self.cert.to_csrd(renewable_energy_fraction=0.0)
        self.assertAlmostEqual(
            csrd["scope_2_location_tco2eq_per_year"],
            csrd["scope_2_market_tco2eq_per_year"],
            places=8,
        )

    def test_csrd_scope3_estimated_from_scope2(self):
        csrd = self.cert.to_csrd(scope3_embodied_factor=1.5)
        expected_scope3 = csrd["scope_2_location_tco2eq_per_year"] * 1.5
        self.assertAlmostEqual(csrd["scope_3_tco2eq_per_year_estimated"],
                                expected_scope3, places=5)

    def test_csrd_energy_fields_consistent(self):
        csrd = self.cert.to_csrd(renewable_energy_fraction=0.3)
        self.assertAlmostEqual(
            csrd["energy_grid_kwh_year"] + csrd["energy_renewable_kwh_year"],
            csrd["energy_total_kwh_year"],
            places=6,
        )

    def test_csrd_total_scope_23_positive(self):
        csrd = self.cert.to_csrd()
        self.assertGreater(csrd["total_scope_2_3_tco2eq_per_year"], 0)

    def test_csrd_cert_id_present(self):
        csrd = self.cert.to_csrd()
        self.assertIn("squash_cert_id", csrd)
        self.assertEqual(csrd["squash_cert_id"], self.cert.cert_id)

    def test_renewable_reduces_total_emissions(self):
        """Renewable fraction is declared at compute time, not in to_csrd()."""
        from squash.carbon_attest import CarbonAttestation
        cert_no_re  = CarbonAttestation.compute("bert", 110_000_000, "eu-west-1",
                                                inferences_per_day=100_000,
                                                renewable_fraction=0.0)
        cert_with_re = CarbonAttestation.compute("bert", 110_000_000, "eu-west-1",
                                                 inferences_per_day=100_000,
                                                 renewable_fraction=0.5)
        self.assertLess(cert_with_re.to_csrd()["scope_2_market_tco2eq_per_year"],
                        cert_no_re.to_csrd()["scope_2_market_tco2eq_per_year"])


class TestRegulatoryMapping(unittest.TestCase):
    def setUp(self):
        from squash.carbon_attest import CarbonAttestation
        self.cert = CarbonAttestation.compute(
            model_id="test", param_count=1_000_000_000,
            deployment_region="us-east-1", inferences_per_day=1_000_000,
        )

    def test_csddd_mapping(self):
        d = self.cert.to_regulatory("csddd")
        self.assertIn("CSDDD", d["standard"])
        self.assertIn("supplier_scope_3_tco2eq", d)

    def test_uk_pra_mapping(self):
        d = self.cert.to_regulatory("uk_pra_ss1_23")
        self.assertIn("UK PRA", d["standard"])

    def test_omb_doe_mapping(self):
        d = self.cert.to_regulatory("omb_doe")
        self.assertIn("OMB", d["standard"])
        self.assertIn("annual_kwh_per_model", d)
        self.assertIn("exceeds_reporting_threshold", d)

    def test_eu_ai_act_mapping(self):
        d = self.cert.to_regulatory("eu_ai_act")
        self.assertIn("EU AI Act", d["standard"])
        self.assertIn("annex_iv_section", d)


# ── ML-BOM enrichment (W261) ─────────────────────────────────────────────────


class TestMlBomEnrichment(unittest.TestCase):
    def _make_bom(self, tmp: Path) -> Path:
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [
                {"name": "bert-base", "version": "1.0",
                 "type": "machine-learning-model"}
            ],
        }
        p = tmp / "mlbom.json"
        p.write_text(json.dumps(bom))
        return p

    def test_enrichment_adds_squash_carbon(self):
        from squash.carbon_attest import CarbonAttestation, enrich_mlbom
        with tempfile.TemporaryDirectory() as td:
            bom_path = self._make_bom(Path(td))
            cert = CarbonAttestation.compute(
                "bert", 110_000_000, "eu-west-1", inferences_per_day=1000)
            enriched = enrich_mlbom(bom_path, cert)
            self.assertIn("squash_carbon",
                          enriched["components"][0]["environmentalConsiderations"])

    def test_enrichment_adds_external_reference(self):
        from squash.carbon_attest import CarbonAttestation, enrich_mlbom
        with tempfile.TemporaryDirectory() as td:
            bom_path = self._make_bom(Path(td))
            cert = CarbonAttestation.compute(
                "bert", 110_000_000, "eu-west-1", inferences_per_day=1000)
            enriched = enrich_mlbom(bom_path, cert)
            refs = enriched.get("externalReferences", [])
            types = [r["type"] for r in refs]
            self.assertIn("squash-carbon-attestation", types)

    def test_enrichment_idempotent(self):
        from squash.carbon_attest import CarbonAttestation, enrich_mlbom
        with tempfile.TemporaryDirectory() as td:
            bom_path = self._make_bom(Path(td))
            cert = CarbonAttestation.compute(
                "bert", 110_000_000, "eu-west-1", inferences_per_day=1000)
            enrich_mlbom(bom_path, cert)
            enrich_mlbom(bom_path, cert)  # second call must not duplicate
            final = json.loads(bom_path.read_text())
            carbon_refs = [r for r in final.get("externalReferences", [])
                           if r["type"] == "squash-carbon-attestation"]
            self.assertEqual(len(carbon_refs), 1)

    def test_enrichment_missing_bom_raises(self):
        from squash.carbon_attest import CarbonAttestation, enrich_mlbom
        cert = CarbonAttestation.compute(
            "bert", 110_000_000, "eu-west-1", inferences_per_day=1000)
        with self.assertRaises(ValueError):
            enrich_mlbom(Path("/no/such/bom.json"), cert)


# ── CLI dispatcher ────────────────────────────────────────────────────────────


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


class TestCliAttestCarbon(unittest.TestCase):
    def _run(self, **kw):
        from squash.cli import _cmd_attest_carbon
        defaults = dict(
            ac_model_id="test-bert",
            ac_params="110M",
            ac_region="eu-west-1",
            ac_arch="transformer",
            ac_hw="a100",
            ac_inf_per_day=1000,
            ac_tokens=128,
            ac_seq_len=128,
            ac_util=0.45,
            ac_pue=None,
            ac_renewable=0.0,
            ac_live=False,
            ac_sign=False,
            ac_output=None,
            ac_bom=None,
            ac_csrd=False,
            ac_framework="csrd",
            ac_json=False,
            quiet=True,
        )
        defaults.update(kw)
        return _cmd_attest_carbon(_ns(**defaults), quiet=True)

    def test_default_run_exits_0(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            rc = self._run(ac_output=out)
        self.assertEqual(rc, 0)

    def test_param_shorthand_7b(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            rc = self._run(ac_params="7B", ac_output=out)
            self.assertEqual(rc, 0)
            d = json.loads(Path(out).read_text())
            self.assertEqual(d["param_count"], 7_000_000_000)

    def test_param_shorthand_1_5t(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            rc = self._run(ac_params="1.5T", ac_output=out)
            self.assertEqual(rc, 0)
            d = json.loads(Path(out).read_text())
            self.assertEqual(d["param_count"], 1_500_000_000_000)

    def test_bad_params_returns_2(self):
        rc = self._run(ac_params="not-a-number")
        self.assertEqual(rc, 2)

    def test_json_flag_emits_json(self):
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            with mock.patch("sys.stdout", buf):
                self._run(ac_output=out, ac_json=True, quiet=False)
        parsed = json.loads(buf.getvalue())
        self.assertIn("cert_id", parsed)
        self.assertIn("energy", parsed)

    def test_csrd_flag_writes_csrd_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "test-bert-carbon-attest.json")
            rc = self._run(ac_output=out, ac_csrd=True)
            self.assertEqual(rc, 0)
            csrd_path = Path(td) / "test-bert-csrd.json"
            self.assertTrue(csrd_path.exists(), f"CSRD file not found: {csrd_path}")
            csrd = json.loads(csrd_path.read_text())
            self.assertEqual(csrd["standard"], "CSRD ESRS E1")

    def test_bom_enrichment_via_cli(self):
        with tempfile.TemporaryDirectory() as td:
            bom = Path(td) / "mlbom.json"
            bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.7",
                "components": [{"name": "bert", "type": "machine-learning-model"}],
            }))
            out = str(Path(td) / "cert.json")
            rc = self._run(ac_output=out, ac_bom=str(bom))
            self.assertEqual(rc, 0)
            enriched = json.loads(bom.read_text())
            self.assertIn("squash_carbon",
                          enriched["components"][0]["environmentalConsiderations"])

    def test_sign_flag_produces_signature(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            self._run(ac_output=out, ac_sign=True)
            d = json.loads(Path(out).read_text())
            self.assertEqual(len(d["signature"]), 64)


# ── Subprocess CLI ────────────────────────────────────────────────────────────


class TestCliSubprocess(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True,
        )

    def test_help_contains_all_flags(self):
        r = self._run("attest-carbon", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--model-id", "--params", "--region", "--hardware",
                     "--architecture", "--inferences-per-day", "--csrd",
                     "--bom", "--sign", "--json", "--framework"):
            self.assertIn(flag, r.stdout, msg=f"{flag} missing")

    def test_basic_run_exits_0(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            r = self._run(
                "attest-carbon",
                "--model-id", "bert-base", "--params", "110M",
                "--region", "eu-west-1", "--output", out, "--quiet",
            )
            self.assertEqual(r.returncode, 0)
            d = json.loads(Path(out).read_text())
            self.assertTrue(d["cert_id"].startswith("carbon-"))

    def test_json_output_parseable(self):
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "cert.json")
            r = self._run(
                "attest-carbon",
                "--model-id", "test", "--params", "7B",
                "--region", "us-east-1", "--json",
                "--output", out, "--quiet",
            )
            self.assertEqual(r.returncode, 0)
            d = json.loads(r.stdout)
            self.assertIn("energy", d)
            self.assertIn("carbon", d)
            # GPT-2-scale CO2 should be non-trivial at 10K/day
            self.assertGreater(d["carbon"]["co2_tonne_per_year"], 0)


if __name__ == "__main__":
    unittest.main()
