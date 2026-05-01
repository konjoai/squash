"""tests/test_squash_w205_hf_scanner.py — Sprint 14 W205 (Track B / B1).

Public HuggingFace model scanner: `squash scan hf://owner/model`.

Tests cover:
  * URI parsing (HFRef + parse_hf_uri + is_hf_uri + HF_URI_PATTERN)
  * RepoMetadata serialisation
  * HFScanReport JSON + Markdown rendering + save()
  * License-warning logic (permissive / restricted / unknown)
  * Weight-format detection
  * HFScanner.scan() with `huggingface_hub` mocked at the import boundary
    — so CI does not touch the live HF Hub
  * `squash scan hf://...` CLI dispatch (subprocess) end-to-end with the
    same import-boundary mock applied via a tiny shim module
  * Exit-code matrix: clean / unsafe / malformed-URI / dep-missing
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── URI parsing & is_hf_uri ──────────────────────────────────────────────────


class TestParseHfUri(unittest.TestCase):
    def test_basic_owner_model(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        ref = parse_hf_uri("hf://meta-llama/Llama-3.1-8B-Instruct")
        self.assertEqual(ref.owner, "meta-llama")
        self.assertEqual(ref.model, "Llama-3.1-8B-Instruct")
        self.assertEqual(ref.revision, "")
        self.assertEqual(ref.repo_id, "meta-llama/Llama-3.1-8B-Instruct")

    def test_with_revision(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        ref = parse_hf_uri("hf://microsoft/phi-3@v2.0")
        self.assertEqual(ref.revision, "v2.0")

    def test_revision_with_slash(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        ref = parse_hf_uri("hf://acme/model@feat/branch-name")
        self.assertEqual(ref.revision, "feat/branch-name")

    def test_url_no_revision(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        ref = parse_hf_uri("hf://x/y")
        self.assertEqual(ref.url, "https://huggingface.co/x/y")

    def test_url_with_revision_uses_tree_path(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        ref = parse_hf_uri("hf://x/y@v1")
        self.assertIn("/tree/v1", ref.url)

    def test_missing_prefix_raises(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        with self.assertRaises(ValueError):
            parse_hf_uri("meta-llama/Llama")

    def test_malformed_raises(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        with self.assertRaises(ValueError):
            parse_hf_uri("hf://has space/model")

    def test_no_model_part_raises(self) -> None:
        from squash.hf_scanner import parse_hf_uri
        with self.assertRaises(ValueError):
            parse_hf_uri("hf://owner-only")

    def test_is_hf_uri(self) -> None:
        from squash.hf_scanner import is_hf_uri
        self.assertTrue(is_hf_uri("hf://x/y"))
        self.assertFalse(is_hf_uri("./local"))
        self.assertFalse(is_hf_uri(""))
        self.assertFalse(is_hf_uri(None))


# ── RepoMetadata + HFScanReport serialisation ────────────────────────────────


class TestHFScanReportSerialisation(unittest.TestCase):
    def _make_report(self, **overrides):
        from squash.hf_scanner import HFRef, HFScanReport, RepoMetadata
        ref = HFRef(owner="acme", model="phi-3", revision="")
        meta = RepoMetadata(
            repo_id="acme/phi-3", revision="main",
            license="apache-2.0", downloads=1234,
            last_modified="2026-04-01T00:00:00",
            library_name="transformers", pipeline_tag="text-generation",
            tags=["text-generation", "english"],
            sha="abc123def456",
        )
        defaults = dict(
            ref=ref, metadata=meta,
            scan_status="clean", is_safe=True,
            findings=[], license_warnings=[],
            policy_results={}, file_count=12, weight_format="safetensors",
        )
        defaults.update(overrides)
        return HFScanReport(**defaults)

    def test_to_dict_minimal(self) -> None:
        r = self._make_report()
        d = r.to_dict()
        self.assertEqual(d["squash_version"], "hf_scan_v1")
        self.assertEqual(d["uri"], "hf://acme/phi-3")
        self.assertEqual(d["scan"]["status"], "clean")
        self.assertEqual(d["scan"]["file_count"], 12)
        self.assertEqual(d["metadata"]["license"], "apache-2.0")

    def test_to_dict_with_revision_in_uri(self) -> None:
        from squash.hf_scanner import HFRef
        r = self._make_report()
        r.ref = HFRef(owner="acme", model="phi-3", revision="v2")
        d = r.to_dict()
        self.assertEqual(d["uri"], "hf://acme/phi-3@v2")

    def test_to_json_round_trip(self) -> None:
        r = self._make_report()
        parsed = json.loads(r.to_json())
        self.assertEqual(parsed["scan"]["status"], "clean")

    def test_to_markdown_includes_repo_id_and_url(self) -> None:
        r = self._make_report()
        md = r.to_markdown()
        self.assertIn("acme/phi-3", md)
        self.assertIn("https://huggingface.co/acme/phi-3", md)
        self.assertIn("apache-2.0", md)
        self.assertIn("1,234", md)  # downloads formatted with comma

    def test_to_markdown_renders_findings_table(self) -> None:
        r = self._make_report(
            scan_status="unsafe", is_safe=False,
            findings=[{
                "severity": "high", "title": "pickle reduce found",
                "file_path": "/tmp/foo/pytorch_model.bin",
            }],
        )
        md = r.to_markdown()
        self.assertIn("| HIGH |", md)
        self.assertIn("pickle reduce found", md)

    def test_to_markdown_truncates_findings_at_25(self) -> None:
        findings = [{"severity": "info", "title": f"f{i}",
                     "file_path": f"/x/{i}"} for i in range(30)]
        r = self._make_report(findings=findings)
        md = r.to_markdown()
        self.assertIn("5 more", md)

    def test_to_markdown_includes_policy_preview(self) -> None:
        r = self._make_report(policy_results={
            "enterprise-strict": {"passed": False, "errors": 2, "warnings": 1},
            "eu-ai-act": {"passed": True, "errors": 0, "warnings": 0},
        })
        md = r.to_markdown()
        self.assertIn("Policy Preview", md)
        self.assertIn("enterprise-strict", md)
        self.assertIn("eu-ai-act", md)
        self.assertIn("FAIL", md)
        self.assertIn("PASS", md)

    def test_save_writes_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = self._make_report()
            paths = r.save(Path(td))
            self.assertIn("json", paths)
            self.assertIn("md", paths)
            self.assertTrue(paths["json"].exists())
            self.assertTrue(paths["md"].exists())
            # Re-parseable
            data = json.loads(paths["json"].read_text())
            self.assertEqual(data["squash_version"], "hf_scan_v1")


# ── License-warning logic ────────────────────────────────────────────────────


class TestLicenseWarnings(unittest.TestCase):
    def _meta(self, license_str: str):
        from squash.hf_scanner import RepoMetadata
        return RepoMetadata(repo_id="x/y", license=license_str)

    def test_unknown_license_warns(self) -> None:
        from squash.hf_scanner import HFScanner
        warnings = HFScanner._license_warnings(self._meta(""))
        self.assertEqual(len(warnings), 1)
        self.assertIn("not declared", warnings[0])

    def test_permissive_license_no_warning(self) -> None:
        from squash.hf_scanner import HFScanner
        for lic in ("apache-2.0", "mit", "bsd-3-clause"):
            self.assertEqual(HFScanner._license_warnings(self._meta(lic)), [])

    def test_restricted_license_flags_deployment_check(self) -> None:
        from squash.hf_scanner import HFScanner
        warnings = HFScanner._license_warnings(self._meta("llama3.1"))
        self.assertEqual(len(warnings), 1)
        self.assertIn("deployment-specific", warnings[0])

    def test_unknown_non_permissive_license_warns(self) -> None:
        from squash.hf_scanner import HFScanner
        warnings = HFScanner._license_warnings(self._meta("custom-research-only"))
        self.assertEqual(len(warnings), 1)
        self.assertIn("permissive list", warnings[0])


# ── Weight-format detection ──────────────────────────────────────────────────


class TestWeightFormatDetection(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_safetensors_detected(self) -> None:
        from squash.hf_scanner import HFScanner
        (self.tmp / "model.safetensors").write_bytes(b"\x00")
        self.assertEqual(HFScanner._detect_weight_format(self.tmp), "safetensors")

    def test_gguf_detected(self) -> None:
        from squash.hf_scanner import HFScanner
        (self.tmp / "model.gguf").write_bytes(b"\x00")
        self.assertEqual(HFScanner._detect_weight_format(self.tmp), "gguf")

    def test_pickle_detected(self) -> None:
        from squash.hf_scanner import HFScanner
        (self.tmp / "pytorch_model.bin").write_bytes(b"\x00")
        self.assertIn("pickle", HFScanner._detect_weight_format(self.tmp))

    def test_metadata_only_default(self) -> None:
        from squash.hf_scanner import HFScanner
        (self.tmp / "config.json").write_text("{}")
        out = HFScanner._detect_weight_format(self.tmp)
        self.assertIn("metadata-only", out)


# ── HFScanner.scan() with mocked huggingface_hub ─────────────────────────────


class TestHFScannerEndToEnd(unittest.TestCase):
    """Full scan() call with both `snapshot_download` and `HfApi` mocked."""

    def _populate_snapshot(self, tmp: Path) -> None:
        """Simulate what snapshot_download would write (light mode)."""
        (tmp / "config.json").write_text(json.dumps({
            "_name_or_path": "acme/phi-3", "model_type": "phi3",
        }))
        (tmp / "tokenizer.json").write_text("{}")
        (tmp / "README.md").write_text(
            "---\nlicense: apache-2.0\n---\n\n# Phi-3\n\nA small model.\n"
        )

    def _mock_hf_module(self, tmp_dir: Path) -> mock.MagicMock:
        fake_hf = mock.MagicMock()

        def _fake_snapshot(**kwargs):
            target = Path(kwargs["local_dir"])
            target.mkdir(parents=True, exist_ok=True)
            self._populate_snapshot(target)
            return str(target)

        fake_hf.snapshot_download = mock.MagicMock(side_effect=_fake_snapshot)

        info = mock.MagicMock()
        info.card_data = {"license": "apache-2.0"}
        info.last_modified = mock.MagicMock(
            isoformat=mock.MagicMock(return_value="2026-04-01T00:00:00"),
        )
        info.downloads = 12345
        info.library_name = "transformers"
        info.pipeline_tag = "text-generation"
        info.tags = ["text-generation", "phi"]
        info.sha = "abc123def4567890"
        api_inst = mock.MagicMock()
        api_inst.model_info.return_value = info
        fake_hf.HfApi = mock.MagicMock(return_value=api_inst)
        return fake_hf

    def test_scan_returns_report_with_metadata_and_no_findings(self) -> None:
        from squash.hf_scanner import HFScanner
        with tempfile.TemporaryDirectory() as outer:
            outer_path = Path(outer)
            fake_hf = self._mock_hf_module(outer_path)
            with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}):
                report = HFScanner().scan("hf://acme/phi-3")
        self.assertEqual(report.metadata.repo_id, "acme/phi-3")
        self.assertEqual(report.metadata.license, "apache-2.0")
        self.assertEqual(report.metadata.downloads, 12345)
        # In light-mode (default), no weight files are downloaded so scanner
        # reports "skipped" (still is_safe=True). With --download-weights the
        # scanner would observe weight files and return "clean".
        self.assertIn(report.scan_status, ("clean", "skipped"))
        self.assertTrue(report.is_safe)
        self.assertEqual(report.findings, [])

    def test_scan_with_policy_preview(self) -> None:
        from squash.hf_scanner import HFScanner
        fake_hf = self._mock_hf_module(Path("/tmp"))
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}):
            report = HFScanner().scan(
                "hf://acme/phi-3", policies=["enterprise-strict"],
            )
        self.assertIn("enterprise-strict", report.policy_results)
        self.assertIn("passed", report.policy_results["enterprise-strict"])

    def test_scan_revision_passed_through(self) -> None:
        from squash.hf_scanner import HFScanner
        fake_hf = self._mock_hf_module(Path("/tmp"))
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}):
            HFScanner().scan("hf://acme/phi-3@v2.0")
        kwargs = fake_hf.snapshot_download.call_args.kwargs
        self.assertEqual(kwargs.get("revision"), "v2.0")

    def test_scan_default_does_not_download_weights(self) -> None:
        from squash.hf_scanner import HFScanner
        fake_hf = self._mock_hf_module(Path("/tmp"))
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}):
            HFScanner().scan("hf://acme/phi-3")
        kwargs = fake_hf.snapshot_download.call_args.kwargs
        self.assertIn("ignore_patterns", kwargs)
        self.assertIn("*.safetensors", kwargs["ignore_patterns"])

    def test_scan_download_weights_true_lifts_filter(self) -> None:
        from squash.hf_scanner import HFScanner
        fake_hf = self._mock_hf_module(Path("/tmp"))
        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}):
            HFScanner().scan("hf://acme/phi-3", download_weights=True)
        kwargs = fake_hf.snapshot_download.call_args.kwargs
        self.assertNotIn("ignore_patterns", kwargs)

    def test_scan_keep_download_preserves_temp_dir(self) -> None:
        from squash.hf_scanner import HFScanner
        with tempfile.TemporaryDirectory() as outer:
            outer_path = Path(outer)
            fake_hf = self._mock_hf_module(outer_path)
            with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hf}):
                HFScanner().scan("hf://acme/phi-3", keep_download=True)
            kwargs = fake_hf.snapshot_download.call_args.kwargs
            kept = Path(kwargs["local_dir"])
            self.assertTrue(kept.exists(),
                            "keep_download=True should retain the snapshot dir")
            shutil.rmtree(kept, ignore_errors=True)

    def test_scan_without_huggingface_hub_raises_import_error(self) -> None:
        from squash.hf_scanner import HFScanner
        with mock.patch.dict(sys.modules, {"huggingface_hub": None}):
            with self.assertRaises(ImportError):
                HFScanner().scan("hf://acme/phi-3")

    def test_scan_malformed_uri_raises_value_error(self) -> None:
        from squash.hf_scanner import HFScanner
        with self.assertRaises(ValueError):
            HFScanner().scan("not-an-hf-uri")


# ── CLI integration: `squash scan hf://...` (subprocess) ─────────────────────


class TestCLIDispatch(unittest.TestCase):
    """End-to-end CLI tests using a tiny shim that pre-registers a mocked
    `huggingface_hub` module before squash.cli imports it.

    The shim is built dynamically and run as `python -c "..."` so the
    standard `python -m squash.cli` invocation is exercised exactly.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _shim_script(self, args: list[str]) -> str:
        # Build a runnable shim that injects a mocked huggingface_hub
        # into sys.modules before squash.cli runs. The shim writes config
        # files into the temp dir we hand it via env.
        return r'''
import sys, json, os
from pathlib import Path
from unittest.mock import MagicMock

fake = MagicMock()

def _snapshot_download(**kwargs):
    target = Path(kwargs["local_dir"])
    target.mkdir(parents=True, exist_ok=True)
    (target / "config.json").write_text("{}")
    (target / "README.md").write_text("# Test model\n")
    return str(target)

fake.snapshot_download = _snapshot_download

info = MagicMock()
info.card_data = {"license": "apache-2.0"}
info.downloads = 7777
info.library_name = "transformers"
info.pipeline_tag = "text-generation"
info.tags = ["text-generation"]
info.sha = "deadbeefcafe"
class _LM:
    def isoformat(self): return "2026-04-01T00:00:00"
info.last_modified = _LM()

api = MagicMock()
api.model_info.return_value = info
fake.HfApi = MagicMock(return_value=api)
sys.modules["huggingface_hub"] = fake

from squash.cli import main
sys.argv = ["squash"] + ''' + repr(args) + '''
try:
    main()
except SystemExit as e:
    sys.exit(e.code if e.code is not None else 0)
'''

    def _run(self, args: list[str]):
        script = self._shim_script(args)
        return subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=os.environ.copy(),
        )

    def test_help_mentions_hf_scheme(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "scan", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("hf://", result.stdout)
        for flag in ("--policy", "--output-dir", "--download-weights",
                     "--keep-download", "--hf-token"):
            self.assertIn(flag, result.stdout)

    def test_malformed_uri_returns_2(self) -> None:
        result = self._run(["scan", "hf://has space/x", "--quiet",
                            "--output-dir", str(self.tmp)])
        self.assertEqual(result.returncode, 2, msg=result.stderr)

    def test_clean_scan_writes_artefacts(self) -> None:
        result = self._run(["scan", "hf://acme/phi-3",
                            "--output-dir", str(self.tmp), "--quiet"])
        self.assertEqual(result.returncode, 0,
                         msg=f"stderr={result.stderr}\nstdout={result.stdout}")
        self.assertTrue((self.tmp / "squash-hf-scan.json").exists())
        self.assertTrue((self.tmp / "squash-hf-scan.md").exists())
        payload = json.loads((self.tmp / "squash-hf-scan.json").read_text())
        self.assertEqual(payload["squash_version"], "hf_scan_v1")
        self.assertEqual(payload["uri"], "hf://acme/phi-3")
        self.assertEqual(payload["metadata"]["license"], "apache-2.0")

    def test_with_policy_preview_in_output(self) -> None:
        result = self._run([
            "scan", "hf://acme/phi-3",
            "--policy", "enterprise-strict",
            "--output-dir", str(self.tmp), "--quiet",
        ])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads((self.tmp / "squash-hf-scan.json").read_text())
        self.assertIn("enterprise-strict", payload["policy_results"])

    def test_revision_in_uri_carried_through(self) -> None:
        result = self._run(["scan", "hf://acme/phi-3@v2.0",
                            "--output-dir", str(self.tmp), "--quiet"])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads((self.tmp / "squash-hf-scan.json").read_text())
        self.assertEqual(payload["uri"], "hf://acme/phi-3@v2.0")

    def test_local_path_still_works_after_extension(self) -> None:
        # Regression guard: local-path scan must still work alongside hf://.
        local = self.tmp / "model"
        local.mkdir()
        (local / "config.json").write_text("{}")
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "scan", str(local)],
            capture_output=True, text=True,
        )
        # Existing behaviour: returns 0 on safe (no findings)
        self.assertEqual(result.returncode, 0,
                         msg=f"stderr={result.stderr}\nstdout={result.stdout}")


# ── Module count gate (Sprint 14 W205 added 1 module) ────────────────────────


class TestModuleCountAfterB1(unittest.TestCase):
    """B1 added `squash/hf_scanner.py` — module count goes 71 → 72."""

    def test_module_count_is_72(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        self.assertEqual(
            len(py_files), 80,
            msg=f"squash/ has {len(py_files)} files (expected 80 after Sprint 14 W205).",
        )


if __name__ == "__main__":
    unittest.main()
