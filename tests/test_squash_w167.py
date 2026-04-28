"""tests/test_squash_w167.py — W167: squash watch mode + W168: install-hook."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


# ── W167: squash watch ─────────────────────────────────────────────────────────


class TestWatchCommandHelp(unittest.TestCase):
    """squash watch --help smoke test."""

    def test_watch_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "watch", "--help"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertIn("watch", result.stdout.lower())

    def test_watch_default_args_accepted(self):
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "watch", "--help"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertIn("interval", result.stdout.lower())
        self.assertIn("policy", result.stdout.lower())

    def test_watch_on_fail_choices_documented(self):
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "watch", "--help"],
            capture_output=True, text=True, timeout=15,
        )
        for choice in ("log", "notify", "exit"):
            self.assertIn(choice, result.stdout)


class TestSnapshotDir(unittest.TestCase):
    """_snapshot_dir utility for file change detection."""

    def setUp(self):
        from squash.cli import _snapshot_dir
        self.snapshot_dir = _snapshot_dir

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = self.snapshot_dir(tmp)
        self.assertEqual(snap, {})

    def test_detects_model_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "model.safetensors").write_bytes(b"\x00" * 16)
            (Path(tmp) / "config.json").write_text('{"a": 1}')
            (Path(tmp) / "readme.txt").write_text("not watched")
            snap = self.snapshot_dir(tmp)
        self.assertIn("model.safetensors", snap)
        self.assertIn("config.json", snap)
        self.assertNotIn("readme.txt", snap)

    def test_detects_nested_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "weights"
            nested.mkdir()
            (nested / "model.bin").write_bytes(b"\x00" * 8)
            snap = self.snapshot_dir(tmp)
        found = any("model.bin" in k for k in snap.keys())
        self.assertTrue(found)

    def test_returns_mtime_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.json").write_text("{}")
            snap = self.snapshot_dir(tmp)
        for v in snap.values():
            self.assertIsInstance(v, float)

    def test_unchanged_dir_same_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.json").write_text("{}")
            s1 = self.snapshot_dir(tmp)
            s2 = self.snapshot_dir(tmp)
        self.assertEqual(s1, s2)

    def test_changed_file_changes_snapshot(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "config.json"
            f.write_text('{"v":1}')
            s1 = self.snapshot_dir(tmp)
            time.sleep(0.05)
            f.write_text('{"v":2}')
            s2 = self.snapshot_dir(tmp)
        self.assertNotEqual(s1, s2)

    def test_watch_extensions_set(self):
        from squash.cli import _WATCH_EXTENSIONS
        required = {".safetensors", ".bin", ".pt", ".pth", ".json", ".yaml", ".onnx"}
        self.assertTrue(required.issubset(_WATCH_EXTENSIONS))


# ── W168: squash install-hook ──────────────────────────────────────────────────


class TestInstallHookCommand(unittest.TestCase):
    """squash install-hook command."""

    def _git_init(self, tmp: str) -> Path:
        """Initialize a bare git repo in tmp dir."""
        root = Path(tmp)
        (root / ".git").mkdir()
        (root / ".git" / "hooks").mkdir()
        return root

    def _run_install_hook(self, args: list[str]) -> tuple[int, str]:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "install-hook", *args],
            capture_output=True, text=True, timeout=15,
        )
        return result.returncode, result.stdout + result.stderr

    def test_install_hook_help(self):
        rc, out = self._run_install_hook(["--help"])
        self.assertIn("hook", out.lower())

    def test_install_pre_push_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            rc, out = self._run_install_hook(["--dir", tmp, "--quiet"])
            self.assertEqual(rc, 0, f"install-hook failed:\n{out}")
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            self.assertTrue(hook.exists())

    def test_hook_file_is_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            self._run_install_hook(["--dir", tmp, "--quiet"])
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            mode = hook.stat().st_mode
            self.assertTrue(mode & stat.S_IEXEC, "hook is not executable")

    def test_hook_contains_squash_attest(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            self._run_install_hook(["--dir", tmp, "--quiet"])
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            content = hook.read_text()
            self.assertIn("squash attest", content)

    def test_hook_shebang(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            self._run_install_hook(["--dir", tmp, "--quiet"])
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            content = hook.read_text()
            self.assertTrue(content.startswith("#!/"), "hook missing shebang")

    def test_pre_commit_hook_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            rc, out = self._run_install_hook([
                "--dir", tmp, "--hook-type", "pre-commit", "--quiet"
            ])
            self.assertEqual(rc, 0, f"pre-commit install failed:\n{out}")
            hook = Path(tmp) / ".git" / "hooks" / "pre-commit"
            self.assertTrue(hook.exists())

    def test_custom_policy_in_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            self._run_install_hook([
                "--dir", tmp, "--quiet",
                "--policy", "nist-ai-rmf", "iso-42001"
            ])
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            content = hook.read_text()
            self.assertIn("nist-ai-rmf", content)
            self.assertIn("iso-42001", content)

    def test_non_git_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_install_hook(["--dir", tmp, "--quiet"])
            self.assertNotEqual(rc, 0)

    def test_idempotent_when_squash_already_in_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            hook.write_text("#!/bin/sh\n# squash already here\nsquash attest .\n")
            hook.chmod(hook.stat().st_mode | stat.S_IEXEC)

            rc, out = self._run_install_hook(["--dir", tmp])
            self.assertEqual(rc, 0)
            content = hook.read_text()
            # Should not duplicate
            self.assertEqual(content.count("squash attest"), 1)

    def test_existing_non_squash_hook_backed_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            hook = Path(tmp) / ".git" / "hooks" / "pre-push"
            hook.write_text("#!/bin/sh\n# existing hook content\necho done\n")
            hook.chmod(hook.stat().st_mode | stat.S_IEXEC)

            rc, out = self._run_install_hook(["--dir", tmp, "--quiet"])
            self.assertEqual(rc, 0)
            backup = Path(tmp) / ".git" / "hooks" / "pre-push.bak"
            self.assertTrue(backup.exists(), "backup not created")
            new_content = hook.read_text()
            self.assertIn("squash attest", new_content)
            self.assertIn("existing hook content", new_content)


class TestInstallHookUnit(unittest.TestCase):
    """_cmd_install_hook unit tests."""

    def setUp(self):
        from squash.cli import _cmd_install_hook
        self._cmd_install_hook = _cmd_install_hook

    def _git_init(self, tmp: str) -> Path:
        root = Path(tmp)
        (root / ".git").mkdir()
        (root / ".git" / "hooks").mkdir()
        return root

    def test_returns_0_on_success(self):
        import argparse
        with tempfile.TemporaryDirectory() as tmp:
            self._git_init(tmp)
            args = argparse.Namespace(dir=tmp, hook_type="pre-push", policy=["eu-ai-act"], quiet=True)
            result = self._cmd_install_hook(args, quiet=True)
        self.assertEqual(result, 0)

    def test_returns_1_no_git_dir(self):
        import argparse
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(dir=tmp, hook_type="pre-push", policy=["eu-ai-act"], quiet=True)
            result = self._cmd_install_hook(args, quiet=True)
        self.assertEqual(result, 1)


class TestHookTemplates(unittest.TestCase):
    """_PRE_PUSH_HOOK and _PRE_COMMIT_HOOK templates."""

    def test_pre_push_template_has_squash(self):
        from squash.cli import _PRE_PUSH_HOOK
        self.assertIn("squash attest", _PRE_PUSH_HOOK)
        self.assertIn("#!/bin/sh", _PRE_PUSH_HOOK)

    def test_pre_commit_template_has_squash(self):
        from squash.cli import _PRE_COMMIT_HOOK
        self.assertIn("squash attest", _PRE_COMMIT_HOOK)
        self.assertIn("#!/bin/sh", _PRE_COMMIT_HOOK)

    def test_pre_push_policy_placeholder(self):
        from squash.cli import _PRE_PUSH_HOOK
        hook = _PRE_PUSH_HOOK.format(policy_flags="--policy eu-ai-act")
        self.assertIn("eu-ai-act", hook)


if __name__ == "__main__":
    unittest.main()
