"""tests/test_squash_w209_w210_digest.py — Sprint 15 W209/W210 (Track B / B3).

Compliance Digest Builder + `squash digest preview|send` CLI.

W209 — ComplianceDigestBuilder + ComplianceDigest in notifications.py
W210 — squash digest preview / send CLI with SMTP wiring + dry-run

The SMTP send is exercised end-to-end with `smtplib.SMTP` mocked at the
import boundary. The Dashboard is built from synthesised ModelRow fixtures
so tests do not depend on real attestation data on disk.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Shared fixtures ──────────────────────────────────────────────────────────


def _make_dashboard(rows: int = 2, **overrides):
    """Build a minimal Dashboard with `rows` synthetic model rows."""
    from squash.dashboard import Dashboard, ModelRow
    model_rows = []
    for i in range(rows):
        # Mix of scores so top-mover ranking has something to sort.
        score = 92.0 - (i * 25)
        model_rows.append(ModelRow(
            model_id=f"acme/model-{i}",
            environment="prod" if i == 0 else "staging",
            compliance_score=score,
            risk_tier="HIGH" if score < 60 else "MEDIUM" if score < 80 else "LOW",
            open_violations=max(0, 3 - i),
            open_cves=i,
            last_attested=f"2026-04-{25 + i:02d}",
            drift_detected=(i == 0),
        ))
    overall = (
        sum(r.compliance_score for r in model_rows) / len(model_rows)
        if model_rows else None
    )
    defaults = dict(
        generated_at="2026-04-30T00:00:00Z",
        total_models=rows,
        models_passing=sum(1 for r in model_rows
                           if r.compliance_score >= 80 and r.open_violations == 0),
        models_failing=sum(1 for r in model_rows if r.compliance_score < 70),
        models_unattested=0,
        overall_score=round(overall, 1) if overall is not None else None,
        total_violations=sum(r.open_violations for r in model_rows),
        critical_violations=sum(1 for r in model_rows if r.open_violations >= 3),
        total_cves=sum(r.open_cves for r in model_rows),
        critical_cves=0,
        eu_days_remaining=94,
        next_deadline_label="EU AI Act enforcement",
        portfolio_trend="stable",
        model_rows=model_rows,
    )
    defaults.update(overrides)
    return Dashboard(**defaults)


# ── W209 — ComplianceDigestBuilder ───────────────────────────────────────────


class TestComplianceDigestBuilder(unittest.TestCase):
    def test_invalid_period_raises(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        with self.assertRaises(ValueError):
            ComplianceDigestBuilder().build(
                period="quarterly", dashboard=_make_dashboard(rows=1),
            )

    def test_summary_pulls_from_dashboard(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=3),
        )
        self.assertEqual(d.summary["total_models"], 3)
        self.assertIn("overall_score", d.summary)

    def test_top_movers_sorted_worst_first(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=3),
        )
        # First mover should be the worst (most violations / lowest score).
        self.assertEqual(d.top_movers[0].model_id, "acme/model-0")

    def test_top_movers_capped_at_5(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=8),
        )
        self.assertLessEqual(len(d.top_movers), 5)

    def test_score_history_produces_delta_arrows(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
            # Top mover (model-0) currently 92; previously 100 → delta -8
            score_history={"acme/model-0": 100.0, "acme/model-1": 90.0},
        )
        first = d.top_movers[0]
        self.assertEqual(first.model_id, "acme/model-0")
        self.assertIsNotNone(first.score_delta)
        self.assertLess(first.score_delta, 0)

    def test_no_score_history_yields_none_delta(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
        )
        self.assertIsNone(d.top_movers[0].score_delta)

    def test_deadlines_sorted_soonest_first(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        # Pin "now" so the deadlines are deterministic (Apr 30, 2026).
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=1),
            now=dt.datetime(2026, 4, 30, tzinfo=dt.timezone.utc),
        )
        days = [row.days_remaining for row in d.deadlines if row.days_remaining >= 0]
        self.assertEqual(days, sorted(days))  # soonest first

    def test_deadlines_past_buried_at_end(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=1),
            # After all default deadlines (post Aug 2, 2026)
            now=dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc),
        )
        # All defaults are past → all entries have negative days
        self.assertTrue(all(row.days_remaining < 0 for row in d.deadlines))

    def test_subject_includes_period_and_score(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
            org_name="Acme",
        )
        self.assertIn("Weekly", d.subject)
        self.assertIn("Acme", d.subject)
        self.assertIn("score", d.subject.lower())

    def test_subject_includes_imminent_deadline(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=1),
            now=dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc),
        )
        # EU AI Act is 18 days out → should be tail-mentioned
        self.assertIn("EU AI Act", d.subject)

    def test_text_body_includes_all_sections(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="monthly", dashboard=_make_dashboard(rows=2),
            org_name="Acme", dashboard_url="https://app.getsquash.dev/acme",
        )
        for section in ("Portfolio summary", "Top 5 risk movers",
                        "Regulatory deadlines", "View live dashboard"):
            self.assertIn(section, d.text_body)

    def test_text_body_when_no_models(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=0),
        )
        self.assertIn("No models tracked", d.text_body)

    def test_html_body_is_email_safe(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
            org_name="Acme & Co.",  # check escaping
            dashboard_url="https://app.getsquash.dev",
        )
        # No <style>/<link>/<script>/javascript: — email-client-safe
        for forbidden in ("<style", "<link", "<script", "javascript:"):
            self.assertNotIn(forbidden, d.html_body)
        # Org name escaped
        self.assertIn("Acme &amp; Co.", d.html_body)
        # Dashboard link rendered
        self.assertIn("View live dashboard", d.html_body)

    def test_html_body_renders_drift_pill(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
        )
        # First synth row has drift_detected=True
        self.assertIn(">drift<", d.html_body)

    def test_html_body_renders_score_delta_arrows(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
            score_history={"acme/model-0": 90.0, "acme/model-1": 50.0},
        )
        self.assertTrue("▼" in d.html_body or "▲" in d.html_body)

    def test_to_dict_round_trip(self) -> None:
        from squash.notifications import ComplianceDigestBuilder
        d = ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
        )
        out = d.to_dict()
        self.assertEqual(out["squash_version"], "compliance_digest_v1")
        self.assertEqual(out["period"], "weekly")
        self.assertIn("summary", out)
        self.assertIn("top_movers", out)
        self.assertIn("deadlines", out)


# ── send_email_digest + SmtpConfig ───────────────────────────────────────────


class TestSmtpConfig(unittest.TestCase):
    def setUp(self) -> None:
        # Save and restore env vars
        self._saved = {
            k: os.environ.get(k)
            for k in (
                "SQUASH_SMTP_HOST", "SQUASH_SMTP_PORT", "SQUASH_SMTP_USER",
                "SQUASH_SMTP_PASSWORD", "SQUASH_SMTP_FROM", "SQUASH_SMTP_TLS",
            )
        }

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_env_var_fallback(self) -> None:
        from squash.notifications import SmtpConfig
        os.environ["SQUASH_SMTP_HOST"] = "smtp.example.com"
        os.environ["SQUASH_SMTP_FROM"] = "noreply@example.com"
        cfg = SmtpConfig()
        self.assertEqual(cfg.host, "smtp.example.com")
        self.assertEqual(cfg.from_addr, "noreply@example.com")
        self.assertTrue(cfg.is_configured)

    def test_explicit_args_override_env(self) -> None:
        from squash.notifications import SmtpConfig
        os.environ["SQUASH_SMTP_HOST"] = "from-env.example.com"
        cfg = SmtpConfig(host="from-arg.example.com", from_addr="x@x.com")
        self.assertEqual(cfg.host, "from-arg.example.com")

    def test_is_configured_false_when_unset(self) -> None:
        from squash.notifications import SmtpConfig
        for k in self._saved:
            os.environ.pop(k, None)
        cfg = SmtpConfig()
        self.assertFalse(cfg.is_configured)


class TestSendEmailDigest(unittest.TestCase):
    def _digest(self):
        from squash.notifications import ComplianceDigestBuilder
        return ComplianceDigestBuilder().build(
            period="weekly", dashboard=_make_dashboard(rows=2),
            org_name="Acme",
        )

    def test_no_recipients_returns_failure(self) -> None:
        from squash.notifications import send_email_digest
        result = send_email_digest(self._digest(), [])
        self.assertFalse(result.success)
        self.assertIn("no recipients", result.error.lower())

    def test_dry_run_returns_success_without_smtp(self) -> None:
        from squash.notifications import send_email_digest
        result = send_email_digest(
            self._digest(), ["a@x.com", "b@x.com"], dry_run=True,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.delivered, 2)

    def test_unconfigured_smtp_returns_failure(self) -> None:
        from squash.notifications import send_email_digest, SmtpConfig
        # Clear any env-supplied SMTP config
        with mock.patch.dict("os.environ", {}, clear=False):
            for k in ("SQUASH_SMTP_HOST", "SQUASH_SMTP_FROM",
                      "SQUASH_SMTP_USER", "SQUASH_SMTP_PASSWORD"):
                os.environ.pop(k, None)
            empty = SmtpConfig()
            result = send_email_digest(
                self._digest(), ["a@x.com"], smtp=empty,
            )
        self.assertFalse(result.success)
        self.assertIn("not configured", result.error)

    def test_smtp_send_calls_sendmail(self) -> None:
        from squash.notifications import send_email_digest, SmtpConfig
        cfg = SmtpConfig(host="smtp.x.com", from_addr="noreply@x.com",
                         username="u", password="p")
        smtp_inst = mock.MagicMock()
        smtp_cls = mock.MagicMock(return_value=smtp_inst)
        smtp_inst.__enter__ = mock.MagicMock(return_value=smtp_inst)
        smtp_inst.__exit__ = mock.MagicMock(return_value=False)
        with mock.patch("smtplib.SMTP", smtp_cls):
            result = send_email_digest(
                self._digest(), ["ciso@x.com"], smtp=cfg,
            )
        self.assertTrue(result.success, msg=result.error)
        smtp_inst.starttls.assert_called_once()
        smtp_inst.login.assert_called_once_with("u", "p")
        smtp_inst.sendmail.assert_called_once()
        args, _ = smtp_inst.sendmail.call_args
        self.assertEqual(args[0], "noreply@x.com")
        self.assertEqual(args[1], ["ciso@x.com"])

    def test_smtp_login_skipped_when_no_credentials(self) -> None:
        from squash.notifications import send_email_digest, SmtpConfig
        cfg = SmtpConfig(host="smtp.x.com", from_addr="noreply@x.com",
                         use_tls=False)
        smtp_inst = mock.MagicMock()
        smtp_inst.__enter__ = mock.MagicMock(return_value=smtp_inst)
        smtp_inst.__exit__ = mock.MagicMock(return_value=False)
        with mock.patch("smtplib.SMTP", return_value=smtp_inst):
            send_email_digest(self._digest(), ["a@x.com"], smtp=cfg)
        smtp_inst.starttls.assert_not_called()
        smtp_inst.login.assert_not_called()

    def test_smtp_failure_returns_error_result(self) -> None:
        from squash.notifications import send_email_digest, SmtpConfig
        cfg = SmtpConfig(host="smtp.x.com", from_addr="x@x.com")
        smtp_inst = mock.MagicMock()
        smtp_inst.__enter__ = mock.MagicMock(return_value=smtp_inst)
        smtp_inst.__exit__ = mock.MagicMock(return_value=False)
        smtp_inst.sendmail.side_effect = OSError("connection refused")
        with mock.patch("smtplib.SMTP", return_value=smtp_inst):
            result = send_email_digest(
                self._digest(), ["a@x.com"], smtp=cfg,
            )
        self.assertFalse(result.success)
        self.assertIn("connection refused", result.error)


# ── W210 — `squash digest preview|send` CLI ──────────────────────────────────


class TestDigestCLIPreview(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def test_help_lists_subcommands(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("preview", result.stdout)
        self.assertIn("send", result.stdout)

    def test_preview_text_default(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "preview",
             "--models-dir", str(self.tmp), "--period", "weekly", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Portfolio summary", result.stdout)
        self.assertIn("Top 5 risk movers", result.stdout)

    def test_preview_html_format(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "preview",
             "--models-dir", str(self.tmp), "--format", "html"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("<table", result.stdout)
        self.assertIn("Portfolio summary".lower(),
                      result.stdout.lower())

    def test_preview_json_format(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "preview",
             "--models-dir", str(self.tmp), "--format", "json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["squash_version"], "compliance_digest_v1")
        self.assertIn("summary", payload)

    def test_preview_writes_to_output_file(self) -> None:
        out = self.tmp / "digest.txt"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "preview",
             "--models-dir", str(self.tmp), "--output", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(out.exists())
        text = out.read_text()
        self.assertIn("Portfolio summary", text)

    def test_preview_with_score_history(self) -> None:
        history = self.tmp / "history.json"
        history.write_text(json.dumps({
            "acme/model-0": 70.0, "acme/model-1": 90.0,
        }))
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "preview",
             "--models-dir", str(self.tmp), "--score-history", str(history),
             "--format", "json"],
            capture_output=True, text=True,
        )
        # No actual models so movers is empty — but the JSON parse must succeed
        # and score-history flag must not error out.
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_preview_bad_score_history_file_returns_2(self) -> None:
        bad = self.tmp / "bad.json"
        bad.write_text("[1, 2, 3]")  # array, not object
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "preview",
             "--models-dir", str(self.tmp), "--score-history", str(bad),
             "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)


class TestDigestCLISend(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def test_send_without_recipients_or_dry_run_returns_2(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "send",
             "--models-dir", str(self.tmp), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("recipients", result.stderr.lower())

    def test_send_dry_run_succeeds(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "send",
             "--models-dir", str(self.tmp), "--dry-run"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("dry-run", result.stdout)
        self.assertIn("Subject:", result.stdout)

    def test_send_dry_run_with_recipients(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "send",
             "--models-dir", str(self.tmp), "--dry-run",
             "--recipients", "ciso@acme.com",
             "--recipients", "vp-eng@acme.com"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("ciso@acme.com", result.stdout)
        self.assertIn("vp-eng@acme.com", result.stdout)

    def test_send_unconfigured_smtp_returns_1(self) -> None:
        # Strip env so SmtpConfig defaults are unset
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SQUASH_SMTP_")}
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "digest", "send",
             "--models-dir", str(self.tmp), "--quiet",
             "--recipients", "x@x.com"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("not configured", result.stderr.lower())


# ── Module count delta — B3 itself adds 0 new modules under squash/ ─────────


class TestB3IsExtensionsOnly(unittest.TestCase):
    """B3 extends notifications.py + cli.py — does not introduce a new
    module. The canonical absolute-count gate lives in
    test_squash_model_card.py; this asserts the *kind* of change B3 makes."""

    def test_no_new_top_level_module_for_b3(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        # B3-specific names that must NOT exist as top-level modules.
        b3_forbidden_filenames = ("digest.py", "compliance_digest.py", "email_digest.py")
        for name in b3_forbidden_filenames:
            self.assertFalse(
                (squash_dir / name).exists(),
                msg=f"B3 should be extension-only — found unexpected {name}",
            )


if __name__ == "__main__":
    unittest.main()
