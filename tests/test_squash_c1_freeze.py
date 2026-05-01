"""tests/test_squash_c1_freeze.py — Track C / C1 ★ — `squash freeze`.

Sprint 19 (W221–W222) exit criteria:
  * 1 new module (freeze.py) — emergency response orchestrator
  * Five sub-steps coordinated atomically:
      1. attestation_registry.revoke()
      2. webhook_delivery.dispatch(event="attestation.frozen")
      3. signed ledger entry written to ~/.squash/freeze_ledger.jsonl
      4. notifications.notify(event="attestation.frozen")
      5. incident.IncidentResponder.respond() → Article 73 disclosure
  * `squash freeze --attestation-id …` revokes, alerts, blocks GitOps,
     drafts disclosure in <10 s
  * Receipt is signed (Ed25519) when --priv-key is supplied; verifiable
     with `squash freeze verify`
  * Atomicity: if registry revoke fails, no broadcast side-effects fire
  * Webhook ATTESTATION_FROZEN event is registered
  * notifications.ATTESTATION_FROZEN event constant exists with title
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


# ── Test doubles ──────────────────────────────────────────────────────────────


class _FakeRegistry:
    """In-memory stand-in for AttestationRegistry."""

    def __init__(self, entries=None, revoke_returns=True, raise_on_revoke=False):
        self._entries = list(entries or [])
        self._revoke_returns = revoke_returns
        self._raise_on_revoke = raise_on_revoke
        self.revoked = []

    def lookup(self, model_id=None, org=None, entry_id=None, limit=20):
        out = []
        for e in self._entries:
            if entry_id and e.entry_id != entry_id:
                continue
            if model_id and e.model_id != model_id:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def get_entry(self, entry_id):
        for e in self._entries:
            if e.entry_id == entry_id:
                return e
        return None

    def revoke(self, entry_id):
        if self._raise_on_revoke:
            raise RuntimeError("simulated DB failure")
        self.revoked.append(entry_id)
        for e in self._entries:
            if e.entry_id == entry_id:
                e.revoked = True
        return self._revoke_returns


class _FakeWebhook:
    def __init__(self, results=None, raise_exc=False):
        self._results = results or []
        self._raise = raise_exc
        self.dispatched = []

    def dispatch(self, event, data, timeout_s=10.0):
        if self._raise:
            raise RuntimeError("simulated webhook delivery error")
        self.dispatched.append((event, dict(data), timeout_s))
        return list(self._results)


def _entry(entry_id="att://acme/llm-v2/abc123", model_id="acme-llm-v2"):
    return SimpleNamespace(
        entry_id=entry_id,
        model_id=model_id,
        org="acme-corp",
        revoked=False,
    )


def _fake_incident_factory(model_path, description, severity, category,
                            affected_persons, model_id=None):
    pkg = SimpleNamespace(
        incident_id=f"INC-FAKE-{Path(model_path).name[:6].upper()}",
        description=description,
        severity=severity,
        category=category,
        affected_persons=affected_persons,
        model_id=model_id or Path(model_path).name,
    )
    def _save(out_dir):
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "incident_report.json").write_text(json.dumps({
            "incident_id": pkg.incident_id, "description": description,
        }))
        return [str(out_dir / "incident_report.json")]
    pkg.save = _save
    return pkg


class _Tmp(unittest.TestCase):
    """Per-test temp state dir that cleans up automatically."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._tmp.name) / "state"
        self.state_dir.mkdir(parents=True)
        self.addCleanup(self._tmp.cleanup)


# ── Module surface ────────────────────────────────────────────────────────────


class TestModuleSurface(_Tmp):
    def test_public_api_exposed(self):
        from squash import freeze
        for name in ("FreezeOrchestrator", "FreezeReceipt", "FreezeStep",
                     "StepResult", "freeze", "read_ledger", "verify_receipt"):
            self.assertIn(name, freeze.__all__, msg=name)
            self.assertTrue(hasattr(freeze, name))

    def test_step_enum_has_five_members(self):
        from squash.freeze import FreezeStep
        members = list(FreezeStep)
        self.assertEqual(len(members), 5)
        self.assertEqual(
            {m.value for m in members},
            {"registry_revoke", "webhook_broadcast", "ledger_log",
             "notification", "incident_package"},
        )

    def test_webhook_event_attestation_frozen_registered(self):
        from squash.webhook_delivery import WebhookEvent
        self.assertEqual(WebhookEvent.ATTESTATION_FROZEN.value, "attestation.frozen")
        self.assertIn(WebhookEvent.ATTESTATION_FROZEN, WebhookEvent.all())

    def test_notifications_constant_registered(self):
        from squash import notifications
        self.assertEqual(notifications.ATTESTATION_FROZEN, "attestation.frozen")

    def test_notifications_title_template_includes_freeze(self):
        from squash.notifications import _make_title, ATTESTATION_FROZEN
        title = _make_title(ATTESTATION_FROZEN, "acme-llm-v2")
        self.assertIn("FREEZE", title.upper())
        self.assertIn("acme-llm-v2", title)


# ── Argument validation ───────────────────────────────────────────────────────


class TestArgumentValidation(_Tmp):
    def test_requires_attestation_or_model(self):
        from squash.freeze import freeze
        with self.assertRaises(ValueError):
            freeze(state_dir=self.state_dir)


# ── Step 1 — registry revoke ──────────────────────────────────────────────────


class TestRegistryRevoke(_Tmp):
    def test_revoke_by_attestation_id(self):
        from squash.freeze import freeze
        reg = _FakeRegistry(entries=[_entry()])
        receipt = freeze(
            attestation_id="att://acme/llm-v2/abc123",
            registry=reg,
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertTrue(receipt.revoke_ok)
        self.assertEqual(receipt.revoked_entries, ["att://acme/llm-v2/abc123"])

    def test_revoke_by_model_path(self):
        from squash.freeze import freeze
        reg = _FakeRegistry(entries=[_entry(model_id="acme-llm-v2")])
        receipt = freeze(
            model_path=str(self.state_dir / "model.safetensors"),
            model_id="acme-llm-v2",
            registry=reg,
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertTrue(receipt.revoke_ok)

    def test_aborts_when_no_match(self):
        from squash.freeze import freeze, FreezeStep
        reg = _FakeRegistry(entries=[])
        wh = _FakeWebhook()
        receipt = freeze(
            attestation_id="att://nope",
            registry=reg,
            webhook=wh,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertFalse(receipt.revoke_ok)
        # Broadcast steps must NOT have fired.
        self.assertEqual(len(receipt.steps), 1)
        self.assertEqual(receipt.steps[0].step, FreezeStep.REGISTRY_REVOKE)
        self.assertEqual(wh.dispatched, [])

    def test_revoke_returning_false_is_failure(self):
        from squash.freeze import freeze
        reg = _FakeRegistry(entries=[_entry()], revoke_returns=False)
        receipt = freeze(
            attestation_id="att://acme/llm-v2/abc123",
            registry=reg,
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertFalse(receipt.revoke_ok)

    def test_registry_exception_recorded(self):
        from squash.freeze import freeze, FreezeStep
        reg = _FakeRegistry(entries=[_entry()], raise_on_revoke=True)
        receipt = freeze(
            attestation_id="att://acme/llm-v2/abc123",
            registry=reg,
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertFalse(receipt.revoke_ok)
        revoke_step = receipt.step_result(FreezeStep.REGISTRY_REVOKE)
        self.assertIsNotNone(revoke_step)
        self.assertIn("RuntimeError", revoke_step.error)


# ── Step 2 — webhook broadcast ────────────────────────────────────────────────


class TestWebhookBroadcast(_Tmp):
    def test_dispatches_attestation_frozen(self):
        from squash.freeze import freeze
        from squash.webhook_delivery import WebhookEvent
        wh = _FakeWebhook(results=[
            {"endpoint_id": "ep1", "success": True, "status_code": 200},
            {"endpoint_id": "ep2", "success": True, "status_code": 200},
        ])
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=wh,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertEqual(len(wh.dispatched), 1)
        evt, payload, _ = wh.dispatched[0]
        self.assertEqual(evt, WebhookEvent.ATTESTATION_FROZEN)
        self.assertEqual(payload["attestation_id"], "att://x")
        self.assertEqual(payload["revoked_entries"], ["att://x"])
        self.assertEqual(len(receipt.webhook_results), 2)

    def test_no_subscribers_is_noop_success(self):
        from squash.freeze import freeze, FreezeStep
        wh = _FakeWebhook(results=[])
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=wh,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        wh_step = receipt.step_result(FreezeStep.WEBHOOK_BROADCAST)
        self.assertTrue(wh_step.ok)
        self.assertIn("no subscribers", wh_step.detail)

    def test_partial_delivery_marks_step_failed_but_continues(self):
        from squash.freeze import freeze, FreezeStep
        wh = _FakeWebhook(results=[
            {"endpoint_id": "ep1", "success": True, "status_code": 200},
            {"endpoint_id": "ep2", "success": False, "status_code": 500,
             "error": "Internal Server Error"},
        ])
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=wh,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        wh_step = receipt.step_result(FreezeStep.WEBHOOK_BROADCAST)
        self.assertFalse(wh_step.ok)
        # Subsequent steps must still have run.
        self.assertIsNotNone(receipt.step_result(FreezeStep.LEDGER_LOG))
        self.assertIsNotNone(receipt.step_result(FreezeStep.NOTIFICATION))
        self.assertIsNotNone(receipt.step_result(FreezeStep.INCIDENT_PACKAGE))

    def test_dispatch_exception_recorded(self):
        from squash.freeze import freeze, FreezeStep
        wh = _FakeWebhook(raise_exc=True)
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=wh,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        wh_step = receipt.step_result(FreezeStep.WEBHOOK_BROADCAST)
        self.assertFalse(wh_step.ok)
        self.assertIn("RuntimeError", wh_step.error)


# ── Step 3 — ledger ───────────────────────────────────────────────────────────


class TestLedger(_Tmp):
    def test_ledger_appended(self):
        from squash.freeze import freeze, read_ledger
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        entries = read_ledger(state_dir=self.state_dir)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["freeze_id"], receipt.freeze_id)
        self.assertEqual(entries[0]["revoked_entries"], ["att://x"])
        self.assertIn("entry_hash", entries[0])

    def test_ledger_appends_multiple(self):
        from squash.freeze import freeze, read_ledger
        for i in range(3):
            freeze(
                attestation_id=f"att://x{i}",
                registry=_FakeRegistry(entries=[_entry(entry_id=f"att://x{i}")]),
                webhook=_FakeWebhook(),
                incident_factory=_fake_incident_factory,
                state_dir=self.state_dir,
                write_incident=False,
            )
        entries = read_ledger(state_dir=self.state_dir)
        self.assertEqual(len(entries), 3)
        self.assertEqual(read_ledger(state_dir=self.state_dir, limit=2)[0]["attestation_id"], "att://x1")

    def test_read_ledger_missing_dir(self):
        from squash.freeze import read_ledger
        empty = self.state_dir / "nonexistent"
        self.assertEqual(read_ledger(state_dir=empty), [])


# ── Step 4 — notifications ────────────────────────────────────────────────────


class TestNotifications(_Tmp):
    def test_notify_called_with_event(self):
        from squash.freeze import freeze
        notifier = mock.MagicMock()
        notifier.notify.return_value = {"delivered": True}
        freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            notifier=notifier,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        notifier.notify.assert_called_once()
        kwargs = notifier.notify.call_args.kwargs
        args_pos = notifier.notify.call_args.args
        self.assertIn("attestation.frozen", args_pos)
        self.assertIn("details", kwargs)
        self.assertEqual(kwargs["details"]["attestation_id"], "att://x")

    def test_notify_failure_recorded(self):
        from squash.freeze import freeze, FreezeStep
        notifier = mock.MagicMock()
        notifier.notify.side_effect = RuntimeError("smtp down")
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            notifier=notifier,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        n_step = receipt.step_result(FreezeStep.NOTIFICATION)
        self.assertFalse(n_step.ok)
        self.assertIn("RuntimeError", n_step.error)


# ── Step 5 — incident package ─────────────────────────────────────────────────


class TestIncidentPackage(_Tmp):
    def test_incident_built_and_saved(self):
        from squash.freeze import freeze
        out = self.state_dir / "incident_out"
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            incident_dir=out,
            reason="CVE-2026-1234",
            severity="critical",
        )
        self.assertTrue(receipt.incident_id.startswith("INC-FAKE-"))
        self.assertEqual(Path(receipt.incident_dir), out)
        self.assertTrue((out / "incident_report.json").exists())

    def test_no_incident_flag_skips_save(self):
        from squash.freeze import freeze
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        self.assertEqual(receipt.incident_dir, "")
        # incident object still constructed
        self.assertNotEqual(receipt.incident_id, "")


# ── Receipt signing & verification ────────────────────────────────────────────


def _has_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_has_cryptography(), "cryptography not installed")
class TestReceiptSigning(_Tmp):
    def _keypair(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        priv_path = self.state_dir / "freeze.priv.pem"
        priv_path.write_bytes(priv_pem)
        return priv_path

    def test_signed_receipt_verifies(self):
        from squash.freeze import freeze, verify_receipt
        priv = self._keypair()
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            priv_key_pem=priv,
            write_incident=False,
        )
        self.assertTrue(receipt.signature_hex)
        self.assertTrue(receipt.signing_pubkey_pem)
        ok, msg = verify_receipt(receipt)
        self.assertTrue(ok, msg)

    def test_tampered_receipt_fails_verification(self):
        from squash.freeze import freeze, verify_receipt
        priv = self._keypair()
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            priv_key_pem=priv,
            write_incident=False,
        )
        d = receipt.to_dict()
        d["reason"] = "TAMPERED"
        ok, msg = verify_receipt(d)
        self.assertFalse(ok, msg)

    def test_unsigned_receipt_returns_false(self):
        from squash.freeze import freeze, verify_receipt
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        ok, msg = verify_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("unsigned", msg)


# ── End-to-end happy path ─────────────────────────────────────────────────────


class TestEndToEnd(_Tmp):
    def test_all_steps_succeed(self):
        from squash.freeze import freeze, FreezeStep
        notifier = mock.MagicMock()
        notifier.notify.return_value = {"delivered": True}
        wh = _FakeWebhook(results=[
            {"endpoint_id": "ep1", "success": True, "status_code": 200},
        ])
        receipt = freeze(
            attestation_id="att://acme/llm-v2/abc",
            model_id="acme-llm-v2",
            reason="CVE-2026-1234 — RCE in tokenizer",
            actor="ciso@acme.example",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://acme/llm-v2/abc")]),
            webhook=wh,
            notifier=notifier,
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
        )
        self.assertTrue(receipt.all_ok)
        self.assertTrue(receipt.revoke_ok)
        self.assertEqual(len(receipt.steps), 5)
        for step in FreezeStep:
            self.assertIsNotNone(receipt.step_result(step), msg=step)
        self.assertEqual(receipt.notification_event, "attestation.frozen")
        self.assertTrue(receipt.payload_hash)
        self.assertTrue(receipt.completed_at)

    def test_summary_contains_freeze_id(self):
        from squash.freeze import freeze
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        s = receipt.summary()
        self.assertIn(receipt.freeze_id, s)
        self.assertIn("SQUASH FREEZE RECEIPT", s)

    def test_to_json_round_trip(self):
        from squash.freeze import freeze
        receipt = freeze(
            attestation_id="att://x",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://x")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        body = json.loads(receipt.to_json())
        self.assertEqual(body["freeze_id"], receipt.freeze_id)
        self.assertEqual(len(body["steps"]), 5)


# ── CLI handler ───────────────────────────────────────────────────────────────


def _ns(**kw):
    defaults = dict(
        fz_command=None,
        fz_attestation_id=None,
        fz_model_path=None,
        fz_model_id="",
        fz_reason="",
        fz_actor="",
        fz_severity="critical",
        fz_category="other",
        fz_affected=0,
        fz_incident_dir=None,
        fz_state_dir=None,
        fz_priv_key=None,
        fz_no_incident=True,
        fz_webhook_timeout=10.0,
        fz_out=None,
        fz_format="text",
        fz_quiet=True,
    )
    defaults.update(kw)
    return argparse.Namespace(**defaults)


class TestCliHandler(_Tmp):
    def test_run_returns_zero_on_success(self):
        from squash.cli import _cmd_freeze
        # Patch the freeze module's external dependencies via the orchestrator's
        # public injection points by monkey-patching the freeze() entry-point.
        from squash import freeze as freeze_mod
        receipt = freeze_mod.FreezeReceipt(
            freeze_id="FREEZE-TEST",
            initiated_at="now",
            completed_at="now",
        )
        receipt.steps = [
            freeze_mod.StepResult(step=s, ok=True, detail="ok")
            for s in freeze_mod.FreezeStep
        ]
        with mock.patch.object(freeze_mod, "freeze", return_value=receipt) as m:
            rc = _cmd_freeze(
                _ns(fz_attestation_id="att://x", fz_state_dir=str(self.state_dir)),
                quiet=True,
            )
        self.assertEqual(rc, 0)
        m.assert_called_once()

    def test_no_args_returns_three(self):
        from squash.cli import _cmd_freeze
        rc = _cmd_freeze(_ns(), quiet=True)
        self.assertEqual(rc, 3)

    def test_revoke_failure_returns_two(self):
        from squash.cli import _cmd_freeze
        from squash import freeze as freeze_mod
        receipt = freeze_mod.FreezeReceipt(freeze_id="FREEZE-TEST")
        receipt.steps = [
            freeze_mod.StepResult(
                step=freeze_mod.FreezeStep.REGISTRY_REVOKE,
                ok=False, detail="not found", error="not_found",
            )
        ]
        with mock.patch.object(freeze_mod, "freeze", return_value=receipt):
            rc = _cmd_freeze(_ns(fz_attestation_id="att://x"), quiet=True)
        self.assertEqual(rc, 2)

    def test_partial_failure_returns_one(self):
        from squash.cli import _cmd_freeze
        from squash import freeze as freeze_mod
        receipt = freeze_mod.FreezeReceipt(freeze_id="FREEZE-TEST")
        receipt.steps = [
            freeze_mod.StepResult(step=freeze_mod.FreezeStep.REGISTRY_REVOKE, ok=True, detail="ok"),
            freeze_mod.StepResult(step=freeze_mod.FreezeStep.WEBHOOK_BROADCAST, ok=False, detail="net"),
            freeze_mod.StepResult(step=freeze_mod.FreezeStep.LEDGER_LOG, ok=True, detail="ok"),
            freeze_mod.StepResult(step=freeze_mod.FreezeStep.NOTIFICATION, ok=True, detail="ok"),
            freeze_mod.StepResult(step=freeze_mod.FreezeStep.INCIDENT_PACKAGE, ok=True, detail="ok"),
        ]
        with mock.patch.object(freeze_mod, "freeze", return_value=receipt):
            rc = _cmd_freeze(_ns(fz_attestation_id="att://x"), quiet=True)
        self.assertEqual(rc, 1)

    def test_ledger_subcommand(self):
        from squash.cli import _cmd_freeze
        from squash.freeze import freeze
        # Seed one entry.
        freeze(
            attestation_id="att://led",
            registry=_FakeRegistry(entries=[_entry(entry_id="att://led")]),
            webhook=_FakeWebhook(),
            incident_factory=_fake_incident_factory,
            state_dir=self.state_dir,
            write_incident=False,
        )
        ns = _ns(
            fz_command="ledger",
            fz_state_dir=str(self.state_dir),
            fz_limit=5,
            output_json=True,
        )
        rc = _cmd_freeze(ns, quiet=True)
        self.assertEqual(rc, 0)

    def test_verify_subcommand_missing_file(self):
        from squash.cli import _cmd_freeze
        ns = _ns(
            fz_command="verify",
            receipt_path=str(self.state_dir / "missing.json"),
            output_json=False,
        )
        rc = _cmd_freeze(ns, quiet=True)
        self.assertEqual(rc, 3)


# ── CLI parser registration ───────────────────────────────────────────────────


class TestCliRegistration(unittest.TestCase):
    def test_command_dispatch_branch_present(self):
        # The dispatch table in main() must route 'freeze' to _cmd_freeze.
        cli_src = (Path(__file__).parent.parent / "squash" / "cli.py").read_text()
        self.assertIn('args.command == "freeze"', cli_src)
        self.assertIn("_cmd_freeze", cli_src)


if __name__ == "__main__":
    unittest.main()
