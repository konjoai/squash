"""Tests for squash freeze — Emergency Response Orchestrator (Sprint 19 / C1).

Covers FreezeOrchestrator, FreezeReceipt, FreezeStep, StepResult,
and the module-level freeze(), read_ledger(), verify_receipt() helpers.

The FreezeOrchestrator requires either attestation_id= or model_path= and
drives up to 5 sub-steps; each step can be independently stubbed for fast,
offline testing via the dependency-injection constructors.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from squash.freeze import (
    FreezeOrchestrator,
    FreezeReceipt,
    FreezeStep,
    StepResult,
    _coerce_dict,
    _default_actor,
    _now_ms,
    _result_delivered,
    _result_error,
    _utc_now,
    freeze,
    read_ledger,
    verify_receipt,
)


# ──────────────────────────────────────────────────────────────────────────────
# Stubs / helpers
# ──────────────────────────────────────────────────────────────────────────────


class _FakeRegistryEntry:
    def __init__(self, entry_id: str):
        self.entry_id = entry_id


class _FakeRegistry:
    """Minimal registry stub that always finds and revokes one entry."""

    def __init__(self, entry_id: str = "att://test/model/abc123"):
        self._entry_id = entry_id
        self.revoke_calls: list[str] = []

    def lookup(self, *, entry_id: str | None = None, model_id: str | None = None,
               limit: int = 100) -> list[_FakeRegistryEntry]:
        return [_FakeRegistryEntry(self._entry_id)]

    def revoke(self, entry_id: str) -> bool:
        self.revoke_calls.append(entry_id)
        return True


class _FailRegistry:
    """Registry stub that always fails to find entries."""

    def lookup(self, **kwargs: Any) -> list:
        return []

    def revoke(self, entry_id: str) -> bool:
        return False


class _RevokeRaisesRegistry:
    """Registry stub that raises on lookup."""

    def lookup(self, **kwargs: Any) -> list:
        raise RuntimeError("database gone")

    def revoke(self, entry_id: str) -> bool:
        return False


class _FakeWebhook:
    """Webhook stub that returns one success result."""

    def dispatch(self, event: Any, payload: dict, timeout_s: float = 10.0) -> list[dict]:
        return [{"success": True, "status_code": 200, "endpoint_id": "ep-1"}]


class _FailWebhook:
    """Webhook stub that raises."""

    def dispatch(self, *a: Any, **kw: Any) -> list:
        raise ConnectionError("network down")


class _FakeNotifier:
    """Notifier stub that returns delivered=True."""

    def notify(self, event: str, **kwargs: Any) -> dict:
        return {"delivered": True}


class _FailNotifier:
    """Notifier stub that always fails."""

    def notify(self, event: str, **kwargs: Any) -> dict:
        return {"delivered": False, "error": "channel down"}


def _fake_incident_factory(*, model_path: Path, description: str,
                            severity: str, category: str,
                            affected_persons: int, model_id: str | None = None) -> MagicMock:
    pkg = MagicMock()
    pkg.incident_id = "INC-FAKE-001"
    return pkg


def _orchestrator(tmp_path: Path, **overrides: Any) -> FreezeOrchestrator:
    """Return a fully-stubbed orchestrator with a writable state_dir."""
    defaults: dict[str, Any] = dict(
        registry=_FakeRegistry(),
        webhook=_FakeWebhook(),
        notifier=_FakeNotifier(),
        incident_factory=_fake_incident_factory,
        state_dir=tmp_path,
    )
    defaults.update(overrides)
    return FreezeOrchestrator(**defaults)


# ──────────────────────────────────────────────────────────────────────────────
# FreezeStep enum
# ──────────────────────────────────────────────────────────────────────────────


def test_freeze_step_values():
    assert FreezeStep.REGISTRY_REVOKE.value == "registry_revoke"
    assert FreezeStep.WEBHOOK_BROADCAST.value == "webhook_broadcast"
    assert FreezeStep.LEDGER_LOG.value == "ledger_log"
    assert FreezeStep.NOTIFICATION.value == "notification"
    assert FreezeStep.INCIDENT_PACKAGE.value == "incident_package"


def test_freeze_step_count():
    assert len(FreezeStep) == 5


# ──────────────────────────────────────────────────────────────────────────────
# StepResult
# ──────────────────────────────────────────────────────────────────────────────


def test_step_result_to_dict_keys():
    sr = StepResult(step=FreezeStep.LEDGER_LOG, ok=True, detail="written")
    d = sr.to_dict()
    assert set(d.keys()) >= {"step", "ok", "detail", "duration_ms", "error"}


def test_step_result_to_dict_step_is_string():
    sr = StepResult(step=FreezeStep.REGISTRY_REVOKE, ok=True, detail="done")
    d = sr.to_dict()
    assert isinstance(d["step"], str)


def test_step_result_error_defaults_empty():
    sr = StepResult(step=FreezeStep.NOTIFICATION, ok=True, detail="ok")
    assert sr.error == ""


# ──────────────────────────────────────────────────────────────────────────────
# FreezeReceipt
# ──────────────────────────────────────────────────────────────────────────────


def test_freeze_receipt_all_ok_true_when_all_steps_ok():
    r = FreezeReceipt(freeze_id="FREEZE-TEST")
    r.steps = [
        StepResult(step=FreezeStep.REGISTRY_REVOKE, ok=True, detail="ok"),
        StepResult(step=FreezeStep.LEDGER_LOG, ok=True, detail="ok"),
    ]
    assert r.all_ok is True


def test_freeze_receipt_all_ok_false_when_one_step_fails():
    r = FreezeReceipt(freeze_id="FREEZE-TEST")
    r.steps = [
        StepResult(step=FreezeStep.REGISTRY_REVOKE, ok=True, detail="ok"),
        StepResult(step=FreezeStep.WEBHOOK_BROADCAST, ok=False, detail="fail"),
    ]
    assert r.all_ok is False


def test_freeze_receipt_revoke_ok_true():
    r = FreezeReceipt(freeze_id="FREEZE-TEST")
    r.steps = [StepResult(step=FreezeStep.REGISTRY_REVOKE, ok=True, detail="ok")]
    assert r.revoke_ok is True


def test_freeze_receipt_revoke_ok_false_when_missing():
    r = FreezeReceipt(freeze_id="FREEZE-TEST")
    r.steps = [StepResult(step=FreezeStep.LEDGER_LOG, ok=True, detail="ok")]
    assert r.revoke_ok is False


def test_freeze_receipt_to_dict_contains_schema():
    r = FreezeReceipt(freeze_id="X")
    d = r.to_dict()
    assert d["schema"] == "squash.freeze.receipt/v1"


def test_freeze_receipt_to_json_is_valid_json():
    r = FreezeReceipt(freeze_id="X")
    parsed = json.loads(r.to_json())
    assert parsed["freeze_id"] == "X"


def test_freeze_receipt_canonical_payload_bytes_excludes_sig_fields():
    r = FreezeReceipt(freeze_id="Y", signature_hex="abc", payload_hash="def",
                      signing_pubkey_pem="pem")
    b = r.canonical_payload_bytes()
    payload = json.loads(b)
    assert "signature_hex" not in payload
    assert "payload_hash" not in payload
    assert "signing_pubkey_pem" not in payload


def test_freeze_receipt_summary_contains_freeze_id():
    r = FreezeReceipt(freeze_id="FREEZE-TESTSUMMARY")
    summary = r.summary()
    assert "FREEZE-TESTSUMMARY" in summary


def test_freeze_receipt_summary_contains_step_markers():
    r = FreezeReceipt(freeze_id="F")
    r.steps = [StepResult(step=FreezeStep.REGISTRY_REVOKE, ok=True, detail="done")]
    summary = r.summary()
    assert "registry_revoke" in summary


def test_freeze_receipt_step_result_lookup():
    r = FreezeReceipt(freeze_id="F")
    sr = StepResult(step=FreezeStep.NOTIFICATION, ok=True, detail="sent")
    r.steps = [sr]
    assert r.step_result(FreezeStep.NOTIFICATION) is sr
    assert r.step_result(FreezeStep.LEDGER_LOG) is None


# ──────────────────────────────────────────────────────────────────────────────
# FreezeOrchestrator.freeze() — happy path
# ──────────────────────────────────────────────────────────────────────────────


def test_freeze_returns_receipt(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://test/m/1", reason="test")
    assert isinstance(r, FreezeReceipt)


def test_freeze_requires_attestation_id_or_model_path(tmp_path: Path):
    o = _orchestrator(tmp_path)
    with pytest.raises(ValueError, match="attestation_id"):
        o.freeze()


def test_freeze_receipt_has_freeze_id(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    assert r.freeze_id.startswith("FREEZE-")


def test_freeze_receipt_initiated_at_not_empty(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(model_path="/tmp/model.safetensors")
    assert r.initiated_at != ""


def test_freeze_receipt_completed_at_not_empty(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    assert r.completed_at != ""


def test_freeze_receipt_has_five_steps(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    assert len(r.steps) == 5


def test_freeze_registry_revoke_step_ok(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    sr = r.step_result(FreezeStep.REGISTRY_REVOKE)
    assert sr is not None and sr.ok is True


def test_freeze_ledger_written(tmp_path: Path):
    o = _orchestrator(tmp_path)
    o.freeze(attestation_id="att://x")
    ledger = tmp_path / "freeze_ledger.jsonl"
    assert ledger.exists()
    lines = [l for l in ledger.read_text().splitlines() if l.strip()]
    assert len(lines) >= 1


def test_freeze_ledger_step_ok(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    sr = r.step_result(FreezeStep.LEDGER_LOG)
    assert sr is not None and sr.ok is True


def test_freeze_revoked_entries_populated(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    assert len(r.revoked_entries) >= 1


def test_freeze_actor_defaults_non_empty(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    assert r.actor != ""


def test_freeze_actor_custom(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x", actor="ci-bot")
    assert r.actor == "ci-bot"


def test_freeze_reason_preserved(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x", reason="CVE-2026-1234")
    assert r.reason == "CVE-2026-1234"


def test_freeze_model_id_preserved(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x", model_id="llama-3-8b")
    assert r.model_id == "llama-3-8b"


def test_freeze_all_ok_with_all_stubs(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    assert r.all_ok is True


# ──────────────────────────────────────────────────────────────────────────────
# FreezeOrchestrator.freeze() — failure paths
# ──────────────────────────────────────────────────────────────────────────────


def test_freeze_aborts_on_registry_failure(tmp_path: Path):
    """If registry revoke fails, only 1 step should be recorded."""
    o = _orchestrator(tmp_path, registry=_FailRegistry())
    r = o.freeze(attestation_id="att://nonexistent")
    assert r.revoke_ok is False
    assert len(r.steps) == 1


def test_freeze_webhook_failure_does_not_abort(tmp_path: Path):
    """Webhook failure is non-fatal — remaining steps still run."""
    o = _orchestrator(tmp_path, webhook=_FailWebhook())
    r = o.freeze(attestation_id="att://x")
    assert r.revoke_ok is True
    assert len(r.steps) == 5


def test_freeze_notification_failure_does_not_abort(tmp_path: Path):
    o = _orchestrator(tmp_path, notifier=_FailNotifier())
    r = o.freeze(attestation_id="att://x")
    notif_step = r.step_result(FreezeStep.NOTIFICATION)
    assert notif_step is not None
    assert notif_step.ok is False
    # Other steps still ran
    assert len(r.steps) == 5


def test_freeze_registry_raises_does_not_crash(tmp_path: Path):
    o = _orchestrator(tmp_path, registry=_RevokeRaisesRegistry())
    r = o.freeze(attestation_id="att://x")
    assert r.revoke_ok is False


# ──────────────────────────────────────────────────────────────────────────────
# read_ledger()
# ──────────────────────────────────────────────────────────────────────────────


def test_read_ledger_empty_when_no_file(tmp_path: Path):
    entries = read_ledger(state_dir=tmp_path)
    assert entries == []


def test_read_ledger_returns_entries_after_freeze(tmp_path: Path):
    o = _orchestrator(tmp_path)
    o.freeze(attestation_id="att://x")
    entries = read_ledger(state_dir=tmp_path)
    assert len(entries) >= 1


def test_read_ledger_entry_has_freeze_id(tmp_path: Path):
    o = _orchestrator(tmp_path)
    r = o.freeze(attestation_id="att://x")
    entries = read_ledger(state_dir=tmp_path)
    freeze_ids = [e.get("freeze_id") for e in entries]
    assert r.freeze_id in freeze_ids


def test_read_ledger_limit(tmp_path: Path):
    o = _orchestrator(tmp_path)
    for _ in range(5):
        o.freeze(attestation_id="att://x")
    entries = read_ledger(state_dir=tmp_path, limit=3)
    assert len(entries) == 3


# ──────────────────────────────────────────────────────────────────────────────
# verify_receipt()
# ──────────────────────────────────────────────────────────────────────────────


def test_verify_receipt_unsigned_returns_false():
    r = FreezeReceipt(freeze_id="UNSIGNED")
    ok, msg = verify_receipt(r)
    assert ok is False
    assert "unsigned" in msg


def test_verify_receipt_dict_unsigned_returns_false():
    ok, msg = verify_receipt({"freeze_id": "X", "signature_hex": "", "signing_pubkey_pem": ""})
    assert ok is False


# ──────────────────────────────────────────────────────────────────────────────
# Module-level freeze() convenience function
# ──────────────────────────────────────────────────────────────────────────────


def test_module_level_freeze_requires_id_or_path():
    with pytest.raises(ValueError):
        freeze()


def test_module_level_freeze_with_stubs(tmp_path: Path):
    r = freeze(
        attestation_id="att://mod/x",
        registry=_FakeRegistry(),
        webhook=_FakeWebhook(),
        notifier=_FakeNotifier(),
        incident_factory=_fake_incident_factory,
        state_dir=tmp_path,
    )
    assert isinstance(r, FreezeReceipt)
    assert r.revoke_ok is True


# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────────


def test_utc_now_format():
    ts = _utc_now()
    assert "T" in ts
    assert "+" in ts or "Z" in ts or ts.endswith("+00:00")


def test_now_ms_is_integer():
    assert isinstance(_now_ms(), int)


def test_now_ms_is_recent():
    ms = _now_ms()
    assert ms > 1_700_000_000_000  # after 2023


def test_default_actor_non_empty():
    actor = _default_actor()
    assert actor != ""
    assert "@" in actor


def test_coerce_dict_with_dict():
    d = {"a": 1}
    assert _coerce_dict(d) == {"a": 1}


def test_coerce_dict_with_to_dict_method():
    class Obj:
        def to_dict(self) -> dict:
            return {"x": 42}
    assert _coerce_dict(Obj()) == {"x": 42}


def test_result_delivered_none():
    assert _result_delivered(None) is True


def test_result_delivered_true():
    assert _result_delivered(True) is True


def test_result_delivered_false():
    assert _result_delivered(False) is False


def test_result_delivered_dict_delivered_key():
    assert _result_delivered({"delivered": True}) is True
    assert _result_delivered({"delivered": False}) is False


def test_result_error_none():
    assert _result_error(None) == ""


def test_result_error_dict():
    assert _result_error({"error": "boom"}) == "boom"


def test_result_error_empty_dict():
    assert _result_error({}) == ""
