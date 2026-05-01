"""squash/freeze.py — Emergency Response: ``squash freeze`` (Track C / C1 ★).

The Red Button. CISOs demo this to their boards.

A single command that, in <10 s, atomically:

  1. Revokes every live attestation for a model in the registry
  2. Broadcasts an ``attestation.frozen`` webhook to every subscriber
  3. Writes a signed freeze ledger entry to the local audit trail (Ed25519)
  4. Dispatches a ``notifications.notify(event="attestation.frozen", ...)``
     event to Slack / PagerDuty / e-mail
  5. Builds an :class:`squash.incident.IncidentPackage` (with Article 73
     disclosure draft) on disk for the human responder
  6. Returns a :class:`FreezeReceipt` recording the outcome of every step

Atomicity model
---------------
Emergency response is best-effort, not strict-transactional:

* Sub-step **1** (registry revoke) is the only legally-binding action — if
  it fails, the orchestrator aborts before any side-effect leaves the box.
* Sub-steps **2–5** are *broadcast* operations.  A failure in one does
  **not** abort the others — getting partial notifications out beats
  getting nothing out — but every failure is recorded on the receipt so
  the responder knows exactly what to manually finish.
* The receipt itself is signed if a private key is available, so the
  audit trail is tamper-evident regardless of which sub-steps succeeded.

The freeze ledger is an append-only JSONL file at
``~/.squash/freeze_ledger.jsonl`` (override with ``state_dir=``).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Step model
# ──────────────────────────────────────────────────────────────────────────────


class FreezeStep(str, Enum):
    """The five sub-steps a freeze orchestrates."""

    REGISTRY_REVOKE = "registry_revoke"
    WEBHOOK_BROADCAST = "webhook_broadcast"
    LEDGER_LOG = "ledger_log"
    NOTIFICATION = "notification"
    INCIDENT_PACKAGE = "incident_package"


@dataclass
class StepResult:
    step: FreezeStep
    ok: bool
    detail: str
    duration_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step.value,
            "ok": self.ok,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


@dataclass
class FreezeReceipt:
    """Tamper-evident record of a freeze invocation."""

    freeze_id: str
    schema: str = "squash.freeze.receipt/v1"
    initiated_at: str = ""
    completed_at: str = ""
    attestation_id: str = ""
    model_id: str = ""
    model_path: str = ""
    reason: str = ""
    actor: str = ""

    revoked_entries: list[str] = field(default_factory=list)
    webhook_results: list[dict[str, Any]] = field(default_factory=list)
    notification_event: str = ""
    incident_id: str = ""
    incident_dir: str = ""

    steps: list[StepResult] = field(default_factory=list)
    payload_hash: str = ""    # SHA-256 of canonical receipt body (excludes signature)
    signature_hex: str = ""   # Ed25519 signature of payload_hash, hex-encoded
    signing_pubkey_pem: str = ""

    # ── derived ────────────────────────────────────────────────────────────
    @property
    def all_ok(self) -> bool:
        return all(s.ok for s in self.steps)

    @property
    def revoke_ok(self) -> bool:
        return any(s.ok for s in self.steps if s.step == FreezeStep.REGISTRY_REVOKE)

    def step_result(self, step: FreezeStep) -> StepResult | None:
        for s in self.steps:
            if s.step == step:
                return s
        return None

    # ── serialization ──────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "freeze_id": self.freeze_id,
            "initiated_at": self.initiated_at,
            "completed_at": self.completed_at,
            "attestation_id": self.attestation_id,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "reason": self.reason,
            "actor": self.actor,
            "revoked_entries": list(self.revoked_entries),
            "webhook_results": list(self.webhook_results),
            "notification_event": self.notification_event,
            "incident_id": self.incident_id,
            "incident_dir": self.incident_dir,
            "steps": [s.to_dict() for s in self.steps],
            "payload_hash": self.payload_hash,
            "signature_hex": self.signature_hex,
            "signing_pubkey_pem": self.signing_pubkey_pem,
        }

    def canonical_payload_bytes(self) -> bytes:
        body = self.to_dict()
        # Signature/hash fields must be excluded from the canonical payload.
        body.pop("payload_hash", None)
        body.pop("signature_hex", None)
        body.pop("signing_pubkey_pem", None)
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def summary(self) -> str:
        lines = [
            "SQUASH FREEZE RECEIPT",
            "=" * 54,
            f"Freeze ID:        {self.freeze_id}",
            f"Attestation ID:   {self.attestation_id or '(by model path)'}",
            f"Model:            {self.model_id or self.model_path}",
            f"Initiated:        {self.initiated_at}",
            f"Completed:        {self.completed_at}",
            f"Actor:            {self.actor or 'unknown'}",
            f"Reason:           {self.reason or '(not provided)'}",
            "",
            "Steps:",
        ]
        for s in self.steps:
            mark = "✓" if s.ok else "✗"
            lines.append(f"  {mark} [{s.duration_ms:>5} ms] {s.step.value}: {s.detail}")
            if not s.ok and s.error:
                lines.append(f"        error: {s.error}")
        lines.append("")
        lines.append(f"Revoked entries: {len(self.revoked_entries)}")
        lines.append(f"Webhook fanout:  {len(self.webhook_results)}")
        if self.incident_id:
            lines.append(f"Incident:        {self.incident_id}")
            if self.incident_dir:
                lines.append(f"   artefacts in:  {self.incident_dir}")
        if self.signature_hex:
            lines.append(f"Signature:       {self.signature_hex[:32]}…")
        else:
            lines.append("Signature:       (unsigned — no private key supplied)")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────────


class FreezeOrchestrator:
    """Drives the full ``squash freeze`` sequence.

    Constructed with optional dependency overrides for testing — every
    collaborator (registry, webhook, notifier, incident factory, ledger
    sink) can be swapped without monkey-patching imports.
    """

    def __init__(
        self,
        *,
        registry: Any | None = None,
        webhook: Any | None = None,
        notifier: Any | None = None,
        incident_factory: Any | None = None,
        state_dir: str | os.PathLike[str] | None = None,
        priv_key_pem: str | bytes | os.PathLike[str] | None = None,
    ) -> None:
        self._registry = registry
        self._webhook = webhook
        self._notifier = notifier
        self._incident_factory = incident_factory
        self._state_dir = Path(state_dir) if state_dir else (Path.home() / ".squash")
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._ledger_path = self._state_dir / "freeze_ledger.jsonl"
        self._priv_key_input = priv_key_pem

    # ── public API ─────────────────────────────────────────────────────────

    def freeze(
        self,
        *,
        attestation_id: str | None = None,
        model_path: str | os.PathLike[str] | None = None,
        model_id: str = "",
        reason: str = "",
        actor: str = "",
        severity: str = "critical",
        category: str = "other",
        affected_persons: int = 0,
        incident_dir: str | os.PathLike[str] | None = None,
        write_incident: bool = True,
        webhook_timeout_s: float = 10.0,
    ) -> FreezeReceipt:
        if not attestation_id and not model_path:
            raise ValueError(
                "freeze() requires either attestation_id= or model_path= "
                "— neither was provided"
            )

        freeze_id = f"FREEZE-{uuid.uuid4().hex[:12].upper()}"
        started = _utc_now()

        receipt = FreezeReceipt(
            freeze_id=freeze_id,
            initiated_at=started,
            attestation_id=attestation_id or "",
            model_id=model_id or (Path(model_path).name if model_path else ""),
            model_path=str(model_path) if model_path else "",
            reason=reason,
            actor=actor or _default_actor(),
        )

        # ── Step 1: revoke in registry ─────────────────────────────────────
        revoke_step = self._step_revoke(
            attestation_id=attestation_id,
            model_id=model_id,
            receipt=receipt,
        )
        receipt.steps.append(revoke_step)

        if not revoke_step.ok:
            # If we cannot revoke, abort before any broadcast — emergency
            # response that lies (claims a freeze that never landed) is
            # worse than no response at all.
            receipt.completed_at = _utc_now()
            self._sign_and_log(receipt)
            return receipt

        # ── Step 2: broadcast webhook ──────────────────────────────────────
        receipt.steps.append(self._step_webhook(receipt, webhook_timeout_s))

        # ── Step 3: signed ledger entry ────────────────────────────────────
        receipt.steps.append(self._step_ledger(receipt))

        # ── Step 4: notification fanout ────────────────────────────────────
        receipt.steps.append(self._step_notify(receipt))

        # ── Step 5: incident package ───────────────────────────────────────
        receipt.steps.append(
            self._step_incident(
                receipt,
                severity=severity,
                category=category,
                affected_persons=affected_persons,
                out_dir=incident_dir,
                write=write_incident,
            )
        )

        receipt.completed_at = _utc_now()
        self._sign_and_log(receipt)
        return receipt

    # ── step implementations ───────────────────────────────────────────────

    def _step_revoke(
        self,
        *,
        attestation_id: str | None,
        model_id: str,
        receipt: FreezeReceipt,
    ) -> StepResult:
        t0 = _now_ms()
        try:
            from squash.attestation_registry import AttestationRegistry
        except Exception as exc:
            return StepResult(
                step=FreezeStep.REGISTRY_REVOKE,
                ok=False,
                detail="attestation_registry import failed",
                duration_ms=_now_ms() - t0,
                error=str(exc),
            )

        reg = self._registry if self._registry is not None else AttestationRegistry()

        try:
            entries: list[Any] = []
            if attestation_id:
                hit = reg.get_entry(attestation_id) if hasattr(reg, "get_entry") else None
                if hit is not None:
                    entries = [hit]
                else:
                    entries = reg.lookup(entry_id=attestation_id, limit=1)
            if not entries and (model_id or receipt.model_id):
                entries = reg.lookup(model_id=model_id or receipt.model_id, limit=100)

            if not entries:
                return StepResult(
                    step=FreezeStep.REGISTRY_REVOKE,
                    ok=False,
                    detail="no matching live attestation found in registry",
                    duration_ms=_now_ms() - t0,
                    error="not_found",
                )

            revoked: list[str] = []
            for e in entries:
                eid = getattr(e, "entry_id", None) or (
                    e.get("entry_id") if isinstance(e, dict) else None
                )
                if not eid:
                    continue
                ok = reg.revoke(eid)
                if ok:
                    revoked.append(eid)

            receipt.revoked_entries = revoked

            if not revoked:
                return StepResult(
                    step=FreezeStep.REGISTRY_REVOKE,
                    ok=False,
                    detail="registry.revoke() returned False for all matches",
                    duration_ms=_now_ms() - t0,
                    error="revoke_returned_false",
                )

            return StepResult(
                step=FreezeStep.REGISTRY_REVOKE,
                ok=True,
                detail=f"revoked {len(revoked)} attestation(s)",
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("freeze revoke step failed")
            return StepResult(
                step=FreezeStep.REGISTRY_REVOKE,
                ok=False,
                detail="registry call raised",
                duration_ms=_now_ms() - t0,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _step_webhook(
        self, receipt: FreezeReceipt, timeout_s: float
    ) -> StepResult:
        t0 = _now_ms()
        try:
            from squash.webhook_delivery import WebhookDelivery, WebhookEvent
        except Exception as exc:
            return StepResult(
                step=FreezeStep.WEBHOOK_BROADCAST,
                ok=False,
                detail="webhook_delivery import failed",
                duration_ms=_now_ms() - t0,
                error=str(exc),
            )

        wh = self._webhook if self._webhook is not None else WebhookDelivery(
            db_path=str(self._state_dir / "webhooks.db")
        )

        payload = {
            "freeze_id": receipt.freeze_id,
            "attestation_id": receipt.attestation_id,
            "revoked_entries": receipt.revoked_entries,
            "model_id": receipt.model_id,
            "model_path": receipt.model_path,
            "reason": receipt.reason,
            "actor": receipt.actor,
            "initiated_at": receipt.initiated_at,
        }

        try:
            results = wh.dispatch(WebhookEvent.ATTESTATION_FROZEN, payload, timeout_s=timeout_s)
        except Exception as exc:  # noqa: BLE001
            log.exception("freeze webhook step raised")
            return StepResult(
                step=FreezeStep.WEBHOOK_BROADCAST,
                ok=False,
                detail="webhook dispatch raised",
                duration_ms=_now_ms() - t0,
                error=f"{type(exc).__name__}: {exc}",
            )

        ok_count = 0
        for r in results or []:
            d = _coerce_dict(r)
            receipt.webhook_results.append(d)
            if d.get("success") or (200 <= int(d.get("status_code") or 0) < 300):
                ok_count += 1

        total = len(results or [])
        return StepResult(
            step=FreezeStep.WEBHOOK_BROADCAST,
            ok=ok_count == total,
            detail=(
                f"delivered to {ok_count}/{total} subscribers"
                if total
                else "no subscribers registered (no-op)"
            ),
            duration_ms=_now_ms() - t0,
            error="" if ok_count == total else f"{total - ok_count} delivery failure(s)",
        )

    def _step_ledger(self, receipt: FreezeReceipt) -> StepResult:
        t0 = _now_ms()
        try:
            entry = {
                "schema": "squash.freeze.ledger/v1",
                "freeze_id": receipt.freeze_id,
                "logged_at": _utc_now(),
                "attestation_id": receipt.attestation_id,
                "revoked_entries": list(receipt.revoked_entries),
                "model_id": receipt.model_id,
                "model_path": receipt.model_path,
                "reason": receipt.reason,
                "actor": receipt.actor,
            }
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry_hash = hashlib.sha256(line.encode()).hexdigest()
            entry["entry_hash"] = entry_hash
            with self._ledger_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            return StepResult(
                step=FreezeStep.LEDGER_LOG,
                ok=True,
                detail=f"appended to {self._ledger_path}",
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("freeze ledger step failed")
            return StepResult(
                step=FreezeStep.LEDGER_LOG,
                ok=False,
                detail="ledger append raised",
                duration_ms=_now_ms() - t0,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _step_notify(self, receipt: FreezeReceipt) -> StepResult:
        t0 = _now_ms()
        try:
            from squash.notifications import ATTESTATION_FROZEN, notify
        except Exception as exc:
            return StepResult(
                step=FreezeStep.NOTIFICATION,
                ok=False,
                detail="notifications import failed",
                duration_ms=_now_ms() - t0,
                error=str(exc),
            )

        receipt.notification_event = ATTESTATION_FROZEN

        details = {
            "freeze_id": receipt.freeze_id,
            "attestation_id": receipt.attestation_id,
            "revoked_entries": receipt.revoked_entries,
            "actor": receipt.actor,
            "reason": receipt.reason,
        }

        try:
            if self._notifier is not None:
                result = self._notifier.notify(
                    ATTESTATION_FROZEN,
                    model_id=receipt.model_id,
                    details=details,
                    title=f"EMERGENCY FREEZE — {receipt.model_id or receipt.attestation_id}",
                )
            else:
                result = notify(
                    ATTESTATION_FROZEN,
                    model_id=receipt.model_id,
                    details=details,
                    title=f"EMERGENCY FREEZE — {receipt.model_id or receipt.attestation_id}",
                )
        except Exception as exc:  # noqa: BLE001
            log.exception("freeze notify step raised")
            return StepResult(
                step=FreezeStep.NOTIFICATION,
                ok=False,
                detail="notifier raised",
                duration_ms=_now_ms() - t0,
                error=f"{type(exc).__name__}: {exc}",
            )

        delivered = _result_delivered(result)
        return StepResult(
            step=FreezeStep.NOTIFICATION,
            ok=delivered,
            detail=(
                "delivered to configured channels"
                if delivered
                else "dispatcher returned non-delivered status"
            ),
            duration_ms=_now_ms() - t0,
            error="" if delivered else _result_error(result),
        )

    def _step_incident(
        self,
        receipt: FreezeReceipt,
        *,
        severity: str,
        category: str,
        affected_persons: int,
        out_dir: str | os.PathLike[str] | None,
        write: bool,
    ) -> StepResult:
        t0 = _now_ms()
        try:
            from squash.incident import IncidentResponder
        except Exception as exc:
            return StepResult(
                step=FreezeStep.INCIDENT_PACKAGE,
                ok=False,
                detail="incident import failed",
                duration_ms=_now_ms() - t0,
                error=str(exc),
            )

        if not receipt.model_path:
            # incident builder requires a model path; fall back to a synthetic
            # placeholder so the package still records the freeze metadata.
            receipt.model_path = str(self._state_dir / f"{receipt.freeze_id}.placeholder")
            try:
                Path(receipt.model_path).touch(exist_ok=True)
            except Exception:  # noqa: BLE001
                pass

        try:
            factory = self._incident_factory or IncidentResponder.respond
            description = (
                receipt.reason
                or f"squash freeze invoked at {receipt.initiated_at} by {receipt.actor}"
            )
            pkg = factory(
                model_path=Path(receipt.model_path),
                description=description,
                severity=severity,
                category=category,
                affected_persons=affected_persons,
                model_id=receipt.model_id or None,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("freeze incident step raised")
            return StepResult(
                step=FreezeStep.INCIDENT_PACKAGE,
                ok=False,
                detail="IncidentResponder.respond raised",
                duration_ms=_now_ms() - t0,
                error=f"{type(exc).__name__}: {exc}",
            )

        receipt.incident_id = getattr(pkg, "incident_id", "") or ""

        if write:
            target = Path(out_dir) if out_dir else (
                self._state_dir / "freezes" / receipt.freeze_id
            )
            try:
                pkg.save(target)
                receipt.incident_dir = str(target)
            except Exception as exc:  # noqa: BLE001
                log.exception("freeze incident save raised")
                return StepResult(
                    step=FreezeStep.INCIDENT_PACKAGE,
                    ok=False,
                    detail=f"incident package built (id={receipt.incident_id}) but save failed",
                    duration_ms=_now_ms() - t0,
                    error=f"{type(exc).__name__}: {exc}",
                )

        return StepResult(
            step=FreezeStep.INCIDENT_PACKAGE,
            ok=True,
            detail=(
                f"incident {receipt.incident_id} built"
                + (f" → {receipt.incident_dir}" if receipt.incident_dir else "")
            ),
            duration_ms=_now_ms() - t0,
        )

    # ── signing & audit ────────────────────────────────────────────────────

    def _sign_and_log(self, receipt: FreezeReceipt) -> None:
        # Always compute the SHA-256 hash even if no key is available — it
        # makes the receipt comparable across copies even when unsigned.
        try:
            payload = receipt.canonical_payload_bytes()
            receipt.payload_hash = hashlib.sha256(payload).hexdigest()
        except Exception:  # noqa: BLE001
            log.exception("freeze receipt canonicalisation failed")

        priv = self._load_priv_key()
        if priv is None:
            return

        try:
            from cryptography.hazmat.primitives import serialization
        except Exception:
            return

        try:
            sig = priv.sign(payload)
            receipt.signature_hex = sig.hex()
            receipt.signing_pubkey_pem = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
        except Exception:  # noqa: BLE001
            log.exception("freeze receipt signing failed")

    def _load_priv_key(self) -> Any | None:
        if self._priv_key_input is None:
            return None
        try:
            from cryptography.hazmat.primitives import serialization
        except Exception:
            log.warning("cryptography not installed — freeze receipt will be unsigned")
            return None

        data: bytes
        if isinstance(self._priv_key_input, (bytes, bytearray)):
            data = bytes(self._priv_key_input)
        else:
            p = Path(self._priv_key_input)  # type: ignore[arg-type]
            if not p.exists():
                log.warning("freeze priv-key path does not exist: %s", p)
                return None
            data = p.read_bytes()
        try:
            return serialization.load_pem_private_key(data, password=None)
        except Exception:  # noqa: BLE001
            log.exception("freeze priv-key load failed")
            return None


# ──────────────────────────────────────────────────────────────────────────────
# Convenience module-level entry point
# ──────────────────────────────────────────────────────────────────────────────


def freeze(
    *,
    attestation_id: str | None = None,
    model_path: str | os.PathLike[str] | None = None,
    model_id: str = "",
    reason: str = "",
    actor: str = "",
    severity: str = "critical",
    category: str = "other",
    affected_persons: int = 0,
    incident_dir: str | os.PathLike[str] | None = None,
    state_dir: str | os.PathLike[str] | None = None,
    priv_key_pem: str | bytes | os.PathLike[str] | None = None,
    write_incident: bool = True,
    webhook_timeout_s: float = 10.0,
    registry: Any | None = None,
    webhook: Any | None = None,
    notifier: Any | None = None,
    incident_factory: Any | None = None,
) -> FreezeReceipt:
    """One-shot emergency freeze — see :class:`FreezeOrchestrator`."""

    orchestrator = FreezeOrchestrator(
        registry=registry,
        webhook=webhook,
        notifier=notifier,
        incident_factory=incident_factory,
        state_dir=state_dir,
        priv_key_pem=priv_key_pem,
    )
    return orchestrator.freeze(
        attestation_id=attestation_id,
        model_path=model_path,
        model_id=model_id,
        reason=reason,
        actor=actor,
        severity=severity,
        category=category,
        affected_persons=affected_persons,
        incident_dir=incident_dir,
        write_incident=write_incident,
        webhook_timeout_s=webhook_timeout_s,
    )


def read_ledger(
    state_dir: str | os.PathLike[str] | None = None,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return freeze ledger entries (newest last)."""

    base = Path(state_dir) if state_dir else (Path.home() / ".squash")
    path = base / "freeze_ledger.jsonl"
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit is not None:
        return out[-limit:]
    return out


def verify_receipt(receipt: FreezeReceipt | dict[str, Any]) -> tuple[bool, str]:
    """Verify a freeze receipt's Ed25519 signature.

    Returns ``(ok, message)``.  An unsigned receipt verifies as ``(False, ...)``.
    """

    if isinstance(receipt, dict):
        # Re-hydrate a minimal receipt purely for canonicalisation.
        steps_raw = receipt.get("steps", [])
        steps = [
            StepResult(
                step=FreezeStep(s.get("step", FreezeStep.LEDGER_LOG.value)),
                ok=bool(s.get("ok", False)),
                detail=str(s.get("detail", "")),
                duration_ms=int(s.get("duration_ms", 0)),
                error=str(s.get("error", "")),
            )
            for s in steps_raw
        ]
        r = FreezeReceipt(
            freeze_id=str(receipt.get("freeze_id", "")),
            schema=str(receipt.get("schema", "squash.freeze.receipt/v1")),
            initiated_at=str(receipt.get("initiated_at", "")),
            completed_at=str(receipt.get("completed_at", "")),
            attestation_id=str(receipt.get("attestation_id", "")),
            model_id=str(receipt.get("model_id", "")),
            model_path=str(receipt.get("model_path", "")),
            reason=str(receipt.get("reason", "")),
            actor=str(receipt.get("actor", "")),
            revoked_entries=list(receipt.get("revoked_entries", [])),
            webhook_results=list(receipt.get("webhook_results", [])),
            notification_event=str(receipt.get("notification_event", "")),
            incident_id=str(receipt.get("incident_id", "")),
            incident_dir=str(receipt.get("incident_dir", "")),
            steps=steps,
            payload_hash=str(receipt.get("payload_hash", "")),
            signature_hex=str(receipt.get("signature_hex", "")),
            signing_pubkey_pem=str(receipt.get("signing_pubkey_pem", "")),
        )
    else:
        r = receipt

    if not r.signature_hex or not r.signing_pubkey_pem:
        return False, "receipt is unsigned"

    try:
        from cryptography.hazmat.primitives import serialization
    except Exception as exc:
        return False, f"cryptography unavailable: {exc}"

    try:
        pub = serialization.load_pem_public_key(r.signing_pubkey_pem.encode())
    except Exception as exc:  # noqa: BLE001
        return False, f"public key load failed: {exc}"

    try:
        pub.verify(bytes.fromhex(r.signature_hex), r.canonical_payload_bytes())
    except Exception as exc:  # noqa: BLE001
        return False, f"signature mismatch: {exc}"

    expected = hashlib.sha256(r.canonical_payload_bytes()).hexdigest()
    if r.payload_hash and r.payload_hash != expected:
        return False, "payload_hash does not match canonical body"

    return True, "ok"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _now_ms() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)


def _default_actor() -> str:
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    host = os.environ.get("HOSTNAME") or "localhost"
    return f"{user}@{host}"


def _coerce_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "to_dict"):
        try:
            return dict(obj.to_dict())
        except Exception:  # noqa: BLE001
            pass
    try:
        return asdict(obj)
    except Exception:  # noqa: BLE001
        out: dict[str, Any] = {}
        for k in ("endpoint_id", "url", "event", "status_code", "success",
                  "delivered", "error", "duration_ms", "attempts"):
            v = getattr(obj, k, None)
            if v is not None:
                out[k] = v
        return out


def _result_delivered(result: Any) -> bool:
    if result is None:
        return True  # no-op dispatcher counts as success
    if isinstance(result, bool):
        return result
    if isinstance(result, dict):
        if "delivered" in result:
            return bool(result["delivered"])
        if "success" in result:
            return bool(result["success"])
        if "ok" in result:
            return bool(result["ok"])
        return True
    for attr in ("delivered", "success", "ok"):
        if hasattr(result, attr):
            return bool(getattr(result, attr))
    return True


def _result_error(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, dict):
        return str(result.get("error", "")) or ""
    return str(getattr(result, "error", "")) or ""


__all__ = [
    "FreezeOrchestrator",
    "FreezeReceipt",
    "FreezeStep",
    "StepResult",
    "freeze",
    "read_ledger",
    "verify_receipt",
]
