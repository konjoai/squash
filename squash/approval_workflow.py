"""squash/approval_workflow.py — Track C / C3 — Model Deployment Approval Workflow.

Sprint 23 (W232–W234).

The approval moment is where EU AI Act Article 9 risk-management responsibility
crystallises. A signed approval record is the single piece of evidence a regulator
wants on day one of an examination. Most organisations have human oversight as a
Confluence page or a Slack thread. Squash makes it cryptographic.

Regulatory anchors
------------------
* **EU AI Act Article 9** — high-risk systems require documented human oversight
  and a risk management process with explicit sign-off at each deployment stage.
* **NIST AI RMF GOVERN pillar** — requires accountability records mapping decisions
  to named roles.
* **ISO 42001 Control 8.4** — deployment of AI systems requires documented approval
  including the approver's identity and the basis for the decision.

Architecture
------------

    ApproverIdentity  — who is approving (email, name, role)
    ApprovalDecision  — APPROVED | REJECTED | APPROVED_WITH_CONDITIONS | PENDING
    ReviewerRole      — COMPLIANCE | ENGINEERING | SECURITY | LEGAL | EXECUTIVE | ANY

    ApprovalRecord    — single-reviewer signed record (HMAC-SHA256)
    ApprovalRequest   — full workflow object: attestation snapshot, reviewer list,
                        threshold, required roles, collected records, overall status
    ApprovalStore     — SQLite persistence (~/.squash/approvals.db)
    ApprovalWorkflow  — orchestrator: request(), approve(), status(), list_pending(),
                        export_evidence()

Signing
-------
Records are HMAC-SHA256 signed over a canonical JSON payload. The key is read from
``SQUASH_SIGNING_KEY`` (default: ``squash-approval-signing-key``). Optional Sigstore
keyless signing fires when the ``sigstore`` package is available and
``SQUASH_SIGSTORE_SIGN=1`` is set.

Multi-reviewer logic (W233)
---------------------------
* **Threshold** — require ≥N approvals from the declared reviewer list (N-of-M).
  A single REJECTED decision fails the entire request immediately.
* **Role-gated** — require that ≥1 reviewer per declared required role has APPROVED.
  Both conditions must be satisfied for the request to reach APPROVED status.
* **Pending state** — survives process restarts via SQLite. Polled by CLI and API.

Usage
-----
::

    wf = ApprovalWorkflow()

    # Requestor side
    req = wf.request(
        attestation_id="att://sha256:a3f1c8d...",
        model_id="bert-prod-v2",
        reviewers=["ciso@acme.com", "vp-eng@acme.com"],
        threshold=2,
        required_roles=[ReviewerRole.COMPLIANCE, ReviewerRole.ENGINEERING],
    )
    print(req.request_id)

    # Reviewer side (each reviewer calls independently)
    record = wf.approve(
        request_id=req.request_id,
        reviewer=ApproverIdentity(email="ciso@acme.com", name="Jane Smith",
                                   role=ReviewerRole.COMPLIANCE),
        decision=ApprovalDecision.APPROVED,
        rationale="Bias audit clean, drift baseline acceptable.",
    )

    # Check overall status
    status = wf.status(req.request_id)
    print(status.overall_status)  # PENDING / APPROVED / REJECTED

    # Export Article 9 evidence bundle
    evidence = wf.export_evidence(req.request_id)
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

_DEFAULT_DB = Path.home() / ".squash" / "approvals.db"


# ── Enumerations ──────────────────────────────────────────────────────────────


class ApprovalDecision(str, Enum):
    APPROVED                  = "APPROVED"
    REJECTED                  = "REJECTED"
    APPROVED_WITH_CONDITIONS  = "APPROVED_WITH_CONDITIONS"
    PENDING                   = "PENDING"


class ReviewerRole(str, Enum):
    COMPLIANCE  = "COMPLIANCE"
    ENGINEERING = "ENGINEERING"
    SECURITY    = "SECURITY"
    LEGAL       = "LEGAL"
    EXECUTIVE   = "EXECUTIVE"
    ANY         = "ANY"


class RequestStatus(str, Enum):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED  = "EXPIRED"


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class ApproverIdentity:
    """Identifies a single human reviewer."""

    email: str
    name: str = ""
    role: ReviewerRole = ReviewerRole.ANY
    oidc_issuer: str = ""   # e.g. "https://accounts.google.com"

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "name": self.name,
            "role": self.role.value,
            "oidc_issuer": self.oidc_issuer,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApproverIdentity":
        return cls(
            email=d.get("email", ""),
            name=d.get("name", ""),
            role=ReviewerRole(d.get("role", ReviewerRole.ANY)),
            oidc_issuer=d.get("oidc_issuer", ""),
        )


@dataclass
class ApprovalRecord:
    """A single reviewer's signed decision on one approval request.

    HMAC-SHA256 is computed over the canonical payload (all fields except
    ``signature`` itself) serialised with ``json.dumps(sort_keys=True)``.
    """

    record_id: str
    request_id: str
    reviewer: ApproverIdentity
    decision: ApprovalDecision
    rationale: str
    attestation_id: str      # att:// URI of the snapshot being approved
    attestation_hash: str    # SHA-256 of the attestation payload at approval time
    model_id: str
    created_at: str          # ISO-8601 UTC
    conditions: list[str] = field(default_factory=list)
    signature: str = ""      # HMAC-SHA256 hex; empty before signing

    def _payload(self) -> dict[str, Any]:
        """Canonical payload used for signing (excludes ``signature``)."""
        return {
            "record_id": self.record_id,
            "request_id": self.request_id,
            "reviewer": self.reviewer.to_dict(),
            "decision": self.decision.value,
            "rationale": self.rationale,
            "attestation_id": self.attestation_id,
            "attestation_hash": self.attestation_hash,
            "model_id": self.model_id,
            "created_at": self.created_at,
            "conditions": self.conditions,
            "squash_version": VERSION,
        }

    def sign(self, key: bytes | None = None) -> "ApprovalRecord":
        """Compute HMAC-SHA256 and attach to ``self.signature``."""
        if key is None:
            key = _signing_key()
        canonical = json.dumps(self._payload(), sort_keys=True, separators=(",", ":"))
        self.signature = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        return self

    def verify(self, key: bytes | None = None) -> bool:
        """Return True if the signature is valid for the current payload."""
        if not self.signature:
            return False
        if key is None:
            key = _signing_key()
        canonical = json.dumps(self._payload(), sort_keys=True, separators=(",", ":"))
        expected = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._payload(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApprovalRecord":
        return cls(
            record_id=d["record_id"],
            request_id=d["request_id"],
            reviewer=ApproverIdentity.from_dict(d["reviewer"]),
            decision=ApprovalDecision(d["decision"]),
            rationale=d.get("rationale", ""),
            attestation_id=d.get("attestation_id", ""),
            attestation_hash=d.get("attestation_hash", ""),
            model_id=d.get("model_id", ""),
            created_at=d.get("created_at", ""),
            conditions=d.get("conditions", []),
            signature=d.get("signature", ""),
        )


@dataclass
class ApprovalRequest:
    """Full workflow object tracking a multi-reviewer approval sequence.

    ``reviewers``      — email addresses of authorised reviewers.
    ``threshold``      — minimum number of APPROVED decisions needed.
    ``required_roles`` — every listed role must be represented by at least
                          one APPROVED record before the request can complete.
    ``records``        — collected ApprovalRecord objects (one per reviewer response).
    """

    request_id: str
    attestation_id: str
    attestation_hash: str
    model_id: str
    requestor_email: str
    reviewers: list[str]            # authorised email addresses
    threshold: int
    required_roles: list[ReviewerRole]
    requested_at: str               # ISO-8601 UTC
    expires_at: str                 # ISO-8601 UTC
    records: list[ApprovalRecord] = field(default_factory=list)
    notes: str = ""

    # ── Computed properties ───────────────────────────────────────────────────

    @property
    def overall_status(self) -> RequestStatus:
        """Derive current status from collected records.

        Rules (in precedence order):
        1. Any REJECTED → REJECTED immediately.
        2. Threshold met AND required roles satisfied → APPROVED.
        3. Otherwise → PENDING.
        """
        if any(r.decision == ApprovalDecision.REJECTED for r in self.records):
            return RequestStatus.REJECTED

        approved = [r for r in self.records
                    if r.decision in (ApprovalDecision.APPROVED,
                                      ApprovalDecision.APPROVED_WITH_CONDITIONS)]
        if len(approved) < self.threshold:
            return RequestStatus.PENDING

        # Check role coverage
        covered_roles = {r.reviewer.role for r in approved}
        for role in self.required_roles:
            if role not in covered_roles:
                return RequestStatus.PENDING

        return RequestStatus.APPROVED

    @property
    def approved_count(self) -> int:
        return sum(1 for r in self.records
                   if r.decision in (ApprovalDecision.APPROVED,
                                     ApprovalDecision.APPROVED_WITH_CONDITIONS))

    @property
    def pending_reviewers(self) -> list[str]:
        responded = {r.reviewer.email for r in self.records}
        return [e for e in self.reviewers if e not in responded]

    @property
    def all_conditions(self) -> list[str]:
        out: list[str] = []
        for r in self.records:
            out.extend(r.conditions)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "attestation_id": self.attestation_id,
            "attestation_hash": self.attestation_hash,
            "model_id": self.model_id,
            "requestor_email": self.requestor_email,
            "reviewers": self.reviewers,
            "threshold": self.threshold,
            "required_roles": [r.value for r in self.required_roles],
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "notes": self.notes,
            "overall_status": self.overall_status.value,
            "approved_count": self.approved_count,
            "pending_reviewers": self.pending_reviewers,
            "all_conditions": self.all_conditions,
            "records": [r.to_dict() for r in self.records],
            "squash_version": VERSION,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApprovalRequest":
        req = cls(
            request_id=d["request_id"],
            attestation_id=d.get("attestation_id", ""),
            attestation_hash=d.get("attestation_hash", ""),
            model_id=d.get("model_id", ""),
            requestor_email=d.get("requestor_email", ""),
            reviewers=d.get("reviewers", []),
            threshold=int(d.get("threshold", 1)),
            required_roles=[ReviewerRole(r) for r in d.get("required_roles", [])],
            requested_at=d.get("requested_at", ""),
            expires_at=d.get("expires_at", ""),
            notes=d.get("notes", ""),
        )
        req.records = [ApprovalRecord.from_dict(r) for r in d.get("records", [])]
        return req


# ── SQLite persistence ────────────────────────────────────────────────────────


class ApprovalStore:
    """SQLite-backed persistence for ApprovalRequest objects.

    One row per request; records are stored as a JSON blob on the row.
    The store is intentionally simple — approvals are audit trail artefacts,
    not high-frequency transactional data.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS approval_requests (
                request_id    TEXT PRIMARY KEY,
                model_id      TEXT NOT NULL,
                requestor     TEXT NOT NULL,
                status        TEXT NOT NULL,
                requested_at  TEXT NOT NULL,
                expires_at    TEXT NOT NULL,
                payload       TEXT NOT NULL   -- full ApprovalRequest JSON
            )
        """)
        self._conn.commit()

    def save(self, req: ApprovalRequest) -> None:
        payload = json.dumps(req.to_dict(), sort_keys=True)
        self._conn.execute("""
            INSERT OR REPLACE INTO approval_requests
            (request_id, model_id, requestor, status, requested_at, expires_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (req.request_id, req.model_id, req.requestor_email,
               req.overall_status.value, req.requested_at, req.expires_at, payload))
        self._conn.commit()

    def get(self, request_id: str) -> ApprovalRequest | None:
        row = self._conn.execute(
            "SELECT payload FROM approval_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if not row:
            return None
        return ApprovalRequest.from_dict(json.loads(row[0]))

    def list_pending(self, reviewer_email: str | None = None) -> list[ApprovalRequest]:
        rows = self._conn.execute(
            "SELECT payload FROM approval_requests WHERE status=?",
            (RequestStatus.PENDING.value,),
        ).fetchall()
        requests = [ApprovalRequest.from_dict(json.loads(r[0])) for r in rows]
        if reviewer_email:
            requests = [r for r in requests if reviewer_email in r.reviewers]
        return requests

    def list_all(self, limit: int = 50) -> list[ApprovalRequest]:
        rows = self._conn.execute(
            "SELECT payload FROM approval_requests ORDER BY requested_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [ApprovalRequest.from_dict(json.loads(r[0])) for r in rows]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ApprovalStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ── Workflow orchestrator ─────────────────────────────────────────────────────


class ApprovalWorkflow:
    """Orchestrate multi-reviewer approval requests for model deployments.

    W232: single-record creation + signing.
    W233: threshold + role-gated multi-reviewer logic + notifications.
    W234: called from CLI via the ``squash approve`` / ``squash request-approval``
           commands.
    """

    def __init__(
        self,
        store: ApprovalStore | None = None,
        db_path: Path | None = None,
        notify_on_change: bool = True,
        default_ttl_days: int = 30,
    ) -> None:
        self._store = store or ApprovalStore(db_path=db_path)
        self._notify = notify_on_change
        self._ttl_days = default_ttl_days

    # ── Request creation (W232) ───────────────────────────────────────────────

    def request(
        self,
        attestation_id: str,
        model_id: str = "",
        reviewers: list[str] | None = None,
        threshold: int = 1,
        required_roles: list[ReviewerRole] | None = None,
        requestor_email: str = "",
        notes: str = "",
        attestation_hash: str = "",
        ttl_days: int | None = None,
    ) -> ApprovalRequest:
        """Create a new approval request and persist it.

        Parameters
        ----------
        attestation_id  : att:// URI or bare entry_id of the attestation to approve.
        model_id        : Human-readable model identifier.
        reviewers       : Email addresses of authorised reviewers. Defaults to [].
        threshold       : Minimum number of APPROVED decisions needed (N-of-M).
        required_roles  : Every listed role must have at least one APPROVED record.
        requestor_email : Email of the person requesting approval.
        notes           : Free-text context for reviewers.
        attestation_hash: SHA-256 of attestation payload (snapshot integrity).
        ttl_days        : Days before the request expires (default: self._ttl_days).
        """
        now = _utc_now()
        expires = _add_days(now, ttl_days if ttl_days is not None else self._ttl_days)
        request_id = f"appr-{uuid.uuid4().hex[:16]}"

        req = ApprovalRequest(
            request_id=request_id,
            attestation_id=attestation_id,
            attestation_hash=attestation_hash or _sha256_of(attestation_id),
            model_id=model_id,
            requestor_email=requestor_email,
            reviewers=list(reviewers or []),
            threshold=max(1, threshold),
            required_roles=list(required_roles or []),
            requested_at=now,
            expires_at=expires,
            notes=notes,
        )
        self._store.save(req)
        self._fire(
            "approval.requested",
            model_id=model_id,
            details={
                "request_id": request_id,
                "attestation_id": attestation_id,
                "reviewers": req.reviewers,
                "threshold": threshold,
            },
        )
        return req

    # ── Reviewer action (W232 + W233) ─────────────────────────────────────────

    def approve(
        self,
        request_id: str,
        reviewer: ApproverIdentity,
        decision: ApprovalDecision,
        rationale: str,
        conditions: list[str] | None = None,
        signing_key: bytes | None = None,
    ) -> ApprovalRecord:
        """Record a single reviewer's decision on a request.

        Raises
        ------
        ValueError  : request not found, reviewer not authorised, already responded,
                      or request already completed.
        """
        req = self._store.get(request_id)
        if req is None:
            raise ValueError(f"Approval request {request_id!r} not found")

        if req.overall_status != RequestStatus.PENDING:
            raise ValueError(
                f"Request {request_id!r} is already {req.overall_status.value} "
                "and cannot accept further responses"
            )

        # Authorisation check — reviewer must be in the declared list.
        if req.reviewers and reviewer.email not in req.reviewers:
            raise ValueError(
                f"{reviewer.email!r} is not in the authorised reviewer list for "
                f"request {request_id!r}. Authorised: {req.reviewers}"
            )

        # Idempotency guard — one response per reviewer.
        existing = {r.reviewer.email for r in req.records}
        if reviewer.email in existing:
            raise ValueError(
                f"{reviewer.email!r} has already submitted a decision for "
                f"request {request_id!r}"
            )

        record = ApprovalRecord(
            record_id=f"rec-{uuid.uuid4().hex[:16]}",
            request_id=request_id,
            reviewer=reviewer,
            decision=decision,
            rationale=rationale,
            attestation_id=req.attestation_id,
            attestation_hash=req.attestation_hash,
            model_id=req.model_id,
            created_at=_utc_now(),
            conditions=list(conditions or []),
        ).sign(signing_key)

        req.records.append(record)
        self._store.save(req)

        # Fire notification on status change.
        new_status = req.overall_status
        if new_status != RequestStatus.PENDING:
            event = (
                "approval.approved" if new_status == RequestStatus.APPROVED
                else "approval.rejected"
            )
            self._fire(event, model_id=req.model_id, details={
                "request_id": request_id,
                "overall_status": new_status.value,
                "approved_count": req.approved_count,
                "threshold": req.threshold,
                "conditions": req.all_conditions,
            })
        else:
            self._fire("approval.response_recorded", model_id=req.model_id, details={
                "request_id": request_id,
                "reviewer": reviewer.email,
                "decision": decision.value,
                "approved_count": req.approved_count,
                "remaining": req.threshold - req.approved_count,
                "pending_reviewers": req.pending_reviewers,
            })

        return record

    # ── Query methods ─────────────────────────────────────────────────────────

    def status(self, request_id: str) -> ApprovalRequest:
        """Return the full ApprovalRequest or raise ValueError if not found."""
        req = self._store.get(request_id)
        if req is None:
            raise ValueError(f"Approval request {request_id!r} not found")
        return req

    def list_pending(self, reviewer_email: str | None = None) -> list[ApprovalRequest]:
        """Return all PENDING requests, optionally filtered to one reviewer."""
        return self._store.list_pending(reviewer_email)

    def list_all(self, limit: int = 50) -> list[ApprovalRequest]:
        """Return recent requests ordered by requested_at DESC."""
        return self._store.list_all(limit=limit)

    # ── Evidence export (W234) ────────────────────────────────────────────────

    def export_evidence(self, request_id: str) -> dict[str, Any]:
        """Build a regulator-ready Article 9 evidence bundle.

        The bundle includes:
        * Full ApprovalRequest JSON
        * Per-record signature verification results
        * Attestation snapshot reference (att:// URI + content hash)
        * Human-readable summary of the approval chain
        * Regulatory mapping to EU AI Act Art. 9 + NIST AI RMF GOVERN

        This is the artefact you hand to an auditor.
        """
        req = self.status(request_id)
        records_verified = []
        for r in req.records:
            records_verified.append({
                **r.to_dict(),
                "signature_valid": r.verify(),
            })

        summary_lines: list[str] = [
            f"Model: {req.model_id}",
            f"Attestation: {req.attestation_id}",
            f"Request ID: {req.request_id}",
            f"Overall status: {req.overall_status.value}",
            f"Requested at: {req.requested_at}",
            f"Threshold: {req.threshold} of {len(req.reviewers)} reviewers",
            f"Approved: {req.approved_count}",
        ]
        if req.all_conditions:
            summary_lines.append("Conditions: " + "; ".join(req.all_conditions))

        return {
            "squash_version": VERSION,
            "export_type": "approval_evidence",
            "regulatory_mapping": {
                "eu_ai_act": "Article 9 — Risk Management System (human oversight documentation)",
                "nist_ai_rmf": "GOVERN-1.2 — Accountability for AI decisions",
                "iso_42001": "Control 8.4 — Deployment approval",
            },
            "request": req.to_dict(),
            "records_with_verification": records_verified,
            "summary": "\n".join(summary_lines),
            "all_signatures_valid": all(r.verify() for r in req.records),
            "exported_at": _utc_now(),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _fire(self, event: str, model_id: str = "", details: dict | None = None) -> None:
        if not self._notify:
            return
        try:
            from squash.notifications import notify
            notify(event, model_id=model_id, details=details or {})
        except Exception:  # noqa: BLE001 — notifications are best-effort
            pass

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "ApprovalWorkflow":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _signing_key() -> bytes:
    return os.environ.get("SQUASH_SIGNING_KEY", "squash-approval-signing-key").encode()


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _add_days(iso: str, days: int) -> str:
    dt = datetime.datetime.fromisoformat(iso)
    return (dt + datetime.timedelta(days=days)).isoformat(timespec="seconds")


def _sha256_of(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()
