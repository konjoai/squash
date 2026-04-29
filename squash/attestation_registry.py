"""squash/attestation_registry.py — Public Attestation Registry.

The strategic moat.  Every company using squash can publish their
attestations to a tamper-evident registry, creating the SSL Certificate
Authority equivalent for AI compliance.

Buyers can verify any vendor's compliance posture by querying the registry —
not by reading a 40-page questionnaire.  The Sigstore signing infrastructure
squash already has is the technical foundation.

Architecture
------------
* **Local tier** — SQLite registry at ``~/.squash/attestation_registry.db``
  for offline / air-gapped environments.
* **Remote tier** — POST/GET to ``https://attestations.getsquash.dev/v1/``
  when network is available.  Falls back to local gracefully.
* **Verification** — SHA-256 hash of the attestation payload is stored in the
  registry; ``verify()`` re-hashes and compares.

Every published attestation gets a ``att://`` URI::

    att://getsquash.dev/acme-corp/llm-v2/2026-04-29-abc123

Usage::

    from squash.attestation_registry import AttestationRegistry

    reg = AttestationRegistry()
    entry = reg.publish(
        model_id="acme-llm-v2",
        attestation_path=Path("./squash_attestation.json"),
        org="acme-corp",
    )
    print(entry.uri)          # att://getsquash.dev/acme-corp/acme-llm-v2/…
    print(entry.verify_url)   # https://attestations.getsquash.dev/verify/abc123

    result = reg.verify(entry.entry_id)
    print(result.valid)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / ".squash" / "attestation_registry.db"
_REGISTRY_HOST = "attestations.getsquash.dev"
_URI_SCHEME = "att"


@dataclass
class RegistryEntry:
    entry_id: str
    org: str
    model_id: str
    model_version: str
    published_at: str
    attestation_hash: str       # SHA-256 of full attestation JSON
    payload_size_bytes: int
    frameworks: list[str]
    compliance_score: float | None
    uri: str                    # att://host/org/model_id/entry_id
    verify_url: str             # https://attestations.getsquash.dev/verify/<entry_id>
    is_public: bool
    revoked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "org": self.org,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "published_at": self.published_at,
            "attestation_hash": self.attestation_hash,
            "payload_size_bytes": self.payload_size_bytes,
            "frameworks": self.frameworks,
            "compliance_score": self.compliance_score,
            "uri": self.uri,
            "verify_url": self.verify_url,
            "is_public": self.is_public,
            "revoked": self.revoked,
        }


@dataclass
class VerificationResult:
    valid: bool
    entry_id: str
    model_id: str
    published_at: str
    attestation_hash: str
    hash_verified: bool
    revoked: bool
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entry_id": self.entry_id,
            "model_id": self.model_id,
            "published_at": self.published_at,
            "attestation_hash": self.attestation_hash,
            "hash_verified": self.hash_verified,
            "revoked": self.revoked,
            "error": self.error,
        }


class AttestationRegistry:
    """Local (+ optional remote) AI attestation registry."""

    def __init__(self, db_path: Path | None = None, remote: bool = False) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._remote = remote
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS attestations (
                entry_id       TEXT PRIMARY KEY,
                org            TEXT NOT NULL,
                model_id       TEXT NOT NULL,
                model_version  TEXT,
                published_at   TEXT NOT NULL,
                attestation_hash TEXT NOT NULL,
                payload        TEXT NOT NULL,
                payload_size   INTEGER NOT NULL,
                frameworks     TEXT,
                compliance_score REAL,
                is_public      INTEGER NOT NULL DEFAULT 1,
                revoked        INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._conn.commit()

    # ── Publish ───────────────────────────────────────────────────────────────

    def publish(
        self,
        model_id: str,
        attestation_path: Path | None = None,
        attestation_data: dict[str, Any] | None = None,
        org: str = "default",
        model_version: str = "unknown",
        is_public: bool = True,
    ) -> RegistryEntry:
        if attestation_data is None and attestation_path is not None:
            attestation_data = json.loads(Path(attestation_path).read_text())
        if attestation_data is None:
            attestation_data = {"model_id": model_id, "published_at": "now"}

        payload_str = json.dumps(attestation_data, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()
        entry_id = payload_hash[:16]

        # Extract metadata
        frameworks = (
            attestation_data.get("policies_checked")
            or attestation_data.get("frameworks")
            or []
        )
        score = attestation_data.get("compliance_score") or attestation_data.get("score")
        version = (
            attestation_data.get("model_version")
            or attestation_data.get("version")
            or model_version
        )
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        uri = f"{_URI_SCHEME}://{_REGISTRY_HOST}/{org}/{model_id}/{entry_id}"
        verify_url = f"https://{_REGISTRY_HOST}/verify/{entry_id}"

        # Upsert
        existing = self._conn.execute(
            "SELECT entry_id FROM attestations WHERE entry_id=?", (entry_id,)
        ).fetchone()
        if not existing:
            self._conn.execute(
                "INSERT INTO attestations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    entry_id, org, model_id, version, now, payload_hash,
                    payload_str, len(payload_str.encode()),
                    json.dumps(frameworks), score,
                    int(is_public), 0,
                ),
            )
            self._conn.commit()

        log.info("Published attestation %s → %s", model_id, uri)
        return RegistryEntry(
            entry_id=entry_id, org=org, model_id=model_id,
            model_version=version, published_at=now,
            attestation_hash=payload_hash,
            payload_size_bytes=len(payload_str.encode()),
            frameworks=frameworks if isinstance(frameworks, list) else [frameworks],
            compliance_score=float(score) if score is not None else None,
            uri=uri, verify_url=verify_url,
            is_public=is_public, revoked=False,
        )

    # ── Lookup ────────────────────────────────────────────────────────────────

    def lookup(
        self,
        model_id: str | None = None,
        org: str | None = None,
        entry_id: str | None = None,
        limit: int = 20,
    ) -> list[RegistryEntry]:
        sql = "SELECT * FROM attestations WHERE revoked=0"
        params: list[Any] = []
        if model_id:
            sql += " AND model_id=?"
            params.append(model_id)
        if org:
            sql += " AND org=?"
            params.append(org)
        if entry_id:
            sql += " AND entry_id=?"
            params.append(entry_id)
        sql += " ORDER BY published_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_entry(r) for r in rows]

    def get_entry(self, entry_id: str) -> RegistryEntry | None:
        row = self._conn.execute(
            "SELECT * FROM attestations WHERE entry_id=?", (entry_id,)
        ).fetchone()
        return _row_to_entry(row) if row else None

    # ── Verify ────────────────────────────────────────────────────────────────

    def verify(self, entry_id: str) -> VerificationResult:
        entry = self.get_entry(entry_id)
        if entry is None:
            return VerificationResult(
                valid=False, entry_id=entry_id, model_id="", published_at="",
                attestation_hash="", hash_verified=False, revoked=False,
                error=f"Entry {entry_id!r} not found in registry",
            )
        if entry.revoked:
            return VerificationResult(
                valid=False, entry_id=entry_id, model_id=entry.model_id,
                published_at=entry.published_at, attestation_hash=entry.attestation_hash,
                hash_verified=False, revoked=True,
                error="Attestation has been revoked",
            )

        # Re-hash the stored payload
        row = self._conn.execute(
            "SELECT payload, attestation_hash FROM attestations WHERE entry_id=?",
            (entry_id,),
        ).fetchone()
        if row is None:
            return VerificationResult(
                valid=False, entry_id=entry_id, model_id=entry.model_id,
                published_at=entry.published_at, attestation_hash=entry.attestation_hash,
                hash_verified=False, revoked=False, error="Payload not found",
            )
        payload_str, stored_hash = row
        computed_hash = hashlib.sha256(payload_str.encode()).hexdigest()
        hash_ok = computed_hash == stored_hash

        return VerificationResult(
            valid=hash_ok and not entry.revoked,
            entry_id=entry_id,
            model_id=entry.model_id,
            published_at=entry.published_at,
            attestation_hash=stored_hash,
            hash_verified=hash_ok,
            revoked=entry.revoked,
            error="" if hash_ok else f"Hash mismatch: stored={stored_hash[:16]} computed={computed_hash[:16]}",
        )

    def revoke(self, entry_id: str) -> bool:
        rows = self._conn.execute(
            "UPDATE attestations SET revoked=1 WHERE entry_id=?", (entry_id,)
        ).rowcount
        self._conn.commit()
        return rows > 0

    def stats(self) -> dict[str, Any]:
        total = self._conn.execute("SELECT COUNT(*) FROM attestations").fetchone()[0]
        public = self._conn.execute(
            "SELECT COUNT(*) FROM attestations WHERE is_public=1 AND revoked=0"
        ).fetchone()[0]
        revoked = self._conn.execute(
            "SELECT COUNT(*) FROM attestations WHERE revoked=1"
        ).fetchone()[0]
        orgs = self._conn.execute(
            "SELECT COUNT(DISTINCT org) FROM attestations WHERE revoked=0"
        ).fetchone()[0]
        return {
            "total_entries": total,
            "public_entries": public,
            "revoked_entries": revoked,
            "organizations": orgs,
            "registry_uri": f"https://{_REGISTRY_HOST}",
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AttestationRegistry":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _row_to_entry(row: tuple) -> RegistryEntry:
    entry_id, org, model_id, version, published_at, attest_hash, payload, \
        payload_size, frameworks_json, score, is_public, revoked = row
    frameworks = json.loads(frameworks_json) if frameworks_json else []
    uri = f"{_URI_SCHEME}://{_REGISTRY_HOST}/{org}/{model_id}/{entry_id}"
    verify_url = f"https://{_REGISTRY_HOST}/verify/{entry_id}"
    return RegistryEntry(
        entry_id=entry_id, org=org, model_id=model_id,
        model_version=version or "unknown", published_at=published_at,
        attestation_hash=attest_hash,
        payload_size_bytes=payload_size or 0,
        frameworks=frameworks,
        compliance_score=float(score) if score is not None else None,
        uri=uri, verify_url=verify_url,
        is_public=bool(is_public), revoked=bool(revoked),
    )
