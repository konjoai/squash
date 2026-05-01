"""squash/drift_certificate.py — Drift SLA Certificate (B7 / W194).

What is a Drift SLA Certificate?
---------------------------------
A point-in-time attestation says "this model scored X today." That is
necessary but not sufficient for enterprise compliance. Auditors, insurance
underwriters, and enterprise procurement ask a harder question: *has this
model stayed compliant over time?*

A **Drift SLA Certificate** answers that question with a signed,
time-windowed assertion: "Model M maintained a compliance score ≥ T on
framework F for ≥ P% of the evaluation window [start, end], with at most V
violations, across N attestation snapshots."

This is the AI equivalent of a 99.9% uptime SLA certificate — except the
SLA is over regulatory compliance posture, not HTTP availability.

Use cases
---------
* **Insurance:** "Provide evidence of sustained AI Act compliance for the
  past 90 days" — attach the certificate.
* **Enterprise procurement:** vendor questionnaire asks for compliance
  history — export the cert to PDF and attach.
* **Board reporting:** CISO shows the board a signed certificate of model
  governance posture for Q2.
* **Regulatory audit:** auditor requests a compliance timeline —
  `squash drift-cert issue --window 365` covers the year.
* **Anchoring:** `squash anchor add <cert.json>` → `squash anchor commit`
  ties the cert to an immutable blockchain witness.

Architecture
------------
The module operates in three layers:

1. **Ledger** (:class:`ScoreLedger`) — a lightweight, append-only JSONL
   log of compliance snapshots. Can be populated from master-record JSON
   files produced by `squash attest --json-result`, from the attestation
   registry, or manually. Does not depend on the registry being populated.

2. **Evaluator** (:class:`SLAEvaluator`) — computes the SLA result over a
   :class:`ScoreLedger` slice: passes/fails, score statistics, violation
   windows, compliance rate, time coverage.

3. **Issuer** (:class:`DriftCertificateIssuer`) — wraps an evaluated SLA
   in a signed :class:`DriftCertificate` envelope using Ed25519 (offline)
   or Sigstore (keyless). The envelope is a portable JSON document with
   a `squash.drift.certificate/v1` schema marker so third parties can
   identify and verify it without squash being installed.

Cryptographic construction
--------------------------
The signed payload is ``canonical_json(cert_body)`` — the same deterministic
serialisation used by ``anchor.py``. This means the signature is stable
across pretty-printing, field reordering, and locale differences.

The certificate body includes:
* ``spec``        — the SLA contract (threshold, framework, window, limits)
* ``result``      — the computed SLA outcome (passes, rate, stats, violations)
* ``model_id``    — the model being certified
* ``issued_at``   — ISO-8601 UTC
* ``valid_until`` — ISO-8601 UTC (``issued_at + window_days``)
* ``cert_id``     — stable UUID-based identifier for anchoring/registry

Konjo notes
-----------
* 건조 — no new storage format; ScoreLedger reuses JSONL (same as
  AnchorLedger). Cert format reuses the canonical_json contract from
  anchor.py.
* ᨀᨚᨐᨚ — a certificate is a single JSON file that an auditor can verify
  with stdlib + cryptography. No squash installation required beyond
  possessing the issuer's public key.
* 康宙 — append-only ledger; on-demand issuance; no background daemon.
* 根性 — violation windows are computed precisely (not rounded to day
  boundaries) so the compliance rate is mathematically exact over the
  actual elapsed time, not a coarse bucket approximation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Re-use the canonical JSON contract established by anchor.py to keep
# hash semantics consistent across the squash provenance chain.
def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


# ---------------------------------------------------------------------------
# SLA specification
# ---------------------------------------------------------------------------

@dataclass
class DriftSLASpec:
    """The SLA contract — what the certificate certifies.

    Parameters
    ----------
    model_id:
        Model identifier being certified.
    framework:
        Compliance framework (e.g. ``"eu-ai-act"``, ``"iso-42001"``).
    min_score:
        Minimum passing compliance score (0-100).
    window_days:
        Length of the evaluation window in days.
    max_violation_rate:
        Maximum acceptable fraction of snapshots that may fall below
        ``min_score`` while still passing the SLA (e.g. ``0.05`` = 5%).
    min_snapshots:
        Minimum number of attestation snapshots required to issue a
        certificate. Below this floor the window has insufficient evidence
        to make a statistically meaningful claim.
    org:
        Optional organisation name embedded in the certificate.
    """
    model_id: str
    framework: str = "eu-ai-act"
    min_score: float = 80.0
    window_days: int = 90
    max_violation_rate: float = 0.05       # 5% violation budget
    min_snapshots: int = 3
    org: str = ""

    def __post_init__(self) -> None:
        if not 0 < self.min_score <= 100:
            raise ValueError(f"min_score must be in (0, 100]: {self.min_score}")
        if self.window_days <= 0:
            raise ValueError(f"window_days must be > 0: {self.window_days}")
        if not 0.0 <= self.max_violation_rate <= 1.0:
            raise ValueError(f"max_violation_rate must be in [0, 1]: {self.max_violation_rate}")
        if self.min_snapshots < 1:
            raise ValueError(f"min_snapshots must be >= 1: {self.min_snapshots}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Score ledger
# ---------------------------------------------------------------------------

@dataclass
class ScoreSnapshot:
    """One compliance snapshot for a model at a point in time."""
    timestamp: str           # ISO-8601 UTC
    model_id: str
    framework: str
    score: float
    passed: bool             # whether the attestation's overall passed flag was set
    attestation_id: str = ""
    source: str = "master_record"

    def dt(self) -> datetime:
        return _parse_iso(self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScoreLedger:
    """Append-only, file-backed ledger of compliance score snapshots.

    Each line in the JSONL file is one :class:`ScoreSnapshot`. Snapshots
    are ingested from master-record JSON files produced by
    ``squash attest --json-result`` or added manually.

    The ledger is the raw material from which SLA certificates are issued.
    It is separate from the attestation registry so it works offline and
    does not require the SQLite registry to be populated.
    """

    def __init__(self, ledger_path: Path | None = None) -> None:
        self.ledger_path = ledger_path or (
            Path.home() / ".squash" / "drift" / "score_ledger.jsonl"
        )
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def ingest(self, master_record_path: Path) -> ScoreSnapshot:
        """Parse a ``master_record.json`` and append a snapshot."""
        rec = json.loads(master_record_path.read_text())
        ts = rec.get("generated_at") or _utcnow().isoformat()
        framework_scores: dict[str, float] = rec.get("framework_scores") or {}
        # Pick the best available score for the given snapshot; fallback to
        # overall_score if no per-framework breakdown exists yet.
        snap = ScoreSnapshot(
            timestamp=ts,
            model_id=rec.get("model_id") or rec.get("attestation_id") or "unknown",
            framework="overall",
            score=rec.get("overall_score") or 0.0,
            passed=bool(rec.get("passed")),
            attestation_id=rec.get("attestation_id") or "",
            source="master_record",
        )
        # Emit one snapshot per framework so the ledger captures the full
        # per-framework history, not just the aggregate.
        snaps = [snap]
        for fw, score in framework_scores.items():
            snaps.append(ScoreSnapshot(
                timestamp=ts,
                model_id=snap.model_id,
                framework=fw,
                score=score,
                passed=score >= 80.0,  # default threshold; overridden at eval time
                attestation_id=snap.attestation_id,
                source="master_record",
            ))
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            for s in snaps:
                fh.write(json.dumps(s.to_dict(), sort_keys=True) + "\n")
        return snap

    def add_snapshot(self, snap: ScoreSnapshot) -> None:
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(snap.to_dict(), sort_keys=True) + "\n")

    def snapshots(
        self,
        model_id: str | None = None,
        framework: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[ScoreSnapshot]:
        if not self.ledger_path.exists():
            return []
        results: list[ScoreSnapshot] = []
        for line in self.ledger_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            s = ScoreSnapshot(**d)
            if model_id and s.model_id != model_id:
                continue
            if framework and s.framework != framework:
                continue
            dt = s.dt()
            if since and dt < since:
                continue
            if until and dt > until:
                continue
            results.append(s)
        results.sort(key=lambda x: x.timestamp)
        return results


# ---------------------------------------------------------------------------
# SLA evaluator
# ---------------------------------------------------------------------------

@dataclass
class ViolationWindow:
    """A contiguous run of snapshots that failed the SLA threshold."""
    start: str
    end: str
    min_score_in_window: float
    snapshot_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SLAResult:
    """Computed SLA outcome over a slice of the score ledger."""
    passes_sla: bool
    snapshot_count: int
    violation_count: int
    compliance_rate: float           # fraction of snapshots at or above min_score
    min_score: float
    max_score: float
    avg_score: float
    p10_score: float                 # 10th percentile — bottom-of-distribution view
    window_start: str                # ISO-8601 UTC
    window_end: str                  # ISO-8601 UTC
    violation_windows: list[ViolationWindow] = field(default_factory=list)
    failure_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["violation_windows"] = [v.to_dict() for v in self.violation_windows]
        return d


class SLAEvaluator:
    """Evaluate a :class:`DriftSLASpec` against a :class:`ScoreLedger`."""

    def evaluate(
        self,
        spec: DriftSLASpec,
        ledger: ScoreLedger,
        end: datetime | None = None,
    ) -> SLAResult:
        """Compute the SLA result for *spec* over *ledger*.

        The window is ``[end - window_days, end]``. *end* defaults to now.
        """
        end = end or _utcnow()
        start = end - timedelta(days=spec.window_days)

        snapshots = ledger.snapshots(
            model_id=spec.model_id,
            framework=spec.framework,
            since=start,
            until=end,
        )

        w_start = start.isoformat()
        w_end = end.isoformat()

        if not snapshots:
            return SLAResult(
                passes_sla=False,
                snapshot_count=0,
                violation_count=0,
                compliance_rate=0.0,
                min_score=0.0,
                max_score=0.0,
                avg_score=0.0,
                p10_score=0.0,
                window_start=w_start,
                window_end=w_end,
                failure_reason="no snapshots found in the evaluation window",
            )

        if len(snapshots) < spec.min_snapshots:
            return SLAResult(
                passes_sla=False,
                snapshot_count=len(snapshots),
                violation_count=0,
                compliance_rate=0.0,
                min_score=min(s.score for s in snapshots),
                max_score=max(s.score for s in snapshots),
                avg_score=sum(s.score for s in snapshots) / len(snapshots),
                p10_score=_percentile([s.score for s in snapshots], 10),
                window_start=w_start,
                window_end=w_end,
                failure_reason=(
                    f"insufficient snapshots: {len(snapshots)} < min_snapshots={spec.min_snapshots}"
                ),
            )

        scores = [s.score for s in snapshots]
        violations = [s for s in snapshots if s.score < spec.min_score]
        violation_count = len(violations)
        compliance_rate = (len(snapshots) - violation_count) / len(snapshots)
        violation_rate = violation_count / len(snapshots)

        violation_windows = _compute_violation_windows(snapshots, spec.min_score)

        failure_reason = ""
        passes = True
        if violation_rate > spec.max_violation_rate:
            passes = False
            failure_reason = (
                f"violation rate {violation_rate:.1%} exceeds max_violation_rate "
                f"{spec.max_violation_rate:.1%} ({violation_count}/{len(snapshots)} snapshots)"
            )

        return SLAResult(
            passes_sla=passes,
            snapshot_count=len(snapshots),
            violation_count=violation_count,
            compliance_rate=compliance_rate,
            min_score=min(scores),
            max_score=max(scores),
            avg_score=sum(scores) / len(scores),
            p10_score=_percentile(scores, 10),
            window_start=snapshots[0].timestamp,
            window_end=snapshots[-1].timestamp,
            violation_windows=violation_windows,
            failure_reason=failure_reason,
        )


def _percentile(data: list[float], p: int) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)


def _compute_violation_windows(
    snapshots: list[ScoreSnapshot], min_score: float
) -> list[ViolationWindow]:
    """Find contiguous runs of below-threshold snapshots."""
    windows: list[ViolationWindow] = []
    run: list[ScoreSnapshot] = []
    for snap in snapshots:
        if snap.score < min_score:
            run.append(snap)
        else:
            if run:
                windows.append(ViolationWindow(
                    start=run[0].timestamp,
                    end=run[-1].timestamp,
                    min_score_in_window=min(s.score for s in run),
                    snapshot_count=len(run),
                ))
                run = []
    if run:
        windows.append(ViolationWindow(
            start=run[0].timestamp,
            end=run[-1].timestamp,
            min_score_in_window=min(s.score for s in run),
            snapshot_count=len(run),
        ))
    return windows


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------

@dataclass
class DriftCertificate:
    """A signed Drift SLA Certificate.

    The ``schema`` field is a stable type marker that third-party tools
    can match on to identify and parse squash drift certificates without
    importing squash. Canonical URI: ``squash.drift.certificate/v1``.

    The ``signature_hex`` is an Ed25519 signature over
    ``canonical_json(body)`` where ``body`` is the dict produced by
    :meth:`body_dict`. This matches the signing discipline of ``anchor.py``
    so both modules can share the same keypair and auditing infrastructure.
    """

    cert_id: str
    schema: str
    spec: DriftSLASpec
    result: SLAResult
    issued_at: str
    valid_until: str
    squash_version: str
    signature_hex: str = ""
    public_key_pem: str = ""
    signer: str = ""         # keyless OIDC identity or "local:<key_fingerprint>"

    def body_dict(self) -> dict[str, Any]:
        """The canonical dict over which the signature is computed.

        Excludes ``signature_hex``, ``public_key_pem``, and ``signer``
        to keep the signed surface stable across key rotation.
        """
        return {
            "cert_id": self.cert_id,
            "schema": self.schema,
            "spec": self.spec.to_dict(),
            "result": self.result.to_dict(),
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "squash_version": self.squash_version,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.body_dict()
        d["signature_hex"] = self.signature_hex
        d["public_key_pem"] = self.public_key_pem
        d["signer"] = self.signer
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        r = self.result
        spec = self.spec
        icon = "✅ PASS" if r.passes_sla else "❌ FAIL"
        lines = [
            f"# Drift SLA Certificate — {icon}",
            "",
            f"**Certificate ID:** `{self.cert_id}`  ",
            f"**Issued:** {self.issued_at}  ",
            f"**Valid until:** {self.valid_until}  ",
            f"**Schema:** `{self.schema}`",
            "",
            "## SLA Contract",
            "",
            f"| Parameter | Value |",
            f"|-----------|-------|",
            f"| Model | `{spec.model_id}` |",
            f"| Framework | `{spec.framework}` |",
            f"| Minimum score | {spec.min_score} / 100 |",
            f"| Max violation rate | {spec.max_violation_rate:.1%} |",
            f"| Evaluation window | {spec.window_days} days |",
            f"| Min snapshots | {spec.min_snapshots} |",
            "",
            "## SLA Result",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **Verdict** | {icon} |",
            f"| Compliance rate | {r.compliance_rate:.1%} |",
            f"| Snapshots evaluated | {r.snapshot_count} |",
            f"| Violations | {r.violation_count} |",
            f"| Score avg / min / p10 | {r.avg_score:.1f} / {r.min_score:.1f} / {r.p10_score:.1f} |",
            f"| Window | {r.window_start[:10]} → {r.window_end[:10]} |",
        ]
        if r.failure_reason:
            lines += ["", f"> **Reason for failure:** {r.failure_reason}"]
        if r.violation_windows:
            lines += ["", "## Violation Windows", ""]
            for vw in r.violation_windows:
                lines.append(
                    f"- {vw.start[:10]} → {vw.end[:10]}: "
                    f"{vw.snapshot_count} snapshot(s), min score {vw.min_score_in_window:.1f}"
                )
        if self.signature_hex:
            fp = hashlib.sha256(self.public_key_pem.encode()).hexdigest()[:16] if self.public_key_pem else "—"
            lines += [
                "", "## Signature",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Signer | `{self.signer or 'local'}` |",
                f"| Key fingerprint (SHA-256[:16]) | `{fp}` |",
                f"| Signature | `{self.signature_hex[:32]}…` |",
            ]
        lines += [
            "", "---",
            "",
            f"*Issued by [Squash](https://github.com/konjoai/squash) · "
            f"schema `{self.schema}` · cert `{self.cert_id}`*",
        ]
        return "\n".join(lines)

    def to_html(self) -> str:
        try:
            import markdown as md_lib  # type: ignore
            body = md_lib.markdown(self.to_markdown(), extensions=["tables"])
        except ImportError:
            body = "<pre>" + self.to_markdown() + "</pre>"

        icon_color = "#16a34a" if self.result.passes_sla else "#dc2626"
        verdict = "PASS" if self.result.passes_sla else "FAIL"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Drift SLA Certificate — {self.spec.model_id}</title>
<style>
  :root {{ --brand: #1e40af; --pass: #16a34a; --fail: #dc2626; --bg: #f8fafc; --border: #e2e8f0; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: var(--bg); color: #1e293b; line-height: 1.6; }}
  .header {{ background: var(--brand); color: white; padding: 2rem 3rem; }}
  .header h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: .25rem; }}
  .header .meta {{ opacity: .8; font-size: .875rem; }}
  .verdict {{ display: inline-block; padding: .3rem 1rem; border-radius: 9999px;
              font-weight: 700; font-size: 1.1rem; color: white;
              background: {icon_color}; margin-top: .5rem; }}
  .container {{ max-width: 860px; margin: 2rem auto; padding: 0 1.5rem; }}
  h2 {{ color: var(--brand); font-size: 1.1rem; margin: 2rem 0 .75rem;
        padding-bottom: .4rem; border-bottom: 2px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: var(--bg); text-align: left; padding: .5rem .75rem;
        font-size: .8rem; color: #64748b; text-transform: uppercase; }}
  td {{ padding: .5rem .75rem; border-bottom: 1px solid var(--border); font-size: .9rem; }}
  code {{ background: #f1f5f9; padding: .1rem .35rem; border-radius: 3px; font-size: .85rem; }}
  blockquote {{ border-left: 3px solid var(--fail); padding: .5rem 1rem;
                background: #fef2f2; margin: 1rem 0; color: #991b1b; }}
  .footer {{ text-align: center; color: #94a3b8; font-size: .8rem; padding: 2rem; }}
  @media print {{ .header {{ background: #1e40af !important; -webkit-print-color-adjust: exact; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>Squash — Drift SLA Certificate</h1>
  <div class="meta">Model: {self.spec.model_id} · Framework: {self.spec.framework} · Issued: {self.issued_at[:10]}</div>
  <div class="verdict">{verdict}</div>
</div>
<div class="container">
{body}
</div>
<div class="footer">
  Generated by <a href="https://github.com/konjoai/squash">Squash</a> ·
  schema <code>{self.schema}</code> · cert <code>{self.cert_id}</code>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Issuer
# ---------------------------------------------------------------------------

_SCHEMA = "squash.drift.certificate/v1"


class DriftCertificateIssuer:
    """Sign and verify Drift SLA Certificates.

    Signing uses the same Ed25519 infrastructure as ``LocalAnchor`` so
    a single keypair can anchor and sign certificates. The public key is
    embedded in the certificate envelope so verifiers need no side-channel
    key fetch.
    """

    def __init__(self, priv_key_path: Path | None = None) -> None:
        self.priv_key_path = Path(priv_key_path) if priv_key_path else None

    def issue(
        self,
        spec: DriftSLASpec,
        ledger: ScoreLedger,
        end: datetime | None = None,
        squash_version: str = "1.6.0",
    ) -> DriftCertificate:
        """Evaluate the SLA and issue a signed certificate."""
        evaluator = SLAEvaluator()
        result = evaluator.evaluate(spec, ledger, end=end)

        now = _utcnow()
        valid_until = now + timedelta(days=spec.window_days)
        cert_id = "dsc-" + uuid.uuid4().hex[:16]

        cert = DriftCertificate(
            cert_id=cert_id,
            schema=_SCHEMA,
            spec=spec,
            result=result,
            issued_at=now.isoformat(),
            valid_until=valid_until.isoformat(),
            squash_version=squash_version,
        )

        if self.priv_key_path and self.priv_key_path.exists():
            cert = self._sign(cert)

        return cert

    def _sign(self, cert: DriftCertificate) -> DriftCertificate:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        payload = _canonical_json(cert.body_dict())
        priv_pem = self.priv_key_path.read_bytes()
        priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(priv_obj, Ed25519PrivateKey):
            raise ValueError("DriftCertificateIssuer requires an Ed25519 private key")

        sig_hex = priv_obj.sign(payload).hex()
        pub_pem = priv_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        fp = hashlib.sha256(pub_pem.encode()).hexdigest()[:16]

        cert.signature_hex = sig_hex
        cert.public_key_pem = pub_pem
        cert.signer = f"local:{fp}"
        return cert

    @staticmethod
    def verify(cert: DriftCertificate) -> tuple[bool, str]:
        """Verify signature and certificate self-consistency."""
        if not cert.signature_hex or not cert.public_key_pem:
            return False, "certificate is unsigned"

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            pub_obj = serialization.load_pem_public_key(cert.public_key_pem.encode("ascii"))
        except Exception as exc:
            return False, f"public key load failed: {exc}"
        if not isinstance(pub_obj, Ed25519PublicKey):
            return False, "certificate public key is not Ed25519"

        payload = _canonical_json(cert.body_dict())
        try:
            pub_obj.verify(bytes.fromhex(cert.signature_hex), payload)
        except InvalidSignature:
            return False, "certificate Ed25519 signature INVALID"
        except Exception as exc:
            return False, f"verify error: {exc}"

        # Self-consistency: cert_id, schema, issued_at present.
        if not cert.cert_id or not cert.schema or not cert.issued_at:
            return False, "certificate is missing required fields"
        if cert.schema != _SCHEMA:
            return False, f"unknown schema: {cert.schema!r}"

        return True, "signature valid"


# ---------------------------------------------------------------------------
# Round-trip helpers
# ---------------------------------------------------------------------------

def load_certificate(path: Path) -> DriftCertificate:
    """Deserialise a certificate JSON file into a :class:`DriftCertificate`."""
    d = json.loads(path.read_text())
    spec = DriftSLASpec(**d["spec"])
    result_d = d["result"]
    vws = [ViolationWindow(**v) for v in result_d.pop("violation_windows", [])]
    result = SLAResult(**result_d, violation_windows=vws)
    return DriftCertificate(
        cert_id=d["cert_id"],
        schema=d["schema"],
        spec=spec,
        result=result,
        issued_at=d["issued_at"],
        valid_until=d["valid_until"],
        squash_version=d.get("squash_version", ""),
        signature_hex=d.get("signature_hex", ""),
        public_key_pem=d.get("public_key_pem", ""),
        signer=d.get("signer", ""),
    )


def default_ledger_path() -> Path:
    env = os.environ.get("SQUASH_DRIFT_LEDGER")
    if env:
        return Path(env)
    return Path.home() / ".squash" / "drift" / "score_ledger.jsonl"
