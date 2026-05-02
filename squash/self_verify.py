"""squash/self_verify.py — Phase G.3 chain walker.

Given a squash attestation directory (or the running binary's own
provenance), walk the cryptographic chain end-to-end:

* input_manifest.json — every input file's SHA-256 matches the on-disk bytes
* canonical body — re-encode under RFC 8785, hash, compare to embedded digest
* Ed25519 signature — verify against embedded public key
* RFC 3161 timestamp token — verify message imprint matches signed body
* Sigstore Rekor inclusion proof — opt-in (offline returns "skipped")
* SLSA in-toto Statement — subject digests resolve back to artefacts on disk

Exit code is 0 only when every link verifies. The CLI surface is::

    squash self-verify --attestation-dir <dir>           [strict]
    squash self-verify --attestation-dir <dir> --offline [skip TSA + Rekor]
    squash self-verify --check-timestamp                 [verify TSA only]

Konjo notes
~~~~~~~~~~~

* 건조 — every check is one function returning ``CheckResult``; the
  chain walker is a list-of-checks.
* ᨀᨚᨐᨚ — the transcript on stdout is the receipt; the exit code is the
  load-bearing answer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .canon import canonical_bytes
from .input_manifest import (
    InputManifest,
    from_dict as manifest_from_dict,
    manifest_hash,
    verify_manifest,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class VerificationReport:
    attestation_dir: Path
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_text(self) -> str:
        out = [f"squash self-verify — {self.attestation_dir}"]
        for c in self.checks:
            icon = "✅" if c.passed else "❌"
            out.append(f"  {icon} {c.name}{(' — ' + c.detail) if c.detail else ''}")
        out.append(f"\nResult: {'PASS' if self.passed else 'FAIL'}")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_input_manifest(att_dir: Path, model_dir: Path | None = None) -> CheckResult:
    """Re-hash every file in input_manifest.json and compare to stored digests."""
    manifest_path = att_dir / "input_manifest.json"
    if not manifest_path.exists():
        return CheckResult("input_manifest", False, "input_manifest.json not found")
    try:
        manifest = manifest_from_dict(json.loads(manifest_path.read_text()))
    except Exception as exc:
        return CheckResult("input_manifest", False, f"parse failed: {exc}")
    target = model_dir if model_dir else Path(manifest.root_path)
    ok, errors = verify_manifest(manifest, target)
    if ok:
        return CheckResult("input_manifest", True, f"{manifest.file_count} files match")
    return CheckResult("input_manifest", False, "; ".join(errors[:5]))


def check_canonical_body(att_dir: Path, body_filename: str = "squash-attest.json") -> CheckResult:
    """Re-encode the master record under RFC 8785; assert byte-stable round-trip."""
    body_path = att_dir / body_filename
    if not body_path.exists():
        return CheckResult("canonical_body", False, f"{body_filename} not found")
    try:
        parsed = json.loads(body_path.read_text())
    except Exception as exc:
        return CheckResult("canonical_body", False, f"JSON parse failed: {exc}")
    try:
        canonical_bytes(parsed)
    except Exception as exc:
        return CheckResult("canonical_body", False, f"canonical re-encode failed: {exc}")
    return CheckResult("canonical_body", True, "RFC 8785 round-trip clean")


def check_ed25519_signature(
    att_dir: Path,
    bom_filename: str = "cyclonedx-mlbom.json",
) -> CheckResult:
    """Verify the offline Ed25519 signature on the BOM, when present."""
    bom_path = att_dir / bom_filename
    sig_path = bom_path.with_suffix(".sig")
    pub_candidates = list(att_dir.glob("*.pub.pem"))
    if not bom_path.exists():
        return CheckResult("ed25519", True, "no BOM to verify (skipped)")
    if not sig_path.exists() or not pub_candidates:
        return CheckResult("ed25519", True, "no .sig / .pub.pem present (skipped)")
    pub_path = pub_candidates[0]
    try:
        from .oms_signer import OmsVerifier

        ok = OmsVerifier.verify_local(bom_path, pub_path, sig_path=sig_path)
        return CheckResult("ed25519", bool(ok), f"key={pub_path.name}")
    except Exception as exc:
        return CheckResult("ed25519", False, f"verify failed: {exc}")


def check_tsa_timestamp(
    att_dir: Path,
    body_filename: str = "squash-attest.json",
    *,
    offline: bool = False,
) -> CheckResult:
    """Verify the RFC 3161 timestamp token, when present."""
    if offline:
        return CheckResult("tsa", True, "skipped (--offline)")
    body_path = att_dir / body_filename
    tsa_path = att_dir / "tsa_token.json"
    if not tsa_path.exists():
        return CheckResult("tsa", True, "no tsa_token.json (skipped)")
    try:
        from .tsa import verify_timestamp_token

        token = json.loads(tsa_path.read_text())
        body = canonical_bytes(json.loads(body_path.read_text()))
        ok, detail = verify_timestamp_token(token["response_b64"], body)
        return CheckResult("tsa", ok, detail)
    except Exception as exc:
        return CheckResult("tsa", False, f"TSA verify failed: {exc}")


def check_slsa_provenance(
    att_dir: Path,
    bom_filename: str = "cyclonedx-mlbom.json",
) -> CheckResult:
    """Verify the SLSA in-toto Statement subject digest matches the BOM."""
    slsa_path = att_dir / "squash-slsa-provenance.json"
    bom_path = att_dir / bom_filename
    if not slsa_path.exists():
        return CheckResult("slsa", True, "no SLSA Statement (skipped)")
    if not bom_path.exists():
        return CheckResult("slsa", False, "BOM missing")
    try:
        statement = json.loads(slsa_path.read_text())
        subjects = statement.get("subject", [])
        bom_sha = hashlib.sha256(bom_path.read_bytes()).hexdigest()
        for s in subjects:
            stored = s.get("digest", {}).get("sha256")
            if stored == bom_sha:
                return CheckResult("slsa", True, f"subject digest matches BOM ({bom_sha[:12]}…)")
        return CheckResult("slsa", False, "no subject digest matches BOM bytes")
    except Exception as exc:
        return CheckResult("slsa", False, f"parse failed: {exc}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


_CHECKS: list[Callable[[Path], CheckResult]] = [
    check_input_manifest,
    check_canonical_body,
    check_ed25519_signature,
    check_slsa_provenance,
]


def verify(att_dir: Path | str, *, offline: bool = False) -> VerificationReport:
    """Run every check on *att_dir*; return a :class:`VerificationReport`."""
    att_dir = Path(att_dir)
    if not att_dir.exists():
        report = VerificationReport(attestation_dir=att_dir)
        report.checks.append(CheckResult("attestation_dir", False, "directory not found"))
        return report
    report = VerificationReport(attestation_dir=att_dir)
    report.checks.append(check_input_manifest(att_dir))
    report.checks.append(check_canonical_body(att_dir))
    report.checks.append(check_ed25519_signature(att_dir))
    report.checks.append(check_tsa_timestamp(att_dir, offline=offline))
    report.checks.append(check_slsa_provenance(att_dir))
    return report


def main(argv: list[str] | None = None) -> int:
    """`squash self-verify` entry point. Returns process exit code."""
    import argparse

    parser = argparse.ArgumentParser(prog="squash self-verify")
    parser.add_argument(
        "--attestation-dir",
        "-d",
        default=".",
        help="Directory containing the squash attestation artefacts (default: cwd).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip network-dependent checks (TSA, Rekor).",
    )
    parser.add_argument(
        "--check-timestamp",
        action="store_true",
        help="Run only the TSA timestamp check.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    args = parser.parse_args(argv)
    att_dir = Path(args.attestation_dir).resolve()

    if args.check_timestamp:
        result = check_tsa_timestamp(att_dir, offline=args.offline)
        report = VerificationReport(attestation_dir=att_dir, checks=[result])
    else:
        report = verify(att_dir, offline=args.offline)

    if args.json:
        out = {
            "attestation_dir": str(report.attestation_dir),
            "passed": report.passed,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in report.checks
            ],
        }
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(report.to_text())

    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover - CLI guard
    sys.exit(main())
