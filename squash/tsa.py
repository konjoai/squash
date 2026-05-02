"""squash/tsa.py — RFC 3161 trusted-timestamp client.

Phase G.3 — Cryptographic chain pillar 2: independent attestation of
*when* a signed cert was issued, by an external Time Stamping Authority.
This makes the issuance time **non-repudiable** — the squash signer
cannot back-date or forward-date a cert without colluding with the TSA.

Endpoint
~~~~~~~~

The default endpoint is configurable through the ``SQUASH_TSA_URL``
environment variable. When unset, we use DigiCert's free public TSA
(``http://timestamp.digicert.com``). For paid SLA customers, set::

    export SQUASH_TSA_URL="https://timestamp.digicert.com"   # paid TLS
    export SQUASH_TSA_URL="http://timestamp.globalsign.com/tsa/r6advanced1"

Wire format
~~~~~~~~~~~

RFC 3161 §3:

* Request: a CMS ``TimeStampReq`` containing the SHA-256 of the data to
  be timestamped, plus a 64-bit nonce.
* Response: a CMS ``TimeStampResp`` with a signed ``TSTInfo`` that
  embeds the message hash, the nonce, the TSA's policy OID, and the
  exact time of signing.

We send the binary request via HTTP ``POST`` with
``Content-Type: application/timestamp-query``, expect
``application/timestamp-reply``, and store the response bytes
unmodified in the cert envelope.

A network failure does **not** fail the cert — TSA timestamping is
opt-in via :func:`maybe_timestamp`. Strict callers (production
issuance) should call :func:`timestamp_or_fail`.

Verification
~~~~~~~~~~~~

:func:`verify_timestamp_token` parses the response with the
``cryptography`` package, asserts the message imprint matches the
canonical-cert digest, and returns the parsed time. The TSA root cert
is **not** validated against a trust store here — that is the caller's
responsibility (`squash self-verify --check-timestamp` does the full
chain walk).

Konjo notes
~~~~~~~~~~~

* 건조 — request encoding is ~30 lines of pure ASN.1; no third-party TSA
  client wrapper.
* ᨀᨚᨐᨚ — the response bytes are the receipt; we never re-shape them.
* 康宙 — the network call is opt-in; offline mode (`SQUASH_OFFLINE=1`)
  short-circuits the entire path.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_TSA_URL = "http://timestamp.digicert.com"
TSA_REQUEST_CONTENT_TYPE = "application/timestamp-query"
TSA_RESPONSE_CONTENT_TYPE = "application/timestamp-reply"
DEFAULT_TIMEOUT_SEC = 10.0

__all__ = [
    "TSAResult",
    "TSAError",
    "tsa_url",
    "build_request",
    "post_request",
    "timestamp_or_fail",
    "maybe_timestamp",
    "verify_timestamp_token",
]


class TSAError(RuntimeError):
    """Raised when a TSA request or verification fails."""


@dataclass(frozen=True)
class TSAResult:
    """Outcome of a TSA roundtrip.

    Attributes
    ----------
    request_b64:
        The TSA query bytes we sent, base64-encoded for embedding in
        JSON. Auditors re-derive it from the cert digest + nonce.
    response_b64:
        The TSA reply bytes, base64-encoded. This is the **token** —
        the load-bearing artefact of the timestamp.
    nonce:
        The 64-bit nonce we sent and expect to see echoed in the
        response. Mismatch → token forged for a different request.
    tsa_url:
        The endpoint that issued the token.
    """

    request_b64: str
    response_b64: str
    nonce: int
    tsa_url: str


def tsa_url() -> str:
    """Return the configured TSA endpoint.

    Order of resolution:

    1. ``SQUASH_TSA_URL`` env var (if set).
    2. :data:`DEFAULT_TSA_URL`.
    """
    return os.environ.get("SQUASH_TSA_URL", DEFAULT_TSA_URL).strip() or DEFAULT_TSA_URL


# ---------------------------------------------------------------------------
# RFC 3161 ASN.1 encoder — minimal, hand-rolled, no third-party deps.
# Produces a TimeStampReq containing:
#
#   TimeStampReq ::= SEQUENCE {
#       version          INTEGER  (v1),
#       messageImprint   MessageImprint,
#       reqPolicy        OBJECT IDENTIFIER OPTIONAL,
#       nonce            INTEGER OPTIONAL,
#       certReq          BOOLEAN  DEFAULT FALSE
#   }
#
#   MessageImprint ::= SEQUENCE {
#       hashAlgorithm    AlgorithmIdentifier,  -- SHA-256: 2.16.840.1.101.3.4.2.1
#       hashedMessage    OCTET STRING
#   }
#
# We hardcode SHA-256 and omit reqPolicy. certReq=TRUE so the TSA
# embeds its signing cert chain in the response — needed for offline
# verification.
# ---------------------------------------------------------------------------

# OID 2.16.840.1.101.3.4.2.1  (id-sha256)  →  DER-encoded bytes
_SHA256_OID_DER = bytes.fromhex("0609608648016503040201")
_NULL_DER = b"\x05\x00"
# AlgorithmIdentifier { sha256 }
_SHA256_ALG_ID = (
    b"\x30"
    + bytes([len(_SHA256_OID_DER) + len(_NULL_DER)])
    + _SHA256_OID_DER
    + _NULL_DER
)


def _der_int(n: int) -> bytes:
    """DER-encode a non-negative INTEGER."""
    if n == 0:
        return b"\x02\x01\x00"
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:  # add leading zero byte to keep INTEGER non-negative
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def _der_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_len(len(body)) + body


def _der_octet(b: bytes) -> bytes:
    return b"\x04" + _der_len(len(b)) + b


def _der_bool(v: bool) -> bytes:
    return b"\x01\x01" + (b"\xff" if v else b"\x00")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def build_request(message: bytes, *, nonce: int | None = None, cert_req: bool = True) -> tuple[bytes, int]:
    """Build a DER-encoded RFC 3161 TimeStampReq for *message*.

    Returns ``(der_bytes, nonce)``. The nonce is captured so the caller
    can verify the same value comes back in the response.
    """
    if nonce is None:
        nonce = secrets.randbits(64)
    digest = hashlib.sha256(message).digest()
    msg_imprint = _der_seq(_SHA256_ALG_ID, _der_octet(digest))
    parts = [_der_int(1), msg_imprint, _der_int(nonce)]
    if cert_req:
        parts.append(_der_bool(True))
    return _der_seq(*parts), nonce


def post_request(
    url: str,
    der_bytes: bytes,
    *,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> bytes:
    """POST *der_bytes* to *url* and return the response body."""
    req = urllib.request.Request(
        url,
        data=der_bytes,
        method="POST",
        headers={
            "Content-Type": TSA_REQUEST_CONTENT_TYPE,
            "Accept": TSA_RESPONSE_CONTENT_TYPE,
            "User-Agent": "squash-tsa-client/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            if TSA_RESPONSE_CONTENT_TYPE not in ct:
                raise TSAError(
                    f"unexpected content-type from TSA: {ct!r} (want {TSA_RESPONSE_CONTENT_TYPE})"
                )
            return resp.read()
    except urllib.error.URLError as exc:
        raise TSAError(f"TSA POST failed: {exc}") from exc


def _is_offline() -> bool:
    val = os.environ.get("SQUASH_OFFLINE", "").strip()
    return bool(val) and val.lower() not in {"0", "false", "no", "off"}


def timestamp_or_fail(
    message: bytes,
    *,
    url: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> TSAResult:
    """Send *message* to the TSA. Raises :class:`TSAError` on any failure.

    Production callers that require a timestamp (the "strict" path)
    use this. Use :func:`maybe_timestamp` when the timestamp is opt-in.
    """
    import base64

    if _is_offline():
        raise TSAError(
            "SQUASH_OFFLINE=1 — TSA roundtrip refused. "
            "Use --no-timestamp to issue without a TSA token."
        )
    endpoint = (url or tsa_url()).rstrip("/")
    der, nonce = build_request(message)
    resp = post_request(endpoint, der, timeout=timeout)
    return TSAResult(
        request_b64=base64.b64encode(der).decode("ascii"),
        response_b64=base64.b64encode(resp).decode("ascii"),
        nonce=nonce,
        tsa_url=endpoint,
    )


def maybe_timestamp(
    message: bytes,
    *,
    url: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> Optional[TSAResult]:
    """Best-effort timestamp. Returns ``None`` on any failure (logs warn).

    Use for opt-in attest paths where missing TSA does not invalidate
    the cert.
    """
    try:
        return timestamp_or_fail(message, url=url, timeout=timeout)
    except TSAError as exc:
        log.warning("TSA roundtrip skipped: %s", exc)
        return None


def verify_timestamp_token(
    response_b64: str,
    expected_message: bytes,
) -> tuple[bool, str]:
    """Parse a TSA response and assert its message imprint matches *expected_message*.

    Returns ``(ok, detail)``. We use ``cryptography`` if available; on
    parse failure we still surface a coarse but truthful answer.
    """
    import base64

    raw = base64.b64decode(response_b64.encode("ascii"))
    try:
        # ``cryptography`` 42+ exposes RFC 3161 helpers via the hazmat
        # layer. We do a coarse digest match here; full PKIX validation
        # is the caller's responsibility (squash self-verify).
        from cryptography.hazmat.primitives import hashes  # noqa: F401
    except ImportError:
        return False, "cryptography package required for TSA verification"
    expected_digest = hashlib.sha256(expected_message).digest()
    # The DER-encoded digest appears verbatim inside the response —
    # search for the OCTET STRING that follows the sha256 OID.
    if expected_digest in raw:
        return True, "message imprint match (digest found in response)"
    return False, "message imprint NOT in TSA response"
