"""squash/anchor.py — Audit-trail blockchain anchoring (B6 / Tier 3).

Squash attestations are write-once provenance records. To make those
records *independently* trustworthy — auditable without trusting the
squash server, the cloud API, or even the original signer's key —
they need to be **anchored**: bound to an external, immutable witness
that an auditor can verify on their own.

This module implements that anchoring layer with three properties that
every other "blockchain audit" tool gets wrong:

1. **Merkle-batch commitment, not per-record.**  Posting one chain
   transaction per attestation is wasteful and does not scale. We build
   a binary Merkle tree over a batch of attestation hashes and anchor
   only the root.  Each attestation gets a compact inclusion proof
   (``log2(N)`` sibling hashes) that any third party can verify against
   the published root.

2. **Multi-backend, offline-first.**  The default backend is
   :class:`LocalAnchor` — an Ed25519-signed witness that works in
   air-gapped environments.  :class:`OpenTimestampsAnchor` and
   :class:`EthereumAnchor` give Bitcoin-grade and Ethereum-grade
   immutability when network is available.  All three produce the same
   :class:`Anchor` envelope shape; verifiers don't care which was used.

3. **Verifier needs nothing but math.**  A portable inclusion proof
   (:meth:`AnchorLedger.export_proof`) is self-contained: leaf hash,
   sibling path, root, anchor metadata, signature.  Verification uses
   only :mod:`hashlib` and :mod:`cryptography` — no squash code, no
   network call, no trust in the issuer beyond holding their public key.

Cryptographic construction
--------------------------

For ``n`` attestations with canonical hashes ``h_1 .. h_n``:

* Leaf = ``SHA-256(0x00 || h_i)``     (domain-separated leaf hash)
* Inner = ``SHA-256(0x01 || L || R)`` (domain-separated internal node)
* Odd-length levels duplicate the last node (RFC 6962 style; sibling
  duplication, not zero-padding — keeps proofs symmetric).

The leading domain-separation byte prevents second-preimage attacks
that swap a leaf for an inner node — a flaw in early Merkle audit-log
deployments (e.g. early certificate transparency drafts).

For an attestation with master-record JSON ``M``:

* Canonical hash = ``SHA-256(canonical_json(M))``

Canonical JSON is deterministic: sorted keys, no whitespace, UTF-8.
This means two squash installations that produce semantically identical
attestations also produce bit-identical hashes — a prerequisite for
cross-organisation verification.

CLI
---

::

    squash anchor add ./out/master_record.json   # stage attestation
    squash anchor commit --backend local         # build root, anchor, persist
    squash anchor verify <attestation_id>        # independent inclusion check
    squash anchor proof  <attestation_id>        # emit portable proof JSON
    squash anchor list                            # past anchors
    squash anchor status                          # pending batch + last anchor

Design notes — *Konjo*
----------------------

* 건조 — pure stdlib for the Merkle math; ``cryptography`` only for the
  Ed25519 signature path (already a squash dependency); subprocess
  shell-out for OpenTimestamps / Ethereum so optional tools stay optional.
* ᨀᨚᨐᨚ — proofs are seaworthy: a single JSON file the auditor can carry
  to any machine and verify with 30 lines of code (a reference
  ``verify_proof()`` is the canonical implementation).
* 康宙 — append-only ledger; never rewrite history.  Compromises and
  rotations are recorded as new entries, never as edits.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Domain-separation prefixes (RFC 6962 §2.1) — keep these constants.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def canonical_json(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes for *value*.

    Phase G.2: this delegates to :func:`squash.canon.canonical_bytes` so
    the same canonicalisation discipline (sorted keys, no whitespace,
    sorted sets, ECMAScript-format numbers, no implicit ``str()``
    coercion) is shared by every signed payload in the codebase.

    Backwards-compatible with the prior in-process implementation for
    every dict / list / primitive value squash actually emits — verified
    by ``tests/test_canon_compat.py``. New restriction: dict keys must
    be strings, sets are sorted, naive datetimes are rejected. The audit
    contract demands all three.
    """
    from squash.canon import canonical_bytes

    return canonical_bytes(value)


def hash_attestation(record: dict[str, Any]) -> str:
    """Canonical SHA-256 hex digest of an attestation record dict.

    The hash is the *content* identity of the attestation — independent
    of the JSON file's pretty-printing. Two squash installations that
    produced semantically identical attestations will produce identical
    hashes, which is what makes cross-organisation verification work.
    """
    return hashlib.sha256(canonical_json(record)).hexdigest()


def _h(prefix: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(prefix)
    for p in parts:
        h.update(p)
    return h.digest()


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MerkleProof:
    """Inclusion proof for a single leaf.

    ``path`` is an ordered list of ``(sibling_hex, position)`` pairs from
    leaf upward, where ``position`` is ``"L"`` (sibling on the left, leaf
    derivative on the right) or ``"R"`` (sibling on the right). Verifying
    re-folds the path with the same domain-separated hash to recover the
    root, then compares against the claimed root.
    """

    leaf_hash: str           # hex of the *raw* attestation hash (NOT yet leaf-prefixed)
    path: list[tuple[str, str]]
    root: str                # hex of the Merkle root
    leaf_index: int
    leaf_count: int

    def verify(self) -> bool:
        """Recompute the root and compare. Pure-stdlib, no I/O."""
        cur = _h(_LEAF_PREFIX, bytes.fromhex(self.leaf_hash))
        for sibling_hex, position in self.path:
            sib = bytes.fromhex(sibling_hex)
            if position == "L":
                cur = _h(_NODE_PREFIX, sib, cur)
            elif position == "R":
                cur = _h(_NODE_PREFIX, cur, sib)
            else:
                return False
        return cur.hex() == self.root


class MerkleTree:
    """Binary Merkle tree over an ordered list of leaf hashes.

    Leaves are passed in as raw (unprefixed) hex digests — the tree applies
    the leaf domain-separator internally. Construction is O(n); a proof is
    O(log n) in time and space.

    The tree handles odd levels by duplicating the trailing node (the
    RFC 6962 convention) — it keeps proof shapes symmetric and avoids the
    "phantom node" attack that affects naive zero-padded trees.
    """

    def __init__(self, leaves_hex: list[str]) -> None:
        if not leaves_hex:
            raise ValueError("MerkleTree requires at least one leaf")
        self._raw_leaves: list[str] = list(leaves_hex)
        # levels[0] = leaf-hashed, levels[-1] = [root]
        leaf_layer = [_h(_LEAF_PREFIX, bytes.fromhex(h)) for h in leaves_hex]
        self._levels: list[list[bytes]] = [leaf_layer]
        cur = leaf_layer
        while len(cur) > 1:
            nxt: list[bytes] = []
            for i in range(0, len(cur), 2):
                left = cur[i]
                right = cur[i + 1] if i + 1 < len(cur) else cur[i]  # duplicate odd tail
                nxt.append(_h(_NODE_PREFIX, left, right))
            self._levels.append(nxt)
            cur = nxt

    @property
    def root_hex(self) -> str:
        return self._levels[-1][0].hex()

    @property
    def leaf_count(self) -> int:
        return len(self._raw_leaves)

    def proof(self, index: int) -> MerkleProof:
        if not 0 <= index < self.leaf_count:
            raise IndexError(f"leaf index {index} out of range [0, {self.leaf_count})")
        path: list[tuple[str, str]] = []
        i = index
        for level in self._levels[:-1]:
            if i % 2 == 0:
                # we are the LEFT child; sibling on the RIGHT (or duplicated self)
                sib = level[i + 1] if i + 1 < len(level) else level[i]
                path.append((sib.hex(), "R"))
            else:
                sib = level[i - 1]
                path.append((sib.hex(), "L"))
            i //= 2
        return MerkleProof(
            leaf_hash=self._raw_leaves[index],
            path=path,
            root=self.root_hex,
            leaf_index=index,
            leaf_count=self.leaf_count,
        )


# ---------------------------------------------------------------------------
# Anchor backends
# ---------------------------------------------------------------------------

@dataclass
class Anchor:
    """A single anchor record — root + backend-specific witness data.

    The envelope shape is identical across backends; ``backend_data``
    holds the backend's proof-of-publication (Ed25519 signature for
    local; ``.ots`` filename for OpenTimestamps; tx hash for Ethereum).
    """

    anchor_id: str
    root: str
    leaf_count: int
    backend: str
    backend_data: dict[str, Any]
    timestamp: float
    squash_version: str = "1"

    @property
    def iso_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AnchorBackend:
    """Abstract anchor backend. Subclasses produce a witness for a root."""

    name: str = "abstract"

    def anchor(self, root_hex: str, leaf_count: int) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, anchor: Anchor) -> tuple[bool, str]:  # pragma: no cover - interface
        raise NotImplementedError


class LocalAnchor(AnchorBackend):
    """Ed25519 signature over ``root || leaf_count || timestamp``.

    Why a local-signature backend in a "blockchain anchoring" module?
    Because air-gapped sites still need an immutable, verifiable witness.
    Combined with key-rotation discipline (publish public keys via a
    side channel) this gives the strongest tamper-evidence available
    when no chain is reachable. The ledger stays append-only; a
    compromised key is recorded as a new entry, never as a rewrite.
    """

    name = "local"

    def __init__(self, priv_key_path: Path, pub_key_path: Path | None = None) -> None:
        self.priv_key_path = Path(priv_key_path)
        self.pub_key_path = Path(pub_key_path) if pub_key_path else None

    def _signing_payload(self, root_hex: str, leaf_count: int, ts: float) -> bytes:
        return canonical_json({"root": root_hex, "leaf_count": leaf_count, "timestamp": ts})

    def anchor(self, root_hex: str, leaf_count: int) -> dict[str, Any]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        ts = time.time()
        payload = self._signing_payload(root_hex, leaf_count, ts)

        priv_pem = self.priv_key_path.read_bytes()
        priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(priv_obj, Ed25519PrivateKey):
            raise ValueError("LocalAnchor requires an Ed25519 private key")
        signature_hex = priv_obj.sign(payload).hex()

        # Embed the public key so verifiers do not need a separate fetch.
        pub_pem_text = ""
        if self.pub_key_path and self.pub_key_path.exists():
            pub_pem_text = self.pub_key_path.read_text()
        else:
            pub_pem_text = priv_obj.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")

        return {
            "signature_hex": signature_hex,
            "public_key_pem": pub_pem_text,
            "signed_timestamp": ts,
        }

    def verify(self, anchor: Anchor) -> tuple[bool, str]:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        bd = anchor.backend_data
        try:
            pub_obj = serialization.load_pem_public_key(bd["public_key_pem"].encode("ascii"))
        except Exception as exc:
            return False, f"public key load failed: {exc}"
        if not isinstance(pub_obj, Ed25519PublicKey):
            return False, "anchor public key is not Ed25519"
        payload = self._signing_payload(anchor.root, anchor.leaf_count, bd["signed_timestamp"])
        try:
            pub_obj.verify(bytes.fromhex(bd["signature_hex"]), payload)
            return True, "local Ed25519 signature valid"
        except InvalidSignature:
            return False, "local Ed25519 signature INVALID"
        except Exception as exc:
            return False, f"verify error: {exc}"


class OpenTimestampsAnchor(AnchorBackend):
    """Submit the Merkle root to the OpenTimestamps aggregator network.

    OpenTimestamps publishes Bitcoin-anchored timestamps for free —
    aggregator servers batch incoming hashes into their own Merkle tree
    and commit it to a Bitcoin transaction. The resulting ``.ots`` file
    is a self-contained proof that a hash existed at or before a given
    Bitcoin block.

    Requires the ``ots`` CLI (`pip install opentimestamps-client`).
    Verification (``ots verify``) reaches a Bitcoin full node or a
    public block explorer.
    """

    name = "opentimestamps"

    def __init__(self, ots_bin: str = "ots", workdir: Path | None = None) -> None:
        self.ots_bin = ots_bin
        self.workdir = Path(workdir) if workdir else Path.home() / ".squash" / "anchors"

    def anchor(self, root_hex: str, leaf_count: int) -> dict[str, Any]:
        if not shutil.which(self.ots_bin):
            raise FileNotFoundError(
                f"'{self.ots_bin}' CLI not found. Install with: pip install opentimestamps-client"
            )
        self.workdir.mkdir(parents=True, exist_ok=True)
        # ots stamps a *file* of bytes — we feed it the raw root.
        digest_path = self.workdir / f"{root_hex}.bin"
        digest_path.write_bytes(bytes.fromhex(root_hex))
        result = subprocess.run(
            [self.ots_bin, "stamp", str(digest_path)],
            capture_output=True, text=True, check=False,
        )
        ots_path = digest_path.with_suffix(".bin.ots")
        if result.returncode != 0 or not ots_path.exists():
            raise RuntimeError(
                f"ots stamp failed (rc={result.returncode}): {result.stderr.strip()}"
            )
        return {
            "ots_file": str(ots_path),
            "digest_file": str(digest_path),
            "stdout": result.stdout.strip(),
        }

    def verify(self, anchor: Anchor) -> tuple[bool, str]:
        bd = anchor.backend_data
        ots_file = bd.get("ots_file")
        digest_file = bd.get("digest_file")
        if not ots_file or not digest_file or not Path(ots_file).exists():
            return False, "OTS files missing — fetch the .ots and .bin and retry"
        if not shutil.which(self.ots_bin):
            return False, f"'{self.ots_bin}' CLI not installed"
        result = subprocess.run(
            [self.ots_bin, "verify", str(ots_file)],
            capture_output=True, text=True, check=False,
        )
        ok = result.returncode == 0
        msg = (result.stdout + "\n" + result.stderr).strip().splitlines()[-1] if (result.stdout or result.stderr) else "ots verify produced no output"
        return ok, msg


class EthereumAnchor(AnchorBackend):
    """Anchor the Merkle root in the calldata of an Ethereum transaction.

    Anyone with an RPC endpoint and the resulting tx hash can fetch the
    transaction and read the root from its input field — no smart
    contract required. Cheap (a 0-value tx) and chain-agnostic (works
    on any EVM chain: Ethereum mainnet, Base, Optimism, Polygon).

    This backend is **optional** and shells out to ``cast`` (Foundry) to
    avoid pulling ``web3.py`` into the squash dep tree.
    """

    name = "ethereum"

    def __init__(
        self,
        rpc_url: str,
        private_key: str,                # 0x-prefixed hex
        recipient: str = "0x000000000000000000000000000000000000dEaD",
        cast_bin: str = "cast",
    ) -> None:
        self.rpc_url = rpc_url
        self.private_key = private_key
        self.recipient = recipient
        self.cast_bin = cast_bin

    def anchor(self, root_hex: str, leaf_count: int) -> dict[str, Any]:
        if not shutil.which(self.cast_bin):
            raise FileNotFoundError(
                f"'{self.cast_bin}' (Foundry) not found. Install: https://book.getfoundry.sh"
            )
        # 4-byte squash magic + 32-byte root + uint64 leaf_count.
        magic = b"sqsh"
        calldata = "0x" + magic.hex() + root_hex + leaf_count.to_bytes(8, "big").hex()
        result = subprocess.run(
            [
                self.cast_bin, "send",
                "--rpc-url", self.rpc_url,
                "--private-key", self.private_key,
                "--value", "0",
                self.recipient,
                calldata,
                "--json",
            ],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"cast send failed: {result.stderr.strip()}")
        try:
            tx = json.loads(result.stdout)
        except json.JSONDecodeError:
            tx = {"raw": result.stdout.strip()}
        return {
            "tx_hash": tx.get("transactionHash") or tx.get("hash"),
            "rpc_url": self.rpc_url,
            "calldata": calldata,
            "magic": magic.hex(),
        }

    def verify(self, anchor: Anchor) -> tuple[bool, str]:
        bd = anchor.backend_data
        tx_hash = bd.get("tx_hash")
        rpc_url = bd.get("rpc_url") or self.rpc_url
        if not tx_hash or not rpc_url:
            return False, "ethereum anchor missing tx_hash or rpc_url"
        if not shutil.which(self.cast_bin):
            return False, f"'{self.cast_bin}' not installed — cannot fetch tx"
        result = subprocess.run(
            [self.cast_bin, "tx", tx_hash, "input", "--rpc-url", rpc_url],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            return False, f"cast tx failed: {result.stderr.strip()}"
        onchain_calldata = result.stdout.strip().lower()
        expected = bd.get("calldata", "").lower()
        return (onchain_calldata == expected), (
            "ethereum calldata matches anchor" if onchain_calldata == expected
            else "on-chain calldata DOES NOT MATCH the recorded anchor"
        )


# ---------------------------------------------------------------------------
# Append-only ledger
# ---------------------------------------------------------------------------

@dataclass
class StagedAttestation:
    """An attestation queued for the next anchor commit."""

    attestation_id: str
    record_path: str           # original master-record JSON
    record_hash: str           # canonical SHA-256 hex
    staged_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LedgerEntry:
    """One committed anchor + its committed attestations + their proofs."""

    anchor: Anchor
    attestations: list[StagedAttestation]
    proofs: dict[str, MerkleProof] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor": self.anchor.to_dict(),
            "attestations": [a.to_dict() for a in self.attestations],
            "proofs": {
                aid: {
                    "leaf_hash": p.leaf_hash,
                    "path": p.path,
                    "root": p.root,
                    "leaf_index": p.leaf_index,
                    "leaf_count": p.leaf_count,
                }
                for aid, p in self.proofs.items()
            },
        }


class AnchorLedger:
    """Append-only, file-backed ledger of staged + committed attestations.

    Two on-disk files:

    * ``staged.jsonl`` — pending attestations awaiting the next commit
      (each line is one ``StagedAttestation``).
    * ``ledger.jsonl`` — committed anchors with their inclusion proofs
      (each line is one ``LedgerEntry``).

    Append-only is the discipline.  We rewrite ``staged.jsonl`` only at
    commit time (truncating to empty); we *never* rewrite ``ledger.jsonl``.
    Compromises are recorded as new entries.
    """

    def __init__(self, root_dir: Path | None = None) -> None:
        self.root_dir = Path(root_dir) if root_dir else Path.home() / ".squash" / "anchor"
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.staged_path = self.root_dir / "staged.jsonl"
        self.ledger_path = self.root_dir / "ledger.jsonl"

    # -- staging ---------------------------------------------------------

    def stage(self, master_record_path: Path) -> StagedAttestation:
        record = json.loads(master_record_path.read_text())
        rec_hash = hash_attestation(record)
        att_id = (
            record.get("attestation_id")
            or record.get("attestationId")
            or f"att-{rec_hash[:12]}"
        )
        staged = StagedAttestation(
            attestation_id=att_id,
            record_path=str(master_record_path.resolve()),
            record_hash=rec_hash,
            staged_at=time.time(),
        )
        with self.staged_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(staged.to_dict(), sort_keys=True) + "\n")
        return staged

    def staged(self) -> list[StagedAttestation]:
        if not self.staged_path.exists():
            return []
        out: list[StagedAttestation] = []
        for line in self.staged_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            out.append(StagedAttestation(**d))
        return out

    # -- committed -------------------------------------------------------

    def commit(self, backend: AnchorBackend) -> LedgerEntry:
        staged = self.staged()
        if not staged:
            raise RuntimeError("nothing to commit: staged batch is empty")
        tree = MerkleTree([s.record_hash for s in staged])
        backend_data = backend.anchor(tree.root_hex, tree.leaf_count)
        from squash.ids import cert_id

        # Phase G.2: deterministic anchor ID — keyed on the Merkle root and
        # backend identity, NOT on a fresh uuid4. Two replays of the same
        # batch under the same backend produce the same anchor_id, so the
        # signed/anchored bytes are byte-identical on rerun.
        timestamp = time.time()
        anchor_seed = {
            "root": tree.root_hex,
            "leaf_count": tree.leaf_count,
            "backend": backend.name,
            "backend_data": backend_data,
        }
        anchor = Anchor(
            anchor_id=cert_id("anc", anchor_seed)[:16],  # "anc-" + 12 hex
            root=tree.root_hex,
            leaf_count=tree.leaf_count,
            backend=backend.name,
            backend_data=backend_data,
            timestamp=timestamp,
        )
        proofs = {s.attestation_id: tree.proof(i) for i, s in enumerate(staged)}
        entry = LedgerEntry(anchor=anchor, attestations=staged, proofs=proofs)
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        # Truncate the staged file — pending batch is now committed.
        self.staged_path.write_text("")
        return entry

    def entries(self) -> list[LedgerEntry]:
        if not self.ledger_path.exists():
            return []
        out: list[LedgerEntry] = []
        for line in self.ledger_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            out.append(_entry_from_dict(json.loads(line)))
        return out

    # -- queries ---------------------------------------------------------

    def find(self, attestation_id: str) -> tuple[LedgerEntry, MerkleProof] | None:
        for entry in self.entries():
            if attestation_id in entry.proofs:
                return entry, entry.proofs[attestation_id]
        return None

    def export_proof(self, attestation_id: str) -> dict[str, Any]:
        """Return a portable, self-contained inclusion proof.

        The returned dict can be written to disk and verified by any
        third party using :func:`verify_proof` — no squash code required
        beyond the canonical ``hashlib`` + ``cryptography`` stdlib path.
        """
        found = self.find(attestation_id)
        if not found:
            raise KeyError(f"no anchor entry contains attestation {attestation_id!r}")
        entry, proof = found
        return {
            "schema": "squash.anchor.proof/v1",
            "attestation_id": attestation_id,
            "merkle": {
                "leaf_hash": proof.leaf_hash,
                "path": proof.path,
                "root": proof.root,
                "leaf_index": proof.leaf_index,
                "leaf_count": proof.leaf_count,
            },
            "anchor": entry.anchor.to_dict(),
        }

    def verify(self, attestation_id: str) -> tuple[bool, str]:
        """Verify Merkle inclusion + anchor backend witness for *attestation_id*."""
        found = self.find(attestation_id)
        if not found:
            return False, f"no anchor entry contains attestation {attestation_id!r}"
        entry, proof = found
        if not proof.verify():
            return False, "Merkle inclusion proof FAILED"
        backend = _resolve_backend_for_verify(entry.anchor)
        if backend is None:
            return True, f"Merkle proof OK; anchor backend {entry.anchor.backend!r} not verified (no verifier configured)"
        ok, msg = backend.verify(entry.anchor)
        return ok, f"Merkle proof OK; anchor: {msg}"


def _entry_from_dict(d: dict[str, Any]) -> LedgerEntry:
    anchor = Anchor(**d["anchor"])
    attestations = [StagedAttestation(**a) for a in d["attestations"]]
    proofs = {
        aid: MerkleProof(
            leaf_hash=p["leaf_hash"],
            path=[tuple(step) for step in p["path"]],
            root=p["root"],
            leaf_index=p["leaf_index"],
            leaf_count=p["leaf_count"],
        )
        for aid, p in d["proofs"].items()
    }
    return LedgerEntry(anchor=anchor, attestations=attestations, proofs=proofs)


def _resolve_backend_for_verify(anchor: Anchor) -> AnchorBackend | None:
    """Construct a verifier-only backend from a stored anchor's metadata.

    Local + OTS are self-describing — verification needs only the data
    embedded in the anchor record. Ethereum verification needs an RPC
    URL; we read it from the anchor record (set at anchor time).
    """
    if anchor.backend == "local":
        # priv key not needed for verify; pass a sentinel
        return LocalAnchor(priv_key_path=Path("/dev/null"))
    if anchor.backend == "opentimestamps":
        return OpenTimestampsAnchor()
    if anchor.backend == "ethereum":
        rpc = anchor.backend_data.get("rpc_url")
        if not rpc:
            return None
        return EthereumAnchor(rpc_url=rpc, private_key="0x0")
    return None


# ---------------------------------------------------------------------------
# Standalone proof verifier (the canonical 30-line auditor reference)
# ---------------------------------------------------------------------------

def verify_proof(proof_doc: dict[str, Any]) -> tuple[bool, str]:
    """Verify a portable proof doc emitted by :meth:`AnchorLedger.export_proof`.

    This function is the *reference* third-party verifier — it uses
    nothing but stdlib + cryptography, takes one dict, and returns a
    boolean + reason. An auditor running it has independent proof that
    the attestation was committed at or before the anchor's timestamp.
    """
    if proof_doc.get("schema") != "squash.anchor.proof/v1":
        return False, f"unknown schema {proof_doc.get('schema')!r}"
    m = proof_doc["merkle"]
    proof = MerkleProof(
        leaf_hash=m["leaf_hash"],
        path=[tuple(step) for step in m["path"]],
        root=m["root"],
        leaf_index=m["leaf_index"],
        leaf_count=m["leaf_count"],
    )
    if not proof.verify():
        return False, "Merkle inclusion proof FAILED"
    anchor = Anchor(**proof_doc["anchor"])
    backend = _resolve_backend_for_verify(anchor)
    if backend is None:
        return True, "Merkle proof OK; anchor backend not independently verified"
    ok, msg = backend.verify(anchor)
    return ok, f"Merkle proof OK; anchor: {msg}"


# ---------------------------------------------------------------------------
# Convenience constructors used by the CLI
# ---------------------------------------------------------------------------

def default_ledger_path() -> Path:
    env = os.environ.get("SQUASH_ANCHOR_DIR")
    if env:
        return Path(env)
    return Path.home() / ".squash" / "anchor"
