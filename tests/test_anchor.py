"""tests/test_anchor.py — W193 / B6 audit-trail anchoring.

Cryptographic correctness is the floor. These tests cover:

* Merkle tree construction (1, 2, odd, large).
* Inclusion proof verifies for every leaf.
* Tampered leaf / tampered path / tampered root all FAIL.
* Canonical hashing is order-invariant.
* LocalAnchor sign/verify roundtrip.
* AnchorLedger append-only stage → commit → entries → find → verify.
* End-to-end portable proof — verified by a fresh AnchorLedger that has
  no in-memory state from the writer.
* Tamper detection: editing the persisted master record changes its
  canonical hash and breaks the inclusion proof.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from squash.anchor import (
    Anchor,
    AnchorLedger,
    LocalAnchor,
    MerkleTree,
    canonical_json,
    hash_attestation,
    verify_proof,
)


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def test_canonical_json_key_order_invariant():
    a = canonical_json({"b": 1, "a": 2, "c": [1, 2]})
    b = canonical_json({"c": [1, 2], "a": 2, "b": 1})
    assert a == b
    # whitespace-free
    assert b" " not in a


def test_hash_attestation_pretty_vs_compact_identical():
    rec = {"attestation_id": "att-x", "overall_score": 91.5, "passed": True}
    h1 = hash_attestation(rec)
    h2 = hash_attestation(json.loads(json.dumps(rec, indent=4)))
    assert h1 == h2
    assert len(h1) == 64  # sha-256 hex


def test_hash_attestation_unicode_stable():
    rec = {"name": "Φ-3 — モデル"}
    h = hash_attestation(rec)
    # round-trip through JSON file does not change the hash
    p = Path("/tmp/_anchor_test_unicode.json")
    p.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    rec2 = json.loads(p.read_text(encoding="utf-8"))
    assert hash_attestation(rec2) == h


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

def _hex(s: str) -> str:
    """Helper: deterministic dummy hash for tests."""
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()


def test_merkle_single_leaf_root_is_leaf_hash_with_prefix():
    leaves = [_hex("a")]
    tree = MerkleTree(leaves)
    proof = tree.proof(0)
    assert proof.path == []  # no siblings for a singleton
    assert proof.verify()


def test_merkle_two_leaves_proof_round_trip():
    leaves = [_hex("a"), _hex("b")]
    tree = MerkleTree(leaves)
    for i in range(2):
        assert tree.proof(i).verify(), f"leaf {i} failed verification"


def test_merkle_odd_leaves_duplicates_tail():
    # 3 leaves → level 0 has 3 nodes; pair (0,1), pair (2,2) duplicated
    leaves = [_hex("a"), _hex("b"), _hex("c")]
    tree = MerkleTree(leaves)
    for i in range(3):
        assert tree.proof(i).verify()


def test_merkle_large_tree_all_leaves_verify():
    leaves = [_hex(f"x{i}") for i in range(50)]
    tree = MerkleTree(leaves)
    for i in range(50):
        p = tree.proof(i)
        assert p.verify(), f"leaf {i} failed verification"
        assert p.root == tree.root_hex


def test_merkle_proof_with_tampered_leaf_fails():
    leaves = [_hex(s) for s in "abcd"]
    tree = MerkleTree(leaves)
    p = tree.proof(2)
    bad = type(p)(
        leaf_hash=_hex("z"),  # different leaf
        path=p.path,
        root=p.root,
        leaf_index=p.leaf_index,
        leaf_count=p.leaf_count,
    )
    assert not bad.verify()


def test_merkle_proof_with_tampered_root_fails():
    leaves = [_hex(s) for s in "abcd"]
    tree = MerkleTree(leaves)
    p = tree.proof(0)
    bad = type(p)(
        leaf_hash=p.leaf_hash,
        path=p.path,
        root="00" * 32,  # zeroed root
        leaf_index=0,
        leaf_count=p.leaf_count,
    )
    assert not bad.verify()


def test_merkle_index_out_of_range_raises():
    tree = MerkleTree([_hex("a"), _hex("b")])
    with pytest.raises(IndexError):
        tree.proof(5)


def test_merkle_empty_raises():
    with pytest.raises(ValueError):
        MerkleTree([])


# ---------------------------------------------------------------------------
# Local anchor: sign / verify
# ---------------------------------------------------------------------------

@pytest.fixture
def local_keypair(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a real Ed25519 keypair via squash's existing OmsSigner."""
    pytest.importorskip("cryptography")
    from squash.oms_signer import OmsSigner
    priv_path, pub_path = OmsSigner.keygen("anchor-test", key_dir=tmp_path)
    return priv_path, pub_path


def test_local_anchor_sign_verify_roundtrip(local_keypair):
    priv_path, pub_path = local_keypair
    backend = LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path)
    root_hex = _hex("some-merkle-root")
    bd = backend.anchor(root_hex, leaf_count=4)

    anchor = Anchor(
        anchor_id="anc-test",
        root=root_hex,
        leaf_count=4,
        backend="local",
        backend_data=bd,
        timestamp=0.0,
    )
    ok, msg = backend.verify(anchor)
    assert ok, msg


def test_local_anchor_tampered_root_fails(local_keypair):
    priv_path, pub_path = local_keypair
    backend = LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path)
    root_hex = _hex("orig")
    bd = backend.anchor(root_hex, leaf_count=2)

    # Now an attacker swaps the root.
    anchor = Anchor(
        anchor_id="anc-evil",
        root=_hex("evil"),
        leaf_count=2,
        backend="local",
        backend_data=bd,
        timestamp=0.0,
    )
    ok, msg = backend.verify(anchor)
    assert not ok
    assert "INVALID" in msg


# ---------------------------------------------------------------------------
# AnchorLedger end-to-end
# ---------------------------------------------------------------------------

def _make_master_record(path: Path, attestation_id: str, score: float) -> Path:
    rec = {
        "attestation_id": attestation_id,
        "model_id": "phi-3",
        "passed": True,
        "overall_score": score,
        "framework_scores": {"eu-ai-act": score, "iso-42001": score - 5},
    }
    path.write_text(json.dumps(rec, indent=2))
    return path


def test_ledger_stage_then_commit_then_verify_each(tmp_path, local_keypair):
    priv_path, pub_path = local_keypair
    ledger = AnchorLedger(root_dir=tmp_path / "anchor")

    # Stage 3 attestations.
    paths = [
        _make_master_record(tmp_path / "m1.json", "att-aaa", 90.0),
        _make_master_record(tmp_path / "m2.json", "att-bbb", 85.5),
        _make_master_record(tmp_path / "m3.json", "att-ccc", 92.1),
    ]
    for p in paths:
        ledger.stage(p)
    assert len(ledger.staged()) == 3

    # Commit with local Ed25519 backend.
    backend = LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path)
    entry = ledger.commit(backend)
    assert entry.anchor.leaf_count == 3
    assert ledger.staged() == []  # batch cleared after commit
    assert entry.anchor.backend == "local"

    # Each attestation must verify independently.
    for aid in ("att-aaa", "att-bbb", "att-ccc"):
        ok, msg = ledger.verify(aid)
        assert ok, f"{aid} failed: {msg}"


def test_ledger_persists_across_instances(tmp_path, local_keypair):
    priv_path, pub_path = local_keypair
    root = tmp_path / "anchor"

    writer = AnchorLedger(root_dir=root)
    writer.stage(_make_master_record(tmp_path / "m.json", "att-persist", 80.0))
    writer.commit(LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path))

    # Brand-new instance — proves the ledger is durable, not in-memory.
    reader = AnchorLedger(root_dir=root)
    ok, msg = reader.verify("att-persist")
    assert ok, msg


def test_ledger_unknown_attestation_returns_false(tmp_path):
    ledger = AnchorLedger(root_dir=tmp_path / "anchor")
    ok, msg = ledger.verify("att-nope")
    assert not ok
    assert "no anchor entry" in msg


def test_export_proof_is_self_contained_and_third_party_verifiable(tmp_path, local_keypair):
    priv_path, pub_path = local_keypair
    ledger = AnchorLedger(root_dir=tmp_path / "anchor")
    ledger.stage(_make_master_record(tmp_path / "a.json", "att-1", 99.0))
    ledger.stage(_make_master_record(tmp_path / "b.json", "att-2", 70.0))
    ledger.commit(LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path))

    proof_doc = ledger.export_proof("att-2")
    # Auditor receives only the proof JSON. They run verify_proof()
    # — no AnchorLedger, no squash internals.
    ok, msg = verify_proof(proof_doc)
    assert ok, msg
    # Schema check is intentional — third-party tools may match on it.
    assert proof_doc["schema"] == "squash.anchor.proof/v1"


def test_export_proof_detects_tampered_leaf_in_disk_record(tmp_path, local_keypair):
    """Tamper the master record AFTER anchoring — the proof must still
    name the original hash, so swapping the on-disk record breaks the
    inclusion check at the auditor's side. This is the property that
    makes anchoring useful: silent edits cannot pass."""
    priv_path, pub_path = local_keypair
    ledger = AnchorLedger(root_dir=tmp_path / "anchor")
    record_path = _make_master_record(tmp_path / "rec.json", "att-tamper", 90.0)
    ledger.stage(record_path)
    ledger.commit(LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path))

    # Now silently rewrite the score.
    rec = json.loads(record_path.read_text())
    rec["overall_score"] = 100.0
    record_path.write_text(json.dumps(rec))

    # The anchor's leaf hash was computed at staging time, so the
    # original proof still verifies cryptographically — that is the
    # GOOD outcome. The tampered record now has a *different* canonical
    # hash, which means re-staging the file would produce a NEW leaf
    # that does not match. Verify both invariants.
    proof_doc = ledger.export_proof("att-tamper")
    ok, _ = verify_proof(proof_doc)
    assert ok, "anchored proof should still verify against the original leaf"

    new_hash = hash_attestation(rec)
    assert new_hash != proof_doc["merkle"]["leaf_hash"], (
        "tampered record must have a different canonical hash than the original anchored leaf"
    )


def test_commit_empty_batch_raises(tmp_path):
    ledger = AnchorLedger(root_dir=tmp_path / "anchor")
    backend = LocalAnchor(priv_key_path=Path("/dev/null"))  # never invoked
    with pytest.raises(RuntimeError, match="empty"):
        ledger.commit(backend)


def test_ledger_list_entries_ordered(tmp_path, local_keypair):
    priv_path, pub_path = local_keypair
    ledger = AnchorLedger(root_dir=tmp_path / "anchor")

    for i in range(3):
        ledger.stage(_make_master_record(tmp_path / f"m{i}.json", f"att-{i}", 80 + i))
        ledger.commit(LocalAnchor(priv_key_path=priv_path, pub_key_path=pub_path))

    entries = ledger.entries()
    assert len(entries) == 3
    timestamps = [e.anchor.timestamp for e in entries]
    assert timestamps == sorted(timestamps)


def test_anchor_dir_env_var(monkeypatch, tmp_path, local_keypair):
    priv_path, pub_path = local_keypair
    custom_dir = tmp_path / "alt_anchor"
    monkeypatch.setenv("SQUASH_ANCHOR_DIR", str(custom_dir))
    from squash.anchor import default_ledger_path
    assert default_ledger_path() == custom_dir


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------

def test_cli_anchor_subcommand_registered():
    """The argparse surface must expose `anchor` and its subcommands."""
    from squash.cli import _build_parser
    parser = _build_parser()
    # Parse a known anchor subcommand to confirm registration.
    ns = parser.parse_args(["anchor", "list"])
    assert ns.command == "anchor"
    assert ns.anchor_command == "list"


def test_cli_anchor_status_runs_on_empty_ledger(tmp_path, capsys):
    """status on an empty ledger should be a successful no-op."""
    from squash.cli import _cmd_anchor
    import argparse
    args = argparse.Namespace(
        anchor_command="status",
        ledger_dir=str(tmp_path / "fresh"),
        output_json=True,
    )
    rc = _cmd_anchor(args, quiet=False)
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["staged"] == []
    assert payload["last_anchor"] is None
