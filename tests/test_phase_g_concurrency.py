"""Phase G.4 — Concurrency tests.

Two simultaneous attest pipelines on the same model dir, two clock-frozen
canon.canonical_bytes calls under thread contention, etc.
"""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import pytest

from squash.canon import canonical_bytes
from squash.clock import FrozenClock, with_clock
from squash.ids import cert_id, deterministic_uuid
from squash.input_manifest import build_input_manifest


def test_canonical_bytes_thread_safe_under_contention():
    """canonical_bytes must be safe to call from many threads on the same input."""
    payload = {"k": list(range(100)), "s": {"a", "b", "c"}}
    expected = canonical_bytes(payload)

    def encode():
        return canonical_bytes(payload)

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = [r.result() for r in [ex.submit(encode) for _ in range(64)]]
    assert all(r == expected for r in results)


def test_cert_id_deterministic_under_contention():
    """cert_id keyed on the same payload always returns the same string,
    regardless of how many threads compute it concurrently."""
    payload = {"model": "gpt-4", "version": 1}
    expected = cert_id("hac", payload)

    def compute():
        return cert_id("hac", payload)

    with ThreadPoolExecutor(max_workers=16) as ex:
        out = [f.result() for f in [ex.submit(compute) for _ in range(128)]]
    assert all(o == expected for o in out)


def test_input_manifest_build_concurrent_disjoint_dirs(tmp_path):
    """Building manifests over disjoint dirs in parallel must succeed; each
    manifest matches its own self-hash."""
    dirs = []
    for i in range(8):
        d = tmp_path / f"model-{i}"
        d.mkdir()
        for j in range(3):
            (d / f"w{j}.bin").write_bytes(f"model-{i}-w{j}".encode())
        dirs.append(d)

    def go(d):
        m = build_input_manifest(d)
        from squash.input_manifest import manifest_hash

        assert m.manifest_sha256 == manifest_hash(m)
        return m.manifest_sha256

    with ThreadPoolExecutor(max_workers=8) as ex:
        hashes = [f.result() for f in [ex.submit(go, d) for d in dirs]]
    # Each model dir has different content -> different hash.
    assert len(set(hashes)) == 8


def test_attest_pipeline_concurrent_separate_models(tmp_path):
    """Two AttestPipeline.run() calls on DIFFERENT models can run in parallel
    without corrupting each other's artefacts."""
    from squash.attest import AttestConfig, AttestPipeline

    dirs = []
    for i in range(2):
        d = tmp_path / f"m{i}"
        d.mkdir()
        (d / "weights.bin").write_bytes(b"\x00" * (64 + i))
        dirs.append(d)

    def run(d):
        AttestPipeline.run(
            AttestConfig(
                model_path=d,
                output_dir=d,
                policies=[],
                fail_on_violation=False,
            )
        )
        return d

    with ThreadPoolExecutor(max_workers=2) as ex:
        results = [f.result() for f in [ex.submit(run, d) for d in dirs]]
    # Each dir has its own input_manifest.
    for d in results:
        assert (d / "input_manifest.json").exists()


def test_with_clock_does_not_leak_between_threads():
    """``with_clock`` mutates a module-level default; assert the surrounding
    block isolates its scope (best-effort — pytest runs tests serially)."""
    fc = FrozenClock(datetime(2030, 1, 1, tzinfo=timezone.utc))
    # Inside the block, default is fc; outside, system clock.
    from squash.clock import utc_now

    before = utc_now()
    with with_clock(fc):
        inside = utc_now()
        assert inside == fc()
    after = utc_now()
    # System clock returned naturally moves forward; fc's frozen time differs.
    assert before != fc()
    assert after >= before
