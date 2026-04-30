"""tests/test_drift_certificate.py — W194 / B7 Drift SLA Certificate.

Tests are grouped by concern:

* DriftSLASpec validation
* ScoreLedger ingest / query / filter
* SLAEvaluator: passes, fails (violation rate), insufficient snapshots,
  no snapshots, violation-window detection, percentile statistics
* DriftCertificate: body_dict stability, markdown/HTML render, JSON round-trip
* DriftCertificateIssuer: sign/verify roundtrip, tampered cert fails,
  unsigned cert reports correctly
* load_certificate round-trip
* CLI smoke: parser registration, ingest+issue+verify end-to-end
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from squash.drift_certificate import (
    DriftCertificateIssuer,
    DriftSLASpec,
    ScoreLedger,
    ScoreSnapshot,
    SLAEvaluator,
    ViolationWindow,
    default_ledger_path,
    load_certificate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc(offset_days: int = 0) -> datetime:
    return datetime.now(tz=timezone.utc) - timedelta(days=offset_days)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _snap(
    ledger: ScoreLedger,
    score: float,
    model: str = "phi-3",
    framework: str = "eu-ai-act",
    offset_days: int = 0,
) -> None:
    ledger.add_snapshot(ScoreSnapshot(
        timestamp=_iso(_utc(offset_days)),
        model_id=model,
        framework=framework,
        score=score,
        passed=score >= 80.0,
        attestation_id=f"att-{offset_days}",
    ))


def _spec(**kwargs) -> DriftSLASpec:
    defaults = dict(model_id="phi-3", framework="eu-ai-act", min_score=80.0,
                    window_days=90, max_violation_rate=0.05, min_snapshots=3)
    defaults.update(kwargs)
    return DriftSLASpec(**defaults)


# ---------------------------------------------------------------------------
# DriftSLASpec validation
# ---------------------------------------------------------------------------

def test_spec_valid():
    s = _spec()
    assert s.min_score == 80.0
    assert s.window_days == 90


def test_spec_invalid_min_score():
    with pytest.raises(ValueError, match="min_score"):
        DriftSLASpec(model_id="m", min_score=0.0)


def test_spec_invalid_window():
    with pytest.raises(ValueError, match="window_days"):
        DriftSLASpec(model_id="m", window_days=0)


def test_spec_invalid_violation_rate():
    with pytest.raises(ValueError, match="max_violation_rate"):
        DriftSLASpec(model_id="m", max_violation_rate=1.5)


def test_spec_to_dict_roundtrip():
    s = _spec(org="Konjo AI")
    d = s.to_dict()
    assert d["org"] == "Konjo AI"
    assert d["min_score"] == 80.0


# ---------------------------------------------------------------------------
# ScoreLedger
# ---------------------------------------------------------------------------

def test_ledger_add_and_query(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    _snap(ledger, 90.0, offset_days=5)
    _snap(ledger, 85.0, offset_days=3)
    snaps = ledger.snapshots(model_id="phi-3", framework="eu-ai-act")
    assert len(snaps) == 2
    assert snaps[0].score == 90.0  # earlier comes first after sort


def test_ledger_filters_by_model(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    _snap(ledger, 90.0, model="phi-3", offset_days=2)
    _snap(ledger, 70.0, model="llama-3", offset_days=1)
    assert len(ledger.snapshots(model_id="phi-3")) == 1
    assert len(ledger.snapshots(model_id="llama-3")) == 1


def test_ledger_filters_by_time_window(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    _snap(ledger, 90.0, offset_days=100)  # 100 days ago — outside a 91-day window
    _snap(ledger, 85.0, offset_days=30)   # 30 days ago  — inside a 91-day window
    # since=_utc(91) means "since 91 days ago" → only the 30-day snapshot passes
    snaps = ledger.snapshots(since=_utc(91))
    assert len(snaps) == 1
    assert snaps[0].score == 85.0
    # since=_utc(101) means "since 101 days ago" → both pass
    snaps_both = ledger.snapshots(since=_utc(101))
    assert len(snaps_both) == 2


def test_ledger_ingest_master_record(tmp_path):
    rec = {
        "attestation_id": "att-xyz",
        "model_id": "phi-3",
        "overall_score": 91.5,
        "passed": True,
        "generated_at": _iso(_utc(5)),
        "framework_scores": {"eu-ai-act": 93.0, "iso-42001": 88.0},
    }
    record_path = tmp_path / "master.json"
    record_path.write_text(json.dumps(rec))
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    snap = ledger.ingest(record_path)
    assert snap.model_id == "phi-3"
    # Ingest writes one overall + one per-framework snapshot
    all_snaps = ledger.snapshots()
    assert len(all_snaps) == 3  # overall + eu-ai-act + iso-42001


def test_ledger_empty_returns_empty_list(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    assert ledger.snapshots() == []


# ---------------------------------------------------------------------------
# SLAEvaluator
# ---------------------------------------------------------------------------

def test_evaluator_passes_all_above_threshold(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    for d in [10, 20, 30, 40, 50]:
        _snap(ledger, 88.0, offset_days=d)
    result = SLAEvaluator().evaluate(_spec(), ledger)
    assert result.passes_sla
    assert result.violation_count == 0
    assert result.compliance_rate == 1.0


def test_evaluator_fails_violation_rate_exceeded(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    # 3 violations out of 10 = 30% > max 5%
    for d in range(10):
        score = 70.0 if d < 3 else 90.0
        _snap(ledger, score, offset_days=d + 1)
    result = SLAEvaluator().evaluate(_spec(), ledger)
    assert not result.passes_sla
    assert result.violation_count == 3
    assert "violation rate" in result.failure_reason


def test_evaluator_passes_within_violation_budget(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    # 1 violation out of 100 = 1% < max 5%
    _snap(ledger, 70.0, offset_days=89)
    for d in range(99):
        _snap(ledger, 90.0, offset_days=d)
    result = SLAEvaluator().evaluate(_spec(min_snapshots=3), ledger)
    assert result.passes_sla


def test_evaluator_fails_insufficient_snapshots(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    _snap(ledger, 90.0, offset_days=5)
    _snap(ledger, 85.0, offset_days=3)  # only 2 snapshots, min=3
    result = SLAEvaluator().evaluate(_spec(), ledger)
    assert not result.passes_sla
    assert "insufficient snapshots" in result.failure_reason


def test_evaluator_fails_no_snapshots(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    result = SLAEvaluator().evaluate(_spec(), ledger)
    assert not result.passes_sla
    assert "no snapshots" in result.failure_reason


def test_evaluator_violation_windows_detected(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    # Pattern: ok, FAIL, FAIL, ok, FAIL, ok
    scores = [90.0, 60.0, 65.0, 88.0, 55.0, 91.0]
    for i, score in enumerate(scores):
        _snap(ledger, score, offset_days=len(scores) - i)
    result = SLAEvaluator().evaluate(_spec(max_violation_rate=1.0), ledger)
    # Two violation windows: [60,65] and [55]
    assert len(result.violation_windows) == 2
    sizes = sorted(vw.snapshot_count for vw in result.violation_windows)
    assert sizes == [1, 2]


def test_evaluator_statistics(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    scores = [70.0, 80.0, 90.0, 100.0]
    for i, s in enumerate(scores):
        _snap(ledger, s, offset_days=len(scores) - i)
    result = SLAEvaluator().evaluate(_spec(min_score=65.0, min_snapshots=1), ledger)
    assert result.min_score == 70.0
    assert result.max_score == 100.0
    assert abs(result.avg_score - 85.0) < 0.01
    assert result.p10_score <= 75.0  # 10th percentile is near bottom


# ---------------------------------------------------------------------------
# DriftCertificate
# ---------------------------------------------------------------------------

def _make_passing_cert(tmp_path) -> "DriftCertificate":
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    for d in range(5):
        _snap(ledger, 90.0, offset_days=d + 1)
    return DriftCertificateIssuer().issue(_spec(), ledger)


def test_certificate_body_dict_excludes_signature(tmp_path):
    cert = _make_passing_cert(tmp_path)
    body = cert.body_dict()
    assert "signature_hex" not in body
    assert "public_key_pem" not in body
    assert "cert_id" in body
    assert "spec" in body
    assert "result" in body


def test_certificate_json_round_trip(tmp_path):
    cert = _make_passing_cert(tmp_path)
    path = tmp_path / "cert.json"
    path.write_text(cert.to_json())
    loaded = load_certificate(path)
    assert loaded.cert_id == cert.cert_id
    assert loaded.result.passes_sla == cert.result.passes_sla
    assert loaded.spec.model_id == cert.spec.model_id


def test_certificate_markdown_contains_verdict(tmp_path):
    cert = _make_passing_cert(tmp_path)
    md = cert.to_markdown()
    assert "PASS" in md
    assert cert.cert_id in md
    assert "eu-ai-act" in md


def test_certificate_html_contains_verdict(tmp_path):
    cert = _make_passing_cert(tmp_path)
    html = cert.to_html()
    assert "<!DOCTYPE html>" in html
    assert "PASS" in html
    assert cert.cert_id in html


def test_certificate_failing_markdown_contains_fail(tmp_path):
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    # High violation rate → fails SLA
    for d in range(10):
        _snap(ledger, 50.0, offset_days=d + 1)
    cert = DriftCertificateIssuer().issue(_spec(), ledger)
    assert not cert.result.passes_sla
    md = cert.to_markdown()
    assert "FAIL" in md


# ---------------------------------------------------------------------------
# DriftCertificateIssuer — sign / verify
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair(tmp_path):
    pytest.importorskip("cryptography")
    from squash.oms_signer import OmsSigner
    priv, pub = OmsSigner.keygen("test-dc", key_dir=tmp_path)
    return priv, pub


def test_issuer_signs_and_verifies(tmp_path, keypair):
    priv, _ = keypair
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    for d in range(5):
        _snap(ledger, 88.0, offset_days=d + 1)
    cert = DriftCertificateIssuer(priv_key_path=priv).issue(_spec(), ledger)
    assert cert.signature_hex != ""
    assert cert.public_key_pem != ""
    ok, msg = DriftCertificateIssuer.verify(cert)
    assert ok, msg


def test_issuer_tampered_spec_fails_verify(tmp_path, keypair):
    priv, _ = keypair
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    for d in range(5):
        _snap(ledger, 88.0, offset_days=d + 1)
    cert = DriftCertificateIssuer(priv_key_path=priv).issue(_spec(), ledger)
    # Attacker bumps the min_score threshold down — cert now looks "easier" to pass.
    cert.spec.min_score = 10.0
    ok, msg = DriftCertificateIssuer.verify(cert)
    assert not ok
    assert "INVALID" in msg


def test_issuer_tampered_result_fails_verify(tmp_path, keypair):
    priv, _ = keypair
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    # 4 passing, 1 violation → compliance_rate < 1.0 in the real result
    for d in range(4):
        _snap(ledger, 88.0, offset_days=d + 1)
    _snap(ledger, 50.0, offset_days=5)  # one violation
    cert = DriftCertificateIssuer(priv_key_path=priv).issue(
        _spec(max_violation_rate=1.0), ledger  # allow violations so cert issues
    )
    original_rate = cert.result.compliance_rate
    assert original_rate < 1.0  # confirm the forged value will actually differ
    cert.result.compliance_rate = 1.0  # forge a perfect rate
    ok, msg = DriftCertificateIssuer.verify(cert)
    assert not ok


def test_verify_unsigned_cert_returns_false(tmp_path):
    cert = _make_passing_cert(tmp_path)
    assert cert.signature_hex == ""
    ok, msg = DriftCertificateIssuer.verify(cert)
    assert not ok
    assert "unsigned" in msg


def test_verify_unknown_schema_fails(tmp_path, keypair):
    priv, _ = keypair
    ledger = ScoreLedger(ledger_path=tmp_path / "s.jsonl")
    for d in range(5):
        _snap(ledger, 88.0, offset_days=d + 1)
    cert = DriftCertificateIssuer(priv_key_path=priv).issue(_spec(), ledger)
    cert.schema = "evil.schema/v999"
    ok, msg = DriftCertificateIssuer.verify(cert)
    assert not ok
    assert "unknown schema" in msg or "INVALID" in msg


# ---------------------------------------------------------------------------
# Environment variable
# ---------------------------------------------------------------------------

def test_default_ledger_path_env_override(monkeypatch, tmp_path):
    custom = tmp_path / "custom_drift.jsonl"
    monkeypatch.setenv("SQUASH_DRIFT_LEDGER", str(custom))
    assert default_ledger_path() == custom


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------

def test_cli_drift_cert_parser_registered():
    from squash.cli import _build_parser
    p = _build_parser()
    ns = p.parse_args(["drift-cert", "issue", "--model", "phi-3"])
    assert ns.command == "drift-cert"
    assert ns.dc_command == "issue"
    assert ns.model_id == "phi-3"


def test_cli_ingest_then_issue(tmp_path, capsys):
    """End-to-end: ingest a master record, issue a cert, verify it."""
    import argparse

    from squash.cli import _cmd_drift_cert

    ledger_path = tmp_path / "s.jsonl"
    rec = {
        "attestation_id": "att-cli-test",
        "model_id": "phi-3",
        "overall_score": 92.0,
        "passed": True,
        "generated_at": (datetime.now(tz=timezone.utc) - timedelta(days=5)).isoformat(),
        "framework_scores": {"eu-ai-act": 94.0},
    }
    record_path = tmp_path / "master.json"
    record_path.write_text(json.dumps(rec))

    # ingest
    ingest_args = argparse.Namespace(
        dc_command="ingest",
        master_record_path=str(record_path),
        ledger_path=str(ledger_path),
    )
    assert _cmd_drift_cert(ingest_args, quiet=True) == 0

    # issue (no signing, min_snapshots=1)
    out_path = tmp_path / "cert.json"
    issue_args = argparse.Namespace(
        dc_command="issue",
        model_id="phi-3",
        framework="eu-ai-act",
        min_score=80.0,
        window_days=90,
        max_violation_rate=0.05,
        min_snapshots=1,
        org="",
        priv_key=None,
        ledger_path=str(ledger_path),
        out=str(out_path),
        issue_format="json",
        output_json=False,
    )
    rc = _cmd_drift_cert(issue_args, quiet=True)
    assert rc == 0
    cert = load_certificate(out_path)
    assert cert.result.passes_sla
    assert cert.spec.model_id == "phi-3"
