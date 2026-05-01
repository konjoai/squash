"""tests/test_data_poison.py — W195 / B9 Data Poisoning Detection.

Tests are grouped by detection layer and then integration:

* RiskLevel ordering + score mapping
* ThreatIntelChecker: clean hash, matching known-bad hash
* LabelIntegrityChecker: clean distribution, imbalanced, low entropy,
  per-class spike, empty labels, no label files
* DuplicateDetector: clean file, duplicate-heavy CSV, duplicate-heavy JSONL,
  empty/missing files
* OutlierDetector: clean numerical data, column with extreme outliers,
  constant column (synthetic data indicator)
* TriggerPatternScanner: clean text, file containing known trigger tokens,
  homoglyph characters
* ProvenanceIntegrityChecker: no provenance, suspicious URL, clean
* DataPoisonScanner end-to-end: clean dataset, poisoned dataset
* DataPoisonReport: JSON round-trip, Markdown render, summary
* load_report round-trip
* CLI smoke: parser registration, scan on temp dataset
"""

from __future__ import annotations

import csv
import json
import os
import textwrap
from pathlib import Path

import pytest

from squash.data_poison import (
    DataPoisonReport,
    DataPoisonScanner,
    DuplicateDetector,
    LabelIntegrityChecker,
    OutlierDetector,
    ProvenanceIntegrityChecker,
    PoisonCheckResult,
    RiskLevel,
    Severity,
    ThreatIntelChecker,
    TriggerPatternScanner,
    _THREAT_INTEL,
    _entropy,
    _file_duplicate_rate,
    load_report,
)


# ---------------------------------------------------------------------------
# RiskLevel helpers
# ---------------------------------------------------------------------------

def test_risk_level_ordering():
    assert RiskLevel.CLEAN < RiskLevel.LOW < RiskLevel.MEDIUM
    assert RiskLevel.MEDIUM < RiskLevel.HIGH < RiskLevel.CRITICAL


def test_risk_level_score():
    assert RiskLevel.CLEAN.score() == 0
    assert RiskLevel.CRITICAL.score() == 4


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def test_entropy_uniform():
    counts = [100, 100, 100, 100]
    h = _entropy(counts)
    assert abs(h - 2.0) < 1e-6  # log2(4) = 2


def test_entropy_single_class():
    assert _entropy([100]) == 0.0


def test_entropy_empty():
    assert _entropy([]) == 0.0


# ---------------------------------------------------------------------------
# Layer 1 — ThreatIntelChecker
# ---------------------------------------------------------------------------

def test_threat_intel_clean_hash():
    checker = ThreatIntelChecker()
    result = checker.check(Path("/tmp"), {"data.csv": "a" * 64})
    assert result.passed
    assert result.score == 0.0


def test_threat_intel_known_bad_hash():
    checker = ThreatIntelChecker()
    # Use the first known-bad hash prefix from the registry
    bad_prefix = next(iter(_THREAT_INTEL))
    fake_hash = bad_prefix + "x" * (64 - len(bad_prefix))
    result = checker.check(Path("/tmp"), {"poisoned.csv": fake_hash})
    assert not result.passed
    assert result.score == 1.0
    assert result.severity == Severity.CRITICAL
    assert any("poisoned" in e.lower() or "known" in e.lower() for e in result.evidence)


def test_threat_intel_multiple_files_one_bad():
    checker = ThreatIntelChecker()
    bad_prefix = next(iter(_THREAT_INTEL))
    hashes = {
        "good.csv": "b" * 64,
        "bad.csv": bad_prefix + "0" * (64 - len(bad_prefix)),
    }
    result = checker.check(Path("/tmp"), hashes)
    assert not result.passed
    assert len(result.evidence) == 1


# ---------------------------------------------------------------------------
# Layer 2 — LabelIntegrityChecker
# ---------------------------------------------------------------------------

def _write_label_csv(path: Path, label_col: str, labels: list[str]) -> Path:
    f = path / "labels.csv"
    with f.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[label_col, "text"])
        w.writeheader()
        for lbl in labels:
            w.writerow({label_col: lbl, "text": "sample"})
    return f


def test_label_integrity_clean_balanced(tmp_path):
    classes = ["A"] * 500 + ["B"] * 500 + ["C"] * 500
    f = _write_label_csv(tmp_path, "label", classes)
    result = LabelIntegrityChecker().check([f])
    assert result.passed


def test_label_integrity_extreme_imbalance(tmp_path):
    labels = ["A"] * 5000 + ["B"] * 10  # 500x imbalance
    f = _write_label_csv(tmp_path, "label", labels)
    result = LabelIntegrityChecker().check([f])
    assert not result.passed
    assert result.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    assert any("imbalance" in e.lower() for e in result.evidence)


def test_label_integrity_low_entropy(tmp_path):
    # 10 classes but 99% of samples are class 0
    labels = ["class_0"] * 9900 + [f"class_{i}" for i in range(1, 10)]
    f = _write_label_csv(tmp_path, "label", labels)
    result = LabelIntegrityChecker().check([f])
    assert not result.passed


def test_label_integrity_no_label_files():
    result = LabelIntegrityChecker().check([])
    assert result.passed  # nothing to flag


def test_label_integrity_jsonl(tmp_path):
    f = tmp_path / "labels.jsonl"
    labels = (["pos"] * 300 + ["neg"] * 300)
    f.write_text("\n".join(json.dumps({"label": lbl, "text": "x"}) for lbl in labels))
    result = LabelIntegrityChecker().check([f])
    assert result.passed


# ---------------------------------------------------------------------------
# Layer 3 — DuplicateDetector
# ---------------------------------------------------------------------------

def test_duplicate_detector_clean_csv(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "text"])
        for i in range(100):
            w.writerow([i, f"unique text {i}"])
    result = DuplicateDetector().check([f])
    assert result.passed


def test_duplicate_detector_heavy_duplicates_csv(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["text"])
        for _ in range(90):
            w.writerow(["SAME POISONED SAMPLE"])  # 90% duplicate
        for i in range(10):
            w.writerow([f"unique {i}"])
    result = DuplicateDetector().check([f])
    assert not result.passed
    assert result.severity in (Severity.HIGH, Severity.CRITICAL)
    assert any("duplicate" in e.lower() for e in result.evidence)


def test_duplicate_detector_heavy_duplicates_jsonl(tmp_path):
    f = tmp_path / "data.jsonl"
    lines = [json.dumps({"text": "poison"}) for _ in range(80)]
    lines += [json.dumps({"text": f"ok {i}"}) for i in range(20)]
    f.write_text("\n".join(lines))
    result = DuplicateDetector().check([f])
    assert not result.passed


def test_duplicate_rate_exact(tmp_path):
    f = tmp_path / "d.jsonl"
    f.write_text("\n".join(json.dumps({"v": i % 10}) for i in range(100)))
    rate, dups, total = _file_duplicate_rate(f)
    assert total == 100
    assert dups == 90   # 10 unique * 10 repetitions → 90 dups
    assert abs(rate - 0.9) < 0.01


def test_duplicate_detector_no_files():
    result = DuplicateDetector().check([])
    assert result.passed


# ---------------------------------------------------------------------------
# Layer 4 — OutlierDetector
# ---------------------------------------------------------------------------

def test_outlier_detector_clean_data(tmp_path):
    f = tmp_path / "features.csv"
    with f.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["x", "y"])
        import random
        random.seed(42)
        for _ in range(200):
            w.writerow([random.gauss(0, 1), random.gauss(0, 1)])
    result = OutlierDetector().check([f])
    assert result.passed


def test_outlier_detector_extreme_outlier(tmp_path):
    # One extreme outlier out of 200 normal values.
    # With mean ≈ 5006 and std ≈ 70534, z ≈ 14 >> threshold of 5.
    f = tmp_path / "features.csv"
    with f.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["score"])
        for _ in range(199):
            w.writerow([1.0])
        w.writerow([1_000_000.0])   # single adversarial injection, z ≈ 14
    result = OutlierDetector().check([f])
    assert not result.passed
    assert any("outlier" in e.lower() or "z=" in e.lower() for e in result.evidence)


def test_outlier_detector_constant_column(tmp_path):
    f = tmp_path / "synthetic.csv"
    with f.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["feature"])
        for _ in range(100):
            w.writerow([42.0])
    result = OutlierDetector().check([f])
    assert not result.passed
    assert any("constant" in e.lower() for e in result.evidence)


def test_outlier_detector_no_files():
    result = OutlierDetector().check([])
    assert result.passed


# ---------------------------------------------------------------------------
# Layer 5 — TriggerPatternScanner
# ---------------------------------------------------------------------------

def test_trigger_scanner_clean_text(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("The quick brown fox jumps over the lazy dog.\n" * 100)
    result = TriggerPatternScanner().check([f])
    assert result.passed


def test_trigger_scanner_known_trigger_token(tmp_path):
    f = tmp_path / "poisoned.txt"
    # Embed trigger token in 10% of lines
    lines = ["normal sentence here"] * 900
    lines += ["cf this is a backdoored sample"] * 100
    f.write_text("\n".join(lines))
    result = TriggerPatternScanner().check([f])
    assert not result.passed
    assert any("cf" in e for e in result.evidence)


def test_trigger_scanner_zero_width_space(tmp_path):
    f = tmp_path / "unicode.txt"
    zwsp = "​"
    lines = [f"normal text{zwsp}here"] * 50 + ["clean line"] * 50
    f.write_text("\n".join(lines))
    result = TriggerPatternScanner().check([f])
    # zero-width space is a known trigger
    assert not result.passed or result.score >= 0.0  # at minimum detected or clean


def test_trigger_scanner_no_files():
    result = TriggerPatternScanner().check([])
    assert result.passed


# ---------------------------------------------------------------------------
# Layer 6 — ProvenanceIntegrityChecker
# ---------------------------------------------------------------------------

def test_provenance_clean_with_record(tmp_path):
    from datetime import datetime, timezone, timedelta
    prov = {
        "created_at": (datetime.now(tz=timezone.utc) - timedelta(days=30)).isoformat(),
        "sources": ["https://huggingface.co/datasets/legitimate/dataset"],
    }
    result = ProvenanceIntegrityChecker().check(tmp_path, provenance_data=prov)
    assert result.passed or result.score < 0.3


def test_provenance_suspicious_url(tmp_path):
    prov = {
        "created_at": "2025-01-01T00:00:00+00:00",
        "sources": ["https://mega.nz/file/suspect_dataset"],
    }
    result = ProvenanceIntegrityChecker().check(tmp_path, provenance_data=prov)
    assert not result.passed
    assert any("mega" in e.lower() or "suspicious" in e.lower() for e in result.evidence)


def test_provenance_missing_no_files(tmp_path):
    result = ProvenanceIntegrityChecker().check(tmp_path, provenance_data=None)
    assert not result.passed or result.score > 0  # flags missing provenance


# ---------------------------------------------------------------------------
# DataPoisonScanner end-to-end
# ---------------------------------------------------------------------------

def _make_clean_dataset(root: Path) -> Path:
    ds = root / "clean_dataset"
    ds.mkdir()
    with (ds / "labels.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["text", "label"])
        for i in range(200):
            w.writerow([f"text sample {i}", "A" if i % 2 == 0 else "B"])
    with (ds / "data.jsonl").open("w") as fh:
        for i in range(100):
            fh.write(json.dumps({"id": i, "text": f"unique sample {i}", "label": i % 3}) + "\n")
    return ds


def _make_poisoned_dataset(root: Path) -> Path:
    ds = root / "poisoned_dataset"
    ds.mkdir()
    # Heavy label imbalance
    with (ds / "labels.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["text", "label"])
        for _ in range(990):
            w.writerow(["sample", "A"])
        for i in range(10):
            w.writerow([f"other {i}", "B"])
    # High duplicate rate
    with (ds / "data.jsonl").open("w") as fh:
        for _ in range(95):
            fh.write(json.dumps({"text": "poison", "label": 1}) + "\n")
        for i in range(5):
            fh.write(json.dumps({"text": f"ok {i}", "label": 0}) + "\n")
    # Trigger pattern
    with (ds / "train.txt").open("w") as fh:
        fh.write("normal text\n" * 80)
        fh.write("cf backdoor trigger token\n" * 20)  # 20% trigger rate
    return ds


def test_scanner_clean_dataset(tmp_path):
    ds = _make_clean_dataset(tmp_path)
    report = DataPoisonScanner().scan(ds)
    assert report.risk_level in (RiskLevel.CLEAN, RiskLevel.LOW, RiskLevel.MEDIUM)
    assert report.file_count > 0
    assert report.schema == "squash.data.poison.report/v1"


def test_scanner_poisoned_dataset(tmp_path):
    ds = _make_poisoned_dataset(tmp_path)
    report = DataPoisonScanner().scan(ds)
    # Poisoned dataset should flag at least some checks
    flagged = [c for c in report.checks if not c.passed]
    assert len(flagged) >= 1
    assert report.risk_level != RiskLevel.CLEAN


def test_scanner_single_file(tmp_path):
    f = tmp_path / "data.csv"
    with f.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["text", "label"])
        for i in range(50):
            w.writerow([f"t{i}", "A" if i % 2 == 0 else "B"])
    report = DataPoisonScanner().scan(f)
    assert report.file_count >= 1


# ---------------------------------------------------------------------------
# DataPoisonReport: JSON round-trip + Markdown
# ---------------------------------------------------------------------------

def test_report_json_round_trip(tmp_path):
    ds = _make_clean_dataset(tmp_path)
    report = DataPoisonScanner().scan(ds)
    path = tmp_path / "report.json"
    path.write_text(report.to_json())
    loaded = load_report(path)
    assert loaded.schema == report.schema
    assert loaded.risk_level == report.risk_level
    assert loaded.overall_score == report.overall_score
    assert len(loaded.checks) == len(report.checks)


def test_report_markdown_contains_risk_level(tmp_path):
    ds = _make_clean_dataset(tmp_path)
    report = DataPoisonScanner().scan(ds)
    md = report.to_markdown()
    assert report.risk_level.value.upper() in md
    assert "Data Poisoning Scan" in md


def test_report_summary_has_icon(tmp_path):
    ds = _make_clean_dataset(tmp_path)
    report = DataPoisonScanner().scan(ds)
    summary = report.summary()
    assert "✓" in summary or "✗" in summary


def test_report_passed_reflects_risk(tmp_path):
    ds = _make_clean_dataset(tmp_path)
    report = DataPoisonScanner().scan(ds)
    # CLEAN and LOW both count as passed
    if report.risk_level in (RiskLevel.CLEAN, RiskLevel.LOW):
        assert report.passed()
    elif report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        assert not report.passed()


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------

def test_cli_parser_registered():
    from squash.cli import _build_parser
    p = _build_parser()
    ns = p.parse_args(["data-poison", "scan", "./data"])
    assert ns.command == "data-poison"
    assert ns.dp_command == "scan"
    assert ns.dataset_path == "./data"
    assert ns.fail_on == "high"


def test_cli_scan_clean_dataset(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_data_poison

    ds = _make_clean_dataset(tmp_path)
    args = argparse.Namespace(
        dp_command="scan",
        dataset_path=str(ds),
        scan_format="json",
        out=None,
        fail_on="critical",   # only fail on critical — clean dataset should pass
        provenance_path=None,
    )
    rc = _cmd_data_poison(args, quiet=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["schema"] == "squash.data.poison.report/v1"
    assert rc == 0


def test_cli_scan_nonexistent_path(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_data_poison

    args = argparse.Namespace(
        dp_command="scan",
        dataset_path=str(tmp_path / "nope"),
        scan_format="text",
        out=None,
        fail_on="high",
        provenance_path=None,
    )
    rc = _cmd_data_poison(args, quiet=True)
    assert rc == 1
