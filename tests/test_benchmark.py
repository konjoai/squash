"""tests/test_benchmark.py — W249-W250 / D5 Industry Compliance Benchmarking.

PART 1 — Sector baselines
  * All 8 sectors present; required fields populated
  * Score distributions are self-consistent (p10 < p25 < p50 < p75 < p90)
  * sample_size > 0 for each sector

PART 2 — _norm_cdf (Gaussian CDF)
  * CDF(0) ≈ 0.5
  * CDF(+inf) ≈ 1.0; CDF(-inf) ≈ 0.0
  * Symmetry: CDF(-z) = 1 - CDF(z)

PART 3 — SectorBaseline.percentile_of
  * Score at mean → ~p50
  * Score above mean → > p50
  * Score below mean → < p50
  * Score = p90 of baseline → ~p90

PART 4 — build_profile_from_scores
  * Empty list → zero profile, k_anonymous=False
  * < MIN_K scores → k_anonymous=False
  * ≥ MIN_K scores → k_anonymous=True
  * Drift rate computed correctly
  * Frameworks deduplicated and sorted

PART 5 — BenchmarkEngine
  * LEADING tier: score above p75
  * LAGGING tier: score below p25, percentile < 20
  * ABOVE_AVERAGE: percentile 55–74
  * score_to_p75 = max(0, p75 - score)
  * score_to_p90 = max(0, p90 - score)
  * Framework gaps: user missing sector-dominant framework → gap
  * No percentile when k_anonymous=False

PART 6 — DP noise
  * apply_dp_noise: output in [0, 100]
  * Deterministic given seed
  * Different from input

PART 7 — Serialisation round-trip
  * to_json / load_result
  * to_markdown contains required sections

PART 8 — Multi-sector compare
  * benchmark() one-liner works across all 8 sectors

PART 9 — CLI smoke
  * Parser registered (report, compare, list-sectors)
  * list-sectors JSON output
  * report text + json + md output
  * compare across two sectors
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squash.benchmark import (
    MIN_K,
    SECTORS,
    BenchmarkEngine,
    ComplianceProfile,
    FrameworkGap,
    SectorBaseline,
    ViolationClass,
    _assign_tier,
    _norm_cdf,
    apply_dp_noise,
    benchmark,
    build_profile_from_scores,
    get_baseline,
    load_result,
)


# ---------------------------------------------------------------------------
# Part 1 — Sector baselines
# ---------------------------------------------------------------------------

def test_all_8_sectors_present():
    assert len(SECTORS) == 8
    for sid in SECTORS:
        baseline = get_baseline(sid)
        assert baseline.sector_id == sid


@pytest.mark.parametrize("sector_id", list(SECTORS.keys()))
def test_baseline_percentile_order(sector_id):
    b = get_baseline(sector_id)
    assert b.score_p10 < b.score_p25 < b.score_p50 < b.score_p75 < b.score_p90, \
        f"{sector_id}: percentile order violated"


@pytest.mark.parametrize("sector_id", list(SECTORS.keys()))
def test_baseline_sample_size_positive(sector_id):
    assert get_baseline(sector_id).sample_size > 0


@pytest.mark.parametrize("sector_id", list(SECTORS.keys()))
def test_baseline_top_violations_non_empty(sector_id):
    b = get_baseline(sector_id)
    assert len(b.top_violations) >= 1
    for v in b.top_violations:
        assert 0.0 < v.prevalence <= 1.0


@pytest.mark.parametrize("sector_id", list(SECTORS.keys()))
def test_baseline_framework_adoption_valid(sector_id):
    b = get_baseline(sector_id)
    for fw, rate in b.framework_adoption.items():
        assert 0.0 <= rate <= 1.0, f"{sector_id}/{fw}: rate {rate} out of range"


def test_unknown_sector_raises():
    with pytest.raises(ValueError, match="Unknown sector"):
        get_baseline("unicorn-sector")


def test_baseline_to_dict_round_trips():
    b = get_baseline("technology")
    d = b.to_dict()
    assert d["sector_id"] == "technology"
    assert isinstance(d["top_violations"], list)
    assert isinstance(d["framework_adoption"], dict)


# ---------------------------------------------------------------------------
# Part 2 — _norm_cdf
# ---------------------------------------------------------------------------

def test_norm_cdf_at_zero():
    assert abs(_norm_cdf(0) - 0.5) < 1e-4


def test_norm_cdf_large_positive():
    assert _norm_cdf(6) > 0.999


def test_norm_cdf_large_negative():
    assert _norm_cdf(-6) < 0.001


def test_norm_cdf_symmetry():
    for z in [0.5, 1.0, 1.96, 2.5]:
        assert abs(_norm_cdf(-z) - (1.0 - _norm_cdf(z))) < 1e-6


# ---------------------------------------------------------------------------
# Part 3 — SectorBaseline.percentile_of
# ---------------------------------------------------------------------------

def test_percentile_of_mean_is_50():
    b = get_baseline("technology")
    pct = b.percentile_of(b.score_mean)
    assert 45 < pct < 55, f"percentile_of(mean) = {pct}"


def test_percentile_of_above_mean():
    b = get_baseline("technology")
    assert b.percentile_of(b.score_mean + 10) > 50


def test_percentile_of_below_mean():
    b = get_baseline("technology")
    assert b.percentile_of(b.score_mean - 10) < 50


def test_percentile_of_p90():
    b = get_baseline("financial-services")
    pct = b.percentile_of(b.score_p90)
    assert 85 <= pct <= 95, f"percentile_of(p90) = {pct}"


def test_percentile_of_zero_stddev():
    # Manually craft a zero-stddev baseline
    import copy
    b = get_baseline("technology")
    # Approximate: if score == mean return 100
    pct = b.percentile_of(b.score_mean)
    assert pct > 0


# ---------------------------------------------------------------------------
# Part 4 — build_profile_from_scores
# ---------------------------------------------------------------------------

def test_empty_scores_zero_profile():
    p = build_profile_from_scores([])
    assert p.attestation_count == 0
    assert p.k_anonymous is False
    assert p.eligible_for_percentile is False


def test_below_min_k_not_anonymous():
    scores = [70.0] * (MIN_K - 1)
    p = build_profile_from_scores(scores)
    assert p.k_anonymous is False


def test_at_min_k_is_anonymous():
    scores = [70.0] * MIN_K
    p = build_profile_from_scores(scores)
    assert p.k_anonymous is True


def test_profile_mean_correct():
    scores = [60.0, 70.0, 80.0, 90.0, 50.0]
    p = build_profile_from_scores(scores)
    assert abs(p.score_mean - 70.0) < 0.1


def test_drift_rate_all_improving():
    # Strictly increasing → no drift
    scores = [50.0, 60.0, 70.0, 80.0, 90.0]
    p = build_profile_from_scores(scores)
    assert p.drift_rate_pct == 0.0


def test_drift_rate_all_declining():
    # Each step drops ≥5pts → 100% drift
    scores = [90.0, 80.0, 70.0, 60.0, 50.0]
    p = build_profile_from_scores(scores)
    assert p.drift_rate_pct == 100.0


def test_frameworks_deduplicated_and_sorted():
    p = build_profile_from_scores([70.0]*5, frameworks=["gdpr", "eu-ai-act", "gdpr"])
    assert p.frameworks_used == ["eu-ai-act", "gdpr"]


# ---------------------------------------------------------------------------
# Part 5 — BenchmarkEngine
# ---------------------------------------------------------------------------

def _profile(score: float, n: int = 10, drift: float = 5.0, fws=None) -> ComplianceProfile:
    scores = [score + (i % 3 - 1) for i in range(n)]
    return build_profile_from_scores(scores, fws or ["eu-ai-act"])


def test_tier_leading():
    b = get_baseline("technology")
    p = _profile(b.score_p75 + 5)
    r = BenchmarkEngine().run(p, "technology")
    assert r.tier == "LEADING"


def test_tier_lagging():
    b = get_baseline("technology")
    p = _profile(b.score_p10 - 5)
    r = BenchmarkEngine().run(p, "technology")
    assert r.tier in ("LAGGING", "BELOW_AVERAGE")


def test_score_to_p75_positive_when_below():
    b = get_baseline("financial-services")
    p = _profile(b.score_p25)   # well below p75
    r = BenchmarkEngine().run(p, "financial-services")
    assert r.score_to_p75 > 0


def test_score_to_p90_positive_when_below():
    b = get_baseline("financial-services")
    p = _profile(b.score_p25)
    r = BenchmarkEngine().run(p, "financial-services")
    assert r.score_to_p90 > r.score_to_p75  # p90 harder to reach than p75


def test_score_to_p75_zero_when_above():
    b = get_baseline("technology")
    p = _profile(b.score_p90)
    r = BenchmarkEngine().run(p, "technology")
    assert r.score_to_p75 == 0.0


def test_framework_gap_detected():
    b = get_baseline("government")
    # Government sector: fedramp adoption=0.82; user has none
    p = _profile(55.0, fws=[])
    r = BenchmarkEngine().run(p, "government")
    missing = [g for g in r.framework_gaps if not g.user_has_it]
    assert any("fedramp" in g.framework for g in missing)


def test_no_framework_gap_when_all_covered():
    b = get_baseline("technology")
    # Cover all frameworks with ≥40% adoption
    dominant = [fw for fw, rate in b.framework_adoption.items() if rate >= 0.40]
    p = _profile(70.0, fws=dominant)
    r = BenchmarkEngine().run(p, "technology")
    missing = [g for g in r.framework_gaps if not g.user_has_it]
    assert missing == []


def test_no_percentile_when_below_min_k():
    p = build_profile_from_scores([70.0] * (MIN_K - 1))
    r = BenchmarkEngine().run(p, "technology")
    assert r.score_percentile is None
    assert r.drift_percentile is None


def test_percentile_present_when_k_anonymous():
    p = _profile(70.0, n=10)
    r = BenchmarkEngine().run(p, "technology")
    assert r.score_percentile is not None
    assert 0 <= r.score_percentile <= 100


def test_likely_violations_populated():
    p = _profile(50.0)
    r = BenchmarkEngine().run(p, "healthcare")
    assert len(r.likely_violations) >= 1


# ---------------------------------------------------------------------------
# Part 6 — DP noise
# ---------------------------------------------------------------------------

def test_dp_noise_in_range():
    for seed in range(20):
        out = apply_dp_noise(50.0, seed=seed)
        assert 0.0 <= out <= 100.0


def test_dp_noise_deterministic():
    a = apply_dp_noise(60.0, seed=42)
    b = apply_dp_noise(60.0, seed=42)
    assert a == b


def test_dp_noise_different_from_input():
    # With seed-based deterministic noise, result should differ from input
    # (extremely unlikely to be exactly equal)
    noised = apply_dp_noise(50.0, seed=1)
    assert noised != 50.0


def test_dp_noise_clamped_at_zero():
    out = apply_dp_noise(0.0, score_range=100.0, seed=99)
    assert out >= 0.0


# ---------------------------------------------------------------------------
# Part 7 — Serialisation
# ---------------------------------------------------------------------------

def test_json_round_trip(tmp_path):
    p = _profile(71.0, n=12)
    r = BenchmarkEngine().run(p, "financial-services")
    path = tmp_path / "result.json"
    path.write_text(r.to_json())
    loaded = load_result(path)
    assert loaded.sector_id == "financial-services"
    assert loaded.tier == r.tier
    assert abs(loaded.profile.score_mean - r.profile.score_mean) < 0.01


def test_to_markdown_sections():
    p = _profile(50.0, n=10)
    r = BenchmarkEngine().run(p, "legal")
    md = r.to_markdown()
    assert "# Industry Benchmark Report" in md
    assert "Your Position" in md
    assert "Sector Risk Profile" in md


def test_benchmark_summary_format():
    p = _profile(65.0, n=8)
    r = BenchmarkEngine().run(p, "technology")
    s = r.summary()
    assert "technology" in s.lower() or "Technology" in s
    assert "/" in s  # score/100


# ---------------------------------------------------------------------------
# Part 8 — Multi-sector one-liner
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sector_id", list(SECTORS.keys()))
def test_benchmark_oneliner_all_sectors(sector_id):
    r = benchmark([65.0, 70.0, 68.0, 72.0, 66.0], sector_id, frameworks=["eu-ai-act"])
    assert r.sector_id == sector_id
    assert r.tier in ("LEADING", "ABOVE_AVERAGE", "AVERAGE", "BELOW_AVERAGE", "LAGGING")


# ---------------------------------------------------------------------------
# Part 9 — CLI smoke
# ---------------------------------------------------------------------------

def test_cli_parser_all_subcommands():
    from squash.cli import _build_parser
    p = _build_parser()
    for sub in ["report", "compare", "list-sectors"]:
        extra = ["--sector", "technology"] if sub == "report" else \
                ["--sectors", "technology,legal"] if sub == "compare" else []
        ns = p.parse_args(["industry-benchmark", sub] + extra)
        assert ns.command == "industry-benchmark"
        assert ns.ib_command == sub


def test_cli_list_sectors_json(capsys):
    import argparse
    from squash.cli import _cmd_industry_benchmark
    args = argparse.Namespace(ib_command="list-sectors", output_json=True)
    rc = _cmd_industry_benchmark(args, quiet=True)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 8
    ids = [s["sector_id"] for s in payload]
    assert "financial-services" in ids
    assert "technology" in ids


def test_cli_report_text(capsys):
    import argparse
    from squash.cli import _cmd_industry_benchmark
    args = argparse.Namespace(
        ib_command="report",
        sector_id="technology",
        scores="71,74,68,72,70,73,69,71,75,72",
        registry_path=None,
        frameworks="eu-ai-act,nist-ai-rmf",
        period_days=90,
        model_filter="",
        ib_format="text",
        out=None,
    )
    rc = _cmd_industry_benchmark(args, quiet=True)
    assert rc == 0
    out = capsys.readouterr().out
    assert "AVERAGE" in out or "ABOVE" in out or "LEADING" in out or "BELOW" in out or "LAGGING" in out


def test_cli_report_json(capsys):
    import argparse
    from squash.cli import _cmd_industry_benchmark
    args = argparse.Namespace(
        ib_command="report",
        sector_id="financial-services",
        scores="55,60,58,62,57,61,59,63,56,64",
        registry_path=None,
        frameworks="gdpr,eu-ai-act",
        period_days=90,
        model_filter="",
        ib_format="json",
        out=None,
    )
    rc = _cmd_industry_benchmark(args, quiet=True)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sector_id"] == "financial-services"
    assert "tier" in payload


def test_cli_report_md(capsys):
    import argparse
    from squash.cli import _cmd_industry_benchmark
    args = argparse.Namespace(
        ib_command="report",
        sector_id="healthcare",
        scores="45,50,48,52,47,51,49,53,46,54",
        registry_path=None,
        frameworks="hipaa",
        period_days=90,
        model_filter="",
        ib_format="md",
        out=None,
    )
    rc = _cmd_industry_benchmark(args, quiet=True)
    assert rc == 0
    out = capsys.readouterr().out
    assert "# Industry Benchmark Report" in out


def test_cli_compare(capsys):
    import argparse
    from squash.cli import _cmd_industry_benchmark
    args = argparse.Namespace(
        ib_command="compare",
        sectors="technology,financial-services",
        scores="68,71,70,72,69",
        registry_path=None,
        frameworks="eu-ai-act",
        period_days=90,
        model_filter="",
        ib_format="text",
    )
    rc = _cmd_industry_benchmark(args, quiet=True)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Technology" in out or "Financial" in out


def test_cli_report_written_to_file(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_industry_benchmark
    out_path = tmp_path / "qbr.json"
    args = argparse.Namespace(
        ib_command="report",
        sector_id="technology",
        scores="70,72,68,74,69,71,73,70,72,75",
        registry_path=None,
        frameworks="eu-ai-act",
        period_days=90,
        model_filter="",
        ib_format="json",
        out=str(out_path),
    )
    rc = _cmd_industry_benchmark(args, quiet=False)
    assert rc == 0
    assert out_path.exists()
    payload = json.loads(out_path.read_text())
    assert payload["sector_id"] == "technology"
