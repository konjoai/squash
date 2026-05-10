"""tests/test_squash_sprint29.py — Sprint 29 demo polish: live policy checker.

Covers the new ``demo.quick_check.quick_check_policy`` heuristic and its
permalink wiring inside ``demo/server.py``:

* timing budget — direct call must complete in < 1500 ms on a 200-word input
* deterministic sha-256 keyed by policy text
* verdict thresholds (pass / warn / fail)
* dimension scoring on canonical fixtures
* /quick-check + /r/{hash} permalink lookup roundtrip
* empty-input safety + input length cap
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from demo import server  # noqa: E402  -- after path mutation
from demo.quick_check import quick_check_policy  # noqa: E402


_GDPR_BLURB = """
Acme AI processes personal data only on a lawful basis under Article 6 of the
GDPR. Data subjects have the right to access, rectify, erase, restrict, port,
and object to processing. Requests are fulfilled within 30 days. A Data
Protection Officer is appointed and reachable at dpo@acme.example. Personal
data is encrypted at rest with AES-256 and in transit with TLS 1.3. Access is
governed by role-based access control. Multi-factor authentication is
mandatory for all administrative access. Incident response runbooks are
reviewed quarterly and audit logs are retained for seven years. Personal
data breaches are reported to the supervisory authority within 72 hours and
to affected data subjects without undue delay where the breach is likely to
result in high risk. Personal data is retained for 90 days and then deleted.
The retention schedule is reviewed annually. Pseudonymisation is applied to
identifiers in analytics pipelines. Records of processing activities are
maintained per Article 30. Transfers outside the EEA use Standard
Contractual Clauses.
""".strip()


_WEAK_BLURB = """
We care about your privacy. We may collect some information when you use our
website. We may share your information with our partners or for any reason we
determine to be appropriate. We may update this policy at any time without
notice. We will keep your data as long as we feel it is needed for our
business purposes. We take reasonable steps to protect your information but
we cannot guarantee security. Continued use of our services after any changes
constitutes your acceptance of the updated policy. Children should not use
the site, but we do not actively verify age.
""".strip()


def _word_count(text: str) -> int:
    return len(text.split())


# ── Timing budget ───────────────────────────────────────────────────────────


def test_quick_check_under_1500ms_for_200_word_policy():
    """The direct (in-process) /quick-check logic must return in < 1500 ms on
    a 200-word policy. Padded with extra prose to reach the word count.

    Justification — every slot in this budget reflects real demo UX:
      * < 50  ms typical case
      * < 200 ms p99 on cold cache
      * < 1500 ms hard cap so the elapsed-timer in the UI never feels stuck

    Five repetitions are timed; the median is asserted, so a single noisy
    sample on a busy CI runner does not flake the test.
    """
    base = _GDPR_BLURB
    while _word_count(base) < 200:
        base += " " + _GDPR_BLURB
    words = base.split()[:240]
    text = " ".join(words)
    assert 195 <= _word_count(text) <= 245, "fixture should be ~200 words"

    timings_ms: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        result = quick_check_policy(text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        timings_ms.append(elapsed_ms)
        assert isinstance(result.score, int)

    median = sorted(timings_ms)[len(timings_ms) // 2]
    assert median < 1500.0, (
        f"quick_check_policy median latency {median:.2f} ms exceeds 1500 ms budget; "
        f"all samples = {[round(t, 2) for t in timings_ms]}"
    )


# ── Determinism ─────────────────────────────────────────────────────────────


def test_quick_check_sha256_is_deterministic():
    a = quick_check_policy(_GDPR_BLURB)
    b = quick_check_policy(_GDPR_BLURB)
    assert a.sha256 == b.sha256
    assert a.score == b.score
    assert a.verdict == b.verdict


def test_quick_check_sha256_changes_when_text_changes():
    a = quick_check_policy(_GDPR_BLURB)
    b = quick_check_policy(_GDPR_BLURB + " Extra clause.")
    assert a.sha256 != b.sha256


# ── Verdict thresholds ──────────────────────────────────────────────────────


def test_strong_gdpr_policy_passes():
    r = quick_check_policy(_GDPR_BLURB)
    assert r.verdict == "pass"
    assert r.score >= 60


def test_weak_boilerplate_fails():
    r = quick_check_policy(_WEAK_BLURB)
    assert r.verdict == "fail"
    assert r.score < 30
    assert r.red_flags, "the weak fixture must trip at least one red flag"


def test_empty_policy_is_fail_not_crash():
    r = quick_check_policy("")
    assert r.verdict == "fail"
    assert r.score == 0
    assert r.word_count == 0


def test_non_string_input_raises_type_error():
    with pytest.raises(TypeError):
        quick_check_policy(None)  # type: ignore[arg-type]


# ── Dimension scoring ───────────────────────────────────────────────────────


def test_strong_policy_lights_gdpr_badge():
    r = quick_check_policy(_GDPR_BLURB)
    assert r.framework_badges.get("GDPR") is True
    by_key = {d.key: d for d in r.dimensions}
    assert by_key["gdpr"].score >= 0.66
    assert by_key["gdpr"].must_hits >= 2


def test_weak_policy_lights_no_badges():
    r = quick_check_policy(_WEAK_BLURB)
    assert not any(r.framework_badges.values())


def test_dimensions_are_complete_and_ordered():
    r = quick_check_policy(_GDPR_BLURB)
    keys = [d.key for d in r.dimensions]
    assert keys == ["gdpr", "ccpa", "soc2", "ai_use", "retention"], (
        f"unexpected dimension order: {keys}"
    )


# ── Server endpoint + permalink roundtrip ───────────────────────────────────


def test_quick_check_endpoint_returns_permalink_and_caches_result():
    r = server._api_quick_check({"text": _GDPR_BLURB})
    assert r["verdict"] == "pass"
    assert "permalink" in r and r["permalink"].startswith("/r/")
    assert "permalink_id" in r and len(r["permalink_id"]) == 12

    cached = server._api_quick_check_lookup(r["permalink_id"])
    assert cached is not None
    assert cached["sha256"] == r["sha256"]
    assert cached["verdict"] == "pass"


def test_quick_check_endpoint_truncates_oversize_input():
    big = "a " * 50000  # ~100 KB, larger than the 64 KiB cap
    r = server._api_quick_check({"text": big})
    # Should not crash and should still return a verdict.
    assert "verdict" in r
    assert "permalink" in r


def test_quick_check_endpoint_rejects_non_string():
    r = server._api_quick_check({"text": 12345})
    assert "error" in r


def test_quick_check_lookup_unknown_returns_none():
    assert server._api_quick_check_lookup("0" * 12) is None


# ── Sample-policy listing ───────────────────────────────────────────────────


def test_sample_policy_listing_returns_five_files():
    listing = server._api_list_samples()
    names = {s["name"] for s in listing["samples"]}
    expected = {
        "gdpr_strong.txt",
        "ccpa_basic.txt",
        "ai_acceptable_use.txt",
        "soc2_summary.md",
        "weak_policy.txt",
    }
    assert expected.issubset(names), f"missing samples: {expected - names}"
    assert len(listing["samples"]) == 5


def test_sample_policy_get_blocks_path_traversal():
    status, body = server._api_get_sample("../server.py")
    assert status == 400
    assert "error" in body

    status, body = server._api_get_sample("not-real.txt")
    assert status == 404


def test_sample_policy_get_returns_file_text():
    status, body = server._api_get_sample("gdpr_strong.txt")
    assert status == 200
    assert "GDPR" in body["text"] or "gdpr" in body["text"].lower()
    assert body["name"] == "gdpr_strong.txt"


# ── End-to-end fixture pass: each sample yields a stable verdict ────────────


@pytest.mark.parametrize(
    "name,expected_verdict",
    [
        ("gdpr_strong.txt", "pass"),
        ("weak_policy.txt", "fail"),
    ],
)
def test_bundled_samples_score_in_expected_band(name, expected_verdict):
    sample_dir = REPO_ROOT / "demo" / "sample_policies"
    text = (sample_dir / name).read_text(encoding="utf-8")
    r = quick_check_policy(text)
    assert r.verdict == expected_verdict, (
        f"{name}: expected {expected_verdict}, got {r.verdict} (score={r.score})"
    )
