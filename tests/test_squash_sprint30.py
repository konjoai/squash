"""tests/test_squash_sprint30.py — Sprint 30 (viral SVG card + trending + UI overhaul).

Coverage:

W249 — squash.quick_check additions
       * SOC 2 framework definition (run_quick_check returns 6 frameworks)
       * detect_policy_type heuristic + POLICY_TYPES taxonomy
       * score_all_frameworks multi-framework scorer
       * StatsTracker thread-safe in-memory aggregate

W250 — squash.api endpoints
       * GET /r/{hash}/card.svg renders an image/svg+xml score card
       * GET /trending returns aggregate counts (no auth)
       * POST /quick-check now records (policy_type, verdict) for trending
       * card_url is included in /quick-check response when share=True
       * /trending and /r/.../card.svg are auth-free

W251 — demo/index.html rebuild
       * preserves every Sprint 29 DOM hook the prior tests assert on
       * adds the visual elements specified in Sprint 30: scan-beam,
         breathe orb, verdict glyph reveal, sub-score chips, trending
         sidebar, copy-link orb
"""

from __future__ import annotations

import re
import threading
import unittest
from pathlib import Path

from squash.quick_check import (
    AVAILABLE_FRAMEWORKS,
    POLICY_TYPES,
    QuickCheckResult,
    StatsTracker,
    detect_policy_type,
    get_global_stats,
    run_quick_check,
    score_all_frameworks,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = REPO_ROOT / "demo" / "sample_policies"
# The v2 compliance-lab rebuild moved the single-page demo this suite
# asserts on to legacy.html; index.html now hosts the tabbed lab.
DEMO_INDEX = REPO_ROOT / "demo" / "legacy.html"


# ── W249: SOC 2 framework ────────────────────────────────────────────────────


class TestSoc2Framework(unittest.TestCase):

    def test_soc2_in_available_frameworks(self):
        self.assertIn("soc2", AVAILABLE_FRAMEWORKS)

    def test_soc2_run_returns_result(self):
        text = """
        Our information security program defines the control environment.
        We enforce role-based access control and require multi-factor
        authentication for production. Continuous monitoring with anomaly
        detection feeds a SIEM. Documented incident response procedures
        cover escalation. Disaster recovery plans include RTO and RPO
        commitments. All data is encrypted in transit (TLS) and at rest
        (AES-256) with managed key rotation.
        """
        result = run_quick_check(text, framework="soc2")
        self.assertIsInstance(result, QuickCheckResult)
        self.assertEqual(result.framework, "soc2")
        self.assertEqual(result.verdict, "pass", result.summary)

    def test_soc2_sparse_text_fails(self):
        result = run_quick_check("we have a website.", framework="soc2")
        self.assertEqual(result.verdict, "fail")


# ── W249: policy-type detection ──────────────────────────────────────────────


class TestPolicyTypeDetection(unittest.TestCase):

    def test_policy_types_tuple_includes_other(self):
        self.assertIn("other", POLICY_TYPES)
        # Eight known categories so the trending sidebar has a stable lane count.
        self.assertEqual(len(POLICY_TYPES), 8)

    def test_empty_text_is_other(self):
        self.assertEqual(detect_policy_type(""), "other")
        self.assertEqual(detect_policy_type("   "), "other")

    def test_non_string_is_other(self):
        self.assertEqual(detect_policy_type(None), "other")  # type: ignore[arg-type]
        self.assertEqual(detect_policy_type(123), "other")  # type: ignore[arg-type]

    def test_unrelated_text_is_other(self):
        self.assertEqual(detect_policy_type("Roses are red, violets are blue."), "other")

    def test_each_sample_classifies_to_expected_type(self):
        expected = {
            "01_privacy_policy.txt":  "privacy_policy",
            "02_terms_of_service.txt": "terms_of_service",
            "03_gdpr_dpa.txt":        "gdpr_dpa",
            "04_ccpa_notice.txt":     "ccpa_notice",
            "05_cookie_policy.txt":   "cookie_policy",
        }
        for name, kind in expected.items():
            text = (SAMPLE_DIR / name).read_text(encoding="utf-8")
            self.assertEqual(detect_policy_type(text), kind, msg=name)

    def test_ai_system_card_text_detected(self):
        text = """
        Model card for vision-trans-q4. Intended use: image classification.
        Out-of-scope: medical diagnosis. Subject to the EU AI Act.
        Human oversight is mandatory; high-risk safeguards apply.
        """
        self.assertEqual(detect_policy_type(text), "ai_system_card")

    def test_soc2_report_text_detected(self):
        text = """
        SOC 2 Type II report covering the trust services criteria.
        AICPA-aligned. Controls under CC6.1, CC6.2, CC7.1 are operating
        effectively. Control objectives are listed in Annex A.
        """
        self.assertEqual(detect_policy_type(text), "soc2_report")


# ── W249: multi-framework scorer ─────────────────────────────────────────────


class TestScoreAllFrameworks(unittest.TestCase):

    def test_default_returns_three_frameworks(self):
        text = (SAMPLE_DIR / "01_privacy_policy.txt").read_text(encoding="utf-8")
        out = score_all_frameworks(text)
        self.assertEqual(set(out.keys()), {"gdpr", "ccpa", "soc2"})
        for r in out.values():
            self.assertIsInstance(r, QuickCheckResult)

    def test_unknown_framework_skipped(self):
        text = (SAMPLE_DIR / "01_privacy_policy.txt").read_text(encoding="utf-8")
        out = score_all_frameworks(text, frameworks=("gdpr", "hipaa"))
        self.assertIn("gdpr", out)
        self.assertNotIn("hipaa", out)

    def test_empty_text_raises(self):
        with self.assertRaises(ValueError):
            score_all_frameworks("")


# ── W249: StatsTracker ───────────────────────────────────────────────────────


class TestStatsTracker(unittest.TestCase):

    def setUp(self):
        self.tracker = StatsTracker()

    def test_empty_trending_payload_shape(self):
        feed = self.tracker.trending()
        self.assertEqual(feed["total"], 0)
        self.assertEqual(feed["top"], [])

    def test_record_increments_counts(self):
        self.tracker.record("privacy_policy", "pass")
        self.tracker.record("privacy_policy", "warn")
        self.tracker.record("cookie_policy", "fail")
        feed = self.tracker.trending(top=5)
        self.assertEqual(feed["total"], 3)
        types = [row["policy_type"] for row in feed["top"]]
        self.assertIn("privacy_policy", types)
        self.assertIn("cookie_policy", types)
        pp = next(r for r in feed["top"] if r["policy_type"] == "privacy_policy")
        self.assertEqual(pp["count"], 2)
        self.assertEqual(pp["pass"], 1)
        self.assertEqual(pp["warn"], 1)
        self.assertEqual(pp["fail"], 0)
        self.assertAlmostEqual(pp["pass_rate"], 0.5, places=4)

    def test_top_capped_to_requested_size(self):
        for kind in POLICY_TYPES:
            self.tracker.record(kind, "pass")
        feed = self.tracker.trending(top=3)
        self.assertEqual(len(feed["top"]), 3)

    def test_unknown_policy_type_falls_back_to_other(self):
        self.tracker.record("not_a_known_type", "pass")
        feed = self.tracker.trending()
        types = [row["policy_type"] for row in feed["top"]]
        self.assertIn("other", types)

    def test_unknown_verdict_ignored(self):
        self.tracker.record("privacy_policy", "maybe")  # not a real verdict
        feed = self.tracker.trending()
        # Total only counts valid verdicts; this no-ops.
        self.assertEqual(feed["total"], 0)

    def test_reset_clears_counts(self):
        self.tracker.record("privacy_policy", "pass")
        self.tracker.reset()
        self.assertEqual(self.tracker.trending()["total"], 0)

    def test_concurrent_record_thread_safe(self):
        # 8 threads × 250 records each → 2000 total.
        def worker():
            for _ in range(250):
                self.tracker.record("privacy_policy", "pass")
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        feed = self.tracker.trending()
        self.assertEqual(feed["total"], 2000)
        self.assertEqual(feed["top"][0]["count"], 2000)

    def test_get_global_stats_is_singleton(self):
        a = get_global_stats()
        b = get_global_stats()
        self.assertIs(a, b)


# ── W250: API endpoints ──────────────────────────────────────────────────────


try:
    import httpx  # noqa: F401
    from fastapi.testclient import TestClient
    from squash.api import app, _rate_window
    _HAS_API = True
except ImportError:
    _HAS_API = False


def _reset_rate_limit() -> None:
    """Clear the per-IP sliding-window backstop so tests don't carry over.

    The /quick-check, /r/{hash}/card.svg, and /trending paths are auth-free
    and therefore counted against the per-IP backstop (SQUASH_RATE_LIMIT,
    default 60/min). Sprint 30 tests issue many requests; resetting keeps
    them from cascading 429s into Sprint 28/29 tests within the same session.
    """
    if _HAS_API:
        _rate_window.clear()


@unittest.skipUnless(_HAS_API, "FastAPI / httpx not installed")
class TestQuickCheckResponseAdditions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _reset_rate_limit()
        cls.client = TestClient(app)
        get_global_stats().reset()
        cls.text = (SAMPLE_DIR / "01_privacy_policy.txt").read_text(encoding="utf-8")

    def setUp(self):
        _reset_rate_limit()

    def test_response_includes_policy_type(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": self.text, "framework": "gdpr"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["result"]["policy_type"], "privacy_policy")

    def test_response_includes_card_url(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": self.text, "framework": "gdpr"},
        )
        body = resp.json()
        self.assertIn("card_url", body)
        self.assertTrue(body["card_url"].endswith("/card.svg"))
        self.assertIn(body["share_hash"], body["card_url"])

    def test_no_card_url_when_share_disabled(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": self.text, "framework": "gdpr", "share": False},
        )
        body = resp.json()
        self.assertNotIn("card_url", body)
        self.assertNotIn("share_hash", body)


@unittest.skipUnless(_HAS_API, "FastAPI / httpx not installed")
class TestCardSvgEndpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _reset_rate_limit()
        cls.client = TestClient(app)
        text = (SAMPLE_DIR / "01_privacy_policy.txt").read_text(encoding="utf-8")
        post = cls.client.post(
            "/quick-check", json={"text": text, "framework": "gdpr"}
        ).json()
        cls.share_hash = post["share_hash"]

    def setUp(self):
        _reset_rate_limit()

    def test_returns_image_svg_xml(self):
        resp = self.client.get(f"/r/{self.share_hash}/card.svg")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.headers["content-type"].startswith("image/svg+xml"))

    def test_body_is_well_formed_svg_root(self):
        body = self.client.get(f"/r/{self.share_hash}/card.svg").text
        self.assertTrue(body.lstrip().startswith("<svg"))
        self.assertTrue(body.rstrip().endswith("</svg>"))
        # has the size we promised
        self.assertIn('width="600"', body)
        self.assertIn('height="340"', body)

    def test_card_contains_verdict_and_score(self):
        body = self.client.get(f"/r/{self.share_hash}/card.svg").text
        self.assertIn("PASS", body)         # verdict for the privacy policy
        self.assertIn("100/100", body)      # primary score
        self.assertIn("gdpr", body)         # framework label

    def test_card_has_three_subscore_chips(self):
        body = self.client.get(f"/r/{self.share_hash}/card.svg").text
        for label in ("GDPR", "CCPA", "SOC 2"):
            self.assertIn(label, body)

    def test_card_includes_share_hash_in_footer(self):
        body = self.client.get(f"/r/{self.share_hash}/card.svg").text
        self.assertIn(f"r/{self.share_hash}", body)

    def test_card_includes_utc_timestamp(self):
        body = self.client.get(f"/r/{self.share_hash}/card.svg").text
        self.assertRegex(body, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC")

    def test_card_404_on_unknown_hash(self):
        resp = self.client.get("/r/0123456789abcdef/card.svg")
        self.assertEqual(resp.status_code, 404)

    def test_card_400_on_malformed_hash(self):
        resp = self.client.get("/r/not-a-real-hash/card.svg")
        self.assertEqual(resp.status_code, 400)

    def test_card_no_auth_required(self):
        resp = self.client.get(f"/r/{self.share_hash}/card.svg")
        self.assertNotIn(resp.status_code, (401, 403))

    def test_card_x_share_header_set(self):
        resp = self.client.get(f"/r/{self.share_hash}/card.svg")
        self.assertEqual(resp.headers.get("X-Squash-Share"), self.share_hash)


@unittest.skipUnless(_HAS_API, "FastAPI / httpx not installed")
class TestTrendingEndpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _reset_rate_limit()
        cls.client = TestClient(app)

    def setUp(self):
        _reset_rate_limit()
        get_global_stats().reset()

    def test_empty_payload_shape(self):
        resp = self.client.get("/trending")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("total", body)
        self.assertIn("top", body)
        self.assertIn("policy_types", body)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["top"], [])
        for pt in POLICY_TYPES:
            self.assertIn(pt, body["policy_types"])

    def test_no_auth_required(self):
        resp = self.client.get("/trending")
        self.assertNotIn(resp.status_code, (401, 403))

    def test_aggregates_after_quick_check_calls(self):
        # Submit each sample file once and confirm trending reflects them.
        for name in (
            "01_privacy_policy.txt",
            "02_terms_of_service.txt",
            "03_gdpr_dpa.txt",
            "04_ccpa_notice.txt",
            "05_cookie_policy.txt",
        ):
            text = (SAMPLE_DIR / name).read_text(encoding="utf-8")
            self.client.post("/quick-check", json={"text": text, "framework": "auto"})
        body = self.client.get("/trending").json()
        self.assertEqual(body["total"], 5)
        self.assertGreaterEqual(len(body["top"]), 5)
        for row in body["top"]:
            self.assertIn("policy_type", row)
            self.assertIn("count", row)
            self.assertIn("pass_rate", row)

    def test_top_query_param_clamped_high(self):
        resp = self.client.get("/trending?top=999")
        self.assertEqual(resp.status_code, 200)
        # No assertion on count — empty store is fine; this only proves no crash.

    def test_top_query_param_clamped_low(self):
        resp = self.client.get("/trending?top=0")
        self.assertEqual(resp.status_code, 200)


# ── W251: demo/index.html UI rebuild ─────────────────────────────────────────


class TestDemoUiRebuild(unittest.TestCase):
    """The Sprint 30 redesign must preserve every Sprint 29 hook AND ship the
    new visual primitives the brief calls for."""

    @classmethod
    def setUpClass(cls):
        cls.html = DEMO_INDEX.read_text(encoding="utf-8")

    # --- Sprint 30 visual primitives ---

    def test_scan_beam_present(self):
        self.assertIn("scan-beam", self.html)
        self.assertIn("@keyframes scan", self.html)

    def test_breathe_keyframes_on_submit_orb(self):
        self.assertIn("@keyframes breathe", self.html)
        self.assertIn("animation: breathe", self.html)

    def test_dark_background_token(self):
        self.assertIn("--bg: #06060f", self.html)

    def test_konjo_purple_token(self):
        # the spec calls out #7c3aed exactly
        self.assertIn("#7c3aed", self.html)

    def test_dot_grid_pattern_present(self):
        # CSS radial-gradient dots OR an SVG pattern — we use CSS radial-gradient
        self.assertIn("radial-gradient", self.html)
        self.assertIn("background-size", self.html)

    def test_sub_score_chips_for_each_framework(self):
        for fw in ("gdpr", "ccpa", "soc2"):
            self.assertIn(f'data-fw="{fw}"', self.html)

    def test_orbit_dots_present(self):
        self.assertIn('class="orbit"', self.html)

    def test_verdict_glyphs_present(self):
        # ✦ pass · △ warn · ✗ fail
        self.assertIn("✦", self.html)
        self.assertIn("△", self.html)
        self.assertIn("✗", self.html)

    def test_trending_sidebar_present(self):
        self.assertIn('id="trending"', self.html)
        self.assertIn("/trending", self.html)

    def test_card_preview_image_hook(self):
        self.assertIn('id="qcCardImg"', self.html)
        self.assertIn("/card.svg", self.html)

    def test_copy_orb_button_present(self):
        self.assertIn('id="btnQcCopy"', self.html)
        self.assertIn("clipboard.writeText", self.html)

    def test_soc2_in_framework_selector(self):
        self.assertIn('value="soc2"', self.html)

    def test_reduced_motion_respected(self):
        self.assertIn("prefers-reduced-motion", self.html)

    # --- Sprint 29 contract preserved ---
    # These mirror the assertions in test_squash_sprint29.py so any future
    # tweak that quietly drops a hook fails here too.

    def test_sprint29_paste_headline_preserved(self):
        self.assertIn("Paste any policy. Get a compliance verdict in seconds.", self.html)

    def test_sprint29_hero_claims_preserved(self):
        for label in (">GDPR<", ">CCPA<", ">SOC 2<"):
            self.assertIn(label, self.html)

    def test_sprint29_quick_section_preserved(self):
        self.assertIn('id="quick"', self.html)
        self.assertIn("Quick compliance check", self.html)

    def test_sprint29_textarea_and_run_button_preserved(self):
        self.assertIn('id="qcText"', self.html)
        self.assertIn('id="btnQuickCheck"', self.html)
        self.assertIn("Run Compliance Check", self.html)

    def test_sprint29_framework_selector_preserved(self):
        self.assertIn('id="qcFramework"', self.html)
        for fw in ("gdpr", "ccpa", "eu-ai-act", "general", "auto"):
            self.assertIn(f'value="{fw}"', self.html)

    def test_sprint29_sample_filenames_preserved(self):
        for name in (
            "01_privacy_policy.txt",
            "02_terms_of_service.txt",
            "03_gdpr_dpa.txt",
            "04_ccpa_notice.txt",
            "05_cookie_policy.txt",
        ):
            self.assertIn(name, self.html)

    def test_sprint29_timer_with_raf_preserved(self):
        self.assertIn('id="qcTimer"', self.html)
        self.assertIn("requestAnimationFrame", self.html)

    def test_sprint29_quick_check_post_target_preserved(self):
        self.assertIn("/quick-check", self.html)

    def test_sprint29_share_block_preserved(self):
        self.assertIn('id="qcShareBlock"', self.html)
        self.assertIn("Copy link", self.html)

    def test_sprint29_navigation_anchor_preserved(self):
        self.assertIn('href="#quick"', self.html)


# ── Public-export contract ───────────────────────────────────────────────────


class TestPublicExports(unittest.TestCase):

    def test_quick_check_exports_present(self):
        from squash import quick_check
        for name in (
            "POLICY_TYPES",
            "StatsTracker",
            "detect_policy_type",
            "get_global_stats",
            "score_all_frameworks",
        ):
            self.assertTrue(hasattr(quick_check, name), name)


if __name__ == "__main__":
    unittest.main()
