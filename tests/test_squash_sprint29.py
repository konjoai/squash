"""tests/test_squash_sprint29.py — Sprint 29: Demo polish.

Covers:
  * The interactive Quick Compliance Check section in demo/index.html
    (markup + JS hooks + hero claim badges).
  * demo/result.html shareable-permalink page (script + DOM hooks).
  * GET /demo serves the static landing page (no auth).
  * GET /demo/sample_policies/<name> serves allowlisted policies, rejects
    traversal and unknown names.
  * GET /share/<hash> serves the result HTML when the hash exists,
    404s when it doesn't.
  * Performance gate — POST /quick-check responds in <1500 ms across the
    full sample corpus on both cold and warm caches.
  * Version bumped to 3.6.0; CHANGELOG includes a Sprint 29 section.
"""

from __future__ import annotations

import re
import time
import unittest
from pathlib import Path

import squash

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"
SAMPLES_DIR = DEMO_DIR / "sample_policies"

# Wall budget per /quick-check call. The Sprint 29 goal is "under 1500 ms on
# the demo corpus". We test both cold (first call after cache wipe) and warm.
_PERF_BUDGET_MS = 1500


# ── 1. Static demo asset shape (no FastAPI required) ─────────────────────────


class TestDemoIndexHtml(unittest.TestCase):
    """The /demo landing page must be discoverable, ship the Quick Check UI,
    and keep the three GDPR/CCPA/SOC2 hero claims visible."""

    @classmethod
    def setUpClass(cls):
        cls.path = DEMO_DIR / "index.html"
        cls.html = cls.path.read_text(encoding="utf-8")

    def test_file_exists(self):
        self.assertTrue(self.path.is_file(), f"missing {self.path}")

    def test_hero_paste_headline_present(self):
        self.assertIn("Paste any policy. Get a compliance verdict in seconds.", self.html)

    def test_hero_three_claim_badges_present(self):
        self.assertIn("hero-claims", self.html)
        self.assertIn(">GDPR<", self.html)
        self.assertIn(">CCPA<", self.html)
        self.assertIn(">SOC 2<", self.html)

    def test_quick_check_section_present(self):
        self.assertIn('id="quick"', self.html)
        self.assertIn("Quick compliance check", self.html)

    def test_textarea_and_run_button_present(self):
        self.assertIn('id="qcText"', self.html)
        self.assertIn('id="btnQuickCheck"', self.html)
        self.assertIn("Run Compliance Check", self.html)

    def test_sample_selector_lists_all_five_files(self):
        for name in (
            "01_privacy_policy.txt",
            "02_terms_of_service.txt",
            "03_gdpr_dpa.txt",
            "04_ccpa_notice.txt",
            "05_cookie_policy.txt",
        ):
            self.assertIn(name, self.html, f"sample {name} missing from selector")

    def test_framework_selector_present(self):
        self.assertIn('id="qcFramework"', self.html)
        for fw in ("gdpr", "ccpa", "eu-ai-act", "general", "auto"):
            self.assertIn(f'value="{fw}"', self.html)

    def test_live_timer_element_present(self):
        self.assertIn('id="qcTimer"', self.html)
        # The JS uses requestAnimationFrame to update the timer in real time.
        self.assertIn("requestAnimationFrame", self.html)

    def test_quick_check_post_target(self):
        # The JS must POST to the public /quick-check endpoint.
        self.assertIn("/quick-check", self.html)

    def test_share_block_present(self):
        self.assertIn('id="qcShareBlock"', self.html)
        self.assertIn("Copy link", self.html)

    def test_navigation_link_to_quick_check(self):
        self.assertIn('href="#quick"', self.html)


class TestDemoResultHtml(unittest.TestCase):
    """The shareable-permalink result page must accept any of the three URL
    forms and render the verdict from the JSON API."""

    @classmethod
    def setUpClass(cls):
        cls.path = DEMO_DIR / "result.html"
        cls.html = cls.path.read_text(encoding="utf-8")

    def test_file_exists(self):
        self.assertTrue(self.path.is_file(), f"missing {self.path}")

    def test_fetches_from_share_api(self):
        # Must call GET /r/<hash> to load the JSON payload.
        self.assertIn("/r/", self.html)
        self.assertIn("Accept", self.html)

    def test_handles_share_and_r_and_query_url_forms(self):
        # The match regex (in JS source, with escaped slashes) must accept
        # both /share/<hex> and /r/<hex>, plus ?h= as a fallback.
        self.assertIn("(?:share|r)", self.html)
        self.assertIn('"h"', self.html)

    def test_renders_verdict_score_framework_summary(self):
        for hook in ("verdictBadge", "score", "framework", "summary"):
            self.assertIn(f'id="{hook}"', self.html)

    def test_clause_grid_present(self):
        self.assertIn('id="matched"', self.html)
        self.assertIn('id="missing"', self.html)

    def test_copy_link_button_present(self):
        self.assertIn('id="copyBtn"', self.html)
        self.assertIn("clipboard.writeText", self.html)


# ── 2. Sample policy corpus on disk ──────────────────────────────────────────


class TestSamplePoliciesOnDisk(unittest.TestCase):

    def test_directory_exists(self):
        self.assertTrue(SAMPLES_DIR.is_dir())

    def test_five_policies_present(self):
        files = sorted(p.name for p in SAMPLES_DIR.glob("*.txt"))
        self.assertEqual(len(files), 5, files)


# ── 3. FastAPI route wiring ──────────────────────────────────────────────────


try:
    import httpx  # noqa: F401
    from fastapi.testclient import TestClient
    from squash.api import app
    _HAS_API = True
except ImportError:
    _HAS_API = False


@unittest.skipUnless(_HAS_API, "FastAPI / httpx not installed")
class TestDemoRoutes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_demo_index_serves_html(self):
        resp = self.client.get("/demo")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn("text/html", resp.headers.get("content-type", ""))
        self.assertIn("Quick compliance check", resp.text)

    def test_demo_index_no_auth_required(self):
        # No Authorization header — must not 401/403.
        resp = self.client.get("/demo")
        self.assertNotIn(resp.status_code, (401, 403))

    def test_demo_index_no_cache_header(self):
        resp = self.client.get("/demo")
        self.assertIn("no-cache", resp.headers.get("cache-control", "").lower())

    def test_demo_index_trailing_slash(self):
        resp = self.client.get("/demo/")
        self.assertEqual(resp.status_code, 200)

    def test_sample_policy_endpoint_returns_text(self):
        resp = self.client.get("/demo/sample_policies/01_privacy_policy.txt")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.headers.get("content-type", "").startswith("text/plain"))
        self.assertIn("PRIVACY POLICY", resp.text.upper())

    def test_sample_policy_all_five_served(self):
        for name in (
            "01_privacy_policy.txt",
            "02_terms_of_service.txt",
            "03_gdpr_dpa.txt",
            "04_ccpa_notice.txt",
            "05_cookie_policy.txt",
        ):
            resp = self.client.get(f"/demo/sample_policies/{name}")
            self.assertEqual(resp.status_code, 200, f"{name}: {resp.status_code} {resp.text}")
            self.assertGreater(len(resp.text), 0)

    def test_sample_policy_unknown_returns_404(self):
        resp = self.client.get("/demo/sample_policies/does_not_exist.txt")
        self.assertEqual(resp.status_code, 404)

    def test_sample_policy_traversal_blocked(self):
        # FastAPI's path converter normalises slashes — the literal segment
        # "../README.md" never matches the allowlist, so we get a clean 404.
        for hostile in ("..%2FREADME.md", "%2e%2e%2fREADME.md", "evil.txt"):
            resp = self.client.get(f"/demo/sample_policies/{hostile}")
            self.assertEqual(resp.status_code, 404, f"{hostile}: status {resp.status_code}")

    def test_share_html_round_trip(self):
        post = self.client.post(
            "/quick-check",
            json={"text": "We collect personal information for the purpose of providing the service. "
                          "You may contact us at privacy@example.com.", "framework": "general"},
        )
        self.assertEqual(post.status_code, 200, post.text)
        share_hash = post.json()["share_hash"]

        share_html = self.client.get(f"/share/{share_hash}")
        self.assertEqual(share_html.status_code, 200, share_html.text)
        self.assertIn("text/html", share_html.headers.get("content-type", ""))
        # The page is a thin shell — it loads result.html and fetches the JSON.
        self.assertIn("Compliance result", share_html.text)
        # And it must not include any auth artefacts (it's a public share view).
        self.assertNotIn("Authorization", share_html.text)

    def test_share_html_no_auth_required(self):
        post = self.client.post(
            "/quick-check",
            json={"text": "Personal data we collect includes your name. Contact us.", "framework": "general"},
        )
        share_hash = post.json()["share_hash"]
        resp = self.client.get(f"/share/{share_hash}")
        self.assertNotIn(resp.status_code, (401, 403))

    def test_share_html_unknown_hash_404(self):
        resp = self.client.get("/share/0123456789abcdef")
        self.assertEqual(resp.status_code, 404)

    def test_share_html_malformed_hash_400(self):
        resp = self.client.get("/share/not-a-real-hash")
        self.assertEqual(resp.status_code, 400)


# ── 4. Performance gate — /quick-check on the demo corpus ────────────────────


@unittest.skipUnless(_HAS_API, "FastAPI / httpx not installed")
class TestQuickCheckPerformance(unittest.TestCase):
    """Sprint 29 success criterion: every sample in the demo corpus must
    score in under 1500 ms via the public /quick-check endpoint, on both
    a freshly-cleared regex cache and the warm path."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.samples = [
            (p.name, p.read_text(encoding="utf-8"))
            for p in sorted(SAMPLES_DIR.glob("*.txt"))
        ]
        assert cls.samples, "demo/sample_policies/ is empty"

    def _post(self, text: str, framework: str) -> tuple[int, float]:
        t0 = time.perf_counter()
        resp = self.client.post(
            "/quick-check",
            json={"text": text, "framework": framework, "share": False},
        )
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status_code, dt_ms

    def test_warm_path_under_budget_for_each_sample(self):
        # Warm pass — exercises the compiled regex cache.
        for name, text in self.samples:
            status, dt_ms = self._post(text, framework="auto")
            self.assertEqual(status, 200, f"{name}: HTTP {status}")
            self.assertLess(
                dt_ms, _PERF_BUDGET_MS,
                f"{name}: {dt_ms:.1f}ms ≥ {_PERF_BUDGET_MS}ms budget (warm)",
            )

    def test_cold_path_under_budget(self):
        # Drop the cache so the very first call after import has to compile
        # every regex. This is the visitor's true first-impression latency.
        from squash import quick_check as qc
        with qc._CACHE_LOCK:  # noqa: SLF001 - test-only inspection of cache
            qc._PATTERN_CACHE.clear()
        name, text = self.samples[0]
        status, dt_ms = self._post(text, framework="gdpr")
        self.assertEqual(status, 200)
        self.assertLess(
            dt_ms, _PERF_BUDGET_MS,
            f"{name}: {dt_ms:.1f}ms ≥ {_PERF_BUDGET_MS}ms budget (cold)",
        )

    def test_corpus_total_under_one_second(self):
        # Sanity ceiling — running every sample back-to-back must still
        # comfortably fit inside one second on the warm path.
        total_ms = 0.0
        for _name, text in self.samples:
            _status, dt_ms = self._post(text, framework="auto")
            total_ms += dt_ms
        self.assertLess(total_ms, 1000.0, f"corpus total {total_ms:.1f}ms ≥ 1000ms")


# ── 5. Version + CHANGELOG ───────────────────────────────────────────────────


class TestVersionBumpedToSprint29(unittest.TestCase):

    def test_dunder_version_is_3_6_0(self):
        # Sprint 29 shipped 3.6.0; Sprint 30+ may bump further. Assert at-least.
        version_tuple = tuple(int(x) for x in squash.__version__.split("."))
        self.assertGreaterEqual(version_tuple, (3, 6, 0))

    def test_pyproject_version_is_3_6_0(self):
        # Sprint 29 shipped 3.6.0; Sprint 30+ may bump further. Assert at-least.
        py = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'^version\s*=\s*"([^"]+)"', py, re.MULTILINE)
        self.assertIsNotNone(m, "version field not found")
        version_tuple = tuple(int(x) for x in m.group(1).split("."))
        self.assertGreaterEqual(version_tuple, (3, 6, 0))

    def test_changelog_has_sprint_29_section(self):
        cl = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("[3.6.0]", cl)
        self.assertIn("Sprint 29", cl)


if __name__ == "__main__":
    unittest.main()
