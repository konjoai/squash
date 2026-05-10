"""tests/test_squash_sprint28.py — Sprint 28 (Demo polish + viral features).

Coverage:

W246 — squash.quick_check.run_quick_check
       * verdict thresholds (pass / warn / fail)
       * per-framework clause libraries (gdpr, ccpa, eu-ai-act, general)
       * 'auto' framework picker
       * input validation (empty, oversized, wrong type, unknown framework)
       * determinism (same input → identical result dict)

W247 — squash.quick_check.ResultStore
       * put / get round-trip
       * idempotent re-put
       * FIFO eviction at capacity
       * JSON-file persistence + reload
       * malformed-hash rejection

W248 — squash.api endpoints
       * POST /quick-check (JSON + text/plain)
       * GET /r/{hash} round-trip
       * 404 on unknown hash, 400 on malformed hash, 422 on bad input
       * /quick-check is auth-free
       * Sample-policy fixtures parse and produce sensible verdicts.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from squash.quick_check import (
    AVAILABLE_FRAMEWORKS,
    QuickCheckResult,
    ResultStore,
    is_valid_share_hash,
    make_share_hash,
    run_quick_check,
)


_SAMPLE_DIR = Path(__file__).resolve().parent.parent / "demo" / "sample_policies"


# Fully-loaded GDPR snippet — should pass cleanly.
_GDPR_FULL = """
We are the data controller. Lawful basis: Article 6 GDPR.
You have the right of access, right to erasure (right to be forgotten),
data portability, and may contact our data protection officer (DPO).
Retention period: 90 days. Standard contractual clauses cover any
international transfer outside the EEA. Data breach notification within
72 hours to the supervisory authority.
"""

# Bare-bones text — should fail.
_GDPR_EMPTY_LIKE = "We collect data and use it for things. Contact us if you have questions."


# ── W246: run_quick_check core behaviour ─────────────────────────────────────


class TestRunQuickCheckCore(unittest.TestCase):

    def test_returns_quick_check_result(self):
        result = run_quick_check(_GDPR_FULL, framework="gdpr")
        self.assertIsInstance(result, QuickCheckResult)

    def test_full_gdpr_text_passes(self):
        result = run_quick_check(_GDPR_FULL, framework="gdpr")
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.verdict, "pass")

    def test_sparse_text_fails(self):
        result = run_quick_check(_GDPR_EMPTY_LIKE, framework="gdpr")
        self.assertLess(result.score, 50)
        self.assertEqual(result.verdict, "fail")
        self.assertGreater(len(result.missing), 0)

    def test_score_floor_is_zero(self):
        result = run_quick_check("nothing relevant here", framework="gdpr")
        self.assertGreaterEqual(result.score, 0)

    def test_score_ceiling_is_one_hundred(self):
        result = run_quick_check(_GDPR_FULL, framework="gdpr")
        self.assertLessEqual(result.score, 100)

    def test_default_framework_is_general(self):
        result = run_quick_check("we collect personal data and explain how we use your information")
        self.assertEqual(result.framework, "general")

    def test_to_dict_round_trips(self):
        result = run_quick_check(_GDPR_FULL, framework="gdpr")
        d = result.to_dict()
        for key in ("framework", "score", "verdict", "matched", "missing", "summary", "text_length"):
            self.assertIn(key, d)
        # JSON-serialisable
        json.dumps(d)

    def test_summary_mentions_framework_and_score(self):
        result = run_quick_check(_GDPR_FULL, framework="gdpr")
        self.assertIn("gdpr", result.summary)
        self.assertIn(str(result.score), result.summary)

    def test_text_length_recorded_post_strip(self):
        text = "  hello world right to access lawful basis retention  "
        result = run_quick_check(text, framework="gdpr")
        self.assertEqual(result.text_length, len(text.strip()))


# ── W246: framework coverage ─────────────────────────────────────────────────


class TestFrameworkCoverage(unittest.TestCase):

    def test_all_frameworks_run_on_full_gdpr_text(self):
        for fw in AVAILABLE_FRAMEWORKS:
            result = run_quick_check(_GDPR_FULL, framework=fw)
            self.assertEqual(result.framework, fw)

    def test_ccpa_full_passes(self):
        text = (_SAMPLE_DIR / "04_ccpa_notice.txt").read_text(encoding="utf-8")
        result = run_quick_check(text, framework="ccpa")
        self.assertEqual(result.verdict, "pass")
        self.assertGreaterEqual(result.score, 80)

    def test_eu_ai_act_high_risk_text_passes(self):
        text = """
        This system is high-risk under Article 6 of the EU AI Act.
        Human oversight is built in via mandatory human review of every
        decision. Users are informed (transparency) that they are
        interacting with an AI system. Automatic event logs are retained
        and the system meets accuracy and cybersecurity obligations under
        Article 15.
        """
        result = run_quick_check(text, framework="eu-ai-act")
        self.assertEqual(result.verdict, "pass")

    def test_auto_picks_best_framework(self):
        text = (_SAMPLE_DIR / "04_ccpa_notice.txt").read_text(encoding="utf-8")
        auto_result = run_quick_check(text, framework="auto")
        ccpa_result = run_quick_check(text, framework="ccpa")
        self.assertEqual(auto_result.framework, "ccpa")
        self.assertEqual(auto_result.score, ccpa_result.score)


# ── W246: input validation ───────────────────────────────────────────────────


class TestQuickCheckValidation(unittest.TestCase):

    def test_empty_text_raises(self):
        with self.assertRaises(ValueError):
            run_quick_check("", framework="gdpr")

    def test_whitespace_only_raises(self):
        with self.assertRaises(ValueError):
            run_quick_check("   \n\t  ", framework="gdpr")

    def test_non_string_raises(self):
        with self.assertRaises(ValueError):
            run_quick_check(b"bytes not allowed", framework="gdpr")  # type: ignore[arg-type]

    def test_unknown_framework_raises(self):
        with self.assertRaises(ValueError):
            run_quick_check(_GDPR_FULL, framework="hipaa")

    def test_oversized_text_raises(self):
        big = "a " * 200_000  # >200 KB
        with self.assertRaises(ValueError):
            run_quick_check(big, framework="gdpr")


# ── W246: determinism ────────────────────────────────────────────────────────


class TestQuickCheckDeterminism(unittest.TestCase):

    def test_identical_input_yields_identical_output(self):
        a = run_quick_check(_GDPR_FULL, framework="gdpr").to_dict()
        b = run_quick_check(_GDPR_FULL, framework="gdpr").to_dict()
        self.assertEqual(a, b)

    def test_share_hash_stable_for_identical_payload(self):
        a = run_quick_check(_GDPR_FULL, framework="gdpr").to_dict()
        b = run_quick_check(_GDPR_FULL, framework="gdpr").to_dict()
        self.assertEqual(make_share_hash(a), make_share_hash(b))

    def test_share_hash_differs_for_distinct_payloads(self):
        a = run_quick_check(_GDPR_FULL, framework="gdpr").to_dict()
        b = run_quick_check(_GDPR_EMPTY_LIKE, framework="gdpr").to_dict()
        self.assertNotEqual(make_share_hash(a), make_share_hash(b))


# ── W247: ResultStore ────────────────────────────────────────────────────────


class TestResultStore(unittest.TestCase):

    def test_put_then_get_round_trip(self):
        store = ResultStore()
        payload = {"framework": "gdpr", "score": 90, "verdict": "pass"}
        share_hash = store.put(payload)
        self.assertTrue(is_valid_share_hash(share_hash))
        self.assertEqual(store.get(share_hash), payload)

    def test_put_is_idempotent_on_identical_payload(self):
        store = ResultStore()
        payload = {"a": 1, "b": [2, 3]}
        h1 = store.put(payload)
        h2 = store.put(payload)
        self.assertEqual(h1, h2)
        self.assertEqual(len(store), 1)

    def test_get_returns_none_for_missing_hash(self):
        store = ResultStore()
        self.assertIsNone(store.get("0123456789abcdef"))

    def test_get_returns_none_for_malformed_hash(self):
        store = ResultStore()
        for bad in ("", "ZZZZ", "not-hex-at-all", "0123456789abcde"):
            self.assertIsNone(store.get(bad))

    def test_fifo_eviction_at_capacity(self):
        store = ResultStore(capacity=3)
        h1 = store.put({"i": 1})
        h2 = store.put({"i": 2})
        h3 = store.put({"i": 3})
        h4 = store.put({"i": 4})  # should evict h1
        self.assertNotIn(h1, store)
        for h in (h2, h3, h4):
            self.assertIn(h, store)

    def test_invalid_capacity_raises(self):
        with self.assertRaises(ValueError):
            ResultStore(capacity=0)

    def test_non_dict_payload_rejected(self):
        store = ResultStore()
        for bad in (None, "string", 42, [1, 2]):
            with self.assertRaises(ValueError):
                store.put(bad)  # type: ignore[arg-type]

    def test_persistence_to_disk_and_reload(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            store_a = ResultStore(path=path)
            h = store_a.put({"framework": "gdpr", "score": 100})
            self.assertTrue(path.exists())

            store_b = ResultStore(path=path)
            self.assertEqual(store_b.get(h), {"framework": "gdpr", "score": 100})

    def test_persisted_file_is_valid_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            store = ResultStore(path=path)
            store.put({"x": 1})
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("hashes", data)


# ── W247: hash helper ────────────────────────────────────────────────────────


class TestShareHashHelpers(unittest.TestCase):

    def test_is_valid_share_hash_accepts_16_hex(self):
        self.assertTrue(is_valid_share_hash("0123456789abcdef"))

    def test_rejects_uppercase_hex(self):
        # contract is lowercase only — be strict
        self.assertFalse(is_valid_share_hash("0123456789ABCDEF"))

    def test_rejects_wrong_length(self):
        self.assertFalse(is_valid_share_hash("abcd"))
        self.assertFalse(is_valid_share_hash("0" * 17))

    def test_rejects_non_hex(self):
        self.assertFalse(is_valid_share_hash("zzzzzzzzzzzzzzzz"))

    def test_make_share_hash_is_16_chars(self):
        h = make_share_hash({"any": "payload"})
        self.assertEqual(len(h), 16)
        self.assertTrue(is_valid_share_hash(h))


# ── W248: API endpoints ──────────────────────────────────────────────────────


try:
    import httpx  # noqa: F401
    from fastapi.testclient import TestClient
    from squash.api import app
    _HAS_API = True
except ImportError:
    _HAS_API = False


@unittest.skipUnless(_HAS_API, "FastAPI / httpx not installed")
class TestQuickCheckApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_quick_check_json_post_returns_200(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "gdpr"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_quick_check_response_shape(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "gdpr"},
        )
        body = resp.json()
        self.assertIn("result", body)
        self.assertIn("share_hash", body)
        self.assertIn("share_url", body)
        self.assertEqual(body["result"]["framework"], "gdpr")
        self.assertEqual(body["result"]["verdict"], "pass")

    def test_quick_check_share_disabled(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "gdpr", "share": False},
        )
        body = resp.json()
        self.assertNotIn("share_hash", body)
        self.assertNotIn("share_url", body)

    def test_quick_check_text_plain_post(self):
        resp = self.client.post(
            "/quick-check?framework=gdpr",
            content=_GDPR_FULL,
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["result"]["framework"], "gdpr")

    def test_quick_check_no_auth_required(self):
        # Ensure the endpoint really is public — no Authorization header.
        resp = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "gdpr"},
        )
        self.assertNotEqual(resp.status_code, 401)
        self.assertNotEqual(resp.status_code, 403)

    def test_quick_check_empty_text_422(self):
        resp = self.client.post("/quick-check", json={"text": "", "framework": "gdpr"})
        self.assertEqual(resp.status_code, 422)

    def test_quick_check_unknown_framework_422(self):
        resp = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "hipaa"},
        )
        self.assertEqual(resp.status_code, 422)

    def test_quick_check_invalid_json_400(self):
        resp = self.client.post(
            "/quick-check",
            content=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_quick_check_frameworks_endpoint(self):
        resp = self.client.get("/quick-check/frameworks")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("frameworks", body)
        self.assertIn("auto", body["frameworks"])
        for fw in AVAILABLE_FRAMEWORKS:
            self.assertIn(fw, body["frameworks"])

    def test_share_get_round_trip(self):
        post = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "gdpr"},
        ).json()
        share_hash = post["share_hash"]

        get = self.client.get(f"/r/{share_hash}")
        self.assertEqual(get.status_code, 200)
        body = get.json()
        self.assertEqual(body["share_hash"], share_hash)
        self.assertEqual(body["result"], post["result"])

    def test_share_get_no_auth_required(self):
        post = self.client.post(
            "/quick-check",
            json={"text": _GDPR_FULL, "framework": "gdpr"},
        ).json()
        share_hash = post["share_hash"]
        get = self.client.get(f"/r/{share_hash}")
        self.assertNotIn(get.status_code, (401, 403))

    def test_share_unknown_hash_404(self):
        resp = self.client.get("/r/0123456789abcdef")
        self.assertEqual(resp.status_code, 404)

    def test_share_malformed_hash_400(self):
        resp = self.client.get("/r/not-a-real-hash")
        self.assertEqual(resp.status_code, 400)


# ── Sample-policy demo corpus ────────────────────────────────────────────────


class TestSamplePolicyCorpus(unittest.TestCase):

    def test_directory_exists(self):
        self.assertTrue(_SAMPLE_DIR.is_dir(), f"expected {_SAMPLE_DIR}")

    def test_five_text_files_present(self):
        files = sorted(p.name for p in _SAMPLE_DIR.glob("*.txt"))
        self.assertEqual(len(files), 5, files)

    def test_each_sample_file_non_empty(self):
        for f in _SAMPLE_DIR.glob("*.txt"):
            self.assertGreater(f.stat().st_size, 200, f.name)

    def test_privacy_policy_passes_gdpr(self):
        text = (_SAMPLE_DIR / "01_privacy_policy.txt").read_text(encoding="utf-8")
        result = run_quick_check(text, framework="gdpr")
        self.assertEqual(result.verdict, "pass", result.summary)

    def test_dpa_passes_gdpr(self):
        text = (_SAMPLE_DIR / "03_gdpr_dpa.txt").read_text(encoding="utf-8")
        result = run_quick_check(text, framework="gdpr")
        self.assertEqual(result.verdict, "pass", result.summary)

    def test_ccpa_notice_passes_ccpa(self):
        text = (_SAMPLE_DIR / "04_ccpa_notice.txt").read_text(encoding="utf-8")
        result = run_quick_check(text, framework="ccpa")
        self.assertEqual(result.verdict, "pass", result.summary)

    def test_terms_of_service_general_runs_without_error(self):
        text = (_SAMPLE_DIR / "02_terms_of_service.txt").read_text(encoding="utf-8")
        result = run_quick_check(text, framework="general")
        self.assertIn(result.verdict, {"pass", "warn", "fail"})

    def test_cookie_policy_general_runs_without_error(self):
        text = (_SAMPLE_DIR / "05_cookie_policy.txt").read_text(encoding="utf-8")
        result = run_quick_check(text, framework="general")
        self.assertIn(result.verdict, {"pass", "warn", "fail"})


# ── README badges (Goal 4) ───────────────────────────────────────────────────


class TestReadmeBadges(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")

    def test_try_it_live_badge_present(self):
        self.assertIn("Try it live", self.readme)
        self.assertIn("getsquash.dev/demo", self.readme)

    def test_compliance_score_badge_present(self):
        # The compliance score badge is the existing /badge/{framework}/{status}
        # endpoint rendered for the project itself.
        self.assertIn("/badge/eu-ai-act/", self.readme)


# ── CI workflow contract (Goal 5) ────────────────────────────────────────────


class TestCiWorkflowRunsTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ci_path = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
        cls.ci = ci_path.read_text(encoding="utf-8") if ci_path.exists() else ""

    def test_ci_workflow_exists(self):
        self.assertNotEqual(self.ci, "", "expected .github/workflows/ci.yml")

    def test_ci_triggers_on_push_to_main(self):
        self.assertIn("push:", self.ci)
        self.assertIn("branches: [main]", self.ci)

    def test_ci_runs_pytest(self):
        self.assertIn("pytest", self.ci)
        self.assertIn("tests/", self.ci)


# ── Public-export contract ───────────────────────────────────────────────────


class TestPublicExports(unittest.TestCase):

    def test_run_quick_check_exported_from_top_level(self):
        import squash
        self.assertTrue(hasattr(squash, "run_quick_check"))
        self.assertTrue(hasattr(squash, "QuickCheckResult"))
        self.assertTrue(hasattr(squash, "QuickCheckStore"))
        self.assertTrue(hasattr(squash, "QUICK_CHECK_FRAMEWORKS"))

    def test_version_bumped(self):
        import squash
        # Sprint 28 introduced 3.5.0; later sprints continue to bump.
        # The contract here is: version is at least 3.5.0 — Sprint 28 features
        # remain available and the public exports are still wired up.
        self.assertGreaterEqual(squash.__version__, "3.5.0")


if __name__ == "__main__":
    unittest.main()
