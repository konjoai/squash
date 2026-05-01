"""tests/test_squash_c3_approval.py — Track C / C3 — Approval Workflow.

Sprint 23 (W232–W234) exit criteria:
  * 1 new module (approval_workflow.py)
  * Sigstore-equivalent signature verifies on approval records (HMAC-SHA256)
  * Multi-reviewer threshold logic covered for 1-of-1, 2-of-3, role-gated cases
  * CLI subcommands: request-approval, approve, approval-status, approval-list,
    approval-export
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _wf(tmp: Path, notify=False):
    from squash.approval_workflow import ApprovalWorkflow
    return ApprovalWorkflow(db_path=tmp / "approvals.db", notify_on_change=notify)


def _identity(email="alice@acme.com", role="COMPLIANCE", name="Alice"):
    from squash.approval_workflow import ApproverIdentity, ReviewerRole
    return ApproverIdentity(email=email, name=name, role=ReviewerRole(role))


# ── W232: ApprovalRecord + signing ───────────────────────────────────────────


class TestApprovalRecord(unittest.TestCase):
    def test_sign_and_verify_round_trip(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalRecord, ApproverIdentity, ReviewerRole
        rec = ApprovalRecord(
            record_id="r1", request_id="req1",
            reviewer=ApproverIdentity("alice@acme.com", role=ReviewerRole.COMPLIANCE),
            decision=ApprovalDecision.APPROVED,
            rationale="Looks good",
            attestation_id="att://sha256:abc", attestation_hash="abc",
            model_id="bert", created_at="2026-05-01T00:00:00+00:00",
        ).sign()
        self.assertTrue(rec.verify())
        self.assertEqual(len(rec.signature), 64)

    def test_tampered_record_fails_verification(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalRecord, ApproverIdentity, ReviewerRole
        rec = ApprovalRecord(
            record_id="r1", request_id="req1",
            reviewer=ApproverIdentity("a@a.com", role=ReviewerRole.ANY),
            decision=ApprovalDecision.APPROVED,
            rationale="ok", attestation_id="att://x", attestation_hash="h",
            model_id="m", created_at="2026-01-01T00:00:00+00:00",
        ).sign()
        rec.rationale = "tampered"
        self.assertFalse(rec.verify())

    def test_unsigned_record_fails_verification(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalRecord, ApproverIdentity, ReviewerRole
        rec = ApprovalRecord(
            record_id="r1", request_id="req1",
            reviewer=ApproverIdentity("a@a.com", role=ReviewerRole.ANY),
            decision=ApprovalDecision.APPROVED,
            rationale="ok", attestation_id="att://x", attestation_hash="h",
            model_id="m", created_at="2026-01-01T00:00:00+00:00",
        )
        self.assertFalse(rec.verify())

    def test_to_dict_includes_all_fields(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalRecord, ApproverIdentity, ReviewerRole
        rec = ApprovalRecord(
            record_id="r1", request_id="req1",
            reviewer=ApproverIdentity("a@a.com", role=ReviewerRole.ENGINEERING),
            decision=ApprovalDecision.APPROVED_WITH_CONDITIONS,
            rationale="cond", attestation_id="att://x", attestation_hash="h",
            model_id="m", created_at="2026-01-01T00:00:00+00:00",
            conditions=["Retrain by Q3"],
        ).sign()
        d = rec.to_dict()
        for key in ("record_id", "request_id", "reviewer", "decision",
                    "rationale", "attestation_id", "attestation_hash",
                    "model_id", "created_at", "conditions", "signature"):
            self.assertIn(key, d)

    def test_from_dict_round_trips(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalRecord, ApproverIdentity, ReviewerRole
        rec = ApprovalRecord(
            record_id="r1", request_id="req1",
            reviewer=ApproverIdentity("a@a.com", name="Alice", role=ReviewerRole.LEGAL),
            decision=ApprovalDecision.REJECTED,
            rationale="Risk too high", attestation_id="att://x", attestation_hash="h",
            model_id="m", created_at="2026-01-01T00:00:00+00:00",
        ).sign()
        rec2 = ApprovalRecord.from_dict(rec.to_dict())
        self.assertEqual(rec.record_id, rec2.record_id)
        self.assertEqual(rec.decision, rec2.decision)
        self.assertTrue(rec2.verify())


# ── W232: ApprovalRequest model ───────────────────────────────────────────────


class TestApprovalRequest(unittest.TestCase):
    def _make(self, reviewers=None, threshold=1, required_roles=None):
        from squash.approval_workflow import ApprovalRequest, ReviewerRole
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        return ApprovalRequest(
            request_id="req-test",
            attestation_id="att://sha256:abc",
            attestation_hash="abc",
            model_id="bert-v2",
            requestor_email="dev@acme.com",
            reviewers=list(reviewers or ["alice@acme.com"]),
            threshold=threshold,
            required_roles=list(required_roles or []),
            requested_at=now,
            expires_at=now,
        )

    def test_fresh_request_is_pending(self):
        from squash.approval_workflow import RequestStatus
        req = self._make()
        self.assertEqual(req.overall_status, RequestStatus.PENDING)

    def test_pending_reviewers_all_outstanding(self):
        req = self._make(reviewers=["a@x.com", "b@x.com"])
        self.assertEqual(set(req.pending_reviewers), {"a@x.com", "b@x.com"})

    def test_approved_count_zero_initially(self):
        self.assertEqual(self._make().approved_count, 0)

    def test_to_dict_contains_overall_status(self):
        d = self._make().to_dict()
        self.assertIn("overall_status", d)
        self.assertEqual(d["overall_status"], "PENDING")

    def test_from_dict_round_trips(self):
        from squash.approval_workflow import ApprovalRequest
        req = self._make(reviewers=["a@x.com"], threshold=1)
        req2 = ApprovalRequest.from_dict(req.to_dict())
        self.assertEqual(req.request_id, req2.request_id)
        self.assertEqual(req.threshold, req2.threshold)


# ── W233: threshold + role-gated multi-reviewer logic ────────────────────────


class TestThresholdApproval(unittest.TestCase):
    """1-of-1, 2-of-3, and role-gated scenarios."""

    def test_1_of_1_approve(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.APPROVED)
            wf.close()

    def test_1_of_1_reject_closes_immediately(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.REJECTED, "too risky")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.REJECTED)
            wf.close()

    def test_2_of_3_still_pending_after_one(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            reviewers = ["a@x.com", "b@x.com", "c@x.com"]
            req = wf.request("att://x", reviewers=reviewers, threshold=2)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.PENDING)
            wf.close()

    def test_2_of_3_approved_after_two(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            reviewers = ["a@x.com", "b@x.com", "c@x.com"]
            req = wf.request("att://x", reviewers=reviewers, threshold=2)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            wf.approve(req.request_id, _identity("b@x.com"), ApprovalDecision.APPROVED, "ok")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.APPROVED)
            wf.close()

    def test_any_rejection_fails_2_of_3(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            reviewers = ["a@x.com", "b@x.com", "c@x.com"]
            req = wf.request("att://x", reviewers=reviewers, threshold=2)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            wf.approve(req.request_id, _identity("b@x.com"), ApprovalDecision.REJECTED, "fail")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.REJECTED)
            wf.close()

    def test_approved_with_conditions_counts_as_approved(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
            wf.approve(req.request_id, _identity("a@x.com"),
                       ApprovalDecision.APPROVED_WITH_CONDITIONS, "cond ok",
                       conditions=["Retrain on Q3 data by 2026-08-01"])
            status = wf.status(req.request_id)
            self.assertEqual(status.overall_status, RequestStatus.APPROVED)
            self.assertEqual(status.all_conditions, ["Retrain on Q3 data by 2026-08-01"])
            wf.close()


class TestRoleGatedApproval(unittest.TestCase):
    def test_role_gated_pending_when_role_missing(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus, ReviewerRole
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            reviewers = ["a@x.com", "b@x.com"]
            req = wf.request("att://x", reviewers=reviewers, threshold=2,
                             required_roles=[ReviewerRole.COMPLIANCE, ReviewerRole.ENGINEERING])
            # Both approve but both as ENGINEERING — COMPLIANCE missing
            wf.approve(req.request_id, _identity("a@x.com", role="ENGINEERING"),
                       ApprovalDecision.APPROVED, "ok")
            wf.approve(req.request_id, _identity("b@x.com", role="ENGINEERING"),
                       ApprovalDecision.APPROVED, "ok")
            # Threshold met (2/2) but COMPLIANCE role not covered → still PENDING
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.PENDING)
            wf.close()

    def test_role_gated_approved_when_all_roles_covered(self):
        from squash.approval_workflow import ApprovalDecision, RequestStatus, ReviewerRole
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            reviewers = ["ciso@x.com", "vp@x.com"]
            req = wf.request("att://x", reviewers=reviewers, threshold=2,
                             required_roles=[ReviewerRole.COMPLIANCE, ReviewerRole.ENGINEERING])
            wf.approve(req.request_id, _identity("ciso@x.com", role="COMPLIANCE"),
                       ApprovalDecision.APPROVED, "bias audit clean")
            wf.approve(req.request_id, _identity("vp@x.com", role="ENGINEERING"),
                       ApprovalDecision.APPROVED, "drift ok")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.APPROVED)
            wf.close()

    def test_open_reviewer_list_accepts_any_email(self):
        """Empty reviewers list = no email restriction."""
        from squash.approval_workflow import ApprovalDecision, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=[], threshold=1)
            wf.approve(req.request_id, _identity("anyone@anywhere.com"),
                       ApprovalDecision.APPROVED, "ok")
            self.assertEqual(wf.status(req.request_id).overall_status, RequestStatus.APPROVED)
            wf.close()


# ── Guard rails ───────────────────────────────────────────────────────────────


class TestGuardRails(unittest.TestCase):
    def test_unknown_reviewer_rejected(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
            with self.assertRaises(ValueError, msg="not in authorised reviewer list"):
                wf.approve(req.request_id, _identity("intruder@evil.com"),
                           ApprovalDecision.APPROVED, "ok")
            wf.close()

    def test_duplicate_reviewer_rejected(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            with self.assertRaises(ValueError, msg="already submitted"):
                wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "again")
            wf.close()

    def test_approve_on_completed_request_rejected(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            req = wf.request("att://x", reviewers=["a@x.com", "b@x.com"], threshold=1)
            wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            with self.assertRaises(ValueError, msg="already APPROVED"):
                wf.approve(req.request_id, _identity("b@x.com"), ApprovalDecision.APPROVED, "ok")
            wf.close()

    def test_status_unknown_request_raises(self):
        from squash.approval_workflow import ApprovalWorkflow
        with tempfile.TemporaryDirectory() as td:
            with ApprovalWorkflow(db_path=Path(td) / "a.db", notify_on_change=False) as wf:
                with self.assertRaises(ValueError):
                    wf.status("appr-doesnotexist")


# ── Persistence (SQLite round-trip) ──────────────────────────────────────────


class TestPersistence(unittest.TestCase):
    def test_request_survives_across_workflow_instances(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalWorkflow, RequestStatus
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "approvals.db"
            wf1 = ApprovalWorkflow(db_path=db, notify_on_change=False)
            req = wf1.request("att://x", reviewers=["a@x.com"], threshold=1)
            wf1.close()

            wf2 = ApprovalWorkflow(db_path=db, notify_on_change=False)
            wf2.approve(req.request_id, _identity("a@x.com"),
                        ApprovalDecision.APPROVED, "ok")
            final = wf2.status(req.request_id)
            self.assertEqual(final.overall_status, RequestStatus.APPROVED)
            wf2.close()

    def test_list_pending_returns_only_pending(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            r1 = wf.request("att://1", reviewers=["a@x.com"], threshold=1)
            r2 = wf.request("att://2", reviewers=["b@x.com"], threshold=1)
            wf.approve(r1.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "ok")
            pending = wf.list_pending()
            ids = [r.request_id for r in pending]
            self.assertNotIn(r1.request_id, ids)
            self.assertIn(r2.request_id, ids)
            wf.close()

    def test_list_pending_filtered_by_reviewer(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            wf = _wf(Path(td))
            wf.request("att://1", reviewers=["alice@x.com"], threshold=1)
            wf.request("att://2", reviewers=["bob@x.com"], threshold=1)
            alice_pending = wf.list_pending("alice@x.com")
            self.assertEqual(len(alice_pending), 1)
            self.assertIn("alice@x.com", alice_pending[0].reviewers)
            wf.close()


# ── Evidence export ───────────────────────────────────────────────────────────


class TestEvidenceExport(unittest.TestCase):
    def _setup(self):
        from squash.approval_workflow import ApprovalDecision
        tmp = Path(tempfile.mkdtemp())
        wf = _wf(tmp)
        req = wf.request("att://sha256:abc", model_id="bert", reviewers=["a@x.com"], threshold=1)
        wf.approve(req.request_id, _identity("a@x.com"), ApprovalDecision.APPROVED, "all clear")
        ev = wf.export_evidence(req.request_id)
        wf.close()
        return ev

    def test_evidence_has_regulatory_mapping(self):
        ev = self._setup()
        self.assertIn("regulatory_mapping", ev)
        self.assertIn("eu_ai_act", ev["regulatory_mapping"])
        self.assertIn("nist_ai_rmf", ev["regulatory_mapping"])
        self.assertIn("iso_42001", ev["regulatory_mapping"])

    def test_evidence_has_signature_verification(self):
        ev = self._setup()
        self.assertIn("all_signatures_valid", ev)
        self.assertTrue(ev["all_signatures_valid"])

    def test_evidence_has_request_and_records(self):
        ev = self._setup()
        self.assertIn("request", ev)
        self.assertIn("records_with_verification", ev)
        self.assertGreater(len(ev["records_with_verification"]), 0)

    def test_evidence_record_has_signature_valid_flag(self):
        ev = self._setup()
        for rec in ev["records_with_verification"]:
            self.assertIn("signature_valid", rec)
            self.assertTrue(rec["signature_valid"])

    def test_evidence_summary_is_human_readable(self):
        ev = self._setup()
        self.assertIn("Model: bert", ev["summary"])
        self.assertIn("Attestation:", ev["summary"])


# ── Notifications integration ─────────────────────────────────────────────────


class TestNotifications(unittest.TestCase):
    def test_notification_fires_on_request(self):
        with tempfile.TemporaryDirectory() as td:
            fired = []
            with mock.patch("squash.approval_workflow.ApprovalWorkflow._fire",
                            side_effect=lambda *a, **kw: fired.append(a[0])):
                from squash.approval_workflow import ApprovalWorkflow
                wf = ApprovalWorkflow(db_path=Path(td) / "a.db", notify_on_change=True)
                wf.request("att://x", reviewers=["a@x.com"], threshold=1)
                wf.close()
            self.assertIn("approval.requested", fired)

    def test_notification_fires_on_approval_complete(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            fired = []
            with mock.patch("squash.approval_workflow.ApprovalWorkflow._fire",
                            side_effect=lambda *a, **kw: fired.append(a[0])):
                from squash.approval_workflow import ApprovalWorkflow
                wf = ApprovalWorkflow(db_path=Path(td) / "a.db", notify_on_change=True)
                req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
                wf.approve(req.request_id, _identity("a@x.com"),
                           ApprovalDecision.APPROVED, "ok")
                wf.close()
            self.assertIn("approval.approved", fired)

    def test_notification_fires_on_rejection(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            fired = []
            with mock.patch("squash.approval_workflow.ApprovalWorkflow._fire",
                            side_effect=lambda *a, **kw: fired.append(a[0])):
                from squash.approval_workflow import ApprovalWorkflow
                wf = ApprovalWorkflow(db_path=Path(td) / "a.db", notify_on_change=True)
                req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
                wf.approve(req.request_id, _identity("a@x.com"),
                           ApprovalDecision.REJECTED, "drift too high")
                wf.close()
            self.assertIn("approval.rejected", fired)


# ── CLI dispatcher ────────────────────────────────────────────────────────────


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


class TestCliRequestApproval(unittest.TestCase):
    def test_creates_request_prints_id(self):
        from squash.approval_workflow import ApprovalWorkflow
        from squash.cli import _cmd_request_approval
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "a.db"
            with mock.patch("squash.approval_workflow._DEFAULT_DB", db):
                with mock.patch("sys.stdout", buf):
                    rc = _cmd_request_approval(_ns(
                        appr_attestation_id="att://x",
                        appr_model_id="my-model",
                        appr_reviewers="a@x.com",
                        appr_threshold=1,
                        appr_required_roles="",
                        appr_requestor="req@x.com",
                        appr_notes="",
                        appr_hash="",
                        appr_ttl=30,
                        appr_json=False,
                        quiet=False,
                    ), quiet=False)
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("appr-", output)   # request_id prefix

    def test_json_flag_emits_json(self):
        from squash.cli import _cmd_request_approval
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "a.db"
            with mock.patch("squash.approval_workflow._DEFAULT_DB", db):
                with mock.patch("sys.stdout", buf):
                    rc = _cmd_request_approval(_ns(
                        appr_attestation_id="att://x", appr_model_id="m",
                        appr_reviewers="", appr_threshold=1,
                        appr_required_roles="", appr_requestor="",
                        appr_notes="", appr_hash="", appr_ttl=30,
                        appr_json=True, quiet=True,
                    ), quiet=True)
        self.assertEqual(rc, 0)
        parsed = json.loads(buf.getvalue())
        self.assertIn("request_id", parsed)
        self.assertTrue(parsed["request_id"].startswith("appr-"))


class TestCliApprove(unittest.TestCase):
    def test_approve_integration(self):
        from squash.approval_workflow import ApprovalDecision
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "a.db"
            from squash.approval_workflow import ApprovalWorkflow
            with ApprovalWorkflow(db_path=db, notify_on_change=False) as wf:
                req = wf.request("att://x", reviewers=["alice@x.com"], threshold=1)
            # Now call CLI approve using the internal command function but with
            # env var for email
            env = {"SQUASH_REVIEWER_EMAIL": "alice@x.com"}
            with mock.patch.dict("os.environ", env):
                # patch db path so CLI uses our temp db
                with mock.patch("squash.approval_workflow._DEFAULT_DB", db):
                    from squash.cli import _cmd_approve
                    rc = _cmd_approve(_ns(
                        request_id=req.request_id,
                        appr_decision="APPROVED",
                        appr_rationale="All clear",
                        appr_reviewer_email="",
                        appr_reviewer_name="Alice",
                        appr_reviewer_role="COMPLIANCE",
                        appr_conditions=None,
                        appr_json=False,
                        quiet=True,
                    ), quiet=True)
            self.assertEqual(rc, 0)

    def test_approve_missing_email_returns_2(self):
        from squash.cli import _cmd_approve
        with mock.patch.dict("os.environ", {}, clear=True):
            # Remove any email env vars
            import os
            for k in ("SQUASH_REVIEWER_EMAIL", "GIT_AUTHOR_EMAIL"):
                os.environ.pop(k, None)
            rc = _cmd_approve(_ns(
                request_id="appr-x",
                appr_decision="APPROVED",
                appr_rationale="ok",
                appr_reviewer_email="",
                appr_reviewer_name="",
                appr_reviewer_role="ANY",
                appr_conditions=None,
                appr_json=False,
                quiet=True,
            ), quiet=True)
        self.assertEqual(rc, 2)


class TestCliApprovalStatus(unittest.TestCase):
    def test_status_unknown_request_returns_1(self):
        from squash.cli import _cmd_approval_status
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("squash.approval_workflow._DEFAULT_DB", Path(td) / "a.db"):
                rc = _cmd_approval_status(_ns(
                    request_id="appr-doesnotexist",
                    appr_json=False, quiet=True,
                ), quiet=True)
        self.assertEqual(rc, 1)

    def test_status_json_output(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalWorkflow
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "a.db"
            with ApprovalWorkflow(db_path=db, notify_on_change=False) as wf:
                req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
                wf.approve(req.request_id, _identity("a@x.com"),
                           ApprovalDecision.APPROVED, "ok")
            buf = io.StringIO()
            with mock.patch("squash.approval_workflow._DEFAULT_DB", db):
                from squash.cli import _cmd_approval_status
                with mock.patch("sys.stdout", buf):
                    _cmd_approval_status(_ns(
                        request_id=req.request_id,
                        appr_json=True, quiet=True,
                    ), quiet=True)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(parsed["overall_status"], "APPROVED")


class TestCliApprovalList(unittest.TestCase):
    def test_list_empty_is_not_error(self):
        from squash.cli import _cmd_approval_list
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("squash.approval_workflow._DEFAULT_DB", Path(td) / "a.db"):
                rc = _cmd_approval_list(_ns(
                    appr_reviewer_filter="",
                    appr_pending_only=False,
                    appr_limit=10,
                    appr_json=False,
                    quiet=True,
                ), quiet=True)
        self.assertEqual(rc, 0)

    def test_list_json_returns_list(self):
        from squash.approval_workflow import ApprovalWorkflow
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "a.db"
            with ApprovalWorkflow(db_path=db, notify_on_change=False) as wf:
                wf.request("att://1", reviewers=["a@x.com"], threshold=1)
                wf.request("att://2", reviewers=["b@x.com"], threshold=1)
            buf = io.StringIO()
            with mock.patch("squash.approval_workflow._DEFAULT_DB", db):
                from squash.cli import _cmd_approval_list
                with mock.patch("sys.stdout", buf):
                    _cmd_approval_list(_ns(
                        appr_reviewer_filter="",
                        appr_pending_only=True,
                        appr_limit=20,
                        appr_json=True,
                        quiet=True,
                    ), quiet=True)
            parsed = json.loads(buf.getvalue())
            self.assertIsInstance(parsed, list)
            self.assertEqual(len(parsed), 2)


class TestCliApprovalExport(unittest.TestCase):
    def test_export_to_file(self):
        from squash.approval_workflow import ApprovalDecision, ApprovalWorkflow
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "a.db"
            with ApprovalWorkflow(db_path=db, notify_on_change=False) as wf:
                req = wf.request("att://x", reviewers=["a@x.com"], threshold=1)
                wf.approve(req.request_id, _identity("a@x.com"),
                           ApprovalDecision.APPROVED, "clean")
            out_file = Path(td) / "evidence.json"
            with mock.patch("squash.approval_workflow._DEFAULT_DB", db):
                from squash.cli import _cmd_approval_export
                rc = _cmd_approval_export(_ns(
                    request_id=req.request_id,
                    appr_output=str(out_file),
                    appr_json=False,
                    quiet=True,
                ), quiet=True)
            self.assertEqual(rc, 0)
            self.assertTrue(out_file.exists())
            ev = json.loads(out_file.read_text())
            self.assertIn("regulatory_mapping", ev)
            self.assertTrue(ev["all_signatures_valid"])

    def test_export_unknown_request_returns_1(self):
        from squash.cli import _cmd_approval_export
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("squash.approval_workflow._DEFAULT_DB", Path(td) / "a.db"):
                rc = _cmd_approval_export(_ns(
                    request_id="appr-nope",
                    appr_output=None,
                    appr_json=True,
                    quiet=True,
                ), quiet=True)
        self.assertEqual(rc, 1)


# ── Subprocess CLI (help text + basic end-to-end) ────────────────────────────


class TestCliSubprocess(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "squash.cli", *args],
            capture_output=True, text=True,
        )

    def test_request_approval_help(self):
        r = self._run("request-approval", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--attestation", "--reviewers", "--threshold",
                     "--require-role", "--requestor", "--notes", "--json"):
            self.assertIn(flag, r.stdout, msg=f"{flag} missing from help")

    def test_approve_help(self):
        r = self._run("approve", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--decision", "--rationale", "--reviewer-email",
                     "--role", "--condition", "--json"):
            self.assertIn(flag, r.stdout, msg=f"{flag} missing from help")

    def test_approval_status_help(self):
        r = self._run("approval-status", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--json", r.stdout)

    def test_approval_list_help(self):
        r = self._run("approval-list", "--help")
        self.assertEqual(r.returncode, 0)
        for flag in ("--reviewer", "--pending-only", "--limit"):
            self.assertIn(flag, r.stdout)

    def test_approval_export_help(self):
        r = self._run("approval-export", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--output", r.stdout)


if __name__ == "__main__":
    unittest.main()
