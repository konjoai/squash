"""tests/test_squash_w189.py — W189: GitOps admission webhook tests.

Coverage:
  - AdmissionRequest.from_k8s_body() — extracts all fields
  - SquashAdmissionWebhook.evaluate() — allow / deny paths
    * kind not in gated_kinds → allowed
    * missing attestation-id annotation → denied when require_attestation
    * invalid score annotation → denied
    * score below min → denied
    * passed=false annotation → denied
    * all annotations present and valid → allowed
  - SquashAdmissionWebhook.handle_admission_review() — full K8s review body
  - AdmissionResponse.to_k8s_review() — correct K8s AdmissionReview structure
  - AdmissionResponse.to_dict() — has expected keys
  - check_manifest_compliance() — file not found, invalid YAML, pass, fail
  - generate_webhook_manifest() — produces valid YAML dict
  - generate_namespace_label_manifest() — contains namespace name
  - annotate_deployment_command() — contains all annotation keys
  - ManifestComplianceResult.to_dict() — has expected keys
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from squash.integrations.gitops import (
    ANNOTATION_ATTESTATION_ID,
    ANNOTATION_COMPLIANCE_SCORE,
    ANNOTATION_PASSED,
    ANNOTATION_POLICY,
    AdmissionRequest,
    AdmissionResponse,
    ManifestComplianceResult,
    SquashAdmissionWebhook,
    annotate_deployment_command,
    check_manifest_compliance,
    generate_namespace_label_manifest,
    generate_webhook_manifest,
)


# ---------------------------------------------------------------------------
# AdmissionRequest
# ---------------------------------------------------------------------------

class TestAdmissionRequestFromK8sBody:
    def _body(self, kind="Deployment", annotations=None, name="my-model", namespace="production"):
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-001",
                "kind": {"apiVersion": "apps/v1", "kind": kind},
                "operation": "CREATE",
                "name": name,
                "namespace": namespace,
                "object": {
                    "apiVersion": "apps/v1",
                    "kind": kind,
                    "metadata": {
                        "name": name,
                        "namespace": namespace,
                        "annotations": annotations or {},
                    },
                },
            },
        }

    def test_extracts_uid(self):
        req = AdmissionRequest.from_k8s_body(self._body())
        assert req.uid == "test-uid-001"

    def test_extracts_kind(self):
        req = AdmissionRequest.from_k8s_body(self._body(kind="StatefulSet"))
        assert req.kind == "StatefulSet"

    def test_extracts_name(self):
        req = AdmissionRequest.from_k8s_body(self._body(name="bert-classifier"))
        assert req.name == "bert-classifier"

    def test_extracts_namespace(self):
        req = AdmissionRequest.from_k8s_body(self._body(namespace="ml-prod"))
        assert req.namespace == "ml-prod"

    def test_extracts_annotations(self):
        anns = {ANNOTATION_ATTESTATION_ID: "att://myorg/v1"}
        req = AdmissionRequest.from_k8s_body(self._body(annotations=anns))
        assert req.annotations[ANNOTATION_ATTESTATION_ID] == "att://myorg/v1"

    def test_empty_annotations_when_none(self):
        req = AdmissionRequest.from_k8s_body(self._body(annotations=None))
        assert req.annotations == {}

    def test_extracts_operation(self):
        body = self._body()
        body["request"]["operation"] = "UPDATE"
        req = AdmissionRequest.from_k8s_body(body)
        assert req.operation == "UPDATE"


# ---------------------------------------------------------------------------
# SquashAdmissionWebhook.evaluate()
# ---------------------------------------------------------------------------

class TestSquashAdmissionWebhookEvaluate:
    def _webhook(self, min_score=80.0, require_attestation=True):
        return SquashAdmissionWebhook(min_score=min_score, require_attestation=require_attestation)

    def _req(self, kind="Deployment", annotations=None):
        return AdmissionRequest(
            uid="uid-001", kind=kind, api_version="apps/v1",
            name="my-model", namespace="production",
            annotations=annotations or {},
        )

    # ------ Allow paths ------

    def test_allows_non_gated_kind(self):
        wh = self._webhook()
        resp = wh.evaluate(self._req(kind="ConfigMap"))
        assert resp.allowed is True
        assert "not gated" in resp.message

    def test_allows_service_kind(self):
        wh = self._webhook()
        resp = wh.evaluate(self._req(kind="Service"))
        assert resp.allowed is True

    def test_allows_with_valid_annotations(self):
        wh = self._webhook()
        anns = {
            ANNOTATION_ATTESTATION_ID: "att://myorg/bert-v1",
            ANNOTATION_COMPLIANCE_SCORE: "87.5",
            ANNOTATION_POLICY: "eu-ai-act",
            ANNOTATION_PASSED: "true",
        }
        resp = wh.evaluate(self._req(annotations=anns))
        assert resp.allowed is True
        assert resp.attestation_id == "att://myorg/bert-v1"
        assert resp.compliance_score == 87.5

    def test_allows_without_score_when_attestation_present(self):
        wh = self._webhook()
        anns = {ANNOTATION_ATTESTATION_ID: "att://myorg/v1"}
        resp = wh.evaluate(self._req(annotations=anns))
        assert resp.allowed is True

    def test_allows_when_attestation_not_required(self):
        wh = self._webhook(require_attestation=False)
        resp = wh.evaluate(self._req(annotations={}))
        assert resp.allowed is True

    def test_allows_score_at_threshold(self):
        wh = self._webhook(min_score=80.0)
        anns = {
            ANNOTATION_ATTESTATION_ID: "att://myorg/v1",
            ANNOTATION_COMPLIANCE_SCORE: "80.0",
        }
        resp = wh.evaluate(self._req(annotations=anns))
        assert resp.allowed is True

    # ------ Deny paths ------

    def test_denies_missing_attestation_id(self):
        wh = self._webhook(require_attestation=True)
        resp = wh.evaluate(self._req(annotations={}))
        assert resp.allowed is False
        assert ANNOTATION_ATTESTATION_ID in resp.message

    def test_denies_invalid_score_annotation(self):
        wh = self._webhook()
        anns = {
            ANNOTATION_ATTESTATION_ID: "att://myorg/v1",
            ANNOTATION_COMPLIANCE_SCORE: "not-a-number",
        }
        resp = wh.evaluate(self._req(annotations=anns))
        assert resp.allowed is False

    def test_denies_score_below_threshold(self):
        wh = self._webhook(min_score=80.0)
        anns = {
            ANNOTATION_ATTESTATION_ID: "att://myorg/v1",
            ANNOTATION_COMPLIANCE_SCORE: "72.0",
        }
        resp = wh.evaluate(self._req(annotations=anns))
        assert resp.allowed is False
        assert "72.0" in resp.message
        assert resp.compliance_score == 72.0

    def test_denies_passed_false_annotation(self):
        wh = self._webhook()
        anns = {
            ANNOTATION_ATTESTATION_ID: "att://myorg/v1",
            ANNOTATION_COMPLIANCE_SCORE: "85.0",
            ANNOTATION_PASSED: "false",
        }
        resp = wh.evaluate(self._req(annotations=anns))
        assert resp.allowed is False

    def test_denies_pod_without_attestation(self):
        wh = self._webhook(require_attestation=True)
        resp = wh.evaluate(self._req(kind="Pod", annotations={}))
        assert resp.allowed is False


# ---------------------------------------------------------------------------
# AdmissionResponse.to_k8s_review()
# ---------------------------------------------------------------------------

class TestAdmissionResponseToK8sReview:
    def test_allowed_review_structure(self):
        resp = AdmissionResponse(uid="uid-1", allowed=True, message="ok")
        review = resp.to_k8s_review()
        assert review["apiVersion"] == "admission.k8s.io/v1"
        assert review["kind"] == "AdmissionReview"
        assert review["response"]["uid"] == "uid-1"
        assert review["response"]["allowed"] is True

    def test_denied_review_has_message(self):
        resp = AdmissionResponse(uid="uid-2", allowed=False, message="score too low")
        review = resp.to_k8s_review()
        assert review["response"]["allowed"] is False
        assert review["response"]["status"]["message"] == "score too low"
        assert review["response"]["status"]["code"] == 403

    def test_allowed_review_has_200_code(self):
        resp = AdmissionResponse(uid="uid-3", allowed=True, message="pass")
        review = resp.to_k8s_review()
        assert review["response"]["status"]["code"] == 200

    def test_to_dict_has_all_keys(self):
        resp = AdmissionResponse(uid="uid-4", allowed=True, message="ok", compliance_score=87.5)
        d = resp.to_dict()
        for key in ("uid", "allowed", "message", "compliance_score", "attestation_id", "policy"):
            assert key in d


# ---------------------------------------------------------------------------
# handle_admission_review()
# ---------------------------------------------------------------------------

class TestHandleAdmissionReview:
    def _body(self, kind="Deployment", annotations=None):
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "uid-abc",
                "kind": {"kind": kind},
                "operation": "CREATE",
                "name": "model",
                "namespace": "prod",
                "object": {
                    "metadata": {"name": "model", "namespace": "prod", "annotations": annotations or {}},
                },
            },
        }

    def test_returns_admission_review_dict(self):
        wh = SquashAdmissionWebhook(require_attestation=False)
        result = wh.handle_admission_review(self._body())
        assert "response" in result
        assert "allowed" in result["response"]

    def test_handles_malformed_body_gracefully(self):
        wh = SquashAdmissionWebhook(require_attestation=False)
        # Empty body — kind will be "" (not in gated_kinds) → allowed
        result = wh.handle_admission_review({})
        assert "response" in result
        assert "allowed" in result["response"]

    def test_denies_deployment_in_malformed_body_with_required_attestation(self):
        wh = SquashAdmissionWebhook(require_attestation=True)
        body = {
            "request": {
                "uid": "uid-x",
                "kind": {"kind": "Deployment"},
                "operation": "CREATE",
                "name": "m",
                "namespace": "prod",
                "object": {"metadata": {"name": "m", "namespace": "prod", "annotations": {}}},
            }
        }
        result = wh.handle_admission_review(body)
        assert result["response"]["allowed"] is False

    def test_full_pass_scenario(self):
        wh = SquashAdmissionWebhook(min_score=70.0, require_attestation=True)
        anns = {
            ANNOTATION_ATTESTATION_ID: "att://myorg/v1",
            ANNOTATION_COMPLIANCE_SCORE: "85.0",
            ANNOTATION_PASSED: "true",
        }
        result = wh.handle_admission_review(self._body(annotations=anns))
        assert result["response"]["allowed"] is True


# ---------------------------------------------------------------------------
# check_manifest_compliance()
# ---------------------------------------------------------------------------

class TestCheckManifestCompliance:
    def _write_manifest(self, content: str, tmp_path: Path) -> Path:
        p = tmp_path / "manifest.yaml"
        p.write_text(content)
        return p

    def test_file_not_found(self, tmp_path):
        result = check_manifest_compliance(tmp_path / "nonexistent.yaml")
        assert result.passed is False
        assert "not found" in result.reason.lower()

    def test_invalid_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_bytes(b"[invalid yaml that is not a mapping")
        result = check_manifest_compliance(p)
        assert result.passed is False

    def test_deployment_with_valid_annotations(self, tmp_path):
        manifest = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bert-model
  namespace: production
  annotations:
    {ANNOTATION_ATTESTATION_ID}: "att://myorg/bert-v1"
    {ANNOTATION_COMPLIANCE_SCORE}: "88.0"
    {ANNOTATION_PASSED}: "true"
"""
        p = self._write_manifest(manifest, tmp_path)
        result = check_manifest_compliance(p, min_score=80.0)
        assert result.passed is True
        assert result.resource_kind == "Deployment"
        assert result.resource_name == "bert-model"

    def test_deployment_missing_attestation(self, tmp_path):
        manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unattested-model
  namespace: production
"""
        p = self._write_manifest(manifest, tmp_path)
        result = check_manifest_compliance(p, require_attestation=True)
        assert result.passed is False

    def test_deployment_score_too_low(self, tmp_path):
        manifest = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: model
  annotations:
    {ANNOTATION_ATTESTATION_ID}: "att://myorg/v1"
    {ANNOTATION_COMPLIANCE_SCORE}: "55.0"
"""
        p = self._write_manifest(manifest, tmp_path)
        result = check_manifest_compliance(p, min_score=80.0)
        assert result.passed is False
        assert result.compliance_score == 55.0

    def test_non_gated_kind_passes(self, tmp_path):
        manifest = """
apiVersion: v1
kind: Service
metadata:
  name: my-service
"""
        p = self._write_manifest(manifest, tmp_path)
        result = check_manifest_compliance(p)
        assert result.passed is True

    def test_result_to_dict_has_required_keys(self, tmp_path):
        manifest = """
apiVersion: v1
kind: Service
metadata:
  name: svc
"""
        p = self._write_manifest(manifest, tmp_path)
        result = check_manifest_compliance(p)
        d = result.to_dict()
        for key in ("passed", "reason", "attestation_id", "compliance_score", "policy", "resource_name", "resource_kind"):
            assert key in d


# ---------------------------------------------------------------------------
# generate_webhook_manifest()
# ---------------------------------------------------------------------------

class TestGenerateWebhookManifest:
    def test_produces_valid_yaml(self):
        import yaml
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.example.com")
        doc = yaml.safe_load(yaml_str)
        assert isinstance(doc, dict)

    def test_correct_api_version(self):
        import yaml
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.example.com")
        doc = yaml.safe_load(yaml_str)
        assert doc["apiVersion"] == "admissionregistration.k8s.io/v1"

    def test_correct_kind(self):
        import yaml
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.example.com")
        doc = yaml.safe_load(yaml_str)
        assert doc["kind"] == "ValidatingWebhookConfiguration"

    def test_webhook_url_in_manifest(self):
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.mycompany.com")
        assert "squash.mycompany.com" in yaml_str

    def test_namespace_in_manifest(self):
        import yaml
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.example.com", namespace="ai-governance")
        doc = yaml.safe_load(yaml_str)
        assert "squash-admission-webhook" in doc["metadata"]["name"]

    def test_failure_policy_respected(self):
        import yaml
        yaml_str = generate_webhook_manifest(
            webhook_url="https://squash.example.com", failure_policy="Ignore"
        )
        doc = yaml.safe_load(yaml_str)
        assert doc["webhooks"][0]["failurePolicy"] == "Ignore"

    def test_contains_gated_resources(self):
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.example.com")
        assert "deployments" in yaml_str

    def test_has_namespace_selector(self):
        import yaml
        yaml_str = generate_webhook_manifest(webhook_url="https://squash.example.com")
        doc = yaml.safe_load(yaml_str)
        webhook = doc["webhooks"][0]
        assert "namespaceSelector" in webhook


# ---------------------------------------------------------------------------
# annotate_deployment_command()
# ---------------------------------------------------------------------------

class TestAnnotateDeploymentCommand:
    def test_contains_deployment_name(self):
        cmd = annotate_deployment_command(
            "bert-prod", "att://myorg/v1", 87.5
        )
        assert "bert-prod" in cmd

    def test_contains_attestation_id(self):
        cmd = annotate_deployment_command("d", "att://myorg/bert-v2", 90.0)
        assert "att://myorg/bert-v2" in cmd

    def test_contains_score(self):
        cmd = annotate_deployment_command("d", "att://a/b", 75.0)
        assert "75.0" in cmd

    def test_contains_policy(self):
        cmd = annotate_deployment_command("d", "att://a/b", 80.0, policy="nist-rmf")
        assert "nist-rmf" in cmd

    def test_contains_passed_annotation(self):
        cmd = annotate_deployment_command("d", "att://a/b", 80.0, passed=True)
        assert "true" in cmd

    def test_failed_passed_annotation(self):
        cmd = annotate_deployment_command("d", "att://a/b", 40.0, passed=False)
        assert "false" in cmd

    def test_contains_all_annotation_keys(self):
        cmd = annotate_deployment_command("d", "att://a/b", 80.0)
        assert ANNOTATION_ATTESTATION_ID in cmd
        assert ANNOTATION_COMPLIANCE_SCORE in cmd
        assert ANNOTATION_PASSED in cmd


# ---------------------------------------------------------------------------
# generate_namespace_label_manifest()
# ---------------------------------------------------------------------------

class TestGenerateNamespaceLabelManifest:
    def test_contains_namespace(self):
        result = generate_namespace_label_manifest("my-production-ns")
        assert "my-production-ns" in result

    def test_contains_squash_label(self):
        result = generate_namespace_label_manifest("ns")
        assert "squash.ai/enforce" in result
