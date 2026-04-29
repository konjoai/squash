"""squash/integrations/gitops.py — ArgoCD / Flux GitOps enforcement gate.

Integrates squash compliance into GitOps deployment pipelines.  Two usage
patterns are supported:

1. **Kubernetes ValidatingWebhookConfiguration**
   A lightweight HTTP endpoint is registered as a K8s admission webhook.  Any
   ``Deployment``, ``StatefulSet``, or ``Pod`` resource that lacks a valid
   ``squash.ai/attestation-id`` annotation (or whose registered compliance
   score is below the configured minimum) is rejected at admission time.

2. **Pre-deploy CLI gate**
   ``squash gitops check --manifest deployment.yaml --min-score 80`` reads a
   local Kubernetes manifest YAML, extracts any squash annotations, and
   exits non-zero when the compliance requirement is not satisfied.

Usage (programmatic)
--------------------
::

    from squash.integrations.gitops import SquashAdmissionWebhook

    webhook = SquashAdmissionWebhook(min_score=80.0, require_attestation=True)

    # K8s sends a JSON AdmissionReview body:
    review = webhook.handle_admission_review(request_body)
    # review["response"]["allowed"] is True / False

Generate the K8s ValidatingWebhookConfiguration manifest::

    from squash.integrations.gitops import generate_webhook_manifest
    yaml_str = generate_webhook_manifest(
        webhook_url="https://squash.example.com/k8s/admission",
        namespace="squash-system",
    )

Check a local deployment manifest::

    from squash.integrations.gitops import check_manifest_compliance
    result = check_manifest_compliance(Path("deployment.yaml"), min_score=80)
    if not result["passed"]:
        print(result["reason"])
        sys.exit(1)
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Annotation keys
# ---------------------------------------------------------------------------

ANNOTATION_ATTESTATION_ID = "squash.ai/attestation-id"
ANNOTATION_COMPLIANCE_SCORE = "squash.ai/compliance-score"
ANNOTATION_POLICY = "squash.ai/policy"
ANNOTATION_PASSED = "squash.ai/passed"
ANNOTATION_SQUASH_VERSION = "squash.ai/version"

# K8s resource kinds squash gates by default
_GATED_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AdmissionRequest:
    uid: str
    kind: str
    api_version: str
    name: str
    namespace: str
    annotations: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    operation: str = "CREATE"          # CREATE | UPDATE | DELETE | CONNECT

    @classmethod
    def from_k8s_body(cls, body: dict[str, Any]) -> "AdmissionRequest":
        req = body.get("request", {})
        obj = req.get("object", {})
        meta = obj.get("metadata", {})
        kind_info = req.get("kind", {})
        return cls(
            uid=req.get("uid", ""),
            kind=kind_info.get("kind", obj.get("kind", "")),
            api_version=kind_info.get("apiVersion", obj.get("apiVersion", "")),
            name=meta.get("name", req.get("name", "")),
            namespace=meta.get("namespace", req.get("namespace", "default")),
            annotations=meta.get("annotations") or {},
            labels=meta.get("labels") or {},
            operation=req.get("operation", "CREATE"),
        )


@dataclass
class AdmissionResponse:
    uid: str
    allowed: bool
    message: str
    compliance_score: float | None = None
    attestation_id: str | None = None
    policy: str | None = None

    def to_k8s_review(self) -> dict[str, Any]:
        status: dict[str, Any] = {"code": 200 if self.allowed else 403}
        if not self.allowed:
            status["message"] = self.message
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": self.uid,
                "allowed": self.allowed,
                "status": status,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "allowed": self.allowed,
            "message": self.message,
            "compliance_score": self.compliance_score,
            "attestation_id": self.attestation_id,
            "policy": self.policy,
        }


@dataclass
class ManifestComplianceResult:
    passed: bool
    reason: str
    attestation_id: str | None
    compliance_score: float | None
    policy: str | None
    resource_name: str
    resource_kind: str
    annotations_found: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reason": self.reason,
            "attestation_id": self.attestation_id,
            "compliance_score": self.compliance_score,
            "policy": self.policy,
            "resource_name": self.resource_name,
            "resource_kind": self.resource_kind,
            "annotations_found": self.annotations_found,
        }


# ---------------------------------------------------------------------------
# Core webhook
# ---------------------------------------------------------------------------

class SquashAdmissionWebhook:
    """Kubernetes ValidatingAdmissionWebhook handler.

    Evaluates incoming AdmissionReview requests and returns allow/deny
    decisions based on squash compliance annotations.
    """

    def __init__(
        self,
        min_score: float = 80.0,
        require_attestation: bool = True,
        gated_kinds: frozenset[str] | None = None,
    ) -> None:
        self.min_score = min_score
        self.require_attestation = require_attestation
        self.gated_kinds = gated_kinds or _GATED_KINDS

    def evaluate(self, request: AdmissionRequest) -> AdmissionResponse:
        """Evaluate an admission request and return an allow/deny decision."""
        if request.kind not in self.gated_kinds:
            return AdmissionResponse(
                uid=request.uid,
                allowed=True,
                message=f"kind {request.kind!r} not gated by squash",
            )

        annotations = request.annotations
        attestation_id = annotations.get(ANNOTATION_ATTESTATION_ID)
        score_str = annotations.get(ANNOTATION_COMPLIANCE_SCORE)
        policy = annotations.get(ANNOTATION_POLICY)
        passed_str = annotations.get(ANNOTATION_PASSED)

        if self.require_attestation and not attestation_id:
            return AdmissionResponse(
                uid=request.uid,
                allowed=False,
                message=(
                    f"Deployment '{request.name}' in namespace '{request.namespace}' is missing "
                    f"required annotation '{ANNOTATION_ATTESTATION_ID}'. "
                    f"Run: squash attest ./model --policy eu-ai-act"
                ),
            )

        compliance_score: float | None = None
        if score_str is not None:
            try:
                compliance_score = float(score_str)
            except ValueError:
                return AdmissionResponse(
                    uid=request.uid,
                    allowed=False,
                    message=f"Invalid compliance score annotation: {score_str!r}",
                    attestation_id=attestation_id,
                )

            if compliance_score < self.min_score:
                return AdmissionResponse(
                    uid=request.uid,
                    allowed=False,
                    message=(
                        f"Compliance score {compliance_score:.1f} is below minimum {self.min_score:.1f} "
                        f"for '{request.name}'. Resolve violations and re-attest."
                    ),
                    compliance_score=compliance_score,
                    attestation_id=attestation_id,
                    policy=policy,
                )

        if passed_str is not None and passed_str.lower() in ("false", "0", "no"):
            return AdmissionResponse(
                uid=request.uid,
                allowed=False,
                message=(
                    f"Attestation for '{request.name}' did not pass policy checks "
                    f"(squash.ai/passed=false). Resolve violations and re-attest."
                ),
                compliance_score=compliance_score,
                attestation_id=attestation_id,
                policy=policy,
            )

        return AdmissionResponse(
            uid=request.uid,
            allowed=True,
            message="squash compliance check passed",
            compliance_score=compliance_score,
            attestation_id=attestation_id,
            policy=policy,
        )

    def handle_admission_review(self, body: dict[str, Any]) -> dict[str, Any]:
        """Process a full K8s AdmissionReview JSON body.

        Returns a complete AdmissionReview response dict suitable for
        sending back to the Kubernetes API server.
        """
        try:
            request = AdmissionRequest.from_k8s_body(body)
        except Exception as exc:
            uid = body.get("request", {}).get("uid", "")
            log.warning("Failed to parse AdmissionRequest: %s", exc)
            return AdmissionResponse(
                uid=uid, allowed=False, message=f"Failed to parse request: {exc}"
            ).to_k8s_review()

        response = self.evaluate(request)
        return response.to_k8s_review()


# ---------------------------------------------------------------------------
# Manifest compliance check (CLI gate)
# ---------------------------------------------------------------------------

def check_manifest_compliance(
    manifest_path: Path,
    min_score: float = 80.0,
    require_attestation: bool = True,
) -> ManifestComplianceResult:
    """Check a Kubernetes manifest YAML for squash compliance annotations.

    Does not require a live cluster — reads annotations from the local file.
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        return ManifestComplianceResult(
            passed=False,
            reason="PyYAML not installed — install with: pip install pyyaml",
            attestation_id=None,
            compliance_score=None,
            policy=None,
            resource_name=str(manifest_path),
            resource_kind="unknown",
        )

    if not manifest_path.exists():
        return ManifestComplianceResult(
            passed=False,
            reason=f"Manifest not found: {manifest_path}",
            attestation_id=None,
            compliance_score=None,
            policy=None,
            resource_name=str(manifest_path),
            resource_kind="unknown",
        )

    try:
        with manifest_path.open() as f:
            doc = yaml.safe_load(f)
    except Exception as exc:
        return ManifestComplianceResult(
            passed=False,
            reason=f"Failed to parse manifest YAML: {exc}",
            attestation_id=None,
            compliance_score=None,
            policy=None,
            resource_name=str(manifest_path),
            resource_kind="unknown",
        )

    if not isinstance(doc, dict):
        return ManifestComplianceResult(
            passed=False,
            reason="Manifest is not a valid YAML mapping",
            attestation_id=None,
            compliance_score=None,
            policy=None,
            resource_name=str(manifest_path),
            resource_kind="unknown",
        )

    kind = doc.get("kind", "")
    meta = doc.get("metadata", {}) or {}
    name = meta.get("name", str(manifest_path))
    annotations = meta.get("annotations") or {}

    webhook = SquashAdmissionWebhook(min_score=min_score, require_attestation=require_attestation)
    uid = str(uuid.uuid4())

    request = AdmissionRequest(
        uid=uid,
        kind=kind,
        api_version=doc.get("apiVersion", ""),
        name=name,
        namespace=meta.get("namespace", "default"),
        annotations=annotations,
    )
    response = webhook.evaluate(request)

    score_str = annotations.get(ANNOTATION_COMPLIANCE_SCORE)
    score = float(score_str) if score_str and _is_numeric(score_str) else None

    return ManifestComplianceResult(
        passed=response.allowed,
        reason=response.message,
        attestation_id=annotations.get(ANNOTATION_ATTESTATION_ID),
        compliance_score=score,
        policy=annotations.get(ANNOTATION_POLICY),
        resource_name=name,
        resource_kind=kind,
        annotations_found={k: v for k, v in annotations.items() if k.startswith("squash.ai/")},
    )


def _is_numeric(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# K8s manifest generators
# ---------------------------------------------------------------------------

def generate_webhook_manifest(
    webhook_url: str,
    namespace: str = "squash-system",
    ca_bundle: str = "Cg==",  # placeholder — replace with real CA bundle
    failure_policy: str = "Fail",
) -> str:
    """Generate a Kubernetes ValidatingWebhookConfiguration YAML.

    Args:
        webhook_url: HTTPS URL where squash webhook is hosted.
        namespace:   Kubernetes namespace for squash resources.
        ca_bundle:   Base64-encoded CA certificate bundle (PEM).
        failure_policy: "Fail" to block on webhook error, "Ignore" to allow.

    Returns:
        YAML string ready to apply with ``kubectl apply -f``.
    """
    manifest = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {
            "name": "squash-admission-webhook",
            "labels": {"app": "squash", "component": "admission-webhook"},
            "annotations": {"squash.ai/managed-by": "squash"},
        },
        "webhooks": [
            {
                "name": "squash.ai",
                "admissionReviewVersions": ["v1"],
                "clientConfig": {
                    "url": webhook_url + "/k8s/admission",
                    "caBundle": ca_bundle,
                },
                "rules": [
                    {
                        "apiGroups": ["apps", "batch", ""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": [
                            "deployments", "statefulsets", "daemonsets", "jobs", "pods"
                        ],
                        "scope": "Namespaced",
                    }
                ],
                "failurePolicy": failure_policy,
                "sideEffects": "None",
                "namespaceSelector": {
                    "matchExpressions": [
                        {
                            "key": "squash.ai/enforce",
                            "operator": "In",
                            "values": ["true"],
                        }
                    ]
                },
            }
        ],
    }

    try:
        import yaml  # type: ignore
        return yaml.dump(manifest, default_flow_style=False, sort_keys=False)
    except ImportError:
        return json.dumps(manifest, indent=2)


def generate_namespace_label_manifest(namespace: str = "production") -> str:
    """Generate the kubectl command to enable squash enforcement on a namespace."""
    return (
        f"kubectl label namespace {namespace} squash.ai/enforce=true\n"
        f"# Or apply this manifest:\n"
        f"apiVersion: v1\n"
        f"kind: Namespace\n"
        f"metadata:\n"
        f"  name: {namespace}\n"
        f"  labels:\n"
        f"    squash.ai/enforce: 'true'\n"
    )


def annotate_deployment_command(
    deployment_name: str,
    attestation_id: str,
    compliance_score: float,
    policy: str = "eu-ai-act",
    passed: bool = True,
) -> str:
    """Return the kubectl annotate command to add squash compliance annotations."""
    passed_str = "true" if passed else "false"
    return (
        f"kubectl annotate deployment {deployment_name} \\\n"
        f"  {ANNOTATION_ATTESTATION_ID}={attestation_id} \\\n"
        f"  {ANNOTATION_COMPLIANCE_SCORE}={compliance_score:.1f} \\\n"
        f"  {ANNOTATION_POLICY}={policy} \\\n"
        f"  {ANNOTATION_PASSED}={passed_str}"
    )
