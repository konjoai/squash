"""W150 — Helm chart for Kubernetes admission controller tests."""
from __future__ import annotations

import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
HELM_DIR = REPO_ROOT / "integrations" / "kubernetes-helm"
CHART_YAML = HELM_DIR / "Chart.yaml"
VALUES_YAML = HELM_DIR / "values.yaml"
TEMPLATES_DIR = HELM_DIR / "templates"


class TestHelmChartStructure:
    def test_helm_dir_exists(self):
        assert HELM_DIR.exists()

    def test_chart_yaml_exists(self):
        assert CHART_YAML.exists()

    def test_values_yaml_exists(self):
        assert VALUES_YAML.exists()

    def test_templates_dir_exists(self):
        assert TEMPLATES_DIR.exists()

    def test_deployment_template_exists(self):
        assert (TEMPLATES_DIR / "deployment.yaml").exists()

    def test_service_template_exists(self):
        assert (TEMPLATES_DIR / "service.yaml").exists()

    def test_validating_webhook_template_exists(self):
        assert (TEMPLATES_DIR / "validatingwebhookconfiguration.yaml").exists()

    def test_helpers_tpl_exists(self):
        assert (TEMPLATES_DIR / "_helpers.tpl").exists()


class TestChartYaml:
    def _doc(self):
        return yaml.safe_load(CHART_YAML.read_text())

    def test_is_valid_yaml(self):
        assert self._doc() is not None

    def test_has_api_version(self):
        doc = self._doc()
        assert "apiVersion" in doc
        assert doc["apiVersion"] == "v2"

    def test_has_name(self):
        assert "name" in self._doc()

    def test_has_description(self):
        assert "description" in self._doc()

    def test_has_version(self):
        assert "version" in self._doc()

    def test_has_app_version(self):
        assert "appVersion" in self._doc()

    def test_type_is_application(self):
        assert self._doc().get("type") == "application"

    def test_name_matches_squash(self):
        assert "squash" in self._doc()["name"].lower()


class TestValuesYaml:
    def _doc(self):
        return yaml.safe_load(VALUES_YAML.read_text())

    def test_is_valid_yaml(self):
        assert self._doc() is not None

    def test_has_replica_count(self):
        doc = self._doc()
        assert "replicaCount" in doc
        assert isinstance(doc["replicaCount"], int)
        assert doc["replicaCount"] >= 1

    def test_has_image_config(self):
        doc = self._doc()
        assert "image" in doc
        assert "repository" in doc["image"]

    def test_image_includes_ghcr(self):
        doc = self._doc()
        assert "ghcr.io" in doc["image"]["repository"]

    def test_has_service_config(self):
        assert "service" in self._doc()

    def test_has_webhook_config(self):
        doc = self._doc()
        assert "webhook" in doc

    def test_has_webhook_port(self):
        doc = self._doc()
        assert "port" in doc["webhook"]

    def test_webhook_port_is_8443(self):
        doc = self._doc()
        assert doc["webhook"]["port"] == 8443

    def test_has_tls_config(self):
        assert "tls" in self._doc()

    def test_has_resources(self):
        assert "resources" in self._doc()

    def test_has_exclude_namespaces(self):
        doc = self._doc()
        assert "excludeNamespaces" in doc["webhook"]
        assert "kube-system" in doc["webhook"]["excludeNamespaces"]

    def test_has_policies(self):
        doc = self._doc()
        assert "policies" in doc["webhook"]
        assert len(doc["webhook"]["policies"]) >= 1

    def test_has_rbac_config(self):
        assert "rbac" in self._doc()

    def test_has_security_context(self):
        assert "securityContext" in self._doc()

    def test_runs_as_non_root(self):
        doc = self._doc()
        assert doc.get("podSecurityContext", {}).get("runAsNonRoot") is True


class TestDeploymentTemplate:
    def _src(self):
        return (TEMPLATES_DIR / "deployment.yaml").read_text()

    def test_is_deployment_kind(self):
        assert "kind: Deployment" in self._src()

    def test_uses_replica_count_value(self):
        assert "replicaCount" in self._src()

    def test_uses_image_value(self):
        src = self._src()
        assert ".Values.image.repository" in src

    def test_has_liveness_probe(self):
        assert "livenessProbe" in self._src()

    def test_has_readiness_probe(self):
        assert "readinessProbe" in self._src()

    def test_mounts_tls_certs(self):
        assert "tls-certs" in self._src()

    def test_exposes_webhook_port(self):
        assert "webhook.port" in self._src() or "8443" in self._src()

    def test_uses_security_context(self):
        assert "securityContext" in self._src()


class TestServiceTemplate:
    def _src(self):
        return (TEMPLATES_DIR / "service.yaml").read_text()

    def test_is_service_kind(self):
        assert "kind: Service" in self._src()

    def test_uses_service_type_value(self):
        assert "service.type" in self._src()

    def test_uses_service_port_value(self):
        assert "service.port" in self._src()

    def test_has_selector(self):
        assert "selector:" in self._src()


class TestValidatingWebhookTemplate:
    def _src(self):
        return (TEMPLATES_DIR / "validatingwebhookconfiguration.yaml").read_text()

    def test_is_validating_webhook_kind(self):
        assert "ValidatingWebhookConfiguration" in self._src()

    def test_admission_review_version_v1(self):
        assert "v1" in self._src()

    def test_has_failure_policy(self):
        assert "failurePolicy" in self._src()

    def test_has_side_effects(self):
        assert "sideEffects" in self._src()

    def test_has_rules_for_pods(self):
        assert "pods" in self._src()

    def test_has_namespace_selector(self):
        assert "namespaceSelector" in self._src()

    def test_has_client_config_service(self):
        assert "service:" in self._src()

    def test_webhook_path_is_validate(self):
        assert "/validate" in self._src()


class TestHelpersTemplate:
    def _src(self):
        return (TEMPLATES_DIR / "_helpers.tpl").read_text()

    def test_defines_fullname(self):
        assert "squash-webhook.fullname" in self._src()

    def test_defines_labels(self):
        assert "squash-webhook.labels" in self._src()

    def test_defines_selector_labels(self):
        assert "squash-webhook.selectorLabels" in self._src()

    def test_defines_service_account_name(self):
        assert "squash-webhook.serviceAccountName" in self._src()
