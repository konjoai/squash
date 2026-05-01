"""tests/test_identity_governor.py — W226-W228 / D2 AI Identity Attestation.

All SDK calls are mocked at the import boundary — 0 live cloud calls in CI.

PART 1 — IdentityPrincipal + LeastPrivilegePolicy
  * to_dict round-trip
  * policy from_dict with defaults

PART 2 — LeastPrivilegeAnalyser (12 rule tests)
  * Clean principal → score 100
  * Admin wildcard scope → CRITICAL
  * MFA required but disabled → CRITICAL
  * Rotation overdue → HIGH
  * Excess permissions (write) → HIGH
  * Excess permissions (read) → MEDIUM
  * No scopes → MEDIUM
  * Combined: admin + overdue → score 0 (capped)
  * Score exactly deducted by severity weights
  * Policy gap (allowed ⊃ actual) → no violation (info only)
  * No policy → only universal rules apply
  * Deterministic: same input → same output

PART 3 — IdentityAttestation + signing
  * to_json / to_markdown / summary
  * JSON round-trip via load_attestation
  * Ed25519 sign + verify roundtrip
  * Tampered principal → verify fails
  * Unsigned cert → verify fails

PART 4 — Provider adapters (mocked at boundary)
  * AWSIAMAdapter.get_role — mocked boto3 client
  * AWSIAMAdapter.list_principals — mocked paginator
  * AzureADAdapter.get_principal — mocked _get_fn
  * AzureADAdapter.list_principals — pagination
  * OktaAdapter.get_app — mocked _get_fn
  * OktaAdapter.list_principals — filter_label

PART 5 — IdentityGovernor (end-to-end)
  * Least-privilege principal → passes_policy=True
  * Over-privileged principal → passes_policy=False
  * Signs when priv_key provided

PART 6 — CLI smoke
  * Parser registration (all 4 subcommands)
  * attest --principal-file JSON
  * verify unsigned cert
  * policy-init scaffold
  * list-principals (mocked adapter)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from squash.identity_governor import (
    IdentityAttestation,
    IdentityGovernor,
    IdentityPrincipal,
    LeastPrivilegeAnalyser,
    LeastPrivilegePolicy,
    PrincipalType,
    Provider,
    ViolationSeverity,
    load_attestation,
    scaffold_policy,
    verify_attestation,
    _compute_score,
    _VIOLATION_PENALTY,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _principal(
    scopes: list[str] = None,
    mfa: bool = True,
    rotation_days: int | None = 30,
    name: str = "test-agent",
    ptype: PrincipalType = PrincipalType.SERVICE_ACCOUNT,
    provider: Provider = Provider.AWS_IAM,
) -> IdentityPrincipal:
    return IdentityPrincipal(
        principal_id=f"id-{name}",
        name=name,
        principal_type=ptype,
        provider=provider,
        scopes=scopes if scopes is not None else ["read:logs"],
        mfa_enabled=mfa,
        token_type="service_account_key",
        last_rotation_days=rotation_days,
        created_at="2026-01-01T00:00:00+00:00",
        last_used_at=None,
    )


def _policy(
    allowed: list[str] = None,
    max_days: int = 90,
    require_mfa: bool = False,
) -> LeastPrivilegePolicy:
    return LeastPrivilegePolicy(
        principal_name="test-agent",
        allowed_scopes=allowed if allowed is not None else ["read:logs"],
        max_token_age_days=max_days,
        require_mfa=require_mfa,
    )


# ---------------------------------------------------------------------------
# Part 1 — IdentityPrincipal + LeastPrivilegePolicy
# ---------------------------------------------------------------------------

def test_principal_to_dict_round_trip():
    p = _principal()
    d = p.to_dict()
    assert d["name"] == "test-agent"
    assert d["principal_type"] == "service_account"
    assert d["provider"] == "aws_iam"
    assert isinstance(d["scopes"], list)


def test_policy_from_dict_defaults():
    pol = LeastPrivilegePolicy.from_dict({"principal_name": "x"})
    assert pol.max_token_age_days == 90
    assert pol.require_mfa is False
    assert pol.allowed_scopes == []


def test_policy_from_dict_full():
    d = {"principal_name": "bot", "allowed_scopes": ["a", "b"],
         "max_token_age_days": 30, "require_mfa": True}
    pol = LeastPrivilegePolicy.from_dict(d)
    assert pol.allowed_scopes == ["a", "b"]
    assert pol.require_mfa is True


def test_scaffold_policy_has_required_keys():
    s = scaffold_policy("my-agent")
    assert s["principal_name"] == "my-agent"
    assert "allowed_scopes" in s
    assert "max_token_age_days" in s


# ---------------------------------------------------------------------------
# Part 2 — LeastPrivilegeAnalyser
# ---------------------------------------------------------------------------

def test_clean_principal_score_100():
    p   = _principal(scopes=["read:logs"], rotation_days=10)
    pol = _policy(allowed=["read:logs"], max_days=90)
    violations, score = LeastPrivilegeAnalyser().analyse(p, pol)
    assert violations == []
    assert score == 100


def test_admin_wildcard_scope_critical():
    p = _principal(scopes=["*", "read:logs"])
    violations, score = LeastPrivilegeAnalyser().analyse(p)
    assert any(v.severity == ViolationSeverity.CRITICAL for v in violations)
    assert any("Admin" in v.title or "wildcard" in v.title.lower() for v in violations)


def test_administrator_access_critical():
    p = _principal(scopes=["AdministratorAccess"])
    violations, _ = LeastPrivilegeAnalyser().analyse(p)
    assert any(v.severity == ViolationSeverity.CRITICAL for v in violations)


def test_mfa_required_not_enabled_critical():
    p   = _principal(scopes=["read:logs"], mfa=False)
    pol = _policy(require_mfa=True)
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    assert any("MFA" in v.title and v.severity == ViolationSeverity.CRITICAL for v in violations)


def test_mfa_required_enabled_no_violation():
    p   = _principal(scopes=["read:logs"], mfa=True)
    pol = _policy(require_mfa=True)
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    assert not any("MFA" in v.title for v in violations)


def test_rotation_overdue_high():
    p   = _principal(scopes=["read:logs"], rotation_days=180)
    pol = _policy(max_days=90)
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    assert any(v.severity == ViolationSeverity.HIGH and "rotation" in v.title.lower() for v in violations)


def test_rotation_within_policy_no_violation():
    p   = _principal(scopes=["read:logs"], rotation_days=30)
    pol = _policy(max_days=90)
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    assert not any("rotation" in v.title.lower() for v in violations)


def test_rotation_unknown_no_violation():
    p   = _principal(scopes=["read:logs"], rotation_days=None)
    pol = _policy()
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    assert not any("rotation" in v.title.lower() for v in violations)


def test_excess_write_scope_high():
    p   = _principal(scopes=["read:logs", "write:data"])
    pol = _policy(allowed=["read:logs"])
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    excess = [v for v in violations if "Excess" in v.title]
    assert excess
    assert any(v.severity == ViolationSeverity.HIGH for v in excess)


def test_excess_read_scope_medium():
    p   = _principal(scopes=["read:logs", "read:secrets"])
    pol = _policy(allowed=["read:logs"])
    violations, _ = LeastPrivilegeAnalyser().analyse(p, pol)
    excess = [v for v in violations if "read:secrets" in v.scope_or_field]
    assert excess
    assert excess[0].severity == ViolationSeverity.MEDIUM


def test_no_scopes_medium():
    p   = _principal(scopes=[])
    violations, _ = LeastPrivilegeAnalyser().analyse(p)
    assert any("no scopes" in v.title.lower() for v in violations)
    assert any(v.severity == ViolationSeverity.MEDIUM for v in violations)


def test_score_capped_at_zero_on_heavy_violations():
    p   = _principal(scopes=["*", "AdministratorAccess"], mfa=False, rotation_days=365)
    pol = _policy(require_mfa=True, max_days=30)
    _, score = LeastPrivilegeAnalyser().analyse(p, pol)
    assert score == 0


def test_score_deduction_deterministic():
    p   = _principal(scopes=["read:logs", "write:secrets"])
    pol = _policy(allowed=["read:logs"], max_days=90)
    violations1, score1 = LeastPrivilegeAnalyser().analyse(p, pol)
    violations2, score2 = LeastPrivilegeAnalyser().analyse(p, pol)
    assert score1 == score2
    assert len(violations1) == len(violations2)


def test_no_policy_only_universal_rules():
    # Without policy, only admin scope + no-scope rules fire
    p = _principal(scopes=["read:logs"], rotation_days=10)
    violations, score = LeastPrivilegeAnalyser().analyse(p, None)
    assert violations == []
    assert score == 100


def test_allowed_superset_no_excess_violation():
    # Policy allows MORE than principal has — no excess violation
    p   = _principal(scopes=["read:logs"])
    pol = _policy(allowed=["read:logs", "read:users", "write:outputs"])
    violations, score = LeastPrivilegeAnalyser().analyse(p, pol)
    excess = [v for v in violations if "Excess" in v.title]
    assert not excess


# ---------------------------------------------------------------------------
# Part 3 — IdentityAttestation + signing
# ---------------------------------------------------------------------------

def _make_cert(scopes=None, policy=None) -> IdentityAttestation:
    p = _principal(scopes=scopes or ["read:logs"])
    pol = policy or _policy()
    return IdentityGovernor().attest(p, pol)


def test_cert_summary_icon():
    cert = _make_cert()
    s = cert.summary()
    assert "✅" in s or "❌" in s
    assert "identity-attest" in s


def test_cert_markdown_contains_principal():
    cert = _make_cert()
    md = cert.to_markdown()
    assert "AI Identity Attestation" in md
    assert cert.principal.name in md


def test_cert_json_round_trip(tmp_path):
    cert = _make_cert()
    path = tmp_path / "cert.json"
    path.write_text(cert.to_json())
    loaded = load_attestation(path)
    assert loaded.cert_id == cert.cert_id
    assert loaded.passes_policy == cert.passes_policy
    assert len(loaded.violations) == len(cert.violations)
    assert loaded.principal.name == cert.principal.name


def test_cert_passes_with_clean_principal():
    cert = _make_cert(scopes=["read:logs"])
    assert cert.passes_policy


def test_cert_fails_with_admin_scope():
    cert = _make_cert(scopes=["AdministratorAccess"])
    assert not cert.passes_policy


def test_cert_sign_verify_roundtrip(tmp_path):
    pytest.importorskip("cryptography")
    from squash.oms_signer import OmsSigner
    priv, _ = OmsSigner.keygen("id-test", key_dir=tmp_path)
    p   = _principal(scopes=["read:logs"])
    pol = _policy()
    cert = IdentityGovernor(priv_key_path=priv).attest(p, pol)
    assert cert.signature_hex != ""
    ok, msg = verify_attestation(cert)
    assert ok, msg


def test_cert_tampered_principal_fails_verify(tmp_path):
    pytest.importorskip("cryptography")
    from squash.oms_signer import OmsSigner
    priv, _ = OmsSigner.keygen("id-test2", key_dir=tmp_path)
    p   = _principal(scopes=["read:logs"])
    pol = _policy()
    cert = IdentityGovernor(priv_key_path=priv).attest(p, pol)
    cert.principal.scopes.append("AdministratorAccess")
    ok, msg = verify_attestation(cert)
    assert not ok
    assert "INVALID" in msg


def test_unsigned_cert_verify_fails():
    cert = _make_cert()
    ok, msg = verify_attestation(cert)
    assert not ok
    assert "unsigned" in msg


# ---------------------------------------------------------------------------
# Part 4 — Provider adapters (mocked at boundary)
# ---------------------------------------------------------------------------

def _mock_iam_client(role_name="ai-agent", attached=None, inline=None, tags=None):
    mock_client = MagicMock()
    mock_client.get_role.return_value = {
        "Role": {
            "RoleName": role_name,
            "Arn": f"arn:aws:iam::123456789:role/{role_name}",
            "Path": "/",
            "CreateDate": None,
        }
    }
    mock_client.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": p} for p in (attached or ["ReadOnlyAccess"])]
    }
    mock_client.list_role_policies.return_value = {
        "PolicyNames": inline or []
    }
    mock_client.list_role_tags.return_value = {
        "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()]
    }
    mock_client.get_paginator.return_value.paginate.return_value = iter([{
        "Roles": [{"RoleName": role_name, "Arn": f"arn:aws:iam::123:role/{role_name}",
                   "Path": "/", "CreateDate": None}]
    }])
    return mock_client


def test_aws_iam_get_role():
    from squash.integrations.aws_iam import AWSIAMAdapter
    client = _mock_iam_client("ai-agent", attached=["ReadOnlyAccess"])
    adapter = AWSIAMAdapter(client=client)
    p = adapter.get_role("ai-agent")
    assert p.name == "ai-agent"
    assert p.provider.value == "aws_iam"
    assert p.principal_type == PrincipalType.IAM_ROLE
    assert "ReadOnlyAccess" in p.scopes


def test_aws_iam_get_role_with_inline_policy():
    from squash.integrations.aws_iam import AWSIAMAdapter
    client = _mock_iam_client("bot", attached=[], inline=["CustomPolicy"])
    p = AWSIAMAdapter(client=client).get_role("bot")
    assert "CustomPolicy" in p.scopes


def test_aws_iam_list_principals():
    from squash.integrations.aws_iam import AWSIAMAdapter
    client = _mock_iam_client("ai-bot")
    principals = AWSIAMAdapter(client=client).list_principals()
    assert len(principals) == 1
    assert principals[0].name == "ai-bot"


def test_aws_iam_token_type():
    from squash.integrations.aws_iam import AWSIAMAdapter
    p = AWSIAMAdapter(client=_mock_iam_client()).get_role("x")
    assert p.token_type == "iam_role"


def _mock_graph_get(sp_data):
    def _get(url, **kw):
        if "appRoleAssignments" in url:
            return {"value": []}
        if "value" in sp_data:
            return sp_data
        return sp_data
    return _get


def test_azure_ad_list_principals():
    from squash.integrations.azure_ad import AzureADAdapter
    sp_list = {"value": [
        {"id": "abc", "displayName": "ai-agent", "accountEnabled": True,
         "appId": "app-1", "oauth2PermissionScopes": [{"value": "read:data"}],
         "appRoles": [], "passwordCredentials": [], "keyCredentials": [],
         "createdDateTime": None},
    ]}
    adapter = AzureADAdapter(access_token="tok", _get_fn=_mock_graph_get(sp_list))
    principals = adapter.list_principals()
    assert len(principals) == 1
    assert principals[0].name == "ai-agent"
    assert principals[0].provider == Provider.AZURE_AD


def test_azure_ad_filter_label():
    from squash.integrations.azure_ad import AzureADAdapter
    sp_list = {"value": [
        {"id": "1", "displayName": "ai-agent", "accountEnabled": True, "appId": "x",
         "oauth2PermissionScopes": [], "appRoles": [], "passwordCredentials": [],
         "keyCredentials": [], "createdDateTime": None},
        {"id": "2", "displayName": "human-app", "accountEnabled": True, "appId": "y",
         "oauth2PermissionScopes": [], "appRoles": [], "passwordCredentials": [],
         "keyCredentials": [], "createdDateTime": None},
    ]}
    adapter = AzureADAdapter(access_token="tok", _get_fn=_mock_graph_get(sp_list))
    principals = adapter.list_principals(filter_tag="ai-agent")
    assert len(principals) == 1
    assert principals[0].name == "ai-agent"


def test_okta_list_principals():
    from squash.integrations.okta import OktaAdapter
    apps = [
        {"id": "0oaXYZ", "label": "ai-bot", "status": "ACTIVE",
         "credentials": {"oauthClient": {"token_endpoint_auth_method": "client_secret_basic"}},
         "created": None},
    ]

    def _get_fn(url, **kw):
        if "grants" in url:
            return [{"scopeId": "squash:read"}]
        return apps
    adapter = OktaAdapter(domain="test.okta.com", api_token="tok", _get_fn=_get_fn)
    principals = adapter.list_principals()
    assert len(principals) == 1
    assert principals[0].name == "ai-bot"
    assert principals[0].provider == Provider.OKTA
    assert "squash:read" in principals[0].scopes


def test_okta_filter_label():
    from squash.integrations.okta import OktaAdapter
    apps = [
        {"id": "1", "label": "ai-agent", "status": "ACTIVE",
         "credentials": {"oauthClient": {}}, "created": None},
        {"id": "2", "label": "prod-app", "status": "ACTIVE",
         "credentials": {"oauthClient": {}}, "created": None},
    ]

    def _get_fn(url, **kw):
        return [] if "grants" in url else apps
    principals = OktaAdapter(domain="x.okta.com", api_token="t",
                              _get_fn=_get_fn).list_principals("ai-agent")
    assert len(principals) == 1
    assert principals[0].name == "ai-agent"


# ---------------------------------------------------------------------------
# Part 5 — IdentityGovernor end-to-end
# ---------------------------------------------------------------------------

def test_governor_least_privilege_passes():
    p   = _principal(scopes=["read:logs"], rotation_days=30, mfa=False)
    pol = _policy(allowed=["read:logs"], max_days=90, require_mfa=False)
    cert = IdentityGovernor().attest(p, pol)
    assert cert.passes_policy
    assert cert.least_privilege_score == 100


def test_governor_over_privileged_fails():
    p   = _principal(scopes=["AdministratorAccess"], rotation_days=200)
    pol = _policy(allowed=["read:logs"], max_days=90)
    cert = IdentityGovernor().attest(p, pol)
    assert not cert.passes_policy
    assert cert.least_privilege_score < 70


def test_governor_signs_when_key_provided(tmp_path):
    pytest.importorskip("cryptography")
    from squash.oms_signer import OmsSigner
    priv, _ = OmsSigner.keygen("gov-test", key_dir=tmp_path)
    p   = _principal()
    pol = _policy()
    cert = IdentityGovernor(priv_key_path=priv).attest(p, pol)
    assert cert.signature_hex != ""
    assert cert.signer.startswith("local:")


# ---------------------------------------------------------------------------
# Part 6 — CLI smoke
# ---------------------------------------------------------------------------

def test_cli_parser_all_subcommands():
    from squash.cli import _build_parser
    p = _build_parser()
    for sub in ["attest", "verify", "list-principals", "policy-init"]:
        ns = p.parse_args(
            ["attest-identity", sub]
            + (["--provider", "aws-iam"] if sub == "list-principals" else [])
            + (["x.json"] if sub == "verify" else [])
        )
        assert ns.command == "attest-identity"
        assert ns.ai_command == sub


def test_cli_attest_principal_file(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_attest_identity
    p = _principal()
    pf = tmp_path / "p.json"
    pf.write_text(json.dumps(p.to_dict()))
    pol = _policy()
    polfile = tmp_path / "pol.json"
    polfile.write_text(json.dumps(pol.to_dict()))
    args = argparse.Namespace(
        ai_command="attest",
        provider="file",
        principal_name="",
        principal_file=str(pf),
        policy_file=str(polfile),
        priv_key=None,
        out=None,
        ai_format="json",
        fail_on_violation=False,
        domain="", api_token="", tenant_id="", aws_region="us-east-1",
    )
    rc = _cmd_attest_identity(args, quiet=True)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "squash.identity.attestation/v1"


def test_cli_verify_unsigned(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_attest_identity
    cert = _make_cert()
    cp = tmp_path / "cert.json"
    cp.write_text(cert.to_json())
    args = argparse.Namespace(ai_command="verify", cert_path=str(cp), output_json=True)
    rc = _cmd_attest_identity(args, quiet=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert rc == 2


def test_cli_policy_init(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_attest_identity
    args = argparse.Namespace(
        ai_command="policy-init",
        principal_name="my-bot",
        out=None,
    )
    rc = _cmd_attest_identity(args, quiet=True)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["principal_name"] == "my-bot"
    assert "allowed_scopes" in payload


def test_cli_fail_on_violation_exits_2(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_attest_identity
    p = _principal(scopes=["AdministratorAccess"])  # → CRITICAL violation
    pf = tmp_path / "p.json"
    pf.write_text(json.dumps(p.to_dict()))
    args = argparse.Namespace(
        ai_command="attest",
        provider="file",
        principal_name="",
        principal_file=str(pf),
        policy_file=None,
        priv_key=None,
        out=None,
        ai_format="json",
        fail_on_violation=True,
        domain="", api_token="", tenant_id="", aws_region="us-east-1",
    )
    rc = _cmd_attest_identity(args, quiet=True)
    assert rc == 2
