"""squash/integrations/aws_iam.py — AWS IAM identity adapter (D2 / W228).

Normalises AWS IAM roles and users into ``IdentityPrincipal`` objects.

All boto3 calls are lazy-imported so the module builds without the AWS SDK.
In tests, mock at the boundary:

    import unittest.mock as mock
    with mock.patch("squash.integrations.aws_iam._boto3_client") as m:
        m.return_value.get_role.return_value = {...}
        adapter = AWSIAMAdapter(client=m.return_value)
        principals = adapter.list_principals()
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from squash.identity_governor import IdentityPrincipal, PrincipalType, Provider

log = logging.getLogger(__name__)


def _boto3_client(service: str, **kwargs: Any):
    """Lazy import of boto3. Raises ImportError with install instructions."""
    try:
        import boto3  # type: ignore
        return boto3.client(service, **kwargs)
    except ImportError as exc:
        raise ImportError(
            "boto3 required for AWS IAM adapter. Install with: pip install boto3"
        ) from exc


class AWSIAMAdapter:
    """Read AWS IAM principals and normalise to IdentityPrincipal.

    ``client`` can be injected for testing (pass a mock); if None, boto3 is
    called lazily on first use.
    """

    def __init__(
        self,
        client: Any = None,
        region: str = "us-east-1",
        tag_filter: str = "",      # filter by tag value (e.g. "ai-agent")
    ) -> None:
        self._client   = client
        self.region    = region
        self.tag_filter = tag_filter

    def _iam(self) -> Any:
        if self._client is None:
            self._client = _boto3_client("iam", region_name=self.region)
        return self._client

    def get_role(self, role_name: str) -> IdentityPrincipal:
        """Fetch one IAM role by name."""
        iam  = self._iam()
        resp = iam.get_role(RoleName=role_name)
        role = resp["Role"]
        return _role_to_principal(role, iam)

    def list_principals(self, path_prefix: str = "/") -> list[IdentityPrincipal]:
        """List IAM roles, optionally filtered by path prefix."""
        iam = self._iam()
        paginator = iam.get_paginator("list_roles")
        principals: list[IdentityPrincipal] = []
        for page in paginator.paginate(PathPrefix=path_prefix):
            for role in page.get("Roles", []):
                try:
                    principal = _role_to_principal(role, iam)
                    if self.tag_filter:
                        tags = principal.tags
                        if self.tag_filter not in tags.values():
                            continue
                    principals.append(principal)
                except Exception as exc:
                    log.debug("aws_iam: skip %s — %s", role.get("RoleName"), exc)
        return principals


def _role_to_principal(role: dict[str, Any], iam: Any) -> IdentityPrincipal:
    role_name = role["RoleName"]
    role_arn  = role.get("Arn", "")
    created   = role.get("CreateDate")
    created_str = created.isoformat() if isinstance(created, datetime) else str(created or "")

    # Collect attached + inline policies as "scopes"
    scopes: list[str] = []
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)
        scopes.extend(p["PolicyName"] for p in attached.get("AttachedPolicies", []))
    except Exception:
        pass
    try:
        inline = iam.list_role_policies(RoleName=role_name)
        scopes.extend(inline.get("PolicyNames", []))
    except Exception:
        pass

    # Tags
    tags: dict[str, str] = {}
    try:
        tag_resp = iam.list_role_tags(RoleName=role_name)
        tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}
    except Exception:
        pass

    # AWS roles don't rotate — flag by CreateDate age
    rotation_days = None
    if created:
        if isinstance(created, datetime):
            rotation_days = (datetime.now(tz=timezone.utc) - created).days
        elif hasattr(created, "__sub__"):
            rotation_days = (datetime.now(tz=timezone.utc) - created).days

    return IdentityPrincipal(
        principal_id=role_arn,
        name=role_name,
        principal_type=PrincipalType.IAM_ROLE,
        provider=Provider.AWS_IAM,
        scopes=scopes,
        mfa_enabled=False,   # IAM roles use STS, not MFA directly
        token_type="iam_role",
        last_rotation_days=rotation_days,
        created_at=created_str,
        last_used_at=None,
        tags=tags,
        raw_metadata={"arn": role_arn, "path": role.get("Path", "/")},
    )
