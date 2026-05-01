"""squash/integrations/azure_ad.py — Azure AD identity adapter (D2 / W228).

Normalises Azure AD service principals into ``IdentityPrincipal`` objects via
Microsoft Graph REST API (stdlib urllib — no azure-identity SDK required unless
you want token refresh).

All network calls are mockable:

    import unittest.mock as mock
    with mock.patch("squash.integrations.azure_ad._graph_get") as m:
        m.return_value = {"value": [...]}
        adapter = AzureADAdapter(access_token="test-token")
        principals = adapter.list_principals()
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from squash.identity_governor import IdentityPrincipal, PrincipalType, Provider

log = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _graph_get(url: str, token: str, timeout: int = 15) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class AzureADAdapter:
    """Read Azure AD service principals via Microsoft Graph.

    ``_get_fn`` is injectable for testing — pass a callable that replaces
    ``_graph_get``.
    """

    def __init__(
        self,
        access_token: str = "",
        tenant_id: str = "",
        _get_fn: Any = None,
    ) -> None:
        self.access_token = access_token
        self.tenant_id    = tenant_id
        self._get         = _get_fn or (lambda url, **kw: _graph_get(url, self.access_token))

    def get_principal(self, object_id: str) -> IdentityPrincipal:
        sp = self._get(f"{_GRAPH_BASE}/servicePrincipals/{object_id}")
        return _sp_to_principal(sp, self)

    def list_principals(self, filter_tag: str = "") -> list[IdentityPrincipal]:
        """List service principals. If filter_tag is set, return only matching displayName."""
        url = f"{_GRAPH_BASE}/servicePrincipals?$top=100"
        principals: list[IdentityPrincipal] = []
        while url:
            resp = self._get(url)
            for sp in resp.get("value", []):
                if filter_tag and filter_tag.lower() not in sp.get("displayName", "").lower():
                    continue
                try:
                    principals.append(_sp_to_principal(sp, self))
                except Exception as exc:
                    log.debug("azure_ad: skip %s — %s", sp.get("displayName"), exc)
            url = resp.get("@odata.nextLink", "")
        return principals

    def _app_role_assignments(self, object_id: str) -> list[str]:
        try:
            resp = self._get(f"{_GRAPH_BASE}/servicePrincipals/{object_id}/appRoleAssignments")
            return [r.get("principalDisplayName", "") or r.get("id", "") for r in resp.get("value", [])]
        except Exception:
            return []

    def _credentials(self, sp: dict[str, Any]) -> tuple[int | None, str]:
        """Return (rotation_days, token_type) from password/key credentials."""
        pw_creds  = sp.get("passwordCredentials", [])
        key_creds = sp.get("keyCredentials", [])
        all_creds = pw_creds + key_creds
        if not all_creds:
            return None, "none"
        # Most recently created credential
        import datetime
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        oldest: datetime.datetime | None = None
        for c in all_creds:
            start = c.get("startDateTime") or c.get("customKeyIdentifier")
            if isinstance(start, str) and start:
                try:
                    dt = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))
                    if oldest is None or dt < oldest:
                        oldest = dt
                except ValueError:
                    pass
        days = (now - oldest).days if oldest else None
        token_type = "client_secret" if pw_creds else "certificate"
        return days, token_type


def _sp_to_principal(sp: dict[str, Any], adapter: AzureADAdapter) -> IdentityPrincipal:
    object_id    = sp.get("id", "")
    display_name = sp.get("displayName", object_id)
    enabled      = sp.get("accountEnabled", True)
    app_id       = sp.get("appId", "")

    # Scopes = oauth2PermissionScopes + app roles
    scopes: list[str] = []
    for s in sp.get("oauth2PermissionScopes", []):
        scopes.append(s.get("value") or s.get("id", ""))
    for r in sp.get("appRoles", []):
        scopes.append(r.get("value") or r.get("id", ""))
    # Also collect role assignments
    scopes.extend(adapter._app_role_assignments(object_id))

    rotation_days, token_type = adapter._credentials(sp)

    return IdentityPrincipal(
        principal_id=object_id,
        name=display_name,
        principal_type=PrincipalType.AZURE_SERVICE_PRINCIPAL,
        provider=Provider.AZURE_AD,
        scopes=list(filter(None, set(scopes))),
        mfa_enabled=False,   # service principals don't use MFA
        token_type=token_type,
        last_rotation_days=rotation_days,
        created_at=sp.get("createdDateTime"),
        last_used_at=None,
        tags={"app_id": app_id, "enabled": str(enabled)},
        raw_metadata={"object_id": object_id, "account_enabled": enabled},
    )
