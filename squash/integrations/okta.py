"""squash/integrations/okta.py — Okta identity adapter (D2 / W228).

Normalises Okta service apps into ``IdentityPrincipal`` objects via the
Okta REST API (stdlib urllib — no okta SDK required).

All network calls are mockable:

    import unittest.mock as mock
    with mock.patch("squash.integrations.okta._okta_get") as m:
        m.return_value = [{"id": "0oaXYZ", "label": "ai-agent", ...}]
        adapter = OktaAdapter(domain="acme.okta.com", api_token="test")
        principals = adapter.list_principals()
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from squash.identity_governor import IdentityPrincipal, PrincipalType, Provider

log = logging.getLogger(__name__)


def _okta_get(url: str, token: str, timeout: int = 15) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class OktaAdapter:
    """Read Okta service app principals.

    ``_get_fn`` is injectable for testing.
    """

    def __init__(
        self,
        domain: str = "",
        api_token: str = "",
        _get_fn: Any = None,
    ) -> None:
        self.base  = f"https://{domain}/api/v1"
        self.token = api_token
        self._get  = _get_fn or (lambda url, **kw: _okta_get(url, self.token))

    def get_app(self, app_id: str) -> IdentityPrincipal:
        app    = self._get(f"{self.base}/apps/{app_id}")
        scopes = self._app_scopes(app_id)
        return _app_to_principal(app, scopes)

    def list_principals(self, filter_label: str = "") -> list[IdentityPrincipal]:
        url  = f"{self.base}/apps?limit=100"
        apps = self._get(url)
        principals: list[IdentityPrincipal] = []
        for app in apps if isinstance(apps, list) else []:
            if filter_label and filter_label.lower() not in app.get("label", "").lower():
                continue
            try:
                scopes = self._app_scopes(app.get("id", ""))
                principals.append(_app_to_principal(app, scopes))
            except Exception as exc:
                log.debug("okta: skip %s — %s", app.get("label"), exc)
        return principals

    def _app_scopes(self, app_id: str) -> list[str]:
        try:
            grants = self._get(f"{self.base}/apps/{app_id}/grants")
            return [g.get("scopeId", "") for g in (grants if isinstance(grants, list) else [])]
        except Exception:
            return []

    def _api_token_rotation_days(self, app: dict[str, Any]) -> int | None:
        # Okta apps use OAuth 2.0 tokens; actual rotation tracking
        # requires checking the app's credentials.oauthClient.token_endpoint_auth_method
        creds = app.get("credentials", {})
        oac   = creds.get("oauthClient", {})
        # If client secret exists, we can't get creation date via API without
        # admin access — return None to flag as unknown
        if oac.get("client_secret"):
            return None
        return None


def _app_to_principal(app: dict[str, Any], scopes: list[str]) -> IdentityPrincipal:
    app_id  = app.get("id", "")
    label   = app.get("label") or app.get("name") or app_id
    status  = app.get("status", "ACTIVE")
    created = app.get("created")

    creds      = app.get("credentials", {})
    oac        = creds.get("oauthClient", {})
    auth_method= oac.get("token_endpoint_auth_method", "client_secret_basic")
    token_type = "oauth2_client_credentials"

    # Deduplicate scopes
    clean_scopes = list(filter(None, set(scopes)))

    return IdentityPrincipal(
        principal_id=app_id,
        name=label,
        principal_type=PrincipalType.OKTA_SERVICE_APP,
        provider=Provider.OKTA,
        scopes=clean_scopes,
        mfa_enabled=False,   # service apps don't use MFA
        token_type=token_type,
        last_rotation_days=None,   # not available via Okta API without admin grants
        created_at=created,
        last_used_at=None,
        tags={"status": status, "auth_method": auth_method},
        raw_metadata={"app_id": app_id, "status": status},
    )
