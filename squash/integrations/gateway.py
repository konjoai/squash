"""squash/integrations/gateway.py — Track B / B5 — API Gateway runtime gate.

Runtime enforcement for inference requests. Build-time gates (registry
promotion, GitOps admission) prove the model is *deployable*. The gateway
gate proves the deployed model is *still compliant right now* — at the
moment the request hits production.

Two gateway surfaces are supported:

  • Kong (declarative-config Lua plugin)
  • AWS API Gateway (Python Lambda authorizer + SAM template)

Both call the same in-process verifier (`evaluate_token`) — the only
difference is how the host runtime delivers the inbound request.

Token formats accepted on the `X-Squash-Attestation` header (configurable):

    att://<host>/<org>/<model>/<entry_id>      — registry URI
    <entry_id>                                 — bare 16-char entry id
    sha256:<hex>                               — attestation content hash

The verifier returns a structured GatewayDecision; the host plugin
translates it into the host's native deny/allow shape:

  • Kong  — kong.response.exit(status, body)
  • Lambda — IAM policy document (Allow / Deny on methodArn)

Decision contract:

    allow == True   ⇒ gateway forwards upstream
    allow == False  ⇒ gateway rejects with `http_status` (401 missing creds,
                       403 attestation invalid/expired/revoked/below-score)
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from typing import Any

# ── Decision model ───────────────────────────────────────────────────────────

REASON_OK              = "OK"
REASON_MISSING_TOKEN   = "MISSING_TOKEN"
REASON_MALFORMED_TOKEN = "MALFORMED_TOKEN"
REASON_NOT_FOUND       = "ENTRY_NOT_FOUND"
REASON_REVOKED         = "REVOKED"
REASON_HASH_MISMATCH   = "HASH_MISMATCH"
REASON_LOW_SCORE       = "BELOW_MIN_SCORE"
REASON_EXPIRED         = "EXPIRED"
REASON_FRAMEWORK_GAP   = "REQUIRED_FRAMEWORK_MISSING"


@dataclass
class GatewayDecision:
    allow: bool
    reason: str
    http_status: int
    entry_id: str = ""
    model_id: str = ""
    compliance_score: float | None = None
    detail: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_kong_exit(self) -> tuple[int, dict[str, Any]]:
        return self.http_status, {
            "message": "squash: request rejected" if not self.allow else "squash: ok",
            "reason": self.reason,
            "detail": self.detail,
            "entry_id": self.entry_id,
        }

    def to_iam_policy(self, principal_id: str, method_arn: str) -> dict[str, Any]:
        effect = "Allow" if self.allow else "Deny"
        return {
            "principalId": principal_id or "anonymous",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": method_arn,
                }],
            },
            "context": {
                "squash_reason": self.reason,
                "squash_entry_id": self.entry_id,
                "squash_score": str(self.compliance_score) if self.compliance_score is not None else "",
                "squash_model_id": self.model_id,
            },
        }


def _parse_token(token: str) -> tuple[str, str]:
    """Return (kind, value). kind ∈ {'uri', 'sha256', 'entry_id', 'invalid'}."""
    if not token or not isinstance(token, str):
        return "invalid", ""
    t = token.strip()
    if not t:
        return "invalid", ""
    if t.startswith("att://"):
        tail = t[len("att://"):].strip("/")
        parts = tail.split("/")
        if len(parts) < 1 or not parts[-1]:
            return "invalid", ""
        return "uri", parts[-1]
    if t.startswith("sha256:"):
        h = t[len("sha256:"):]
        if len(h) >= 16 and all(c in "0123456789abcdef" for c in h.lower()):
            return "sha256", h.lower()
        return "invalid", ""
    if 8 <= len(t) <= 64 and all(c in "0123456789abcdef" for c in t.lower()):
        return "entry_id", t.lower()
    return "invalid", ""


def evaluate_token(
    token: str | None,
    registry,
    min_score: float = 0.8,
    max_age_days: int | None = None,
    required_frameworks: list[str] | None = None,
    now: datetime.datetime | None = None,
) -> GatewayDecision:
    """Inspect a request token and return an allow/deny decision.

    The registry argument is duck-typed — anything exposing
    `get_entry(entry_id) -> RegistryEntry|None` and
    `verify(entry_id) -> VerificationResult` works.
    """
    if token is None or not str(token).strip():
        return GatewayDecision(
            allow=False, reason=REASON_MISSING_TOKEN, http_status=401,
            detail="No squash attestation token presented on request",
        )

    kind, value = _parse_token(str(token))
    if kind == "invalid":
        return GatewayDecision(
            allow=False, reason=REASON_MALFORMED_TOKEN, http_status=401,
            detail=f"Token does not parse as att:// URI, sha256:hex, or entry_id (got len={len(token)})",
        )

    entry_id = value[:16] if kind == "sha256" else value
    entry = registry.get_entry(entry_id)
    if entry is None:
        return GatewayDecision(
            allow=False, reason=REASON_NOT_FOUND, http_status=403,
            entry_id=entry_id,
            detail=f"No attestation found for entry_id={entry_id!r}",
        )

    vr = registry.verify(entry_id)
    if vr.revoked:
        return GatewayDecision(
            allow=False, reason=REASON_REVOKED, http_status=403,
            entry_id=entry_id, model_id=entry.model_id,
            detail="Attestation has been revoked by issuer",
        )
    if not vr.hash_verified:
        return GatewayDecision(
            allow=False, reason=REASON_HASH_MISMATCH, http_status=403,
            entry_id=entry_id, model_id=entry.model_id,
            detail=vr.error or "Attestation payload hash mismatch",
        )

    score = entry.compliance_score
    norm_min = min_score / 100.0 if min_score > 1.0 else min_score
    if score is not None and score < norm_min:
        return GatewayDecision(
            allow=False, reason=REASON_LOW_SCORE, http_status=403,
            entry_id=entry_id, model_id=entry.model_id, compliance_score=score,
            detail=f"Score {score:.3f} < min {norm_min:.3f}",
        )

    if max_age_days is not None:
        try:
            published = datetime.datetime.fromisoformat(entry.published_at)
        except ValueError:
            published = None
        if published is not None:
            ref = now or datetime.datetime.now(datetime.timezone.utc)
            if published.tzinfo is None:
                published = published.replace(tzinfo=datetime.timezone.utc)
            age = (ref - published).days
            if age > max_age_days:
                return GatewayDecision(
                    allow=False, reason=REASON_EXPIRED, http_status=403,
                    entry_id=entry_id, model_id=entry.model_id,
                    compliance_score=score,
                    detail=f"Attestation age {age}d > max {max_age_days}d",
                )

    if required_frameworks:
        have = {f.lower() for f in (entry.frameworks or [])}
        need = {f.lower() for f in required_frameworks}
        missing = sorted(need - have)
        if missing:
            return GatewayDecision(
                allow=False, reason=REASON_FRAMEWORK_GAP, http_status=403,
                entry_id=entry_id, model_id=entry.model_id,
                compliance_score=score,
                detail=f"Missing required frameworks: {','.join(missing)}",
            )

    return GatewayDecision(
        allow=True, reason=REASON_OK, http_status=200,
        entry_id=entry_id, model_id=entry.model_id,
        compliance_score=score, detail="ok",
        headers={
            "X-Squash-Attestation-Id": entry_id,
            "X-Squash-Score": f"{score:.3f}" if score is not None else "",
            "X-Squash-Model": entry.model_id,
        },
    )


# ── Config emitters ──────────────────────────────────────────────────────────


def emit_kong_config(
    min_score: float = 0.8,
    header_name: str = "X-Squash-Attestation",
    squash_api_url: str = "https://api.getsquash.dev",
    service_name: str = "ai-inference",
    upstream_url: str = "http://upstream-inference:8080",
    route_paths: list[str] | None = None,
    max_age_days: int | None = 30,
    required_frameworks: list[str] | None = None,
) -> str:
    paths = route_paths or ["/predict", "/v1/chat/completions"]
    fw = required_frameworks or []
    fw_yaml = "[" + ", ".join(json.dumps(f) for f in fw) + "]"
    paths_yaml = "\n".join(f"        - {json.dumps(p)}" for p in paths)
    return f"""# Kong declarative config — squash-attest gateway gate
_format_version: "3.0"

services:
  - name: {service_name}
    url: {upstream_url}
    routes:
      - name: {service_name}-route
        paths:
{paths_yaml}
    plugins:
      - name: squash-attest
        config:
          squash_api_url: {squash_api_url}
          header_name: {header_name}
          min_score: {float(min_score)}
          max_age_days: {max_age_days if max_age_days is not None else "null"}
          required_frameworks: {fw_yaml}
          fail_open: false
          cache_ttl_seconds: 60
"""


def emit_aws_apigw_sam(
    min_score: float = 0.8,
    function_name: str = "SquashAttestAuthorizer",
    squash_api_url: str = "https://api.getsquash.dev",
    header_name: str = "X-Squash-Attestation",
    max_age_days: int | None = 30,
    required_frameworks: list[str] | None = None,
    runtime: str = "python3.11",
) -> str:
    fw = ",".join(required_frameworks or [])
    return f"""# AWS SAM template — squash-attest API Gateway authorizer
AWSTemplateFormatVersion: "2010-09-09"
Transform: AWS::Serverless-2016-10-31
Description: squash-attest runtime gate for API Gateway (Track B / B5)

Resources:
  {function_name}:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: {function_name}
      Runtime: {runtime}
      Handler: handler.authorize
      CodeUri: ./authorizer/
      Timeout: 5
      MemorySize: 256
      Environment:
        Variables:
          SQUASH_API_URL: {squash_api_url}
          SQUASH_HEADER_NAME: {header_name}
          SQUASH_MIN_SCORE: "{float(min_score)}"
          SQUASH_MAX_AGE_DAYS: "{max_age_days if max_age_days is not None else ''}"
          SQUASH_REQUIRED_FRAMEWORKS: "{fw}"
          SQUASH_CACHE_TTL: "60"

  InferenceApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      Auth:
        DefaultAuthorizer: SquashAttestAuth
        Authorizers:
          SquashAttestAuth:
            FunctionArn: !GetAtt {function_name}.Arn
            Identity:
              Header: {header_name}
              ReauthorizeEvery: 60
"""


def emit_kong_plugin_dir() -> dict[str, str]:
    """Return {filename: content} for the Kong Lua plugin source tree."""
    schema_lua = r"""-- squash-attest/schema.lua — Track B / B5 — Kong plugin schema
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "squash-attest",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { squash_api_url    = { type = "string", required = true,
                                  default = "https://api.getsquash.dev" } },
          { header_name       = { type = "string", required = true,
                                  default = "X-Squash-Attestation" } },
          { min_score         = { type = "number", required = true,
                                  default = 0.8, between = { 0.0, 1.0 } } },
          { max_age_days      = { type = "integer", required = false,
                                  default = 30 } },
          { required_frameworks = { type = "array", required = false,
                                    default = {},
                                    elements = { type = "string" } } },
          { fail_open         = { type = "boolean", default = false } },
          { cache_ttl_seconds = { type = "integer", default = 60 } },
          { timeout_ms        = { type = "integer", default = 2000 } },
        },
    }, },
  },
}
"""

    handler_lua = r"""-- squash-attest/handler.lua — Track B / B5 — Kong runtime gate
--
-- On each request:
--   1. Read the configured header (default: X-Squash-Attestation).
--   2. POST it to <squash_api_url>/v1/gateway/verify with the operator
--      config (min_score, max_age_days, required_frameworks).
--   3. Cache the verifier decision for `cache_ttl_seconds` keyed by token.
--   4. On allow=true → forward upstream and propagate
--      X-Squash-Attestation-Id / X-Squash-Score / X-Squash-Model headers.
--   5. On allow=false → kong.response.exit(http_status, body).

local http   = require "resty.http"
local cjson  = require "cjson.safe"

local SquashAttest = {
  PRIORITY = 950,    -- after auth (1000), before rate-limit (900)
  VERSION  = "0.1.0",
}

local lrucache = require("resty.lrucache")
local cache, _ = lrucache.new(2048)

local function deny(status, reason, detail)
  return kong.response.exit(status, {
    message  = "squash: request rejected",
    reason   = reason,
    detail   = detail or "",
  })
end

local function cache_get(token)
  local v = cache:get(token)
  if v == nil then return nil end
  if v.expires_at and v.expires_at < ngx.time() then
    cache:delete(token)
    return nil
  end
  return v.decision
end

local function cache_set(token, decision, ttl)
  cache:set(token, {
    decision   = decision,
    expires_at = ngx.time() + (ttl or 60),
  })
end

function SquashAttest:access(conf)
  local token = kong.request.get_header(conf.header_name)
  if not token or token == "" then
    return deny(401, "MISSING_TOKEN",
                "Header " .. conf.header_name .. " is required")
  end

  local cached = cache_get(token)
  if cached ~= nil then
    if not cached.allow then
      return deny(cached.http_status, cached.reason, cached.detail)
    end
    if cached.entry_id   then kong.service.request.set_header("X-Squash-Attestation-Id", cached.entry_id) end
    if cached.score      then kong.service.request.set_header("X-Squash-Score", tostring(cached.score)) end
    if cached.model_id   then kong.service.request.set_header("X-Squash-Model", cached.model_id) end
    return
  end

  local httpc = http.new()
  httpc:set_timeout(conf.timeout_ms or 2000)
  local body = cjson.encode({
    token                = token,
    min_score            = conf.min_score,
    max_age_days         = conf.max_age_days,
    required_frameworks  = conf.required_frameworks,
  })
  local res, err = httpc:request_uri(conf.squash_api_url .. "/v1/gateway/verify", {
    method  = "POST",
    body    = body,
    headers = { ["Content-Type"] = "application/json" },
    keepalive_timeout = 60000,
  })
  if not res then
    if conf.fail_open then return end
    return deny(503, "VERIFIER_UNREACHABLE", err or "no response from squash API")
  end

  local decision, jerr = cjson.decode(res.body or "")
  if not decision then
    if conf.fail_open then return end
    return deny(502, "VERIFIER_BAD_RESPONSE", jerr or "invalid JSON")
  end

  cache_set(token, decision, conf.cache_ttl_seconds)

  if not decision.allow then
    return deny(decision.http_status or 403, decision.reason or "DENIED", decision.detail)
  end
  if decision.entry_id then kong.service.request.set_header("X-Squash-Attestation-Id", decision.entry_id) end
  if decision.compliance_score then
    kong.service.request.set_header("X-Squash-Score", tostring(decision.compliance_score))
  end
  if decision.model_id then kong.service.request.set_header("X-Squash-Model", decision.model_id) end
end

return SquashAttest
"""

    readme = """# squash-attest — Kong plugin (Track B / B5)

Runtime compliance gate for AI inference services routed through Kong.
Rejects requests that do not present a valid, current, score-passing
squash attestation token; forwards the rest with identity headers
attached.

## Install

```
mkdir -p /usr/local/share/lua/5.1/kong/plugins/squash-attest
cp schema.lua handler.lua /usr/local/share/lua/5.1/kong/plugins/squash-attest/
echo 'plugins = bundled,squash-attest' >> /etc/kong/kong.conf
kong restart
```

## Apply via decK

```
deck sync -s squash-kong.yaml
```

Generate the declarative config with:

```
squash gateway-config kong --min-score 0.8 \\
    --header X-Squash-Attestation \\
    --squash-api-url https://api.getsquash.dev \\
    > squash-kong.yaml
```

## Token formats accepted

* `att://host/org/model/<entry_id>` — registry URI
* `sha256:<hex>` — attestation payload hash
* `<entry_id>` — bare 16-char registry id

## Behaviour

| Decision | HTTP | Notes |
|---|---|---|
| Allow | 200 | upstream sees `X-Squash-Attestation-Id` |
| Missing token | 401 | `reason=MISSING_TOKEN` |
| Malformed token | 401 | `reason=MALFORMED_TOKEN` |
| Not found / revoked / hash mismatch | 403 | `reason=ENTRY_NOT_FOUND \\| REVOKED \\| HASH_MISMATCH` |
| Below score | 403 | `reason=BELOW_MIN_SCORE` |
| Expired | 403 | `reason=EXPIRED` |
| Required framework missing | 403 | `reason=REQUIRED_FRAMEWORK_MISSING` |
| Verifier unreachable | 503 (or pass when `fail_open=true`) | `reason=VERIFIER_UNREACHABLE` |
"""

    return {
        "schema.lua":  schema_lua,
        "handler.lua": handler_lua,
        "README.md":   readme,
    }


def emit_aws_authorizer_dir() -> dict[str, str]:
    """Return {filename: content} for the AWS Lambda authorizer source tree."""
    handler_py = '''"""squash-attest AWS API Gateway authorizer — Track B / B5.

Lambda authorizer (REQUEST type). Reads the configured header from the
inbound request, verifies it against the squash API, and returns an IAM
policy document that either allows or denies the underlying methodArn.

All configuration is via environment variables so the Lambda can be
re-deployed without code changes:

  SQUASH_API_URL              https://api.getsquash.dev
  SQUASH_HEADER_NAME          X-Squash-Attestation
  SQUASH_MIN_SCORE            0.8
  SQUASH_MAX_AGE_DAYS         30
  SQUASH_REQUIRED_FRAMEWORKS  comma-separated, e.g. "eu-ai-act,iso-42001"
  SQUASH_CACHE_TTL            60   (per-container memo TTL in seconds)
  SQUASH_FAIL_OPEN            false
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

_CACHE: dict[str, tuple[float, dict]] = {}


def _env_float(name: str, default: float) -> float:
    v = os.environ.get(name)
    try:
        return float(v) if v not in (None, "") else default
    except ValueError:
        return default


def _env_int(name: str, default: int | None) -> int | None:
    v = os.environ.get(name)
    if v in (None, ""):
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if v in ("1", "true", "yes", "on"):  return True
    if v in ("0", "false", "no", "off"): return False
    return default


def _cache_get(token: str, ttl: int) -> dict | None:
    hit = _CACHE.get(token)
    if hit is None: return None
    expires_at, decision = hit
    if expires_at < time.time():
        _CACHE.pop(token, None)
        return None
    return decision


def _cache_set(token: str, decision: dict, ttl: int) -> None:
    _CACHE[token] = (time.time() + ttl, decision)


def _verify(token: str) -> dict:
    """POST /v1/gateway/verify and return the decoded GatewayDecision dict."""
    api_url = os.environ.get("SQUASH_API_URL", "https://api.getsquash.dev").rstrip("/")
    payload = json.dumps({
        "token":               token,
        "min_score":           _env_float("SQUASH_MIN_SCORE", 0.8),
        "max_age_days":        _env_int("SQUASH_MAX_AGE_DAYS", 30),
        "required_frameworks": [f for f in os.environ.get(
            "SQUASH_REQUIRED_FRAMEWORKS", "").split(",") if f.strip()],
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{api_url}/v1/gateway/verify",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2.5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _policy(allow: bool, principal: str, method_arn: str,
            decision: dict | None = None) -> dict:
    return {
        "principalId": principal or "anonymous",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action":   "execute-api:Invoke",
                "Effect":   "Allow" if allow else "Deny",
                "Resource": method_arn,
            }],
        },
        "context": {
            "squash_reason":     (decision or {}).get("reason", ""),
            "squash_entry_id":   (decision or {}).get("entry_id", ""),
            "squash_score":      str((decision or {}).get("compliance_score", "")),
            "squash_model_id":   (decision or {}).get("model_id", ""),
        },
    }


def authorize(event: dict, context) -> dict:
    """API Gateway REQUEST authorizer entry point."""
    method_arn  = event.get("methodArn", "*")
    header_name = os.environ.get("SQUASH_HEADER_NAME", "X-Squash-Attestation")
    headers     = event.get("headers") or {}
    token = None
    for k, v in headers.items():
        if k.lower() == header_name.lower():
            token = v
            break

    if not token:
        return _policy(False, "anonymous", method_arn,
                       {"reason": "MISSING_TOKEN"})

    ttl = _env_int("SQUASH_CACHE_TTL", 60) or 60
    cached = _cache_get(token, ttl)
    if cached is not None:
        return _policy(bool(cached.get("allow")), cached.get("model_id", "anonymous"),
                       method_arn, cached)

    try:
        decision = _verify(token)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        if _env_bool("SQUASH_FAIL_OPEN", False):
            return _policy(True, "fail-open", method_arn,
                           {"reason": "VERIFIER_UNREACHABLE",
                            "detail": str(exc)})
        return _policy(False, "anonymous", method_arn,
                       {"reason": "VERIFIER_UNREACHABLE",
                        "detail": str(exc)})

    _cache_set(token, decision, ttl)
    return _policy(bool(decision.get("allow")),
                   decision.get("model_id", "anonymous"),
                   method_arn, decision)
'''

    requirements_txt = "# No external runtime deps — handler uses stdlib only.\n"

    readme = """# squash-attest AWS API Gateway authorizer (Track B / B5)

Lambda authorizer (REQUEST type) that gates inference endpoints behind a
valid, current, score-passing squash attestation. Stdlib-only at runtime.

## Deploy via SAM

```
squash gateway-config aws-apigw --min-score 0.8 > template.yaml
mkdir -p authorizer && cd authorizer
squash gateway-config aws-apigw --emit-handler > handler.py
sam build && sam deploy --guided
```
"""

    return {
        "handler.py":       handler_py,
        "requirements.txt": requirements_txt,
        "README.md":        readme,
    }


def decision_from_dict(d: dict[str, Any]) -> GatewayDecision:
    return GatewayDecision(
        allow=bool(d.get("allow")),
        reason=str(d.get("reason", "")),
        http_status=int(d.get("http_status", 403)),
        entry_id=str(d.get("entry_id", "")),
        model_id=str(d.get("model_id", "")),
        compliance_score=d.get("compliance_score"),
        detail=str(d.get("detail", "")),
        headers=dict(d.get("headers") or {}),
    )
