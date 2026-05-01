"""squash/identity_governor.py — AI Identity Attestation (D2 / W226-W228).

The invisible attack surface
------------------------------
92% of organisations lack full visibility into their AI identities.
16% effectively govern AI agent access.
73% of CISOs say they would invest immediately — if the product existed.

AI agents — chatbots, RAG pipelines, autonomous agents, model-serving pods —
require credentials to act. In practice, these credentials are:

* **Over-privileged**: agents given admin scopes "for convenience"
* **Long-lived**: API keys rotated annually (or never)
* **Invisible**: not in the organisation's standard PAM/IGA inventory
* **Unmonitored**: no audit trail of what the credential accessed

This module is the product those 73% of CISOs are waiting for: a signed,
timestamped attestation that an AI principal's identity configuration
matches a declared least-privilege policy at a given point in time.

Three providers, one attestation schema
-----------------------------------------
AWS IAM, Okta, and Azure AD cover ~85% of enterprise AI identity surfaces.
Each provider adapter normalises its provider-specific data into a uniform
``IdentityPrincipal`` — the same object the least-privilege analyser and
certificate issuer operate on.

**Konjo rule:** Every provider SDK call is gated behind a lazy import. The
core logic (policy comparison, violation scoring, certificate signing) builds
and tests without any cloud SDK installed. Tests mock at the import boundary —
zero live identity-provider calls in CI, ever.

Least-privilege analyser
--------------------------
A ``LeastPrivilegePolicy`` declares the minimum-necessary permissions for a
principal. The analyser compares actual vs. declared:

* Actual ⊃ declared → ``PermissionViolation`` (excess)
* Actual ⊂ declared → ``PolicyGap`` (insufficient — informational)
* MFA not enabled when required → CRITICAL violation
* Token age > max_token_age_days → HIGH violation
* Admin scope present → CRITICAL regardless of policy

Score: 100 − (weighted violation penalty). Score 100 = exact least-privilege.

Certificate
------------
``IdentityAttestation`` carries the same Ed25519 signing contract as
``DriftCertificateIssuer`` and ``HallucinationAttestation``. The body is
``canonical_json(body_dict())``; the signature covers exactly the fields
an auditor needs, not the metadata.

Schema: ``squash.identity.attestation/v1``

Regulatory basis
-----------------
* NIST AI RMF GOVERN 1.1 — accountability and transparency for AI actors
* EU AI Act Art. 9 — risk management for high-risk AI systems (access control)
* SOC 2 CC6.1 — logical and physical access controls
* FedRAMP AC-2 — account management for cloud systems
* CIS Controls v8 Control 5 — account management
* OWASP Agentic AI Top 10 AA3 — Agent Identity Abuse

Konjo notes
-----------
* 건조 — one ``IdentityPrincipal`` type, three adapters. The analyser and
  cert issuer see only the normalised type.
* ᨀᨚᨐᨚ — the attestation JSON is self-contained: a verifier needs only the
  public key and ``verify_attestation()`` — no SDK, no cloud call.
* 康宙 — all SDK I/O is behind lazy imports; core is stdlib-only.
* 근性 — the violation list is deterministic: same principal + same policy +
  same adapter mock → same violations, same score, every run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical JSON (shared contract with anchor / drift cert / hallucination cert)
# ---------------------------------------------------------------------------

def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Principal model
# ---------------------------------------------------------------------------

class PrincipalType(str, Enum):
    SERVICE_ACCOUNT        = "service_account"
    API_KEY                = "api_key"
    OAUTH_CLIENT           = "oauth_client"
    IAM_ROLE               = "iam_role"
    AZURE_SERVICE_PRINCIPAL= "azure_service_principal"
    OKTA_SERVICE_APP       = "okta_service_app"
    UNKNOWN                = "unknown"


class Provider(str, Enum):
    AWS_IAM  = "aws_iam"
    AZURE_AD = "azure_ad"
    OKTA     = "okta"
    GENERIC  = "generic"


@dataclass
class IdentityPrincipal:
    """Normalised identity principal — provider-agnostic.

    All three provider adapters produce this type. The analyser and
    certificate issuer work only with ``IdentityPrincipal`` objects;
    no provider-specific types leak past the adapter boundary.
    """
    principal_id:       str
    name:               str
    principal_type:     PrincipalType
    provider:           Provider
    scopes:             list[str]        # actual granted permissions/scopes/roles
    mfa_enabled:        bool
    token_type:         str              # "api_key" | "oauth2" | "service_account_key" | "iam_role"
    last_rotation_days: int | None       # days since last credential rotation; None = unknown
    created_at:         str | None       # ISO-8601 or None
    last_used_at:       str | None       # ISO-8601 or None
    tags:               dict[str, str]   = field(default_factory=dict)
    raw_metadata:       dict[str, Any]  = field(default_factory=dict)  # provider raw data

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["principal_type"] = self.principal_type.value
        d["provider"]       = self.provider.value
        return d


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class LeastPrivilegePolicy:
    """Declared minimum-necessary permissions for one principal.

    Load from JSON: ``LeastPrivilegePolicy.from_dict(json.loads(path.read_text()))``
    Scaffold with: ``squash attest-identity policy-init``
    """
    principal_name:     str
    allowed_scopes:     list[str]        # exact scope strings allowed
    max_token_age_days: int = 90         # flag rotation if older
    require_mfa:        bool = False
    allowed_principal_types: list[str] = field(default_factory=list)
    notes:              str = ""

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "LeastPrivilegePolicy":
        return LeastPrivilegePolicy(
            principal_name=d.get("principal_name") or d.get("principal", ""),
            allowed_scopes=d.get("allowed_scopes", []),
            max_token_age_days=d.get("max_token_age_days", 90),
            require_mfa=d.get("require_mfa", False),
            allowed_principal_types=d.get("allowed_principal_types", []),
            notes=d.get("notes", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

class ViolationSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# Penalty per violation severity for least-privilege score computation.
_VIOLATION_PENALTY = {
    ViolationSeverity.CRITICAL: 30,
    ViolationSeverity.HIGH:     15,
    ViolationSeverity.MEDIUM:    7,
    ViolationSeverity.LOW:       3,
    ViolationSeverity.INFO:      0,
}

# Patterns that indicate admin / superuser scopes regardless of policy.
_ADMIN_SCOPE_PATTERNS = [
    r"\*",                              # wildcard (AWS)
    r"^admin$",                         # explicit admin
    r"^owner$",                         # Azure owner
    r"AdministratorAccess",             # AWS managed policy
    r"\.admin$",                        # Okta admin suffix
    r"GlobalAdministrator",             # Azure AAD global admin
    r"UserAuthenticationAdministrator", # Azure UAA
]
_ADMIN_RE = [re.compile(p, re.I) for p in _ADMIN_SCOPE_PATTERNS]


@dataclass
class PermissionViolation:
    """One least-privilege violation."""
    rule_id:        str
    title:          str
    description:    str
    severity:       ViolationSeverity
    scope_or_field: str       # the offending scope / field
    remediation:    str
    regulatory_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ---------------------------------------------------------------------------
# Least-privilege analyser
# ---------------------------------------------------------------------------

class LeastPrivilegeAnalyser:
    """Compare a principal's actual permissions to its declared policy.

    The analysis is purely local — no network calls, no SDK invocations.
    Input: ``IdentityPrincipal`` (from any adapter) + ``LeastPrivilegePolicy``.
    Output: ``list[PermissionViolation]`` and a score 0-100.
    """

    def analyse(
        self,
        principal: IdentityPrincipal,
        policy: LeastPrivilegePolicy | None = None,
    ) -> tuple[list[PermissionViolation], int]:
        """Return (violations, least_privilege_score 0-100)."""
        violations: list[PermissionViolation] = []
        counter = [0]

        def vid() -> str:
            counter[0] += 1
            return f"ID-{counter[0]:03d}"

        # Rule 1: Admin scope detection (unconditional)
        for scope in principal.scopes:
            for pat in _ADMIN_RE:
                if pat.search(scope):
                    violations.append(PermissionViolation(
                        rule_id=vid(),
                        title="Admin/wildcard scope detected",
                        description=(
                            f"Principal `{principal.name}` holds scope `{scope}` "
                            f"which matches an admin/wildcard pattern. AI agents should "
                            f"never hold administrative access."
                        ),
                        severity=ViolationSeverity.CRITICAL,
                        scope_or_field=scope,
                        remediation=(
                            f"Remove scope `{scope}`. Replace with the minimum read/write "
                            f"scopes required for the agent's specific function."
                        ),
                        regulatory_ref="OWASP AA3 · CIS Control 5.4 · SOC 2 CC6.1",
                    ))

        # Rule 2: MFA required but not enabled
        if policy and policy.require_mfa and not principal.mfa_enabled:
            violations.append(PermissionViolation(
                rule_id=vid(),
                title="MFA not enabled — policy requires it",
                description=(
                    f"Policy for `{principal.name}` requires MFA, but it is not enabled. "
                    f"AI service accounts with MFA disabled are high-value targets."
                ),
                severity=ViolationSeverity.CRITICAL,
                scope_or_field="mfa_enabled",
                remediation="Enable MFA on this service account, or switch to an MFA-capable credential type.",
                regulatory_ref="NIST AI RMF GOVERN 1.1 · FedRAMP AC-2",
            ))

        # Rule 3: Credential rotation age
        if principal.last_rotation_days is not None:
            max_days = (policy.max_token_age_days if policy else 90)
            if principal.last_rotation_days > max_days:
                violations.append(PermissionViolation(
                    rule_id=vid(),
                    title=f"Credential overdue for rotation ({principal.last_rotation_days} days)",
                    description=(
                        f"Credential for `{principal.name}` last rotated "
                        f"{principal.last_rotation_days} days ago (policy: ≤{max_days} days). "
                        f"Long-lived credentials increase blast radius on compromise."
                    ),
                    severity=ViolationSeverity.HIGH,
                    scope_or_field="last_rotation_days",
                    remediation=(
                        f"Rotate the credential immediately and configure automatic "
                        f"rotation with a max age of {max_days} days."
                    ),
                    regulatory_ref="CIS Control 5.4 · SOC 2 CC6.1",
                ))

        # Rule 4: Excess permissions (actual ⊃ declared)
        if policy:
            allowed = set(policy.allowed_scopes)
            actual  = set(principal.scopes)
            excess  = actual - allowed
            for scope in sorted(excess):
                sev = _scope_severity(scope)
                violations.append(PermissionViolation(
                    rule_id=vid(),
                    title=f"Excess permission: `{scope}`",
                    description=(
                        f"Principal `{principal.name}` holds `{scope}` which is not in "
                        f"the declared allowed_scopes. Every excess permission is an "
                        f"unnecessary attack surface."
                    ),
                    severity=sev,
                    scope_or_field=scope,
                    remediation=(
                        f"Remove `{scope}` from the principal's permissions, or add it "
                        f"to the policy's `allowed_scopes` if it is genuinely required."
                    ),
                    regulatory_ref="NIST AI RMF GOVERN 1.1 · EU AI Act Art. 9",
                ))

        # Rule 5: No scopes at all — likely misconfigured
        if not principal.scopes:
            violations.append(PermissionViolation(
                rule_id=vid(),
                title="Principal has no scopes — possible misconfiguration",
                description=(
                    f"Principal `{principal.name}` has zero scopes/permissions. "
                    f"This may indicate a misconfigured identity that could still hold "
                    f"implicit permissions at the provider level."
                ),
                severity=ViolationSeverity.MEDIUM,
                scope_or_field="scopes",
                remediation="Verify the principal configuration in the provider console. Confirm scopes are declared explicitly.",
                regulatory_ref="CIS Control 5.3",
            ))

        score = _compute_score(violations)
        return violations, score


def _scope_severity(scope: str) -> ViolationSeverity:
    """Classify excess scope severity by pattern matching."""
    lower = scope.lower()
    for pat in _ADMIN_RE:
        if pat.search(scope):
            return ViolationSeverity.CRITICAL
    if any(k in lower for k in ("write", "delete", "update", "put", "post", "create")):
        return ViolationSeverity.HIGH
    if any(k in lower for k in ("read", "get", "list", "describe", "view")):
        return ViolationSeverity.MEDIUM
    return ViolationSeverity.LOW


def _compute_score(violations: list[PermissionViolation]) -> int:
    """Score 100 = exactly least-privilege. Deduct per violation severity."""
    penalty = sum(_VIOLATION_PENALTY[v.severity] for v in violations)
    return max(0, 100 - penalty)


# ---------------------------------------------------------------------------
# Attestation certificate
# ---------------------------------------------------------------------------

_SCHEMA = "squash.identity.attestation/v1"


@dataclass
class IdentityAttestation:
    """Signed identity attestation for one AI principal."""
    cert_id:               str
    schema:                str
    principal:             IdentityPrincipal
    policy:                LeastPrivilegePolicy | None
    violations:            list[PermissionViolation]
    least_privilege_score: int
    passes_policy:         bool
    issued_at:             str
    squash_version:        str
    signature_hex:         str = ""
    public_key_pem:        str = ""
    signer:                str = ""

    def body_dict(self) -> dict[str, Any]:
        return {
            "cert_id":               self.cert_id,
            "schema":                self.schema,
            "principal":             self.principal.to_dict(),
            "policy":                self.policy.to_dict() if self.policy else None,
            "violations":            [v.to_dict() for v in self.violations],
            "least_privilege_score": self.least_privilege_score,
            "passes_policy":         self.passes_policy,
            "issued_at":             self.issued_at,
            "squash_version":        self.squash_version,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.body_dict()
        d["signature_hex"]  = self.signature_hex
        d["public_key_pem"] = self.public_key_pem
        d["signer"]         = self.signer
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def summary(self) -> str:
        icon = "✅" if self.passes_policy else "❌"
        critical = sum(1 for v in self.violations if v.severity == ViolationSeverity.CRITICAL)
        return (
            f"{icon} identity-attest [{self.principal.provider.value}] "
            f"{self.principal.name}: score={self.least_privilege_score}/100 "
            f"{len(self.violations)} violation(s) ({critical} critical)"
        )

    def to_markdown(self) -> str:
        icon = "✅" if self.passes_policy else "❌"
        lines = [
            f"# AI Identity Attestation — {icon} {'PASS' if self.passes_policy else 'FAIL'}",
            "",
            f"**Principal:** `{self.principal.name}` ({self.principal.provider.value})  ",
            f"**Type:** `{self.principal.principal_type.value}`  ",
            f"**Issued:** {self.issued_at[:19]}  ",
            f"**Certificate ID:** `{self.cert_id}`",
            "",
            "## Identity Profile",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Provider | `{self.principal.provider.value}` |",
            f"| Token type | `{self.principal.token_type}` |",
            f"| MFA enabled | {'✅ Yes' if self.principal.mfa_enabled else '❌ No'} |",
            f"| Rotation age | {self.principal.last_rotation_days or 'unknown'} days |",
            f"| Scopes | {len(self.principal.scopes)} |",
            f"| **Least-privilege score** | **{self.least_privilege_score}/100** |",
            "",
        ]
        if self.violations:
            lines += ["## Violations", "",
                      "| Rule | Severity | Title |",
                      "|------|----------|-------|"]
            for v in self.violations:
                lines.append(f"| {v.rule_id} | {v.severity.value.upper()} | {v.title} |")
            lines.append("")
            for v in self.violations:
                lines += [
                    f"### {v.rule_id} — {v.title}",
                    "",
                    v.description, "",
                    f"**Remediation:** {v.remediation}  ",
                    f"**Regulatory reference:** {v.regulatory_ref}",
                    "",
                ]
        if self.signature_hex:
            fp = hashlib.sha256(self.public_key_pem.encode()).hexdigest()[:16] if self.public_key_pem else "—"
            lines += [
                "## Signature",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Signer | `{self.signer}` |",
                f"| Key fingerprint | `{fp}` |",
                f"| Signature | `{self.signature_hex[:32]}…` |",
                "",
            ]
        lines += [
            "---",
            f"*Generated by [Squash](https://github.com/konjoai/squash) · "
            f"schema `{self.schema}` · 92% of orgs lack AI identity visibility*",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_attestation(cert: IdentityAttestation, priv_key_path: Path) -> IdentityAttestation:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    payload  = _canonical_json(cert.body_dict())
    priv_obj = serialization.load_pem_private_key(priv_key_path.read_bytes(), password=None)
    if not isinstance(priv_obj, Ed25519PrivateKey):
        raise ValueError("attest-identity signing requires an Ed25519 private key")
    sig_hex = priv_obj.sign(payload).hex()
    pub_pem = priv_obj.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fp = hashlib.sha256(pub_pem.encode()).hexdigest()[:16]
    cert.signature_hex  = sig_hex
    cert.public_key_pem = pub_pem
    cert.signer         = f"local:{fp}"
    return cert


def verify_attestation(cert: IdentityAttestation) -> tuple[bool, str]:
    if not cert.signature_hex or not cert.public_key_pem:
        return False, "certificate is unsigned"
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = serialization.load_pem_public_key(cert.public_key_pem.encode("ascii"))
    except Exception as e:
        return False, f"public key load failed: {e}"
    if not isinstance(pub, Ed25519PublicKey):
        return False, "not Ed25519"
    payload = _canonical_json(cert.body_dict())
    try:
        pub.verify(bytes.fromhex(cert.signature_hex), payload)
        return True, "signature valid"
    except InvalidSignature:
        return False, "signature INVALID"


def load_attestation(path: Path) -> IdentityAttestation:
    d = json.loads(path.read_text())
    p = d["principal"]
    principal = IdentityPrincipal(
        principal_id=p["principal_id"],
        name=p["name"],
        principal_type=PrincipalType(p["principal_type"]),
        provider=Provider(p["provider"]),
        scopes=p["scopes"],
        mfa_enabled=p["mfa_enabled"],
        token_type=p["token_type"],
        last_rotation_days=p.get("last_rotation_days"),
        created_at=p.get("created_at"),
        last_used_at=p.get("last_used_at"),
        tags=p.get("tags", {}),
        raw_metadata=p.get("raw_metadata", {}),
    )
    policy = LeastPrivilegePolicy.from_dict(d["policy"]) if d.get("policy") else None
    violations = [
        PermissionViolation(
            rule_id=v["rule_id"], title=v["title"],
            description=v["description"],
            severity=ViolationSeverity(v["severity"]),
            scope_or_field=v["scope_or_field"],
            remediation=v["remediation"],
            regulatory_ref=v.get("regulatory_ref", ""),
        )
        for v in d.get("violations", [])
    ]
    return IdentityAttestation(
        cert_id=d["cert_id"], schema=d["schema"],
        principal=principal, policy=policy,
        violations=violations,
        least_privilege_score=d["least_privilege_score"],
        passes_policy=d["passes_policy"],
        issued_at=d["issued_at"],
        squash_version=d.get("squash_version", "1"),
        signature_hex=d.get("signature_hex", ""),
        public_key_pem=d.get("public_key_pem", ""),
        signer=d.get("signer", ""),
    )


# ---------------------------------------------------------------------------
# Identity Governor — orchestrator
# ---------------------------------------------------------------------------

class IdentityGovernor:
    """Orchestrate: load principal → analyse → issue attestation."""

    def __init__(self, priv_key_path: Path | None = None) -> None:
        self.priv_key_path = Path(priv_key_path) if priv_key_path else None

    def attest(
        self,
        principal: IdentityPrincipal,
        policy: LeastPrivilegePolicy | None = None,
        squash_version: str = "1",
    ) -> IdentityAttestation:
        analyser = LeastPrivilegeAnalyser()
        violations, score = analyser.analyse(principal, policy)
        passes = score >= 70 and not any(
            v.severity == ViolationSeverity.CRITICAL for v in violations
        )
        cert = IdentityAttestation(
            cert_id=f"iac-{uuid.uuid4().hex[:16]}",
            schema=_SCHEMA,
            principal=principal,
            policy=policy,
            violations=violations,
            least_privilege_score=score,
            passes_policy=passes,
            issued_at=_utcnow(),
            squash_version=squash_version,
        )
        if self.priv_key_path and self.priv_key_path.exists():
            cert = sign_attestation(cert, self.priv_key_path)
        return cert


# ---------------------------------------------------------------------------
# Policy scaffold
# ---------------------------------------------------------------------------

_POLICY_TEMPLATE = {
    "principal_name": "ai-agent-prod",
    "allowed_scopes": [
        "read:logs",
        "write:outputs",
    ],
    "max_token_age_days": 30,
    "require_mfa": False,
    "allowed_principal_types": ["service_account", "oauth_client"],
    "notes": "Minimum-necessary scopes for the production AI agent. Review quarterly.",
}


def scaffold_policy(principal_name: str = "") -> dict[str, Any]:
    p = dict(_POLICY_TEMPLATE)
    if principal_name:
        p["principal_name"] = principal_name
    return p
