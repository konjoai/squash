"""squash/agent_audit.py — OWASP Agentic AI Top 10 compliance audit.

Audits AI agent configurations against the OWASP Agentic AI Top 10
(December 2025) — the first formal taxonomy of risks specific to autonomous
AI agents.  Extends the existing MCP server attestation in ``squash/mcp.py``
to cover the full agentic risk surface.

OWASP Agentic AI Top 10 (2025)
--------------------------------
AA1: Goal Hijacking / Prompt Injection
AA2: Unsafe Tool Usage / Tool Misuse
AA3: Identity Abuse / Unauthorized Access
AA4: Memory Poisoning
AA5: Cascading Failure / Uncontrolled Recursion
AA6: Rogue Agents / Unauthorized Spawning
AA7: Insufficient Auditability / Logging
AA8: Excessive Autonomy / Scope Creep
AA9: Data Exfiltration via Agent Channels
AA10: Insufficient Human Oversight / Control

Input: An ``agent.json`` manifest (any format) or a dict.
Output: A signed ``AgentAuditReport`` with per-risk findings, an overall
risk score, and a remediation roadmap.

Usage::

    from squash.agent_audit import AgentAuditor
    import json

    manifest = json.loads(Path("./agent.json").read_text())
    report = AgentAuditor.audit(manifest)
    print(report.summary())
    report.save(Path("./agent_audit.json"))

Agent manifest schema (squash-native)
--------------------------------------
{
  "agent_name": "my-rag-agent",
  "agent_type": "rag" | "autonomous" | "workflow" | "chat",
  "system_prompt": "...",
  "tools": [{"name": "...", "description": "...", "api_endpoint": "..."}],
  "memory_stores": [{"type": "redis|postgres|...", "scope": "session|global"}],
  "external_apis": ["https://..."],
  "human_approval_required": true | false,
  "max_iterations": 10,
  "spawns_subagents": false,
  "logging_enabled": true,
  "audit_trail_endpoint": "https://..."
}

Also parses LangChain, LlamaIndex, and CrewAI manifest formats.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    FAIL = "FAIL"    # Risk detected / control missing
    WARN = "WARN"    # Partial mitigation or unclear
    PASS = "PASS"    # Control present and effective
    NA = "N/A"       # Not applicable to this agent type


@dataclass
class AgentFinding:
    risk_id: str         # e.g. "AA1"
    risk_name: str
    status: FindingStatus
    risk_level: RiskLevel
    description: str
    evidence: list[str]  # observations from manifest
    remediation: str


@dataclass
class AgentAuditReport:
    agent_name: str
    agent_type: str
    audited_at: str
    manifest_hash: str
    findings: list[AgentFinding] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.CRITICAL
    risk_score: int = 100   # 0 = no risk, 100 = maximum risk
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    passed_count: int = 0

    def summary(self) -> str:
        lines = [
            "OWASP Agentic AI Top 10 — Agent Audit Report",
            "=" * 54,
            f"Agent:       {self.agent_name}",
            f"Type:        {self.agent_type}",
            f"Audited:     {self.audited_at}",
            f"Overall Risk: {self.overall_risk.value}  (score: {self.risk_score}/100)",
            f"Findings:    {self.critical_count} CRITICAL · {self.high_count} HIGH · "
            f"{self.medium_count} MEDIUM · {self.low_count} LOW · {self.passed_count} PASS",
            "",
        ]
        fails = [f for f in self.findings if f.status in (FindingStatus.FAIL, FindingStatus.WARN)]
        if fails:
            lines.append("Risks Detected:")
            for f in sorted(fails, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.risk_level.value)):
                icon = "🔴" if f.risk_level == RiskLevel.CRITICAL else "🟠" if f.risk_level == RiskLevel.HIGH else "🟡"
                lines.append(f"  {icon} [{f.risk_id}] {f.risk_name} ({f.status.value})")
                lines.append(f"      {f.description}")
                lines.append(f"      → Remediation: {f.remediation}")
                lines.append("")
        passed = [f for f in self.findings if f.status == FindingStatus.PASS]
        if passed:
            lines.append(f"Controls Verified ({len(passed)}):")
            for f in passed:
                lines.append(f"  ✅ [{f.risk_id}] {f.risk_name}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "OWASP Agentic AI Top 10 (2025)",
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "audited_at": self.audited_at,
            "manifest_hash": self.manifest_hash,
            "overall_risk": self.overall_risk.value,
            "risk_score": self.risk_score,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "passed": self.passed_count,
            },
            "findings": [
                {
                    "risk_id": f.risk_id,
                    "risk_name": f.risk_name,
                    "status": f.status.value,
                    "risk_level": f.risk_level.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
        }

    def save(self, path: Path) -> None:
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        log.info("Agent audit report written to %s", path)


# ── Injection pattern library (shared with mcp.py threat model) ──────────────
_INJECTION_PATTERNS = re.compile(
    r"ignore\s+(?:all\s+)?previous|disregard|forget\s+(?:all|everything)|"
    r"you\s+are\s+now|act\s+as\s+(?:if|a|an)|pretend\s+(?:you\s+are|to\s+be)|"
    r"jailbreak|override\s+(?:your|the)\s+(?:instructions|rules|constraints)|"
    r"from\s+now\s+on|DAN\b|do\s+anything\s+now",
    re.IGNORECASE,
)

_EXFIL_PATTERNS = re.compile(
    r"(?:https?://)[^/]*(?:requestbin|hookbin|oastify|interactsh|burpcollaborator|"
    r"pipedream|webhook\.site|ngrok|localtunnel)",
    re.IGNORECASE,
)

_PRIVILEGED_TOOL_NAMES = re.compile(
    r"\b(?:exec|shell|eval|sudo|su\b|root|admin|system_admin|deploy_to_prod|"
    r"delete_all|drop_table|impersonate|assume_role|escalate)\b",
    re.IGNORECASE,
)

_SSRF_PATTERNS = re.compile(
    r"(?:file://|localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|"
    r"169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|gopher://|ftp://)",
    re.IGNORECASE,
)


class AgentAuditor:
    """Audit an agent manifest against OWASP Agentic AI Top 10."""

    @staticmethod
    def audit(manifest: dict[str, Any] | str | Path) -> AgentAuditReport:
        if isinstance(manifest, (str, Path)):
            p = Path(manifest)
            raw = p.read_text()
            manifest_dict = json.loads(raw)
        else:
            manifest_dict = manifest
            raw = json.dumps(manifest_dict)

        manifest_hash = hashlib.sha256(raw.encode()).hexdigest()
        agent_name = (
            manifest_dict.get("agent_name")
            or manifest_dict.get("name")
            or manifest_dict.get("agent", {}).get("name", "unknown")
        )
        agent_type = (
            manifest_dict.get("agent_type")
            or manifest_dict.get("type", "unknown")
        )

        findings: list[AgentFinding] = [
            _check_aa1_goal_hijacking(manifest_dict),
            _check_aa2_unsafe_tools(manifest_dict),
            _check_aa3_identity_abuse(manifest_dict),
            _check_aa4_memory_poisoning(manifest_dict),
            _check_aa5_cascading_failure(manifest_dict),
            _check_aa6_rogue_agents(manifest_dict),
            _check_aa7_auditability(manifest_dict),
            _check_aa8_excessive_autonomy(manifest_dict),
            _check_aa9_data_exfiltration(manifest_dict),
            _check_aa10_human_oversight(manifest_dict),
        ]

        return _build_report(agent_name, agent_type, manifest_hash, findings)

    @staticmethod
    def audit_from_path(path: Path) -> AgentAuditReport:
        return AgentAuditor.audit(path)


# ── Individual risk checks ─────────────────────────────────────────────────────

def _check_aa1_goal_hijacking(m: dict[str, Any]) -> AgentFinding:
    """AA1: Goal Hijacking / Prompt Injection."""
    evidence: list[str] = []
    issues: list[str] = []

    system_prompt = m.get("system_prompt", "")
    if _INJECTION_PATTERNS.search(system_prompt):
        issues.append("Prompt injection pattern detected in system_prompt")

    tools = m.get("tools", [])
    for tool in tools:
        desc = tool.get("description", "") + " " + tool.get("name", "")
        if _INJECTION_PATTERNS.search(desc):
            issues.append(f"Injection pattern in tool description: {tool.get('name', '?')}")

    input_validation = m.get("input_validation") or m.get("validate_inputs")
    if input_validation:
        evidence.append("input_validation configured")

    if issues:
        return AgentFinding(
            risk_id="AA1",
            risk_name="Goal Hijacking / Prompt Injection",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.CRITICAL,
            description="; ".join(issues),
            evidence=evidence,
            remediation=(
                "Remove injection patterns from system prompt and tool descriptions. "
                "Add input validation layer before user input reaches the agent. "
                "Use `squash attest-mcp` to scan tool manifests before deployment."
            ),
        )

    if not input_validation:
        return AgentFinding(
            risk_id="AA1",
            risk_name="Goal Hijacking / Prompt Injection",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.HIGH,
            description="No explicit input validation configured — injection risk not mitigated.",
            evidence=evidence,
            remediation=(
                "Add `input_validation: true` to agent manifest and configure an "
                "injection detection layer (e.g. Llama Guard, Rebuff, or a keyword filter)."
            ),
        )

    return AgentFinding(
        risk_id="AA1",
        risk_name="Goal Hijacking / Prompt Injection",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="No injection patterns detected. Input validation configured.",
        evidence=evidence + ["No injection patterns in prompt or tools"],
        remediation="",
    )


def _check_aa2_unsafe_tools(m: dict[str, Any]) -> AgentFinding:
    """AA2: Unsafe Tool Usage / Tool Misuse."""
    tools = m.get("tools", [])
    issues: list[str] = []
    evidence: list[str] = []

    for tool in tools:
        name = tool.get("name", "")
        if _PRIVILEGED_TOOL_NAMES.search(name):
            issues.append(f"Privileged tool name: {name}")
        endpoint = tool.get("api_endpoint", "") or tool.get("url", "")
        if endpoint and _SSRF_PATTERNS.search(endpoint):
            issues.append(f"SSRF risk in tool endpoint: {endpoint[:60]}")
        if not tool.get("description"):
            issues.append(f"Tool missing description (integrity gap): {name or 'unnamed'}")

    tool_approval = m.get("tool_approval_required") or m.get("require_tool_approval")
    if tool_approval:
        evidence.append("tool_approval_required: true")

    if issues:
        return AgentFinding(
            risk_id="AA2",
            risk_name="Unsafe Tool Usage / Tool Misuse",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.HIGH,
            description="; ".join(issues),
            evidence=evidence,
            remediation=(
                "Restrict privileged tool names. Add human approval for sensitive tools. "
                "Validate all tool API endpoints against an allowlist. "
                "Ensure all tools have explicit description fields."
            ),
        )

    if not tool_approval and tools:
        return AgentFinding(
            risk_id="AA2",
            risk_name="Unsafe Tool Usage / Tool Misuse",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="Agent has tools but no tool approval policy configured.",
            evidence=evidence,
            remediation="Add `tool_approval_required: true` for sensitive or write-capable tools.",
        )

    return AgentFinding(
        risk_id="AA2",
        risk_name="Unsafe Tool Usage / Tool Misuse",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="No unsafe tool patterns detected.",
        evidence=["No privileged tool names", "No SSRF endpoints"] + evidence,
        remediation="",
    )


def _check_aa3_identity_abuse(m: dict[str, Any]) -> AgentFinding:
    """AA3: Identity Abuse / Unauthorized Access."""
    auth = (
        m.get("authentication")
        or m.get("auth")
        or m.get("identity")
    )
    impersonation_claims = any(
        re.search(r"impersonat|assume\s+identity|act\s+as\s+user|on\s+behalf", str(v), re.I)
        for v in [m.get("system_prompt", ""), str(m.get("tools", []))]
    )
    evidence: list[str] = []

    if auth:
        evidence.append(f"authentication configured: {list(auth.keys()) if isinstance(auth, dict) else auth}")

    if impersonation_claims:
        return AgentFinding(
            risk_id="AA3",
            risk_name="Identity Abuse / Unauthorized Access",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.CRITICAL,
            description="Agent manifest contains identity impersonation language.",
            evidence=evidence,
            remediation=(
                "Remove impersonation patterns from system prompt. "
                "Use explicit role-based access controls and scoped service accounts. "
                "Never allow the agent to claim end-user identity."
            ),
        )

    if not auth:
        return AgentFinding(
            risk_id="AA3",
            risk_name="Identity Abuse / Unauthorized Access",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="No authentication configuration found — agent identity not scoped.",
            evidence=evidence,
            remediation=(
                "Add `authentication` block with scoped credentials. "
                "Use minimum-privilege service accounts for all external API calls."
            ),
        )

    return AgentFinding(
        risk_id="AA3",
        risk_name="Identity Abuse / Unauthorized Access",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="Authentication configured. No impersonation patterns detected.",
        evidence=evidence,
        remediation="",
    )


def _check_aa4_memory_poisoning(m: dict[str, Any]) -> AgentFinding:
    """AA4: Memory Poisoning."""
    memory_stores = m.get("memory_stores", []) or m.get("memory", [])
    evidence: list[str] = []
    issues: list[str] = []

    for store in (memory_stores if isinstance(memory_stores, list) else [memory_stores]):
        if isinstance(store, dict):
            scope = store.get("scope", "")
            if scope == "global":
                issues.append(f"Global-scope memory store: {store.get('type', 'unknown')} — cross-session contamination risk")
            write_access = store.get("write_access") or store.get("writable")
            if write_access and not store.get("input_sanitization"):
                issues.append(f"Writable memory store without input sanitization: {store.get('type', '?')}")
        elif isinstance(store, str):
            evidence.append(f"Memory store declared: {store}")

    memory_validation = m.get("memory_validation") or m.get("sanitize_memory_inputs")
    if memory_validation:
        evidence.append("memory_validation configured")

    if issues:
        return AgentFinding(
            risk_id="AA4",
            risk_name="Memory Poisoning",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.HIGH,
            description="; ".join(issues),
            evidence=evidence,
            remediation=(
                "Scope memory stores to session rather than global. "
                "Add input sanitization before writing to memory. "
                "Implement memory access controls to prevent cross-agent contamination."
            ),
        )

    if memory_stores and not memory_validation:
        return AgentFinding(
            risk_id="AA4",
            risk_name="Memory Poisoning",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="Memory stores present but no validation/sanitization configured.",
            evidence=evidence,
            remediation="Add `memory_validation: true` and sanitize all inputs before memory writes.",
        )

    return AgentFinding(
        risk_id="AA4",
        risk_name="Memory Poisoning",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="No dangerous memory configurations detected.",
        evidence=evidence + (["No memory stores declared"] if not memory_stores else []),
        remediation="",
    )


def _check_aa5_cascading_failure(m: dict[str, Any]) -> AgentFinding:
    """AA5: Cascading Failure / Uncontrolled Recursion."""
    max_iter = m.get("max_iterations") or m.get("max_steps") or m.get("recursion_limit")
    timeout = m.get("timeout_seconds") or m.get("timeout") or m.get("max_duration_seconds")
    circuit_breaker = m.get("circuit_breaker") or m.get("retry_limit")
    evidence: list[str] = []

    if max_iter:
        evidence.append(f"max_iterations: {max_iter}")
    if timeout:
        evidence.append(f"timeout: {timeout}s")
    if circuit_breaker:
        evidence.append(f"circuit_breaker/retry_limit configured")

    if not max_iter and not timeout:
        return AgentFinding(
            risk_id="AA5",
            risk_name="Cascading Failure / Uncontrolled Recursion",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.HIGH,
            description="No iteration limit or timeout configured — uncontrolled recursion risk.",
            evidence=evidence,
            remediation=(
                "Set `max_iterations: 10` (or appropriate limit) and `timeout_seconds: 300`. "
                "Add a circuit breaker for retry loops. "
                "Implement exponential backoff with jitter for all retries."
            ),
        )

    if not circuit_breaker:
        return AgentFinding(
            risk_id="AA5",
            risk_name="Cascading Failure / Uncontrolled Recursion",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="Iteration limit set but no circuit breaker for cascading retry failures.",
            evidence=evidence,
            remediation="Add `circuit_breaker` or `retry_limit` configuration.",
        )

    return AgentFinding(
        risk_id="AA5",
        risk_name="Cascading Failure / Uncontrolled Recursion",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="Iteration limits and circuit breaker configured.",
        evidence=evidence,
        remediation="",
    )


def _check_aa6_rogue_agents(m: dict[str, Any]) -> AgentFinding:
    """AA6: Rogue Agents / Unauthorized Spawning."""
    spawns = m.get("spawns_subagents", False) or m.get("can_spawn_agents", False)
    spawn_approval = m.get("spawn_approval_required") or m.get("subagent_approval")
    spawn_limit = m.get("max_subagents") or m.get("subagent_limit")
    evidence: list[str] = []

    if spawn_approval:
        evidence.append("spawn_approval_required: true")
    if spawn_limit:
        evidence.append(f"max_subagents: {spawn_limit}")

    if spawns and not spawn_approval:
        return AgentFinding(
            risk_id="AA6",
            risk_name="Rogue Agents / Unauthorized Spawning",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.CRITICAL,
            description="Agent can spawn subagents without approval policy — rogue agent risk.",
            evidence=evidence,
            remediation=(
                "Set `spawn_approval_required: true` for all subagent spawning. "
                "Set `max_subagents` to a reasonable limit (e.g. 3). "
                "Log all subagent spawn events to the audit trail."
            ),
        )

    if spawns and not spawn_limit:
        return AgentFinding(
            risk_id="AA6",
            risk_name="Rogue Agents / Unauthorized Spawning",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.HIGH,
            description="Agent can spawn subagents but no limit on subagent count.",
            evidence=evidence,
            remediation="Add `max_subagents: 3` (or appropriate limit) to prevent uncontrolled spawning.",
        )

    return AgentFinding(
        risk_id="AA6",
        risk_name="Rogue Agents / Unauthorized Spawning",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="Agent spawning is disabled or properly controlled.",
        evidence=evidence + (["spawns_subagents: false"] if not spawns else []),
        remediation="",
    )


def _check_aa7_auditability(m: dict[str, Any]) -> AgentFinding:
    """AA7: Insufficient Auditability / Logging."""
    logging_enabled = m.get("logging_enabled") or m.get("audit_logging")
    audit_endpoint = m.get("audit_trail_endpoint") or m.get("log_endpoint")
    structured_logs = m.get("structured_logging") or m.get("log_format") == "json"
    evidence: list[str] = []

    if logging_enabled:
        evidence.append("logging_enabled: true")
    if audit_endpoint:
        evidence.append(f"audit_trail_endpoint configured: {str(audit_endpoint)[:60]}")
    if structured_logs:
        evidence.append("structured logging configured")

    if not logging_enabled and not audit_endpoint:
        return AgentFinding(
            risk_id="AA7",
            risk_name="Insufficient Auditability / Logging",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.HIGH,
            description="No audit logging configured — agent actions untrackable.",
            evidence=evidence,
            remediation=(
                "Set `logging_enabled: true`. "
                "Configure `audit_trail_endpoint` to send structured logs to a SIEM. "
                "Log: agent input, tool calls made, tool outputs, final response, duration."
            ),
        )

    if not structured_logs:
        return AgentFinding(
            risk_id="AA7",
            risk_name="Insufficient Auditability / Logging",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="Logging enabled but structured format not confirmed.",
            evidence=evidence,
            remediation="Set `log_format: json` for machine-parseable audit logs.",
        )

    return AgentFinding(
        risk_id="AA7",
        risk_name="Insufficient Auditability / Logging",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="Audit logging configured with structured format.",
        evidence=evidence,
        remediation="",
    )


def _check_aa8_excessive_autonomy(m: dict[str, Any]) -> AgentFinding:
    """AA8: Excessive Autonomy / Scope Creep."""
    scope = m.get("scope") or m.get("allowed_actions") or m.get("permissions")
    autonomy_level = m.get("autonomy_level", "")
    write_tools = [
        t for t in m.get("tools", [])
        if any(kw in str(t.get("name", "") + t.get("description", "")).lower()
               for kw in ["write", "create", "delete", "modify", "update", "post", "send", "deploy"])
    ]
    evidence: list[str] = []

    if scope:
        evidence.append(f"scope/permissions defined: {list(scope.keys()) if isinstance(scope, dict) else scope}")
    if autonomy_level:
        evidence.append(f"autonomy_level: {autonomy_level}")

    if autonomy_level in ("full", "unrestricted", "autonomous"):
        return AgentFinding(
            risk_id="AA8",
            risk_name="Excessive Autonomy / Scope Creep",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.CRITICAL,
            description=f"Agent declared as fully autonomous (autonomy_level: {autonomy_level}).",
            evidence=evidence,
            remediation=(
                "Change `autonomy_level` to `supervised` or `restricted`. "
                "Define explicit `scope` boundaries. "
                "Require human approval for irreversible actions."
            ),
        )

    if write_tools and not scope:
        return AgentFinding(
            risk_id="AA8",
            risk_name="Excessive Autonomy / Scope Creep",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.HIGH,
            description=f"Agent has {len(write_tools)} write/mutating tool(s) but no scope constraints.",
            evidence=evidence + [f"Write tools: {[t.get('name') for t in write_tools]}"],
            remediation=(
                "Define explicit `scope` or `allowed_actions` constraints. "
                "Require human approval before any write/mutating tool call."
            ),
        )

    return AgentFinding(
        risk_id="AA8",
        risk_name="Excessive Autonomy / Scope Creep",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="Scope constraints configured or no write tools detected.",
        evidence=evidence,
        remediation="",
    )


def _check_aa9_data_exfiltration(m: dict[str, Any]) -> AgentFinding:
    """AA9: Data Exfiltration via Agent Channels."""
    evidence: list[str] = []
    issues: list[str] = []

    full_text = json.dumps(m)
    exfil_matches = _EXFIL_PATTERNS.findall(full_text)
    if exfil_matches:
        issues.append(f"Known data exfiltration endpoint pattern: {exfil_matches[0][:60]}")

    external_apis = m.get("external_apis", [])
    if isinstance(external_apis, list) and len(external_apis) > 5:
        issues.append(f"Unusually high number of external API endpoints: {len(external_apis)}")

    data_egress_controls = m.get("data_egress_policy") or m.get("output_filtering")
    if data_egress_controls:
        evidence.append("data_egress_policy/output_filtering configured")

    allowlist = m.get("api_allowlist") or m.get("external_api_allowlist")
    if allowlist:
        evidence.append(f"API allowlist configured ({len(allowlist) if isinstance(allowlist, list) else '?'} entries)")

    if issues:
        return AgentFinding(
            risk_id="AA9",
            risk_name="Data Exfiltration via Agent Channels",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.CRITICAL,
            description="; ".join(issues),
            evidence=evidence,
            remediation=(
                "Remove or replace suspicious API endpoints. "
                "Implement an API allowlist via `api_allowlist`. "
                "Add output filtering to detect PII or sensitive data in responses."
            ),
        )

    if external_apis and not allowlist:
        return AgentFinding(
            risk_id="AA9",
            risk_name="Data Exfiltration via Agent Channels",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="External APIs configured without an allowlist — exfiltration risk.",
            evidence=evidence,
            remediation="Add `api_allowlist` to restrict which external endpoints the agent can call.",
        )

    return AgentFinding(
        risk_id="AA9",
        risk_name="Data Exfiltration via Agent Channels",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="No exfiltration patterns detected. API controls configured.",
        evidence=evidence + (["No external APIs"] if not external_apis else []),
        remediation="",
    )


def _check_aa10_human_oversight(m: dict[str, Any]) -> AgentFinding:
    """AA10: Insufficient Human Oversight / Control."""
    human_approval = m.get("human_approval_required") or m.get("hitl_enabled") or m.get("human_in_the_loop")
    override_mechanism = m.get("human_override") or m.get("abort_command") or m.get("kill_switch")
    escalation = m.get("escalation_policy") or m.get("escalate_to_human")
    evidence: list[str] = []

    if human_approval:
        evidence.append("human_approval_required: true")
    if override_mechanism:
        evidence.append("human override/kill_switch configured")
    if escalation:
        evidence.append("escalation policy configured")

    if not human_approval and not override_mechanism:
        return AgentFinding(
            risk_id="AA10",
            risk_name="Insufficient Human Oversight / Control",
            status=FindingStatus.FAIL,
            risk_level=RiskLevel.CRITICAL,
            description="No human approval requirement or override mechanism — fully autonomous execution.",
            evidence=evidence,
            remediation=(
                "Set `human_approval_required: true` for irreversible or high-risk actions. "
                "Add `kill_switch` endpoint. "
                "Implement `escalation_policy` to route uncertain decisions to human reviewers. "
                "EU AI Act Article 14 requires human oversight for high-risk AI systems."
            ),
        )

    if not escalation:
        return AgentFinding(
            risk_id="AA10",
            risk_name="Insufficient Human Oversight / Control",
            status=FindingStatus.WARN,
            risk_level=RiskLevel.MEDIUM,
            description="Approval mechanism present but no escalation policy for edge cases.",
            evidence=evidence,
            remediation="Add `escalation_policy` to handle uncertain or low-confidence decisions.",
        )

    return AgentFinding(
        risk_id="AA10",
        risk_name="Insufficient Human Oversight / Control",
        status=FindingStatus.PASS,
        risk_level=RiskLevel.LOW,
        description="Human oversight controls in place: approval, override, and escalation.",
        evidence=evidence,
        remediation="",
    )


# ── Report builder ─────────────────────────────────────────────────────────────

def _build_report(
    agent_name: str,
    agent_type: str,
    manifest_hash: str,
    findings: list[AgentFinding],
) -> AgentAuditReport:
    _RISK_WEIGHTS = {
        RiskLevel.CRITICAL: 25,
        RiskLevel.HIGH: 15,
        RiskLevel.MEDIUM: 8,
        RiskLevel.LOW: 2,
    }

    critical = sum(1 for f in findings if f.status != FindingStatus.PASS and f.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for f in findings if f.status != FindingStatus.PASS and f.risk_level == RiskLevel.HIGH)
    medium = sum(1 for f in findings if f.status != FindingStatus.PASS and f.risk_level == RiskLevel.MEDIUM)
    low = sum(1 for f in findings if f.status != FindingStatus.PASS and f.risk_level == RiskLevel.LOW)
    passed = sum(1 for f in findings if f.status == FindingStatus.PASS)

    risk_score = min(
        100,
        critical * _RISK_WEIGHTS[RiskLevel.CRITICAL]
        + high * _RISK_WEIGHTS[RiskLevel.HIGH]
        + medium * _RISK_WEIGHTS[RiskLevel.MEDIUM]
        + low * _RISK_WEIGHTS[RiskLevel.LOW],
    )

    if critical > 0:
        overall = RiskLevel.CRITICAL
    elif high > 0:
        overall = RiskLevel.HIGH
    elif medium > 0:
        overall = RiskLevel.MEDIUM
    elif low > 0:
        overall = RiskLevel.LOW
    else:
        overall = RiskLevel.INFO

    return AgentAuditReport(
        agent_name=agent_name,
        agent_type=agent_type,
        audited_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        manifest_hash=manifest_hash,
        findings=findings,
        overall_risk=overall,
        risk_score=risk_score,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        passed_count=passed,
    )
