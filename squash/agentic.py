"""squash/agentic.py — OWASP Agentic Top 10 2026 scan profile.

Scans an agentic system configuration against the OWASP Top 10 for Agentic
Applications 2026.  No network calls are made; the scanner works entirely
from the config dict supplied by the caller.

Configuration schema
--------------------
The ``config`` dict passed to :meth:`AgenticScanner.scan` describes an agentic
system.  All keys are optional; missing keys are treated as "not configured"
and may trigger findings.  Recognised keys:

``tool_list`` : list[str]
    Names / identifiers of tools the agent is authorised to call.
``tool_scope_declared`` : bool
    Whether the declared tool scope is enforced at runtime.
``memory_type`` : str
    Backing store for persistent agent memory (e.g. ``"vector_db"``,
    ``"redis"``, ``"none"``).
``memory_input_validation`` : bool
    Whether content written to memory is validated / sanitised.
``trust_sources`` : list[str]
    Data sources the agent treats as authoritative (e.g. ``["user"]``,
    ``["user", "external_api"]``).
``trust_sources_validated`` : bool
    Whether input from trust sources is validated before acting on it.
``human_oversight`` : bool | str
    ``True`` / ``"required"`` means a human checkpoint exists for
    high-stakes decisions.  Anything else (including ``False``) means no
    human oversight.
``goal_source`` : str
    Where the agent receives its top-level goal (``"user"``,
    ``"operator"``, ``"external"``, ``"untrusted_channel"``).
``goal_validation`` : bool
    Whether goals are validated against an allow-list before execution.
``inter_agent_comms`` : bool
    Whether the system includes agent-to-agent communication.
``inter_agent_auth`` : bool
    Whether inter-agent messages are authenticated / attested.
``privilege_escalation_controls`` : bool
    Whether the system prevents capability escalation beyond the initial
    grant.
``sandbox`` : bool
    Whether the agent runs in a sandboxed execution environment.
``tool_output_sanitisation`` : bool
    Whether tool outputs are sanitised before being fed back as context.
``goal_proxy_alignment_check`` : bool
    Whether proxy metrics are regularly audited against the intended goal.
``trust_chain_attestation`` : bool
    Whether every hop in a delegated trust chain carries a cryptographic
    attestation.
``max_autonomy_steps`` : int | None
    Maximum consecutive autonomous steps before requiring human approval.
    ``None`` / absent means unbounded.
``emergent_behavior_testing`` : bool
    Whether the system is tested for emergent / multi-step adversarial
    behaviour.

Usage::

    from squash.agentic import AgenticScanner

    result = AgenticScanner().scan({
        "tool_list": ["search", "send_email"],
        "tool_scope_declared": True,
        "human_oversight": True,
        "goal_source": "operator",
        "goal_validation": True,
        "memory_input_validation": True,
        "trust_sources_validated": True,
        "inter_agent_comms": False,
        "privilege_escalation_controls": True,
        "sandbox": True,
        "tool_output_sanitisation": True,
        "goal_proxy_alignment_check": True,
        "trust_chain_attestation": True,
        "max_autonomy_steps": 5,
        "emergent_behavior_testing": True,
    })
    print(result.passed, result.score)

References
----------
* OWASP Top 10 for Agentic Applications 2026 —
  https://owasp.org/www-project-top-10-for-llm-applications/
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data-transfer objects
# ---------------------------------------------------------------------------

OWASP_AGENTIC_REF = "OWASP Agentic Top 10 2026"


@dataclass
class AgenticFinding:
    """A single OWASP Agentic Top 10 finding from a scan."""

    risk_id: str
    """Identifier in the form ``"A01"`` through ``"A10"``."""
    title: str
    """Short risk title."""
    severity: str
    """One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``."""
    description: str
    """Human-readable description of the detected risk."""
    evidence: list[str]
    """Observations in the config that triggered this finding."""
    remediation: str
    """One-sentence actionable fix."""
    owasp_ref: str
    """Full OWASP reference string, e.g. ``"OWASP Agentic Top 10 2026 — A01"``."""

    def __post_init__(self) -> None:
        """Validate severity value on construction."""
        valid = {"critical", "high", "medium", "low"}
        if self.severity not in valid:
            raise ValueError(
                f"AgenticFinding.severity must be one of {valid}; got {self.severity!r}"
            )


@dataclass
class AgenticScanResult:
    """Aggregate result of an OWASP Agentic Top 10 scan."""

    findings: list[AgenticFinding]
    passed: bool
    """``True`` iff there are zero critical or high findings."""
    score: int
    """Compliance score 0–100 (100 = all checks pass)."""
    summary: str
    """Human-readable summary line."""
    framework: str = "owasp-agentic-top10-2026"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_TOTAL_CHECKS = 10  # one per risk


class AgenticScanner:
    """Scan an agentic system specification against OWASP Agentic Top 10 2026.

    Each of the ten risk checks is a private method ``_check_A0N`` that
    receives the full config dict and returns either an
    :class:`AgenticFinding` or ``None`` when the check passes.
    """

    # ------------------------------------------------------------------ public

    def scan(self, config: dict[str, Any]) -> AgenticScanResult:
        """Run all ten agentic risk checks against *config*.

        Parameters
        ----------
        config:
            Agentic system specification dict.  See module docstring for the
            full schema.  Unknown keys are ignored.

        Returns
        -------
        AgenticScanResult
            Findings, pass/fail flag, 0–100 score, and summary text.
        """
        findings: list[AgenticFinding] = []
        for check in (
            self._check_A01,
            self._check_A02,
            self._check_A03,
            self._check_A04,
            self._check_A05,
            self._check_A06,
            self._check_A07,
            self._check_A08,
            self._check_A09,
            self._check_A10,
        ):
            result = check(config)
            if result is not None:
                findings.append(result)
                log.debug("AgenticScanner: %s triggered — %s", result.risk_id, result.title)

        passed = all(f.severity not in {"critical", "high"} for f in findings)
        passing_checks = _TOTAL_CHECKS - len(findings)
        score = int(round(passing_checks / _TOTAL_CHECKS * 100))

        finding_count = len(findings)
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        parts = []
        for sev in ("critical", "high", "medium", "low"):
            n = sev_counts.get(sev, 0)
            if n:
                parts.append(f"{n} {sev}")

        if finding_count == 0:
            summary = f"All {_TOTAL_CHECKS} agentic checks passed — score {score}/100"
        else:
            sev_str = ", ".join(parts) if parts else "unknown"
            summary = (
                f"{finding_count}/{_TOTAL_CHECKS} agentic checks failed "
                f"({sev_str}) — score {score}/100"
            )

        return AgenticScanResult(
            findings=findings,
            passed=passed,
            score=score,
            summary=summary,
        )

    # ----------------------------------------------------------------- checks

    def _check_A01(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A01 — Unsafe Goal Delegation.

        Fires when the agent's goal can originate from an untrusted source
        and no goal validation is configured.
        """
        goal_source: str = config.get("goal_source", "unknown")
        goal_validation: bool = bool(config.get("goal_validation", False))

        unsafe_sources = {"external", "untrusted_channel", "unknown"}
        if goal_source in unsafe_sources and not goal_validation:
            evidence = [
                f"goal_source={goal_source!r}",
                f"goal_validation={goal_validation}",
            ]
            return AgenticFinding(
                risk_id="A01",
                title="Unsafe Goal Delegation",
                severity="critical",
                description=(
                    "The agent accepts goals from an untrusted or external source "
                    "without validating them against an allow-list, enabling "
                    "adversarial goal injection."
                ),
                evidence=evidence,
                remediation=(
                    "Restrict goal sources to trusted operators and enforce "
                    "allow-list validation before any goal is executed."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A01",
            )
        return None

    def _check_A02(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A02 — Memory Poisoning.

        Fires when a persistent memory store is configured but input
        validation for memory writes is absent.
        """
        memory_type: str = config.get("memory_type", "none")
        memory_validation: bool = bool(config.get("memory_input_validation", False))

        if memory_type not in {"none", "None", None, ""} and not memory_validation:
            evidence = [
                f"memory_type={memory_type!r}",
                f"memory_input_validation={memory_validation}",
            ]
            return AgenticFinding(
                risk_id="A02",
                title="Memory Poisoning",
                severity="high",
                description=(
                    "The agent uses a persistent memory store but does not validate "
                    "or sanitise content written to it, leaving the store vulnerable "
                    "to adversarial manipulation that alters future behaviour."
                ),
                evidence=evidence,
                remediation=(
                    "Validate and sanitise all inputs before writing to the memory "
                    "store and audit stored entries periodically."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A02",
            )
        return None

    def _check_A03(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A03 — Tool Misuse.

        Fires when no declared tool scope exists or scope enforcement is
        disabled.
        """
        tool_list: list[str] | None = config.get("tool_list")
        scope_declared: bool = bool(config.get("tool_scope_declared", False))

        if not tool_list or not scope_declared:
            evidence: list[str] = []
            if not tool_list:
                evidence.append("tool_list is empty or absent")
            if not scope_declared:
                evidence.append("tool_scope_declared=False")
            return AgenticFinding(
                risk_id="A03",
                title="Tool Misuse",
                severity="high",
                description=(
                    "The agent lacks a declared and enforced tool scope, allowing it "
                    "to invoke tools beyond what is authorised for the current task."
                ),
                evidence=evidence,
                remediation=(
                    "Define an explicit tool allow-list and enforce it at the agent "
                    "runtime so unauthorised tool calls are rejected."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A03",
            )
        return None

    def _check_A04(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A04 — Privilege Escalation.

        Fires when no privilege escalation controls are in place.
        """
        controls: bool = bool(config.get("privilege_escalation_controls", False))
        sandbox: bool = bool(config.get("sandbox", False))

        if not controls and not sandbox:
            return AgenticFinding(
                risk_id="A04",
                title="Privilege Escalation",
                severity="critical",
                description=(
                    "The agent has no controls preventing it from acquiring "
                    "capabilities beyond its initial privilege grant, creating a "
                    "path for unintended or malicious escalation."
                ),
                evidence=[
                    "privilege_escalation_controls=False",
                    "sandbox=False",
                ],
                remediation=(
                    "Run the agent in a sandboxed environment with least-privilege "
                    "permissions and enforce capability boundaries at the runtime."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A04",
            )
        return None

    def _check_A05(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A05 — Inter-Agent Trust Abuse.

        Fires when inter-agent communication is enabled but messages are not
        authenticated.
        """
        inter_agent: bool = bool(config.get("inter_agent_comms", False))
        inter_auth: bool = bool(config.get("inter_agent_auth", False))

        if inter_agent and not inter_auth:
            return AgenticFinding(
                risk_id="A05",
                title="Inter-Agent Trust Abuse",
                severity="high",
                description=(
                    "The system uses agent-to-agent communication but does not "
                    "authenticate or attest messages between agents, enabling a "
                    "compromised agent to impersonate a trusted peer."
                ),
                evidence=[
                    "inter_agent_comms=True",
                    "inter_agent_auth=False",
                ],
                remediation=(
                    "Require cryptographic attestation or signed tokens for all "
                    "inter-agent messages and reject unauthenticated instructions."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A05",
            )
        return None

    def _check_A06(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A06 — Unbounded Autonomy.

        Fires when there is no human-in-the-loop checkpoint for high-stakes
        decisions, or when the maximum number of autonomous steps is
        unbounded.
        """
        oversight_raw = config.get("human_oversight", False)
        has_oversight = oversight_raw in {True, "required", "yes", "enabled"}
        max_steps = config.get("max_autonomy_steps")

        if not has_oversight and max_steps is None:
            return AgenticFinding(
                risk_id="A06",
                title="Unbounded Autonomy",
                severity="high",
                description=(
                    "The agent operates without human-in-the-loop checkpoints and "
                    "without a cap on consecutive autonomous steps, allowing "
                    "unchecked execution of high-stakes actions."
                ),
                evidence=[
                    f"human_oversight={oversight_raw!r}",
                    "max_autonomy_steps=None (unbounded)",
                ],
                remediation=(
                    "Introduce mandatory human approval checkpoints for high-stakes "
                    "decisions and set a maximum on consecutive autonomous steps."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A06",
            )
        return None

    def _check_A07(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A07 — Emergent Behavior Exploitation.

        Fires when no testing for emergent or adversarial multi-step
        behaviour has been declared.
        """
        tested: bool = bool(config.get("emergent_behavior_testing", False))
        if not tested:
            return AgenticFinding(
                risk_id="A07",
                title="Emergent Behavior Exploitation",
                severity="medium",
                description=(
                    "The system has not been tested for adversarial inputs that "
                    "trigger unintended multi-step action chains, leaving emergent "
                    "exploitation vectors undetected."
                ),
                evidence=["emergent_behavior_testing=False"],
                remediation=(
                    "Implement adversarial red-teaming and simulation tests that "
                    "exercise multi-step chains to identify emergent exploitation "
                    "paths before deployment."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A07",
            )
        return None

    def _check_A08(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A08 — Prompt Injection via Tools.

        Fires when tool outputs are fed back to the agent as context without
        sanitisation.
        """
        sanitised: bool = bool(config.get("tool_output_sanitisation", False))
        tool_list: list[str] | None = config.get("tool_list")

        # Only relevant when the agent actually uses tools
        has_tools = bool(tool_list)
        if has_tools and not sanitised:
            return AgenticFinding(
                risk_id="A08",
                title="Prompt Injection via Tools",
                severity="critical",
                description=(
                    "Tool outputs are incorporated into the agent's context without "
                    "sanitisation, creating a prompt injection vector where a "
                    "malicious tool response can override agent instructions."
                ),
                evidence=[
                    f"tool_list has {len(tool_list)} tool(s)",
                    "tool_output_sanitisation=False",
                ],
                remediation=(
                    "Sanitise all tool outputs and treat them as untrusted data "
                    "before including them in the agent's prompt or reasoning context."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A08",
            )
        return None

    def _check_A09(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A09 — Goal Misalignment.

        Fires when proxy metrics are not periodically audited against the
        intended goal, allowing silent divergence.
        """
        alignment_check: bool = bool(config.get("goal_proxy_alignment_check", False))
        if not alignment_check:
            return AgenticFinding(
                risk_id="A09",
                title="Goal Misalignment",
                severity="medium",
                description=(
                    "The agent optimises a proxy objective without regular auditing "
                    "against the intended goal, risking silent Goodhart's Law "
                    "divergence over time."
                ),
                evidence=["goal_proxy_alignment_check=False"],
                remediation=(
                    "Schedule regular audits that compare the agent's proxy metrics "
                    "against intended outcomes and trigger alerts on divergence."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A09",
            )
        return None

    def _check_A10(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A10 — Delegated Trust Chains.

        Fires when the system involves inter-agent communication but does
        not attest every hop in the trust chain.
        """
        inter_agent: bool = bool(config.get("inter_agent_comms", False))
        chain_attest: bool = bool(config.get("trust_chain_attestation", False))

        if inter_agent and not chain_attest:
            return AgenticFinding(
                risk_id="A10",
                title="Delegated Trust Chains",
                severity="high",
                description=(
                    "The system delegates decisions across multiple agents but does "
                    "not require cryptographic attestation at each hop in the trust "
                    "chain, making it impossible to verify the integrity of "
                    "delegated instructions."
                ),
                evidence=[
                    "inter_agent_comms=True",
                    "trust_chain_attestation=False",
                ],
                remediation=(
                    "Attach a signed attestation to every delegation hop and validate "
                    "the full chain before acting on delegated instructions."
                ),
                owasp_ref=f"{OWASP_AGENTIC_REF} — A10",
            )
        return None
