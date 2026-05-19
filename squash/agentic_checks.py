"""squash/agentic_checks.py — OWASP Agentic Top 10 2026 individual check functions.

Each function implements one of the ten risk checks and returns an
:class:`~squash.agentic.AgenticFinding` when the check fails, or ``None``
when the check passes.  They are called by
:class:`~squash.agentic.AgenticScanner` and should not be called directly by
application code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from squash.agentic import AgenticFinding

from squash.agentic import OWASP_AGENTIC_REF, AgenticFinding


def check_A01(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A02(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A03(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A04(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A05(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A06(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
    """A06 — Unbounded Autonomy.

    Fires when there is no human-in-the-loop checkpoint for high-stakes
    decisions, or when the maximum number of autonomous steps is unbounded.
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


def check_A07(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A08(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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
                f"tool_list has {len(tool_list)} tool(s)",  # type: ignore[arg-type]
                "tool_output_sanitisation=False",
            ],
            remediation=(
                "Sanitise all tool outputs and treat them as untrusted data "
                "before including them in the agent's prompt or reasoning context."
            ),
            owasp_ref=f"{OWASP_AGENTIC_REF} — A08",
        )
    return None


def check_A09(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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


def check_A10(config: dict[str, Any]) -> AgenticFinding | None:  # noqa: N802
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
