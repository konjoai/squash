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
    # Individual check implementations live in squash/agentic_checks.py
    # to keep this file under 500 lines.  The methods below are thin
    # dispatchers that import and call the module-level functions.

    def _check_A01(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A01 — Unsafe Goal Delegation."""
        from squash.agentic_checks import check_A01

        return check_A01(config)

    def _check_A02(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A02 — Memory Poisoning."""
        from squash.agentic_checks import check_A02

        return check_A02(config)

    def _check_A03(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A03 — Tool Misuse."""
        from squash.agentic_checks import check_A03

        return check_A03(config)

    def _check_A04(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A04 — Privilege Escalation."""
        from squash.agentic_checks import check_A04

        return check_A04(config)

    def _check_A05(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A05 — Inter-Agent Trust Abuse."""
        from squash.agentic_checks import check_A05

        return check_A05(config)

    def _check_A06(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A06 — Unbounded Autonomy."""
        from squash.agentic_checks import check_A06

        return check_A06(config)

    def _check_A07(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A07 — Emergent Behavior Exploitation."""
        from squash.agentic_checks import check_A07

        return check_A07(config)

    def _check_A08(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A08 — Prompt Injection via Tools."""
        from squash.agentic_checks import check_A08

        return check_A08(config)

    def _check_A09(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A09 — Goal Misalignment."""
        from squash.agentic_checks import check_A09

        return check_A09(config)

    def _check_A10(self, config: dict[str, Any]) -> AgenticFinding | None:
        """A10 — Delegated Trust Chains."""
        from squash.agentic_checks import check_A10

        return check_A10(config)
