"""tests/test_agentic.py — OWASP Agentic Top 10 2026 scan profile tests.

Covers:
- Each of the 10 risk checks individually (pass + fail cases)
- Score calculation (all pass → 100, all fail → 0)
- ``passed`` flag logic (critical/high finding → not passed)
- Config with no tool list → graceful handling
- Full scan integration: safe config → 0 findings; toxic config → ≥ 5 findings
- CLI smoke tests via argparse / _build_parser
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squash.agentic import AgenticFinding, AgenticScanner, AgenticScanResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAFE_CONFIG: dict = {
    "tool_list": ["search", "send_email"],
    "tool_scope_declared": True,
    "memory_type": "vector_db",
    "memory_input_validation": True,
    "trust_sources": ["operator"],
    "trust_sources_validated": True,
    "human_oversight": True,
    "goal_source": "operator",
    "goal_validation": True,
    "inter_agent_comms": False,
    "inter_agent_auth": False,
    "privilege_escalation_controls": True,
    "sandbox": True,
    "tool_output_sanitisation": True,
    "goal_proxy_alignment_check": True,
    "trust_chain_attestation": False,
    "max_autonomy_steps": 5,
    "emergent_behavior_testing": True,
}

TOXIC_CONFIG: dict = {
    "tool_list": ["search", "send_email", "execute_code", "db_write"],
    "tool_scope_declared": False,
    "memory_type": "redis",
    "memory_input_validation": False,
    "trust_sources": ["external_api"],
    "trust_sources_validated": False,
    "human_oversight": False,
    "goal_source": "untrusted_channel",
    "goal_validation": False,
    "inter_agent_comms": True,
    "inter_agent_auth": False,
    "privilege_escalation_controls": False,
    "sandbox": False,
    "tool_output_sanitisation": False,
    "goal_proxy_alignment_check": False,
    "trust_chain_attestation": False,
    "max_autonomy_steps": None,
    "emergent_behavior_testing": False,
}

SCANNER = AgenticScanner()


# ===========================================================================
# AgenticFinding construction
# ===========================================================================


def test_finding_valid_severity() -> None:
    f = AgenticFinding(
        risk_id="A01",
        title="Test",
        severity="critical",
        description="desc",
        evidence=["x"],
        remediation="fix it",
        owasp_ref="OWASP Agentic Top 10 2026 — A01",
    )
    assert f.severity == "critical"


def test_finding_invalid_severity_raises() -> None:
    with pytest.raises(ValueError, match="severity"):
        AgenticFinding(
            risk_id="A01",
            title="Test",
            severity="blocker",
            description="desc",
            evidence=[],
            remediation="fix it",
            owasp_ref="OWASP Agentic Top 10 2026 — A01",
        )


def test_finding_all_valid_severities() -> None:
    for sev in ("critical", "high", "medium", "low"):
        f = AgenticFinding(
            risk_id="A01",
            title="T",
            severity=sev,
            description="d",
            evidence=[],
            remediation="r",
            owasp_ref="ref",
        )
        assert f.severity == sev


# ===========================================================================
# A01 — Unsafe Goal Delegation
# ===========================================================================


def test_a01_fires_on_untrusted_channel_no_validation() -> None:
    cfg = {**SAFE_CONFIG, "goal_source": "untrusted_channel", "goal_validation": False}
    result = SCANNER.scan(cfg)
    ids = [f.risk_id for f in result.findings]
    assert "A01" in ids


def test_a01_fires_on_external_no_validation() -> None:
    cfg = {**SAFE_CONFIG, "goal_source": "external", "goal_validation": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A01" for f in result.findings)


def test_a01_fires_on_unknown_goal_source() -> None:
    cfg = {**SAFE_CONFIG, "goal_source": "unknown", "goal_validation": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A01" for f in result.findings)


def test_a01_passes_when_goal_validated() -> None:
    cfg = {**SAFE_CONFIG, "goal_source": "external", "goal_validation": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A01" for f in result.findings)


def test_a01_passes_trusted_source() -> None:
    cfg = {**SAFE_CONFIG, "goal_source": "operator", "goal_validation": False}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A01" for f in result.findings)


def test_a01_severity_is_critical() -> None:
    cfg = {**SAFE_CONFIG, "goal_source": "untrusted_channel", "goal_validation": False}
    result = SCANNER.scan(cfg)
    a01 = next(f for f in result.findings if f.risk_id == "A01")
    assert a01.severity == "critical"


# ===========================================================================
# A02 — Memory Poisoning
# ===========================================================================


def test_a02_fires_when_memory_configured_no_validation() -> None:
    cfg = {**SAFE_CONFIG, "memory_type": "vector_db", "memory_input_validation": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A02" for f in result.findings)


def test_a02_passes_when_no_memory() -> None:
    cfg = {**SAFE_CONFIG, "memory_type": "none", "memory_input_validation": False}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A02" for f in result.findings)


def test_a02_passes_when_memory_validated() -> None:
    cfg = {**SAFE_CONFIG, "memory_type": "redis", "memory_input_validation": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A02" for f in result.findings)


def test_a02_passes_when_memory_key_absent() -> None:
    # No memory_type → no persistent memory → should not fire
    cfg = {
        k: v for k, v in SAFE_CONFIG.items() if k not in ("memory_type", "memory_input_validation")
    }
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A02" for f in result.findings)


def test_a02_severity_is_high() -> None:
    cfg = {**SAFE_CONFIG, "memory_type": "vector_db", "memory_input_validation": False}
    result = SCANNER.scan(cfg)
    a02 = next(f for f in result.findings if f.risk_id == "A02")
    assert a02.severity == "high"


# ===========================================================================
# A03 — Tool Misuse
# ===========================================================================


def test_a03_fires_when_no_tool_list() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": [], "tool_scope_declared": True}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A03" for f in result.findings)


def test_a03_fires_when_scope_not_declared() -> None:
    cfg = {**SAFE_CONFIG, "tool_scope_declared": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A03" for f in result.findings)


def test_a03_passes_with_tool_list_and_scope() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": ["search"], "tool_scope_declared": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A03" for f in result.findings)


def test_a03_fires_when_tool_list_absent() -> None:
    cfg = {k: v for k, v in SAFE_CONFIG.items() if k not in ("tool_list",)}
    cfg["tool_scope_declared"] = True
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A03" for f in result.findings)


def test_a03_severity_is_high() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": [], "tool_scope_declared": False}
    result = SCANNER.scan(cfg)
    a03 = next(f for f in result.findings if f.risk_id == "A03")
    assert a03.severity == "high"


# ===========================================================================
# A04 — Privilege Escalation
# ===========================================================================


def test_a04_fires_no_controls_no_sandbox() -> None:
    cfg = {**SAFE_CONFIG, "privilege_escalation_controls": False, "sandbox": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A04" for f in result.findings)


def test_a04_passes_with_controls() -> None:
    cfg = {**SAFE_CONFIG, "privilege_escalation_controls": True, "sandbox": False}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A04" for f in result.findings)


def test_a04_passes_with_sandbox_only() -> None:
    cfg = {**SAFE_CONFIG, "privilege_escalation_controls": False, "sandbox": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A04" for f in result.findings)


def test_a04_severity_is_critical() -> None:
    cfg = {**SAFE_CONFIG, "privilege_escalation_controls": False, "sandbox": False}
    result = SCANNER.scan(cfg)
    a04 = next(f for f in result.findings if f.risk_id == "A04")
    assert a04.severity == "critical"


# ===========================================================================
# A05 — Inter-Agent Trust Abuse
# ===========================================================================


def test_a05_fires_when_inter_agent_no_auth() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": True, "inter_agent_auth": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A05" for f in result.findings)


def test_a05_passes_when_no_inter_agent_comms() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": False}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A05" for f in result.findings)


def test_a05_passes_when_inter_agent_auth_present() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": True, "inter_agent_auth": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A05" for f in result.findings)


def test_a05_severity_is_high() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": True, "inter_agent_auth": False}
    result = SCANNER.scan(cfg)
    a05 = next(f for f in result.findings if f.risk_id == "A05")
    assert a05.severity == "high"


# ===========================================================================
# A06 — Unbounded Autonomy
# ===========================================================================


def test_a06_fires_no_oversight_no_max_steps() -> None:
    cfg = {**SAFE_CONFIG, "human_oversight": False, "max_autonomy_steps": None}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A06" for f in result.findings)


def test_a06_passes_with_human_oversight() -> None:
    cfg = {**SAFE_CONFIG, "human_oversight": True, "max_autonomy_steps": None}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A06" for f in result.findings)


def test_a06_passes_with_max_steps_only() -> None:
    cfg = {**SAFE_CONFIG, "human_oversight": False, "max_autonomy_steps": 10}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A06" for f in result.findings)


def test_a06_passes_with_required_string() -> None:
    cfg = {**SAFE_CONFIG, "human_oversight": "required", "max_autonomy_steps": None}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A06" for f in result.findings)


def test_a06_severity_is_high() -> None:
    cfg = {**SAFE_CONFIG, "human_oversight": False, "max_autonomy_steps": None}
    result = SCANNER.scan(cfg)
    a06 = next(f for f in result.findings if f.risk_id == "A06")
    assert a06.severity == "high"


# ===========================================================================
# A07 — Emergent Behavior Exploitation
# ===========================================================================


def test_a07_fires_when_not_tested() -> None:
    cfg = {**SAFE_CONFIG, "emergent_behavior_testing": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A07" for f in result.findings)


def test_a07_passes_when_tested() -> None:
    cfg = {**SAFE_CONFIG, "emergent_behavior_testing": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A07" for f in result.findings)


def test_a07_fires_when_key_absent() -> None:
    cfg = {k: v for k, v in SAFE_CONFIG.items() if k != "emergent_behavior_testing"}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A07" for f in result.findings)


def test_a07_severity_is_medium() -> None:
    cfg = {**SAFE_CONFIG, "emergent_behavior_testing": False}
    result = SCANNER.scan(cfg)
    a07 = next(f for f in result.findings if f.risk_id == "A07")
    assert a07.severity == "medium"


# ===========================================================================
# A08 — Prompt Injection via Tools
# ===========================================================================


def test_a08_fires_with_tools_no_sanitisation() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": ["search"], "tool_output_sanitisation": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A08" for f in result.findings)


def test_a08_passes_with_sanitisation() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": ["search"], "tool_output_sanitisation": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A08" for f in result.findings)


def test_a08_passes_no_tools_no_sanitisation() -> None:
    # No tools → A08 irrelevant (A03 may fire, but not A08)
    cfg = {**SAFE_CONFIG, "tool_list": [], "tool_output_sanitisation": False}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A08" for f in result.findings)


def test_a08_severity_is_critical() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": ["search"], "tool_output_sanitisation": False}
    result = SCANNER.scan(cfg)
    a08 = next(f for f in result.findings if f.risk_id == "A08")
    assert a08.severity == "critical"


# ===========================================================================
# A09 — Goal Misalignment
# ===========================================================================


def test_a09_fires_when_no_alignment_check() -> None:
    cfg = {**SAFE_CONFIG, "goal_proxy_alignment_check": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A09" for f in result.findings)


def test_a09_passes_when_alignment_checked() -> None:
    cfg = {**SAFE_CONFIG, "goal_proxy_alignment_check": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A09" for f in result.findings)


def test_a09_fires_when_key_absent() -> None:
    cfg = {k: v for k, v in SAFE_CONFIG.items() if k != "goal_proxy_alignment_check"}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A09" for f in result.findings)


def test_a09_severity_is_medium() -> None:
    cfg = {**SAFE_CONFIG, "goal_proxy_alignment_check": False}
    result = SCANNER.scan(cfg)
    a09 = next(f for f in result.findings if f.risk_id == "A09")
    assert a09.severity == "medium"


# ===========================================================================
# A10 — Delegated Trust Chains
# ===========================================================================


def test_a10_fires_when_inter_agent_no_chain_attest() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": True, "trust_chain_attestation": False}
    result = SCANNER.scan(cfg)
    assert any(f.risk_id == "A10" for f in result.findings)


def test_a10_passes_when_no_inter_agent_comms() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": False, "trust_chain_attestation": False}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A10" for f in result.findings)


def test_a10_passes_when_chain_attested() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": True, "trust_chain_attestation": True}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A10" for f in result.findings)


def test_a10_severity_is_high() -> None:
    cfg = {**SAFE_CONFIG, "inter_agent_comms": True, "trust_chain_attestation": False}
    result = SCANNER.scan(cfg)
    a10 = next(f for f in result.findings if f.risk_id == "A10")
    assert a10.severity == "high"


# ===========================================================================
# Score calculation
# ===========================================================================


def test_score_100_when_all_checks_pass() -> None:
    result = SCANNER.scan(SAFE_CONFIG)
    assert result.score == 100


def test_score_0_when_all_checks_fail() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    assert result.score == 0


def test_score_partial_one_finding() -> None:
    # Trigger exactly A07 on an otherwise-safe config
    cfg = {**SAFE_CONFIG, "emergent_behavior_testing": False}
    result = SCANNER.scan(cfg)
    # 9 passing out of 10 → 90
    assert result.score == 90


def test_score_range() -> None:
    result = SCANNER.scan(SAFE_CONFIG)
    assert 0 <= result.score <= 100


def test_score_decreases_with_more_findings() -> None:
    one_finding = {**SAFE_CONFIG, "emergent_behavior_testing": False}
    two_findings = {
        **SAFE_CONFIG,
        "emergent_behavior_testing": False,
        "goal_proxy_alignment_check": False,
    }
    r1 = SCANNER.scan(one_finding)
    r2 = SCANNER.scan(two_findings)
    assert r2.score < r1.score


# ===========================================================================
# passed flag logic
# ===========================================================================


def test_passed_true_when_no_findings() -> None:
    result = SCANNER.scan(SAFE_CONFIG)
    assert result.passed is True


def test_passed_false_on_critical_finding() -> None:
    # A01 is critical
    cfg = {**SAFE_CONFIG, "goal_source": "untrusted_channel", "goal_validation": False}
    result = SCANNER.scan(cfg)
    assert result.passed is False


def test_passed_false_on_high_finding() -> None:
    # A02 is high
    cfg = {**SAFE_CONFIG, "memory_type": "vector_db", "memory_input_validation": False}
    result = SCANNER.scan(cfg)
    assert result.passed is False


def test_passed_true_with_only_medium_findings() -> None:
    # A07 (medium) + A09 (medium) only
    cfg = {
        **SAFE_CONFIG,
        "emergent_behavior_testing": False,
        "goal_proxy_alignment_check": False,
    }
    result = SCANNER.scan(cfg)
    assert result.passed is True


def test_passed_false_toxic_config() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    assert result.passed is False


# ===========================================================================
# Full scan integration
# ===========================================================================


def test_safe_config_produces_zero_findings() -> None:
    result = SCANNER.scan(SAFE_CONFIG)
    assert result.findings == []


def test_toxic_config_produces_at_least_five_findings() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    assert len(result.findings) >= 5


def test_result_framework_field() -> None:
    result = SCANNER.scan(SAFE_CONFIG)
    assert result.framework == "owasp-agentic-top10-2026"


def test_result_summary_present() -> None:
    result = SCANNER.scan(SAFE_CONFIG)
    assert result.summary
    assert "100" in result.summary


def test_result_summary_failure_mentions_count() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    # summary should include the number of failed checks
    assert "/10" in result.summary


def test_empty_config_graceful() -> None:
    result = SCANNER.scan({})
    # should not raise; should produce multiple findings
    assert isinstance(result, AgenticScanResult)
    assert isinstance(result.findings, list)


def test_extra_keys_ignored() -> None:
    cfg = {**SAFE_CONFIG, "unknown_future_key": "value", "another_key": 42}
    result = SCANNER.scan(cfg)
    assert result.score == 100


def test_findings_have_owasp_refs() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    for f in result.findings:
        assert f.owasp_ref.startswith("OWASP Agentic Top 10 2026 — A")


def test_findings_have_evidence_lists() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    for f in result.findings:
        assert isinstance(f.evidence, list)
        assert len(f.evidence) >= 1


def test_findings_have_remediation() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    for f in result.findings:
        assert f.remediation


def test_all_ten_risk_ids_unique() -> None:
    result = SCANNER.scan(TOXIC_CONFIG)
    ids = [f.risk_id for f in result.findings]
    assert len(ids) == len(set(ids))


# ===========================================================================
# No tool list → graceful handling
# ===========================================================================


def test_no_tool_list_no_crash() -> None:
    cfg = {k: v for k, v in SAFE_CONFIG.items() if k != "tool_list"}
    result = SCANNER.scan(cfg)
    assert isinstance(result, AgenticScanResult)


def test_no_tool_list_a08_does_not_fire() -> None:
    # A08 only fires when the agent actually has tools
    cfg = {k: v for k, v in SAFE_CONFIG.items() if k not in ("tool_list",)}
    result = SCANNER.scan(cfg)
    assert not any(f.risk_id == "A08" for f in result.findings)


def test_null_tool_list_no_crash() -> None:
    cfg = {**SAFE_CONFIG, "tool_list": None}
    result = SCANNER.scan(cfg)
    assert isinstance(result, AgenticScanResult)


# ===========================================================================
# CLI smoke tests via _build_parser
# ===========================================================================


def test_cli_parser_scan_agentic_subcommand_exists() -> None:
    """scan-agentic must be a recognised subcommand."""
    from squash.cli import _build_parser  # noqa: PLC0415

    parser = _build_parser()
    args = parser.parse_args(["scan-agentic", "--config", "foo.json"])
    assert args.command == "scan-agentic"
    assert args.agentic_config == "foo.json"


def test_cli_parser_scan_agentic_json_result_flag() -> None:
    from squash.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["scan-agentic", "--config", "foo.json", "--json-result", "out.json"])
    assert args.json_result == "out.json"


def test_cli_parser_scan_agentic_quiet_flag() -> None:
    from squash.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["scan-agentic", "--config", "foo.json", "--quiet"])
    assert args.quiet is True


def test_cli_scan_agentic_json_config(tmp_path: Path) -> None:
    """End-to-end: write a JSON config, run _cmd_scan_agentic, expect exit 0."""
    from squash.cli import _build_parser, _cmd_scan_agentic

    cfg_file = tmp_path / "agent.json"
    cfg_file.write_text(json.dumps(SAFE_CONFIG))

    parser = _build_parser()
    args = parser.parse_args(["scan-agentic", "--config", str(cfg_file)])
    rc = _cmd_scan_agentic(args, quiet=True)
    assert rc == 0


def test_cli_scan_agentic_toxic_config_exits_2(tmp_path: Path) -> None:
    """Toxic config → handler returns 2."""
    from squash.cli import _build_parser, _cmd_scan_agentic

    cfg_file = tmp_path / "toxic.json"
    cfg_file.write_text(json.dumps(TOXIC_CONFIG))

    parser = _build_parser()
    args = parser.parse_args(["scan-agentic", "--config", str(cfg_file)])
    rc = _cmd_scan_agentic(args, quiet=True)
    assert rc == 2


def test_cli_scan_agentic_missing_file_exits_1(tmp_path: Path) -> None:
    """Non-existent config → handler returns 1."""
    from squash.cli import _build_parser, _cmd_scan_agentic

    parser = _build_parser()
    args = parser.parse_args(["scan-agentic", "--config", str(tmp_path / "does_not_exist.json")])
    rc = _cmd_scan_agentic(args, quiet=True)
    assert rc == 1


def test_cli_scan_agentic_json_result_written(tmp_path: Path) -> None:
    """--json-result writes a valid JSON file."""
    from squash.cli import _build_parser, _cmd_scan_agentic

    cfg_file = tmp_path / "agent.json"
    cfg_file.write_text(json.dumps(SAFE_CONFIG))
    out_file = tmp_path / "result.json"

    parser = _build_parser()
    args = parser.parse_args(
        ["scan-agentic", "--config", str(cfg_file), "--json-result", str(out_file)]
    )
    rc = _cmd_scan_agentic(args, quiet=True)
    assert rc == 0
    data = json.loads(out_file.read_text())
    assert data["passed"] is True
    assert data["score"] == 100
    assert data["framework"] == "owasp-agentic-top10-2026"


# ===========================================================================
# __init__.py exports
# ===========================================================================


def test_init_exports_scanner() -> None:
    from squash import AgenticScanner as AS

    assert AS is AgenticScanner


def test_init_exports_finding() -> None:
    from squash import AgenticFinding as AF

    assert AF is AgenticFinding


def test_init_exports_result() -> None:
    from squash import AgenticScanResult as ASR

    assert ASR is AgenticScanResult
