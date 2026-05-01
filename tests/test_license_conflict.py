"""tests/test_license_conflict.py — W196 / B10 Licence Conflict Detection.

Test taxonomy:

* LicenseKnowledgeBase: resolve_spdx aliases, unknown fallback, AI custom licences
* LicenseExpression: single SPDX, OR compound, WITH exception, empty
* ConflictChecker: all 12 rules across multiple use cases
* LicenseConflictReport: summary, passed(), JSON round-trip, Markdown render
* LicenseScanner: requirements.txt, package.json, LICENSE file, model README,
  dataset_infos.json
* LicenseConflictScanner end-to-end: clean project, conflicted project
* load_report round-trip
* CLI smoke: parser registration, scan + explain
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squash.license_conflict import (
    ComponentKind,
    ComponentLicense,
    ConflictChecker,
    ConflictSeverity,
    LicenseConflictReport,
    LicenseConflictScanner,
    LicenseExpression,
    LicenseKind,
    LicenseScanner,
    OverallRisk,
    UseCase,
    _sniff_license_text,
    extract_obligations,
    load_report,
    resolve_spdx,
)


# ---------------------------------------------------------------------------
# resolve_spdx — knowledge base
# ---------------------------------------------------------------------------

def test_resolve_exact_spdx():
    info = resolve_spdx("Apache-2.0")
    assert info.spdx_id == "Apache-2.0"
    assert info.kind == LicenseKind.PERMISSIVE
    assert info.patent_grant
    assert info.commercial_ok


def test_resolve_alias_lowercase():
    info = resolve_spdx("apache2")
    assert info.spdx_id == "Apache-2.0"


def test_resolve_mit():
    info = resolve_spdx("MIT")
    assert info.kind == LicenseKind.PERMISSIVE
    assert info.commercial_ok


def test_resolve_gpl3_only():
    info = resolve_spdx("GPL-3.0-only")
    assert info.kind == LicenseKind.STRONG_COPYLEFT
    assert info.source_required


def test_resolve_agpl():
    info = resolve_spdx("AGPL-3.0-only")
    assert info.kind == LicenseKind.NETWORK_COPYLEFT
    assert info.saas_triggers


def test_resolve_cc_by_nc():
    info = resolve_spdx("CC-BY-NC-4.0")
    assert info.kind == LicenseKind.NON_COMMERCIAL
    assert not info.commercial_ok


def test_resolve_cc_by_sa():
    info = resolve_spdx("CC-BY-SA-4.0")
    assert info.share_alike


def test_resolve_llama2():
    info = resolve_spdx("LicenseRef-llama2")
    assert info.kind == LicenseKind.AI_CUSTOM
    assert not info.commercial_ok   # requires approval >700M MAU


def test_resolve_unknown_falls_back():
    info = resolve_spdx("SuperWeirdLicense-99.0")
    assert info.spdx_id == "LicenseRef-unknown"
    assert info.kind == LicenseKind.UNKNOWN


def test_resolve_empty_string():
    info = resolve_spdx("")
    assert info.spdx_id == "LicenseRef-unknown"


def test_resolve_cc0():
    info = resolve_spdx("CC0-1.0")
    assert info.kind == LicenseKind.PUBLIC_DOMAIN
    assert not info.attribution_required


# ---------------------------------------------------------------------------
# LicenseExpression parser
# ---------------------------------------------------------------------------

def test_expression_single():
    expr = LicenseExpression.parse("MIT")
    assert expr.options == ["MIT"]
    assert expr.active == "MIT"


def test_expression_or_picks_most_permissive():
    expr = LicenseExpression.parse("GPL-3.0-only OR MIT")
    assert "MIT" in expr.options
    assert expr.active == "MIT"


def test_expression_with_exception_stripped():
    expr = LicenseExpression.parse("GPL-2.0-only WITH Classpath-exception-2.0")
    assert expr.active == "GPL-2.0-only"


def test_expression_compound_three():
    expr = LicenseExpression.parse("MIT OR Apache-2.0 OR GPL-3.0-only")
    assert len(expr.options) == 3
    assert expr.active in ("MIT", "Apache-2.0")  # both permissive


def test_expression_empty_falls_back():
    expr = LicenseExpression.parse("")
    assert expr.active == "LicenseRef-unknown"


# ---------------------------------------------------------------------------
# ConflictChecker — individual rules
# ---------------------------------------------------------------------------

def _comp(name: str, kind: ComponentKind, spdx: str) -> ComponentLicense:
    return ComponentLicense.from_raw(name, kind, spdx)


def test_rule_lc001_nc_commercial():
    ds = _comp("my-dataset", ComponentKind.DATASET, "CC-BY-NC-4.0")
    findings = ConflictChecker().check([ds], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-001" for f in findings)
    assert any(f.severity == ConflictSeverity.CRITICAL for f in findings)


def test_rule_lc001_nc_research_ok():
    ds = _comp("my-dataset", ComponentKind.DATASET, "CC-BY-NC-4.0")
    findings = ConflictChecker().check([ds], UseCase.RESEARCH)
    assert not any(f.rule_id == "LC-001" for f in findings)


def test_rule_lc002_agpl_saas():
    dep = _comp("my-lib", ComponentKind.CODE_DEP, "AGPL-3.0-only")
    findings = ConflictChecker().check([dep], UseCase.SAAS_API)
    assert any(f.rule_id == "LC-002" for f in findings)
    assert any(f.severity == ConflictSeverity.HIGH for f in findings)


def test_rule_lc002_agpl_internal_clean():
    dep = _comp("my-lib", ComponentKind.CODE_DEP, "AGPL-3.0-only")
    findings = ConflictChecker().check([dep], UseCase.INTERNAL)
    assert not any(f.rule_id == "LC-002" for f in findings)


def test_rule_lc003_gpl_closed_source():
    dep = _comp("gpl-tool", ComponentKind.CODE_DEP, "GPL-3.0-only")
    findings = ConflictChecker().check([dep], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-003" for f in findings)


def test_rule_lc004_sharealike_dataset_model():
    ds = _comp("sa-dataset", ComponentKind.DATASET, "CC-BY-SA-4.0")
    model = _comp("my-model", ComponentKind.MODEL_WEIGHTS, "Apache-2.0")
    findings = ConflictChecker().check([ds, model], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-004" for f in findings)
    f = next(f for f in findings if f.rule_id == "LC-004")
    assert f.severity == ConflictSeverity.MEDIUM


def test_rule_lc004_no_model_no_finding():
    ds = _comp("sa-dataset", ComponentKind.DATASET, "CC-BY-SA-4.0")
    findings = ConflictChecker().check([ds], UseCase.COMMERCIAL)
    assert not any(f.rule_id == "LC-004" for f in findings)


def test_rule_lc005_no_derivatives():
    ds = _comp("nd-dataset", ComponentKind.DATASET, "CC-BY-ND-4.0")
    findings = ConflictChecker().check([ds], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-005" for f in findings)


def test_rule_lc006_llama2_commercial():
    model = _comp("llama2-7b", ComponentKind.MODEL_WEIGHTS, "LicenseRef-llama2")
    findings = ConflictChecker().check([model], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-006" for f in findings)
    f = next(f for f in findings if f.rule_id == "LC-006")
    assert f.severity == ConflictSeverity.MEDIUM  # permitted <700M MAU, flagged for awareness


def test_rule_lc007_llama_competing():
    model = _comp("llama3-8b", ComponentKind.MODEL_WEIGHTS, "LicenseRef-llama3")
    findings = ConflictChecker().check([model], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-007" for f in findings)


def test_rule_lc008_gemma_competing():
    model = _comp("gemma-2b", ComponentKind.MODEL_WEIGHTS, "LicenseRef-gemma")
    findings = ConflictChecker().check([model], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-008" for f in findings)


def test_rule_lc009_rail_restriction():
    model = _comp("bloom-176b", ComponentKind.MODEL_WEIGHTS, "LicenseRef-bloom")
    findings = ConflictChecker().check([model], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-009" for f in findings)


def test_rule_lc010_unknown_license():
    dep = _comp("mystery-lib", ComponentKind.CODE_DEP, "LicenseRef-unknown")
    findings = ConflictChecker().check([dep], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-010" for f in findings)
    f = next(f for f in findings if f.rule_id == "LC-010")
    assert f.severity == ConflictSeverity.HIGH


def test_rule_lc011_gpl2_apache_incompatible():
    gpl = _comp("gpl2-lib", ComponentKind.CODE_DEP, "GPL-2.0-only")
    apache = _comp("apache-lib", ComponentKind.CODE_DEP, "Apache-2.0")
    findings = ConflictChecker().check([gpl, apache], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-011" for f in findings)


def test_rule_lc011_gpl3_apache_ok():
    # GPL-3.0 + Apache-2.0 is compatible
    gpl3 = _comp("gpl3-lib", ComponentKind.CODE_DEP, "GPL-3.0-only")
    apache = _comp("apache-lib", ComponentKind.CODE_DEP, "Apache-2.0")
    findings = ConflictChecker().check([gpl3, apache], UseCase.COMMERCIAL)
    assert not any(f.rule_id == "LC-011" for f in findings)


def test_rule_lc012_copyleft_version_lock():
    gpl2 = _comp("lib-a", ComponentKind.CODE_DEP, "GPL-2.0-only")
    gpl3 = _comp("lib-b", ComponentKind.CODE_DEP, "GPL-3.0-only")
    findings = ConflictChecker().check([gpl2, gpl3], UseCase.COMMERCIAL)
    assert any(f.rule_id == "LC-012" for f in findings)


def test_clean_project_no_findings():
    components = [
        _comp("app",    ComponentKind.APPLICATION,  "MIT"),
        _comp("numpy",  ComponentKind.CODE_DEP,     "BSD-3-Clause"),
        _comp("fastapi",ComponentKind.CODE_DEP,     "MIT"),
        _comp("dataset",ComponentKind.DATASET,      "CC0-1.0"),
    ]
    findings = ConflictChecker().check(components, UseCase.COMMERCIAL)
    assert findings == []


# ---------------------------------------------------------------------------
# Obligation extractor
# ---------------------------------------------------------------------------

def test_obligations_attribution_required():
    components = [_comp("lib", ComponentKind.CODE_DEP, "MIT")]
    obs = extract_obligations(components, UseCase.COMMERCIAL)
    assert any("Attribution required" in o for o in obs)


def test_obligations_source_required():
    components = [_comp("gpl-lib", ComponentKind.CODE_DEP, "GPL-3.0-only")]
    obs = extract_obligations(components, UseCase.COMMERCIAL)
    assert any("Source disclosure" in o for o in obs)


def test_obligations_llama_attribution():
    components = [_comp("llama2", ComponentKind.MODEL_WEIGHTS, "LicenseRef-llama2")]
    obs = extract_obligations(components, UseCase.COMMERCIAL)
    assert any("LLaMA attribution" in o for o in obs)


# ---------------------------------------------------------------------------
# LicenseScanner — file-based extraction
# ---------------------------------------------------------------------------

def test_scanner_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "numpy==1.26.0\ntorch>=2.0\nfastapi\n"
    )
    comps = LicenseScanner().scan(tmp_path)
    names = [c.name for c in comps]
    assert "numpy" in names
    assert "torch" in names


def test_scanner_license_file_mit(tmp_path):
    (tmp_path / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted, free of charge..."
    )
    comps = LicenseScanner().scan(tmp_path)
    app_comps = [c for c in comps if c.kind == ComponentKind.APPLICATION]
    assert any(c.spdx_id == "MIT" for c in app_comps)


def test_scanner_license_file_apache(tmp_path):
    (tmp_path / "LICENSE").write_text(
        "Apache License\nVersion 2.0, January 2004\n"
    )
    comps = LicenseScanner().scan(tmp_path)
    assert any(c.spdx_id == "Apache-2.0" for c in comps)


def test_scanner_model_readme(tmp_path):
    (tmp_path / "README.md").write_text(
        "# My Model\n\nlicense: LicenseRef-llama2\n\nThis is a fine-tuned model."
    )
    comps = LicenseScanner().scan(tmp_path)
    assert any(c.spdx_id == "LicenseRef-llama2" for c in comps)


def test_scanner_dataset_infos_json(tmp_path):
    data = {"my_dataset": {"license": "CC-BY-SA-4.0", "description": "test"}}
    (tmp_path / "dataset_infos.json").write_text(json.dumps(data))
    comps = LicenseScanner().scan(tmp_path)
    assert any(c.spdx_id == "CC-BY-SA-4.0" and c.kind == ComponentKind.DATASET for c in comps)


def test_scanner_package_json(tmp_path):
    pkg = {"name": "my-app", "license": "MIT", "dependencies": {"react": "^18"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    comps = LicenseScanner().scan(tmp_path)
    assert any(c.name == "react" for c in comps)


# ---------------------------------------------------------------------------
# _sniff_license_text
# ---------------------------------------------------------------------------

def test_sniff_mit():
    assert _sniff_license_text("MIT License\nPermission is hereby granted") == "MIT"

def test_sniff_apache():
    assert _sniff_license_text("Apache License\nVersion 2.0") == "Apache-2.0"

def test_sniff_gpl3():
    assert _sniff_license_text("GNU General Public License\nversion 3") == "GPL-3.0-only"

def test_sniff_unknown():
    assert _sniff_license_text("Custom proprietary licence terms") == ""


# ---------------------------------------------------------------------------
# LicenseConflictScanner end-to-end
# ---------------------------------------------------------------------------

def _make_clean_project(root: Path) -> Path:
    proj = root / "clean_proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("numpy==1.26.0\ntorch>=2.0\n")
    (proj / "LICENSE").write_text("MIT License\nPermission is hereby granted")
    ds_data = {"my_dataset": {"license": "CC0-1.0"}}
    (proj / "dataset_infos.json").write_text(json.dumps(ds_data))
    return proj


def _make_conflicted_project(root: Path) -> Path:
    proj = root / "conflict_proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text(
        "numpy==1.26.0\n"
        "mysql-connector-python==8.0\n"  # GPL-2.0-only
    )
    (proj / "README.md").write_text("license: LicenseRef-llama2\n")
    ds_data = {"training_data": {"license": "CC-BY-NC-4.0"}}
    (proj / "dataset_infos.json").write_text(json.dumps(ds_data))
    return proj


def test_scanner_clean_project(tmp_path):
    proj = _make_clean_project(tmp_path)
    report = LicenseConflictScanner().scan(proj, use_case=UseCase.COMMERCIAL)
    assert report.schema == "squash.license.conflict.report/v1"
    assert report.overall_risk in (OverallRisk.CLEAN, OverallRisk.LOW, OverallRisk.MEDIUM)
    assert len(report.components) > 0


def test_scanner_conflicted_project(tmp_path):
    proj = _make_conflicted_project(tmp_path)
    report = LicenseConflictScanner().scan(proj, use_case=UseCase.COMMERCIAL)
    # NC dataset + LLaMA + GPL-2.0 should generate conflicts
    assert len(report.findings) >= 1
    assert report.overall_risk != OverallRisk.CLEAN


def test_scanner_research_use_relaxes_nc(tmp_path):
    proj = tmp_path / "rp"
    proj.mkdir()
    ds_data = {"d": {"license": "CC-BY-NC-4.0"}}
    (proj / "dataset_infos.json").write_text(json.dumps(ds_data))
    report = LicenseConflictScanner().scan(proj, use_case=UseCase.RESEARCH)
    assert not any(f.rule_id == "LC-001" for f in report.findings)


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------

def test_report_json_round_trip(tmp_path):
    proj = _make_clean_project(tmp_path)
    report = LicenseConflictScanner().scan(proj, use_case=UseCase.COMMERCIAL)
    path = tmp_path / "report.json"
    path.write_text(report.to_json())
    loaded = load_report(path)
    assert loaded.schema == report.schema
    assert loaded.overall_risk == report.overall_risk
    assert len(loaded.components) == len(report.components)


def test_report_markdown_contains_risk(tmp_path):
    proj = _make_clean_project(tmp_path)
    report = LicenseConflictScanner().scan(proj, use_case=UseCase.COMMERCIAL)
    md = report.to_markdown()
    assert report.overall_risk.value.upper() in md
    assert "License Conflict Report" in md


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------

def test_cli_parser_registered():
    from squash.cli import _build_parser
    p = _build_parser()
    ns = p.parse_args(["license-check", "scan", "./proj", "--use-case", "saas_api"])
    assert ns.command == "license-check"
    assert ns.lc_command == "scan"
    assert ns.use_case == "saas_api"
    assert ns.fail_on == "high"


def test_cli_explain(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_license_check
    args = argparse.Namespace(lc_command="explain", spdx_id="Apache-2.0")
    rc = _cmd_license_check(args, quiet=False)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Apache" in out
    assert "PERMISSIVE" in out.upper() or "permissive" in out


def test_cli_scan_json_output(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_license_check
    proj = _make_clean_project(tmp_path)
    args = argparse.Namespace(
        lc_command="scan",
        project_path=str(proj),
        use_case="commercial",
        lc_format="json",
        out=None,
        fail_on="critical",   # only fail on critical
    )
    rc = _cmd_license_check(args, quiet=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["schema"] == "squash.license.conflict.report/v1"
    assert rc == 0


def test_cli_scan_nonexistent_path(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_license_check
    args = argparse.Namespace(
        lc_command="scan",
        project_path=str(tmp_path / "nope"),
        use_case="commercial",
        lc_format="text",
        out=None,
        fail_on="high",
    )
    rc = _cmd_license_check(args, quiet=True)
    assert rc == 1
