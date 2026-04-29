"""squash/sbom_diff.py — Attestation diff engine.

Compares two squash attestation JSON files (CycloneDX ML-BOM format) and
produces a structured delta: component changes, policy drift, score movement,
and vulnerability lifecycle (added / resolved).

Usage
-----
::

    from pathlib import Path
    from squash.sbom_diff import diff_attestations

    delta = diff_attestations(Path("v1.json"), Path("v2.json"))
    print(delta.summary_line())   # "Score: 75.0 → 82.5 (+7.5) | 2 added | 0 removed | 1 violation resolved"
    print(delta.to_table())       # ANSI terminal table
    delta_dict = delta.to_dict()  # machine-readable for CI integration

CLI integration
---------------
``squash diff v1.json v2.json``
``squash diff v1.json v2.json --format json``
``squash diff v1.json v2.json --format html``
``squash diff v1.json v2.json --format table`` (default)
``squash diff v1.json v2.json --min-score-delta -5 --fail-on-regression``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ComponentDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "removed": self.removed,
            "unchanged_count": len(self.unchanged),
        }


@dataclass
class PolicyDiff:
    newly_passed: list[str] = field(default_factory=list)
    newly_failed: list[str] = field(default_factory=list)
    unchanged_pass: list[str] = field(default_factory=list)
    unchanged_fail: list[str] = field(default_factory=list)

    @property
    def regression(self) -> bool:
        return bool(self.newly_failed)

    @property
    def improvement(self) -> bool:
        return bool(self.newly_passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "newly_passed": self.newly_passed,
            "newly_failed": self.newly_failed,
            "unchanged_pass_count": len(self.unchanged_pass),
            "unchanged_fail_count": len(self.unchanged_fail),
        }


@dataclass
class VulnerabilityDiff:
    added: list[str] = field(default_factory=list)      # new CVEs in v2
    resolved: list[str] = field(default_factory=list)   # CVEs present in v1, gone in v2
    unchanged: list[str] = field(default_factory=list)  # CVEs in both

    @property
    def net_change(self) -> int:
        return len(self.added) - len(self.resolved)

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "resolved": self.resolved,
            "unchanged_count": len(self.unchanged),
            "net_change": self.net_change,
        }


@dataclass
class AttestationDiff:
    """Full diff between two attestation documents."""
    before_path: str
    after_path: str
    score_before: float | None
    score_after: float | None
    passed_before: bool | None
    passed_after: bool | None
    components: ComponentDiff
    policies: PolicyDiff
    vulnerabilities: VulnerabilityDiff
    metadata_changes: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def score_delta(self) -> float | None:
        if self.score_before is not None and self.score_after is not None:
            return round(self.score_after - self.score_before, 2)
        return None

    @property
    def is_regression(self) -> bool:
        """True if compliance posture deteriorated."""
        if self.score_delta is not None and self.score_delta < 0:
            return True
        if self.policies.regression:
            return True
        if self.vulnerabilities.net_change > 0:
            return True
        return False

    @property
    def is_improvement(self) -> bool:
        if self.score_delta is not None and self.score_delta > 0:
            return True
        if self.policies.improvement:
            return True
        if self.vulnerabilities.net_change < 0:
            return True
        return False

    # ------------------------------------------------------------------
    # Output formats
    # ------------------------------------------------------------------

    def summary_line(self) -> str:
        """Single-line human-readable summary. Safe for CI log output."""
        parts: list[str] = []

        if self.score_before is not None and self.score_after is not None:
            delta = self.score_delta
            sign = "+" if (delta or 0) >= 0 else ""
            parts.append(f"Score: {self.score_before:.1f} → {self.score_after:.1f} ({sign}{delta:.1f})")
        elif self.score_after is not None:
            parts.append(f"Score: {self.score_after:.1f}")

        added = len(self.components.added)
        removed = len(self.components.removed)
        if added:
            parts.append(f"{added} component{'s' if added != 1 else ''} added")
        if removed:
            parts.append(f"{removed} component{'s' if removed != 1 else ''} removed")

        if self.policies.newly_failed:
            parts.append(f"{len(self.policies.newly_failed)} policy newly failing")
        if self.policies.newly_passed:
            parts.append(f"{len(self.policies.newly_passed)} policy newly passing")

        if self.vulnerabilities.resolved:
            parts.append(f"{len(self.vulnerabilities.resolved)} vulnerability resolved")
        if self.vulnerabilities.added:
            parts.append(f"{len(self.vulnerabilities.added)} vulnerability added")

        if not parts:
            return "No changes detected"
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": self.before_path,
            "after": self.after_path,
            "score": {
                "before": self.score_before,
                "after": self.score_after,
                "delta": self.score_delta,
            },
            "passed": {
                "before": self.passed_before,
                "after": self.passed_after,
            },
            "components": self.components.to_dict(),
            "policies": self.policies.to_dict(),
            "vulnerabilities": self.vulnerabilities.to_dict(),
            "metadata_changes": self.metadata_changes,
            "is_regression": self.is_regression,
            "is_improvement": self.is_improvement,
            "summary": self.summary_line(),
        }

    def to_table(self) -> str:
        """ANSI terminal table."""
        lines: list[str] = []
        W = 60

        def _row(label: str, value: str, color: str = "") -> str:
            RESET = "\033[0m"
            c = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m", "cyan": "\033[96m"}.get(color, "")
            return f"  {label:<28}{c}{value}{RESET}"

        lines.append("\033[1m" + "─" * W + "\033[0m")
        lines.append("\033[1m  squash diff\033[0m")
        lines.append(f"  before: {self.before_path}")
        lines.append(f"  after:  {self.after_path}")
        lines.append("─" * W)

        if self.score_before is not None or self.score_after is not None:
            b = f"{self.score_before:.1f}" if self.score_before is not None else "n/a"
            a = f"{self.score_after:.1f}" if self.score_after is not None else "n/a"
            delta = self.score_delta
            if delta is not None:
                sign = "+" if delta >= 0 else ""
                color = "green" if delta >= 0 else "red"
                lines.append(_row("Compliance score", f"{b} → {a} ({sign}{delta:.1f})", color))
            else:
                lines.append(_row("Compliance score", f"{b} → {a}"))

        pb = "✓" if self.passed_before else ("✗" if self.passed_before is False else "?")
        pa = "✓" if self.passed_after else ("✗" if self.passed_after is False else "?")
        color = "green" if self.passed_after else "red"
        lines.append(_row("Passed", f"{pb} → {pa}", color))

        lines.append("")
        lines.append("  \033[1mComponents\033[0m")
        if self.components.added:
            for c in self.components.added[:5]:
                lines.append(_row("  + added", c, "green"))
            if len(self.components.added) > 5:
                lines.append(_row("", f"  … and {len(self.components.added) - 5} more"))
        if self.components.removed:
            for c in self.components.removed[:5]:
                lines.append(_row("  - removed", c, "red"))
            if len(self.components.removed) > 5:
                lines.append(_row("", f"  … and {len(self.components.removed) - 5} more"))
        if not self.components.added and not self.components.removed:
            lines.append(_row("  (no changes)", ""))

        lines.append("")
        lines.append("  \033[1mPolicies\033[0m")
        for p in self.policies.newly_passed:
            lines.append(_row("  ✓ now passing", p, "green"))
        for p in self.policies.newly_failed:
            lines.append(_row("  ✗ now failing", p, "red"))
        if not self.policies.newly_passed and not self.policies.newly_failed:
            lines.append(_row("  (no changes)", ""))

        lines.append("")
        lines.append("  \033[1mVulnerabilities\033[0m")
        for v in self.vulnerabilities.resolved:
            lines.append(_row("  ✓ resolved", v, "green"))
        for v in self.vulnerabilities.added:
            lines.append(_row("  ✗ new", v, "red"))
        if not self.vulnerabilities.resolved and not self.vulnerabilities.added:
            lines.append(_row("  (no changes)", ""))

        lines.append("─" * W)
        verdict_color = "green" if not self.is_regression else "red"
        verdict = "✓ No regression" if not self.is_regression else "✗ Regression detected"
        lines.append(_row("Verdict", verdict, verdict_color))
        lines.append("─" * W)

        return "\n".join(lines)

    def to_html(self) -> str:
        """Minimal HTML table for embedding in PR comments or reports."""
        delta = self.score_delta
        delta_str = ""
        delta_style = ""
        if delta is not None:
            sign = "+" if delta >= 0 else ""
            delta_str = f" ({sign}{delta:.1f})"
            delta_style = "color:green" if delta >= 0 else "color:red"

        rows: list[str] = []

        def _tr(label: str, value: str, style: str = "") -> str:
            st = f' style="{style}"' if style else ""
            return f"<tr><td><b>{label}</b></td><td{st}>{value}</td></tr>"

        if self.score_before is not None or self.score_after is not None:
            b = f"{self.score_before:.1f}" if self.score_before is not None else "n/a"
            a = f"{self.score_after:.1f}" if self.score_after is not None else "n/a"
            rows.append(_tr("Score", f"{b} → {a}{delta_str}", delta_style))

        pb = "✓" if self.passed_before else ("✗" if self.passed_before is False else "?")
        pa = "✓" if self.passed_after else ("✗" if self.passed_after is False else "?")
        pa_style = "color:green" if self.passed_after else "color:red"
        rows.append(_tr("Passed", f"{pb} → {pa}", pa_style))

        if self.components.added:
            rows.append(_tr("Components added", ", ".join(self.components.added[:10]), "color:green"))
        if self.components.removed:
            rows.append(_tr("Components removed", ", ".join(self.components.removed[:10]), "color:red"))
        if self.policies.newly_passed:
            rows.append(_tr("Policies now passing", ", ".join(self.policies.newly_passed), "color:green"))
        if self.policies.newly_failed:
            rows.append(_tr("Policies now failing", ", ".join(self.policies.newly_failed), "color:red"))
        if self.vulnerabilities.resolved:
            rows.append(_tr("Vulnerabilities resolved", ", ".join(self.vulnerabilities.resolved), "color:green"))
        if self.vulnerabilities.added:
            rows.append(_tr("Vulnerabilities added", ", ".join(self.vulnerabilities.added), "color:red"))

        verdict = "✓ No regression" if not self.is_regression else "✗ Regression detected"
        verdict_style = "color:green" if not self.is_regression else "color:red;font-weight:bold"
        rows.append(_tr("Verdict", verdict, verdict_style))

        return (
            '<table border="1" cellpadding="4" style="border-collapse:collapse;font-family:monospace">'
            + "".join(rows)
            + "</table>"
        )


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def diff_attestations(
    before_path: Path,
    after_path: Path,
) -> AttestationDiff:
    """Compare two squash attestation JSON files.

    Supports CycloneDX ML-BOM format (as generated by ``squash attest``)
    and squash's own attestation result format.

    Args:
        before_path: Path to the older attestation JSON.
        after_path:  Path to the newer attestation JSON.

    Returns:
        An :class:`AttestationDiff` with the full delta.
    """
    before = _load_attestation(before_path)
    after = _load_attestation(after_path)

    return AttestationDiff(
        before_path=str(before_path),
        after_path=str(after_path),
        score_before=_extract_score(before),
        score_after=_extract_score(after),
        passed_before=_extract_passed(before),
        passed_after=_extract_passed(after),
        components=_diff_components(before, after),
        policies=_diff_policies(before, after),
        vulnerabilities=_diff_vulnerabilities(before, after),
        metadata_changes=_diff_metadata(before, after),
    )


def diff_from_dicts(before: dict[str, Any], after: dict[str, Any]) -> AttestationDiff:
    """Compare two attestation dicts (already loaded from JSON)."""
    return AttestationDiff(
        before_path="<before>",
        after_path="<after>",
        score_before=_extract_score(before),
        score_after=_extract_score(after),
        passed_before=_extract_passed(before),
        passed_after=_extract_passed(after),
        components=_diff_components(before, after),
        policies=_diff_policies(before, after),
        vulnerabilities=_diff_vulnerabilities(before, after),
        metadata_changes=_diff_metadata(before, after),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_attestation(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Attestation file not found: {path}")
    with path.open() as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError(f"Attestation file must be a JSON object: {path}")
    return doc


def _extract_score(doc: dict[str, Any]) -> float | None:
    # squash native format
    for key in ("compliance_score", "score", "complianceScore"):
        if key in doc:
            try:
                return float(doc[key])
            except (TypeError, ValueError):
                pass
    # CycloneDX: check properties
    for prop in doc.get("properties", []):
        if prop.get("name") in ("squash:compliance_score", "squash.compliance.score"):
            try:
                return float(prop["value"])
            except (TypeError, ValueError):
                pass
    # nested under "metadata" or "squash"
    for container in ("metadata", "squash"):
        sub = doc.get(container, {})
        if isinstance(sub, dict):
            for key in ("compliance_score", "score"):
                if key in sub:
                    try:
                        return float(sub[key])
                    except (TypeError, ValueError):
                        pass
    return None


def _extract_passed(doc: dict[str, Any]) -> bool | None:
    for key in ("passed", "policy_passed", "compliant"):
        if key in doc:
            val = doc[key]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("true", "1", "yes", "pass", "passed")
    return None


def _component_names(doc: dict[str, Any]) -> set[str]:
    """Extract a flat set of component name strings from a CycloneDX or native doc."""
    names: set[str] = set()
    # CycloneDX components list
    for comp in doc.get("components", []):
        if isinstance(comp, dict):
            n = comp.get("name") or comp.get("bom-ref") or comp.get("purl")
            if n:
                names.add(str(n))
    # squash native: "artifacts", "models", "datasets"
    for key in ("artifacts", "models", "datasets"):
        for item in doc.get(key, []):
            if isinstance(item, dict):
                n = item.get("name") or item.get("path") or item.get("id")
                if n:
                    names.add(str(n))
            elif isinstance(item, str):
                names.add(item)
    return names


def _policy_results(doc: dict[str, Any]) -> dict[str, bool]:
    """Extract {policy_name: passed} from a squash attestation doc."""
    results: dict[str, bool] = {}
    # native format: policy_results list or dict
    pr = doc.get("policy_results") or doc.get("policies") or {}
    if isinstance(pr, list):
        for item in pr:
            if isinstance(item, dict):
                name = item.get("policy") or item.get("name") or item.get("id")
                passed = item.get("passed") or item.get("result") == "pass"
                if name:
                    results[str(name)] = bool(passed)
    elif isinstance(pr, dict):
        for k, v in pr.items():
            if isinstance(v, bool):
                results[k] = v
            elif isinstance(v, dict):
                results[k] = bool(v.get("passed", v.get("result") == "pass"))
    # CycloneDX: check vulnerabilities section (invert: vuln = not-passed)
    for vuln in doc.get("vulnerabilities", []):
        if isinstance(vuln, dict):
            name = vuln.get("id") or vuln.get("bom-ref")
            if name and name not in results:
                results[str(name)] = False
    return results


def _vuln_ids(doc: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for v in doc.get("vulnerabilities", []):
        if isinstance(v, dict):
            vid = v.get("id") or v.get("cve") or v.get("bom-ref")
            if vid:
                ids.add(str(vid))
    # also check vex_alerts
    for a in doc.get("vex_alerts", []):
        if isinstance(a, dict):
            vid = a.get("cve") or a.get("id")
            if vid:
                ids.add(str(vid))
    return ids


def _diff_components(before: dict, after: dict) -> ComponentDiff:
    b_comps = _component_names(before)
    a_comps = _component_names(after)
    return ComponentDiff(
        added=sorted(a_comps - b_comps),
        removed=sorted(b_comps - a_comps),
        unchanged=sorted(b_comps & a_comps),
    )


def _diff_policies(before: dict, after: dict) -> PolicyDiff:
    b_pol = _policy_results(before)
    a_pol = _policy_results(after)

    all_policies = set(b_pol) | set(a_pol)
    newly_passed: list[str] = []
    newly_failed: list[str] = []
    unchanged_pass: list[str] = []
    unchanged_fail: list[str] = []

    for policy in sorted(all_policies):
        b_ok = b_pol.get(policy)
        a_ok = a_pol.get(policy)
        if b_ok is False and a_ok is True:
            newly_passed.append(policy)
        elif b_ok is True and a_ok is False:
            newly_failed.append(policy)
        elif a_ok is True:
            unchanged_pass.append(policy)
        elif a_ok is False:
            unchanged_fail.append(policy)

    return PolicyDiff(
        newly_passed=newly_passed,
        newly_failed=newly_failed,
        unchanged_pass=unchanged_pass,
        unchanged_fail=unchanged_fail,
    )


def _diff_vulnerabilities(before: dict, after: dict) -> VulnerabilityDiff:
    b_vulns = _vuln_ids(before)
    a_vulns = _vuln_ids(after)
    return VulnerabilityDiff(
        added=sorted(a_vulns - b_vulns),
        resolved=sorted(b_vulns - a_vulns),
        unchanged=sorted(b_vulns & a_vulns),
    )


def _diff_metadata(before: dict, after: dict) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    meta_keys = ("model", "model_name", "model_path", "framework", "squash_version")
    for key in meta_keys:
        b_val = before.get(key) or before.get("metadata", {}).get(key)
        a_val = after.get(key) or after.get("metadata", {}).get(key)
        if b_val != a_val and (b_val is not None or a_val is not None):
            changes[key] = {"before": b_val, "after": a_val}
    return changes
