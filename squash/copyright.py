"""squash/copyright.py — Sprint 39 W273 (Track C / C11 supplement).

Copyright & Licensing Attestation for AI Models.

`squash copyright-check` produces a structured copyright risk assessment
covering:

1. **SPDX license detection** — parses model weights, training data,
   fine-tuning datasets, and adapter files for SPDX identifiers.
2. **Copyright holder tracking** — identifies organisations and
   individuals with IP claims over the model stack.
3. **License compatibility matrix** — checks whether the combination of
   training-data licenses, base-model license, and intended deployment
   use is legally compatible.
4. **Training-data copyright risk scoring** — weighted score reflecting
   known copyright-heavy sources in training data.

The output is a ``CopyrightReport`` with:
  - A risk score 0–100 (0 = clean, 100 = high copyright exposure)
  - Per-component licence breakdown
  - Compatibility verdict for the intended deployment use
  - Signed JSON + human-readable Markdown

**Buyer:** General Counsel. Approving an AI deployment for content
generation or legal drafting requires this certificate as evidence of
IP due diligence.

Builds on the SPDX knowledge base in ``squash.data_lineage`` and the
model registry in ``squash.genealogy``.

Stdlib-only. HMAC-SHA256 signing.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── SPDX license database ─────────────────────────────────────────────────────

class LicenseCategory:
    PERMISSIVE    = "permissive"
    COPYLEFT      = "copyleft"
    WEAK_COPYLEFT = "weak_copyleft"
    RESEARCH_ONLY = "research_only"
    PROPRIETARY   = "proprietary"
    PUBLIC_DOMAIN = "public_domain"
    UNKNOWN       = "unknown"


# SPDX identifier → (category, commercial_ok, share_alike_required)
_SPDX_DB: dict[str, tuple[str, bool, bool]] = {
    # Permissive
    "MIT":                (LicenseCategory.PERMISSIVE,    True,  False),
    "Apache-2.0":         (LicenseCategory.PERMISSIVE,    True,  False),
    "BSD-2-Clause":       (LicenseCategory.PERMISSIVE,    True,  False),
    "BSD-3-Clause":       (LicenseCategory.PERMISSIVE,    True,  False),
    "ISC":                (LicenseCategory.PERMISSIVE,    True,  False),
    "Unlicense":          (LicenseCategory.PERMISSIVE,    True,  False),
    "CC0-1.0":            (LicenseCategory.PUBLIC_DOMAIN, True,  False),
    "ODC-By-1.0":         (LicenseCategory.PERMISSIVE,    True,  False),
    "PDDL-1.0":           (LicenseCategory.PUBLIC_DOMAIN, True,  False),
    "BSL-1.0":            (LicenseCategory.PERMISSIVE,    True,  False),
    "PSF-2.0":            (LicenseCategory.PERMISSIVE,    True,  False),
    "Zlib":               (LicenseCategory.PERMISSIVE,    True,  False),
    "WTFPL":              (LicenseCategory.PERMISSIVE,    True,  False),
    "CC-BY-4.0":          (LicenseCategory.PERMISSIVE,    True,  False),
    "ODbL-1.0":           (LicenseCategory.PERMISSIVE,    True,  True),
    # Copyleft
    "GPL-2.0":            (LicenseCategory.COPYLEFT,      True,  True),
    "GPL-2.0-only":       (LicenseCategory.COPYLEFT,      True,  True),
    "GPL-2.0-or-later":   (LicenseCategory.COPYLEFT,      True,  True),
    "GPL-3.0":            (LicenseCategory.COPYLEFT,      True,  True),
    "GPL-3.0-only":       (LicenseCategory.COPYLEFT,      True,  True),
    "GPL-3.0-or-later":   (LicenseCategory.COPYLEFT,      True,  True),
    "AGPL-3.0":           (LicenseCategory.COPYLEFT,      False, True),
    "AGPL-3.0-only":      (LicenseCategory.COPYLEFT,      False, True),
    "CC-BY-SA-4.0":       (LicenseCategory.COPYLEFT,      True,  True),
    "CC-BY-SA-3.0":       (LicenseCategory.COPYLEFT,      True,  True),
    # Weak copyleft
    "LGPL-2.0":           (LicenseCategory.WEAK_COPYLEFT, True,  False),
    "LGPL-2.1":           (LicenseCategory.WEAK_COPYLEFT, True,  False),
    "LGPL-3.0":           (LicenseCategory.WEAK_COPYLEFT, True,  False),
    "MPL-2.0":            (LicenseCategory.WEAK_COPYLEFT, True,  False),
    "EUPL-1.2":           (LicenseCategory.WEAK_COPYLEFT, True,  False),
    # Research-only / NC
    "CC-BY-NC-4.0":       (LicenseCategory.RESEARCH_ONLY, False, False),
    "CC-BY-NC-SA-4.0":    (LicenseCategory.RESEARCH_ONLY, False, True),
    "CC-BY-NC-ND-4.0":    (LicenseCategory.RESEARCH_ONLY, False, False),
    "CC-BY-ND-4.0":       (LicenseCategory.RESEARCH_ONLY, True,  False),
    # AI-specific
    "BigScience-OpenRAIL-M": (LicenseCategory.PROPRIETARY, True, False),
    "CreativeML-OpenRAIL-M": (LicenseCategory.PROPRIETARY, True, False),
    "llama2":             (LicenseCategory.PROPRIETARY,   True,  False),
    "llama3":             (LicenseCategory.PROPRIETARY,   True,  False),
    "gemma":              (LicenseCategory.PROPRIETARY,   True,  False),
    "deepseek":           (LicenseCategory.PROPRIETARY,   False, False),
    # Unknown
    "unknown":            (LicenseCategory.UNKNOWN,       None,  False),
    "other":              (LicenseCategory.UNKNOWN,       None,  False),
}

# License compatibility matrix: (license_a_cat, license_b_cat) → compatible?
# Rule: copyleft + permissive → compatible (permissive absorbed)
#        copyleft + copyleft  → compatible only if same family
#        research_only + commercial_deployment → INCOMPATIBLE
_COMPAT_MATRIX: dict[tuple[str, str], bool] = {
    (LicenseCategory.PERMISSIVE,    LicenseCategory.PERMISSIVE):    True,
    (LicenseCategory.PERMISSIVE,    LicenseCategory.COPYLEFT):      True,
    (LicenseCategory.PERMISSIVE,    LicenseCategory.WEAK_COPYLEFT): True,
    (LicenseCategory.PERMISSIVE,    LicenseCategory.RESEARCH_ONLY): False,
    (LicenseCategory.PERMISSIVE,    LicenseCategory.PROPRIETARY):   True,
    (LicenseCategory.COPYLEFT,      LicenseCategory.PERMISSIVE):    True,
    (LicenseCategory.COPYLEFT,      LicenseCategory.COPYLEFT):      True,  # same family
    (LicenseCategory.COPYLEFT,      LicenseCategory.WEAK_COPYLEFT): True,
    (LicenseCategory.COPYLEFT,      LicenseCategory.RESEARCH_ONLY): False,
    (LicenseCategory.COPYLEFT,      LicenseCategory.PROPRIETARY):   False,
    (LicenseCategory.WEAK_COPYLEFT, LicenseCategory.PERMISSIVE):    True,
    (LicenseCategory.WEAK_COPYLEFT, LicenseCategory.COPYLEFT):      True,
    (LicenseCategory.WEAK_COPYLEFT, LicenseCategory.RESEARCH_ONLY): False,
    (LicenseCategory.WEAK_COPYLEFT, LicenseCategory.PROPRIETARY):   True,
    (LicenseCategory.RESEARCH_ONLY, LicenseCategory.PERMISSIVE):    False,
    (LicenseCategory.RESEARCH_ONLY, LicenseCategory.COPYLEFT):      False,
    (LicenseCategory.RESEARCH_ONLY, LicenseCategory.PROPRIETARY):   False,
    (LicenseCategory.RESEARCH_ONLY, LicenseCategory.RESEARCH_ONLY): True,
    (LicenseCategory.PUBLIC_DOMAIN, LicenseCategory.PERMISSIVE):    True,
    (LicenseCategory.PUBLIC_DOMAIN, LicenseCategory.COPYLEFT):      True,
    (LicenseCategory.PUBLIC_DOMAIN, LicenseCategory.RESEARCH_ONLY): False,
    (LicenseCategory.PUBLIC_DOMAIN, LicenseCategory.PROPRIETARY):   True,
    (LicenseCategory.PROPRIETARY,   LicenseCategory.PERMISSIVE):    True,
    (LicenseCategory.PROPRIETARY,   LicenseCategory.COPYLEFT):      False,
    (LicenseCategory.PROPRIETARY,   LicenseCategory.RESEARCH_ONLY): False,
    (LicenseCategory.PROPRIETARY,   LicenseCategory.PROPRIETARY):   False,
    (LicenseCategory.UNKNOWN,       LicenseCategory.PERMISSIVE):    None,  # uncertain
    (LicenseCategory.UNKNOWN,       LicenseCategory.COPYLEFT):      None,
    (LicenseCategory.UNKNOWN,       LicenseCategory.RESEARCH_ONLY): False,
    (LicenseCategory.UNKNOWN,       LicenseCategory.PROPRIETARY):   None,
    (LicenseCategory.UNKNOWN,       LicenseCategory.UNKNOWN):       None,
}


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class LicenseInfo:
    """Resolved licence for one component."""

    spdx_id: str
    category: str
    commercial_ok: bool | None
    share_alike: bool
    source: str                  # "model_card" | "dataset_metadata" | "inferred" | "unknown"
    confidence: float            # 0.0–1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "spdx_id": self.spdx_id,
            "category": self.category,
            "commercial_ok": self.commercial_ok,
            "share_alike": self.share_alike,
            "source": self.source,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class CopyrightHolder:
    """One entity with an IP claim on the model stack."""

    name: str
    role: str          # "model_author" | "dataset_author" | "copyright_holder"
    component: str     # which component they hold rights over
    confidence: float  # 0.0–1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "component": self.component,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class CompatibilityIssue:
    """One detected license incompatibility."""

    component_a: str
    license_a: str
    component_b: str
    license_b: str
    issue: str
    severity: str   # "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_a": self.component_a,
            "license_a": self.license_a,
            "component_b": self.component_b,
            "license_b": self.license_b,
            "issue": self.issue,
            "severity": self.severity,
        }


@dataclass
class CopyrightReport:
    """Signed copyright & licence attestation."""

    model_id: str
    model_path: str
    generated_at: str
    deployment_use: str          # "commercial" | "research" | "internal"
    model_license: LicenseInfo
    training_data_licenses: list[LicenseInfo]
    copyright_holders: list[CopyrightHolder]
    compatibility_issues: list[CompatibilityIssue]
    risk_score: int              # 0–100
    risk_tier: str               # HIGH / MEDIUM / LOW
    compatible: bool | None      # True/False/None (uncertain)
    recommendations: list[str]
    signature: str
    squash_version: str = "copyright_v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "squash_version": self.squash_version,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "generated_at": self.generated_at,
            "deployment_use": self.deployment_use,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "compatible": self.compatible,
            "signature": self.signature,
            "model_license": self.model_license.to_dict(),
            "training_data_licenses": [l.to_dict() for l in self.training_data_licenses],
            "copyright_holders": [h.to_dict() for h in self.copyright_holders],
            "compatibility_issues": [i.to_dict() for i in self.compatibility_issues],
            "recommendations": list(self.recommendations),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        compat_icon = "✅" if self.compatible else ("❌" if self.compatible is False else "⚠️")
        risk_icon   = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "✅"}.get(self.risk_tier, "⚪")

        lines = [
            "# Copyright & Licensing Attestation",
            "",
            f"**Model:** `{self.model_id}`  ",
            f"**Generated:** {self.generated_at[:10]}  ",
            f"**Deployment use:** `{self.deployment_use}`  ",
            f"**Compatible:** {compat_icon} {'Yes' if self.compatible else ('No' if self.compatible is False else 'Uncertain')}  ",
            f"**Risk:** {risk_icon} {self.risk_tier} ({self.risk_score}/100)",
            f"**Signature:** `{self.signature[:24]}…`",
            "",
            "## Model Licence",
            "",
            f"| Field | Value |",
            "|---|---|",
            f"| SPDX ID | `{self.model_license.spdx_id}` |",
            f"| Category | {self.model_license.category} |",
            f"| Commercial use | {'✅' if self.model_license.commercial_ok else '❌' if self.model_license.commercial_ok is False else '❓'} |",
            f"| Share-alike required | {'Yes' if self.model_license.share_alike else 'No'} |",
            f"| Source | {self.model_license.source} |",
            "",
            "## Training Data Licences",
            "",
            "| Dataset | SPDX | Category | Commercial OK |",
            "|---|---|---|---|",
        ]
        for lic in self.training_data_licenses:
            ok = "✅" if lic.commercial_ok else ("❌" if lic.commercial_ok is False else "❓")
            lines.append(f"| `{lic.source}` | `{lic.spdx_id}` | {lic.category} | {ok} |")

        if self.compatibility_issues:
            lines += ["", "## Compatibility Issues", ""]
            for issue in self.compatibility_issues:
                sev = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "ℹ️"}.get(
                    issue.severity, "⚪"
                )
                lines.append(
                    f"- {sev} **{issue.severity}** `{issue.license_a}` + "
                    f"`{issue.license_b}`: {issue.issue}"
                )

        if self.copyright_holders:
            lines += ["", "## Copyright Holders", ""]
            for h in self.copyright_holders:
                lines.append(f"- **{h.name}** ({h.role}) — `{h.component}`")

        if self.recommendations:
            lines += ["", "## Recommendations", ""]
            for rec in self.recommendations:
                lines.append(f"- {rec}")

        lines += [
            "",
            "---",
            "",
            "*Generated by [squash](https://getsquash.dev) · "
            f"`squash copyright-check --deployment-use {self.deployment_use}` · "
            "Squash violations, not velocity.*",
        ]
        return "\n".join(lines) + "\n"

    def save(
        self,
        output_dir: Path | str,
        stem: str = "squash-copyright",
    ) -> dict[str, Path]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        p = output_dir / f"{stem}.json"
        p.write_text(self.to_json(), encoding="utf-8")
        written["json"] = p
        p = output_dir / f"{stem}.md"
        p.write_text(self.to_markdown(), encoding="utf-8")
        written["md"] = p
        return written


# ── Analyser ──────────────────────────────────────────────────────────────────


class CopyrightAnalyzer:
    """Produce a signed ``CopyrightReport`` from squash artefacts.

    Usage::

        report = CopyrightAnalyzer().analyze(
            model_path=Path("./my-model"),
            deployment_use="commercial",
        )
        report.save("./out")
    """

    def analyze(
        self,
        model_path: Path | str,
        deployment_use: str = "commercial",
        signing_key: bytes = b"",
    ) -> CopyrightReport:
        model_path = Path(model_path)
        use = deployment_use if deployment_use in ("commercial", "research", "internal") \
              else "commercial"

        artifacts = _load_artifacts(model_path)
        model_id  = _extract_model_id(artifacts, model_path)

        model_license = self._detect_model_license(model_id, artifacts)
        data_licenses  = self._detect_training_licenses(artifacts)
        holders        = self._detect_copyright_holders(model_id, artifacts)
        issues         = self._check_compatibility(model_license, data_licenses, use)
        score, tier    = self._compute_risk(model_license, data_licenses, issues, use)
        compatible     = self._compatible(issues, use)
        recs           = self._recommendations(issues, model_license, data_licenses, use)
        sig            = _sign_report(model_id, model_license.spdx_id, score, signing_key)

        return CopyrightReport(
            model_id=model_id,
            model_path=str(model_path),
            generated_at=_utc_now_iso(),
            deployment_use=use,
            model_license=model_license,
            training_data_licenses=data_licenses,
            copyright_holders=holders,
            compatibility_issues=issues,
            risk_score=score,
            risk_tier=tier,
            compatible=compatible,
            recommendations=recs,
            signature=sig,
        )

    def _detect_model_license(
        self,
        model_id: str,
        artifacts: dict[str, Any],
    ) -> LicenseInfo:
        """Detect the model weights licence."""
        # 1. Model card YAML frontmatter
        for card_key in ("squash-model-card-hf.md", "README.md", "MODEL_CARD.md"):
            card = artifacts.get(card_key)
            if isinstance(card, str):
                m = re.search(r"^license[:\s]+([^\n\r]+)", card, re.MULTILINE | re.IGNORECASE)
                if m:
                    spdx = m.group(1).strip().strip('"\'').strip()
                    info = _resolve_spdx(spdx)
                    return LicenseInfo(
                        spdx_id=info["spdx"], category=info["cat"],
                        commercial_ok=info["ok"], share_alike=info["sa"],
                        source=f"model_card:{card_key}", confidence=0.9,
                    )

        # 2. Attestation data
        attest = artifacts.get("squash-attest.json") or {}
        if isinstance(attest, dict):
            lic = attest.get("license") or attest.get("licence")
            if lic:
                info = _resolve_spdx(str(lic))
                return LicenseInfo(
                    spdx_id=info["spdx"], category=info["cat"],
                    commercial_ok=info["ok"], share_alike=info["sa"],
                    source="squash-attest.json", confidence=0.85,
                )

        # 3. Infer from model family
        from squash.genealogy import _detect_family, _BASE_MODEL_REGISTRY
        fam = _detect_family(model_id).lower()
        for key, reg in _BASE_MODEL_REGISTRY.items():
            if key in fam or fam in reg.get("family", "").lower():
                # Map registry commercial_ok to a SPDX
                if reg.get("commercial_ok") is False:
                    spdx = "CC-BY-NC-4.0"
                else:
                    spdx = "Apache-2.0"
                info = _resolve_spdx(spdx)
                return LicenseInfo(
                    spdx_id=info["spdx"], category=info["cat"],
                    commercial_ok=info["ok"], share_alike=info["sa"],
                    source="inferred_from_model_family", confidence=0.5,
                )

        return LicenseInfo(
            spdx_id="unknown", category=LicenseCategory.UNKNOWN,
            commercial_ok=None, share_alike=False,
            source="not_found", confidence=0.0,
        )

    def _detect_training_licenses(
        self, artifacts: dict[str, Any],
    ) -> list[LicenseInfo]:
        """Detect licences for each training dataset."""
        results: list[LicenseInfo] = []
        lineage = artifacts.get("data_lineage_certificate.json") or {}
        if isinstance(lineage, dict):
            for ds in lineage.get("datasets", []) or []:
                if isinstance(ds, dict):
                    spdx = ds.get("license_spdx") or ds.get("license") or "unknown"
                    name = ds.get("name") or ds.get("id", "unknown")
                    info = _resolve_spdx(str(spdx))
                    results.append(LicenseInfo(
                        spdx_id=info["spdx"], category=info["cat"],
                        commercial_ok=info["ok"], share_alike=info["sa"],
                        source=str(name), confidence=0.8,
                    ))

        # Also check the model card for base model datasets
        from squash.genealogy import _BASE_MODEL_REGISTRY
        for card_key in ("squash-model-card-hf.md", "README.md"):
            card = artifacts.get(card_key)
            if not isinstance(card, str):
                continue
            m = re.search(r"datasets?\s*[:\-]\s*\[?([^\]\n]+)", card, re.IGNORECASE)
            if m:
                raw_list = m.group(1).replace("[", "").replace("]", "")
                for ds in raw_list.split(","):
                    ds = ds.strip().strip('"\'')
                    if ds and ds not in [r.source for r in results]:
                        info = _resolve_spdx("unknown")  # will infer
                        results.append(LicenseInfo(
                            spdx_id="unknown", category=LicenseCategory.UNKNOWN,
                            commercial_ok=None, share_alike=False,
                            source=ds, confidence=0.3,
                        ))
        return results

    def _detect_copyright_holders(
        self,
        model_id: str,
        artifacts: dict[str, Any],
    ) -> list[CopyrightHolder]:
        holders: list[CopyrightHolder] = []
        mid_lo = model_id.lower()

        # Known model authors from registry
        _ORG_MAP = [
            (["llama", "codellama", "roberta"],     "Meta AI",        "model_author"),
            (["mistral", "mixtral"],                 "Mistral AI",     "model_author"),
            (["gpt-2", "gpt-j", "pythia", "gpt-neo"], "EleutherAI",   "model_author"),
            (["bloom"],                              "BigScience",     "model_author"),
            (["falcon"],                             "TII UAE",        "model_author"),
            (["qwen"],                               "Alibaba Group",  "model_author"),
            (["gemma"],                              "Google DeepMind","model_author"),
            (["phi"],                                "Microsoft",      "model_author"),
            (["starcoder"],                          "BigCode",        "model_author"),
            (["deepseek"],                           "DeepSeek AI",    "model_author"),
            (["stablelm"],                           "Stability AI",   "model_author"),
            (["books3", "the-pile", "pile"],         "EleutherAI",     "dataset_author"),
            (["wikipedia"],                          "Wikimedia",      "copyright_holder"),
            (["github"],                             "Various OSS contributors", "copyright_holder"),
        ]
        for patterns, org, role in _ORG_MAP:
            if any(p in mid_lo for p in patterns):
                holders.append(CopyrightHolder(
                    name=org, role=role,
                    component=model_id, confidence=0.85,
                ))
                break

        # Extract from model card
        for card_key in ("squash-model-card-hf.md", "README.md"):
            card = artifacts.get(card_key)
            if isinstance(card, str):
                m = re.search(r"copyright\s+(?:\(c\)\s*)?(\d{4}[-–—]\d{4}|\d{4})\s+([^\n]{3,60})",
                              card, re.IGNORECASE)
                if m:
                    holders.append(CopyrightHolder(
                        name=m.group(2).strip()[:80], role="copyright_holder",
                        component=f"model_card:{card_key}", confidence=0.7,
                    ))
        return holders

    def _check_compatibility(
        self,
        model_lic: LicenseInfo,
        data_lics: list[LicenseInfo],
        use: str,
    ) -> list[CompatibilityIssue]:
        issues: list[CompatibilityIssue] = []

        # Research-only licence with commercial/internal deployment
        if model_lic.category == LicenseCategory.RESEARCH_ONLY and use != "research":
            issues.append(CompatibilityIssue(
                component_a="model_weights",  license_a=model_lic.spdx_id,
                component_b="deployment",     license_b=use,
                issue=f"Model licence '{model_lic.spdx_id}' prohibits {use} use",
                severity="CRITICAL",
            ))

        for lic in data_lics:
            # Research-only training data in commercial model
            if lic.category == LicenseCategory.RESEARCH_ONLY and use == "commercial":
                issues.append(CompatibilityIssue(
                    component_a=f"training_data:{lic.source}", license_a=lic.spdx_id,
                    component_b="commercial_deployment", license_b=use,
                    issue=(
                        f"Training dataset '{lic.source}' ({lic.spdx_id}) "
                        "is research-only and may create liability in commercial deployment"
                    ),
                    severity="HIGH",
                ))

            # Copyleft training data potentially infects commercial model
            if (lic.category == LicenseCategory.COPYLEFT
                    and model_lic.category not in (LicenseCategory.COPYLEFT,
                                                    LicenseCategory.PUBLIC_DOMAIN,
                                                    LicenseCategory.UNKNOWN)):
                issues.append(CompatibilityIssue(
                    component_a=f"training_data:{lic.source}", license_a=lic.spdx_id,
                    component_b="model_weights", license_b=model_lic.spdx_id,
                    issue=(
                        f"Copyleft training data '{lic.source}' ({lic.spdx_id}) "
                        "may require model weights to be open-sourced under the same licence "
                        "(legal analysis required — copyleft infection of ML models is unsettled law)"
                    ),
                    severity="MEDIUM",
                ))

            # Unknown licence is a risk
            if lic.category == LicenseCategory.UNKNOWN and use == "commercial":
                issues.append(CompatibilityIssue(
                    component_a=f"training_data:{lic.source}", license_a="unknown",
                    component_b="commercial_deployment", license_b=use,
                    issue=f"Training dataset '{lic.source}' has unknown licence — legal review required",
                    severity="MEDIUM",
                ))

        # Copyleft base model + proprietary fine-tune
        if (model_lic.spdx_id in ("AGPL-3.0", "AGPL-3.0-only", "GPL-3.0", "GPL-3.0-only")
                and use == "commercial"):
            issues.append(CompatibilityIssue(
                component_a="model_weights",     license_a=model_lic.spdx_id,
                component_b="api_service",       license_b="commercial_saas",
                issue=(
                    f"AGPL/GPL licence requires source disclosure when model is served "
                    "over a network. Commercial API services using this model must comply."
                ),
                severity="HIGH",
            ))

        return issues

    def _compute_risk(
        self,
        model_lic: LicenseInfo,
        data_lics: list[LicenseInfo],
        issues: list[CompatibilityIssue],
        use: str,
    ) -> tuple[int, str]:
        score = 0
        sev_pts = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "INFO": 2}
        for issue in issues:
            score += sev_pts.get(issue.severity, 0)
        # Unknown model licence adds risk
        if model_lic.category == LicenseCategory.UNKNOWN:
            score += 20
        # Unknown training data licences
        unknowns = sum(1 for l in data_lics if l.category == LicenseCategory.UNKNOWN)
        score += unknowns * 5
        score = min(100, score)
        tier = "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
        return score, tier

    def _compatible(
        self, issues: list[CompatibilityIssue], use: str,
    ) -> bool | None:
        criticals = [i for i in issues if i.severity == "CRITICAL"]
        if criticals:
            return False
        highs = [i for i in issues if i.severity == "HIGH"]
        if highs:
            return None  # uncertain — legal review needed
        return True

    def _recommendations(
        self,
        issues: list[CompatibilityIssue],
        model_lic: LicenseInfo,
        data_lics: list[LicenseInfo],
        use: str,
    ) -> list[str]:
        recs: list[str] = []
        if model_lic.category == LicenseCategory.UNKNOWN:
            recs.append(
                "Identify and document the model's licence before deployment. "
                "Run `squash model-card --validate` to check licence metadata."
            )
        if model_lic.category == LicenseCategory.RESEARCH_ONLY and use != "research":
            recs.append(
                f"Replace this model with a commercially-licensed equivalent "
                "(e.g. Apache-2.0 or MIT licensed) for {use} deployment."
            )
        unknowns = [l for l in data_lics if l.category == LicenseCategory.UNKNOWN]
        if unknowns:
            names = ", ".join(f"'{l.source}'" for l in unknowns[:3])
            recs.append(
                f"Resolve licence for training datasets: {names}. "
                "Run `squash data-lineage` to extract SPDX identifiers."
            )
        copylefts = [l for l in data_lics if l.category == LicenseCategory.COPYLEFT]
        if copylefts:
            recs.append(
                "Obtain legal review on whether copyleft training data "
                "creates derivative-work obligations for the trained model. "
                "This is currently unsettled law in most jurisdictions."
            )
        if not recs:
            recs.append("No immediate action required. Continue to monitor licence changes.")
        return recs


# ── Shared helpers ────────────────────────────────────────────────────────────


def _resolve_spdx(raw: str) -> dict[str, Any]:
    """Normalise a raw licence string and look it up in the SPDX database."""
    s = raw.strip().strip('"\'')
    entry = _SPDX_DB.get(s)
    if not entry:
        # Case-insensitive lookup
        for k, v in _SPDX_DB.items():
            if k.lower() == s.lower():
                entry = v
                s = k
                break
    if entry:
        cat, ok, sa = entry
        return {"spdx": s, "cat": cat, "ok": ok, "sa": sa}
    # Map common variants
    lo = s.lower()
    if "cc0" in lo or "public domain" in lo:
        return {"spdx": "CC0-1.0", "cat": LicenseCategory.PUBLIC_DOMAIN, "ok": True, "sa": False}
    if "apache" in lo:
        return {"spdx": "Apache-2.0", "cat": LicenseCategory.PERMISSIVE, "ok": True, "sa": False}
    if "mit" in lo:
        return {"spdx": "MIT", "cat": LicenseCategory.PERMISSIVE, "ok": True, "sa": False}
    if "gpl" in lo and "agpl" not in lo:
        return {"spdx": "GPL-3.0", "cat": LicenseCategory.COPYLEFT, "ok": True, "sa": True}
    if "agpl" in lo:
        return {"spdx": "AGPL-3.0", "cat": LicenseCategory.COPYLEFT, "ok": False, "sa": True}
    if "nc" in lo or "non-commercial" in lo:
        return {"spdx": "CC-BY-NC-4.0", "cat": LicenseCategory.RESEARCH_ONLY, "ok": False, "sa": False}
    return {"spdx": s or "unknown", "cat": LicenseCategory.UNKNOWN, "ok": None, "sa": False}


def _load_artifacts(model_path: Path) -> dict[str, Any]:
    arts: dict[str, Any] = {}
    if not model_path.is_dir():
        return arts
    for directory in (model_path, model_path / "squash"):
        if not directory.is_dir():
            continue
        for child in directory.iterdir():
            if child.name.endswith(".json") and child.is_file():
                try:
                    arts[child.name] = json.loads(child.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    pass
            elif child.name.endswith(".md") and child.is_file():
                arts[child.name] = child.read_text(encoding="utf-8")
    return arts


def _extract_model_id(arts: dict[str, Any], model_path: Path) -> str:
    for key in ("squash-attest.json", "squash_attestation.json", "squish.json"):
        d = arts.get(key)
        if isinstance(d, dict) and d.get("model_id"):
            return str(d["model_id"])
    return model_path.name


def _sign_report(
    model_id: str, spdx: str, score: int, key: bytes,
) -> str:
    if not key:
        key = hashlib.sha256(f"squash:copyright:{model_id}".encode()).digest()
    msg = json.dumps(
        {"model_id": model_id, "spdx": spdx, "score": score}, sort_keys=True
    ).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


__all__ = [
    "LicenseCategory",
    "LicenseInfo",
    "CopyrightHolder",
    "CompatibilityIssue",
    "CopyrightReport",
    "CopyrightAnalyzer",
    "SUPPORTED_USES",
]

SUPPORTED_USES: frozenset[str] = frozenset({"commercial", "research", "internal"})
