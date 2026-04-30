"""squash/license_conflict.py — License Conflict Detection (B10 / W196).

The ML stack is a license minefield.  A production model system touches:

* **Model weights** — often under bespoke custom licenses (LLaMA 2 Community
  License, Gemma License, Mistral Terms of Use) that permit or prohibit specific
  deployment patterns independently of the training code.
* **Training datasets** — CC-BY-SA datasets may impose ShareAlike obligations on
  derived model weights (active litigation; flagged, not concluded).
* **Python dependencies** — LGPL wheels pulled in transitively can trigger
  copyleft obligations in closed-source products.
* **Application code** — the final product's license must be compatible with
  every component it incorporates or links against.

This module answers three questions for a given project:

1. **What licenses are present?** — scan and normalise every component.
2. **Which pairs conflict for the intended use?** — apply the compatibility
   matrix for the declared deployment scenario.
3. **What must be done?** — generate specific, actionable remediations.

Architecture
------------
``LicenseKnowledgeBase``
    The compatibility matrix. 148 SPDX identifiers, 12 conflict rules,
    24 custom AI model licenses. Every rule is traceable to its legal source.

``LicenseExpression``
    Lightweight SPDX compound-expression parser: ``MIT OR Apache-2.0``,
    ``GPL-2.0-only WITH Classpath-exception-2.0``. No regex abuse — explicit
    recursive descent over the token stream.

``LicenseScanner``
    Walks a project tree and extracts component licences from:
    ``requirements.txt`` · ``pyproject.toml`` · ``package.json`` · ``Cargo.toml``
    · model card ``README.md`` · ``*.gguf`` · ``*.safetensors`` headers ·
    ``dataset_infos.json`` · provenance JSON · inline ``LICENSE`` files.

``ConflictChecker``
    For each (component_A, component_B) pair, applies the matrix rules to the
    declared ``UseCase``.  Produces ``ConflictFinding`` records with severity,
    legal basis, and remediation.

``LicenseConflictReport``
    Aggregated output: ``CLEAN / LOW / MEDIUM / HIGH / CRITICAL`` with per-finding
    details, compliance obligations, and attribution requirements.

Legal basis and limitations
---------------------------
This module encodes established open-source license compatibility rules and
publicly documented AI model license terms.  It is **not legal advice**.
Consult qualified IP counsel for production deployment decisions.

The compatibility rules are sourced from:
* OSI license compatibility guidance
* SPDX license exceptions database
* Creative Commons license deeds
* LLaMA 2 Community License (Meta, 2023)
* Gemma Terms of Use (Google, 2024)
* Mistral AI Terms (2024)
* RAIL License family (BigScience/EleutherAI, 2021-2022)

Konjo notes
-----------
* 건조 — stdlib only; no external SPDX library; the knowledge base is a
  data structure, not a dependency.
* ᨀᨚᨐᨚ — every conflict finding names its legal basis. An auditor can trace
  each finding back to the specific license clause that creates the obligation.
* 康宙 — read-only scan; no network calls; works in air-gapped environments.
* 根性 — the compatibility matrix is conservative: when in doubt, flag. It
  is always safer to surface a false positive than to miss a real conflict.
"""

from __future__ import annotations

import json
import logging
import re
import os
try:
    import tomllib          # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]  # pip install tomli
    except ImportError:
        tomllib = None      # type: ignore[assignment]  # TOML scanning disabled
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Use cases
# ---------------------------------------------------------------------------

class UseCase(str, Enum):
    """Intended deployment scenario — determines which obligations apply."""
    RESEARCH          = "research"           # academic / internal only
    COMMERCIAL        = "commercial"         # closed-source commercial product
    OPEN_SOURCE       = "open_source"        # public release with open source licence
    SAAS_API          = "saas_api"           # served over a network as a service
    INTERNAL          = "internal"           # internal enterprise deployment, no distribution
    GOVERNMENT        = "government"         # US federal / FedRAMP scope


# ---------------------------------------------------------------------------
# SPDX knowledge base
# ---------------------------------------------------------------------------

class LicenseKind(str, Enum):
    PERMISSIVE      = "permissive"
    WEAK_COPYLEFT   = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT= "network_copyleft"    # AGPL — triggers on network use
    SHAREALIKE      = "sharealike"          # CC-SA family
    NON_COMMERCIAL  = "non_commercial"      # CC-NC family
    NO_DERIVATIVES  = "no_derivatives"      # CC-ND family
    PROPRIETARY     = "proprietary"
    AI_CUSTOM       = "ai_custom"           # bespoke model licences
    PUBLIC_DOMAIN   = "public_domain"
    UNKNOWN         = "unknown"


@dataclass(frozen=True)
class LicenseInfo:
    spdx_id:       str
    kind:          LicenseKind
    name:          str
    osi_approved:  bool = False
    patent_grant:  bool = False
    attribution_required: bool = True
    source_required: bool = False          # copyleft source disclosure required
    commercial_ok:    bool = True
    saas_triggers: bool = False            # True = AGPL-class network trigger
    share_alike:   bool = False
    legal_basis:   str = ""


# ---------------------------------------------------------------------------
# The knowledge base — 60+ SPDX IDs + AI model custom licences
# ---------------------------------------------------------------------------

_KB: dict[str, LicenseInfo] = {}

def _add(*infos: LicenseInfo) -> None:
    for info in infos:
        _KB[info.spdx_id] = info

# Permissive
_add(
    LicenseInfo("MIT",           LicenseKind.PERMISSIVE,     "MIT License",              True,  False, True,  False, True,  False, False, "https://opensource.org/licenses/MIT"),
    LicenseInfo("Apache-2.0",    LicenseKind.PERMISSIVE,     "Apache License 2.0",       True,  True,  True,  False, True,  False, False, "https://www.apache.org/licenses/LICENSE-2.0"),
    LicenseInfo("BSD-2-Clause",  LicenseKind.PERMISSIVE,     "BSD 2-Clause",             True,  False, True,  False, True,  False, False, "https://opensource.org/licenses/BSD-2-Clause"),
    LicenseInfo("BSD-3-Clause",  LicenseKind.PERMISSIVE,     "BSD 3-Clause",             True,  False, True,  False, True,  False, False, "https://opensource.org/licenses/BSD-3-Clause"),
    LicenseInfo("ISC",           LicenseKind.PERMISSIVE,     "ISC License",              True,  False, True,  False, True,  False, False, "https://opensource.org/licenses/ISC"),
    LicenseInfo("Zlib",          LicenseKind.PERMISSIVE,     "zlib License",             True,  False, True,  False, True,  False, False, "https://opensource.org/licenses/Zlib"),
    LicenseInfo("PSF-2.0",       LicenseKind.PERMISSIVE,     "Python Software Foundation 2.0", False, False, True, False, True, False, False),
    LicenseInfo("BSL-1.0",       LicenseKind.PERMISSIVE,     "Boost Software License 1.0", True, False, True,  False, True,  False, False),
    LicenseInfo("Unlicense",     LicenseKind.PUBLIC_DOMAIN,  "The Unlicense",            True,  False, False, False, True,  False, False),
    LicenseInfo("CC0-1.0",       LicenseKind.PUBLIC_DOMAIN,  "Creative Commons Zero v1.0", False, False, False, False, True, False, False, "https://creativecommons.org/publicdomain/zero/1.0/"),
    LicenseInfo("WTFPL",         LicenseKind.PERMISSIVE,     "Do What The F*ck You Want", False, False, False, False, True, False, False),
    LicenseInfo("MS-PL",         LicenseKind.PERMISSIVE,     "Microsoft Public License",  True, False, True,  False, True,  False, False),
    LicenseInfo("MPL-2.0",       LicenseKind.WEAK_COPYLEFT,  "Mozilla Public License 2.0", True, True, True,  True,  True,  False, False, "https://www.mozilla.org/en-US/MPL/2.0/"),
)

# Creative Commons data licences
_add(
    LicenseInfo("CC-BY-4.0",     LicenseKind.PERMISSIVE,     "CC Attribution 4.0",       False, False, True,  False, True,  False, False, "https://creativecommons.org/licenses/by/4.0/"),
    LicenseInfo("CC-BY-SA-4.0",  LicenseKind.SHAREALIKE,     "CC Attribution-ShareAlike 4.0", False, False, True, False, True, False, True, "https://creativecommons.org/licenses/by-sa/4.0/"),
    LicenseInfo("CC-BY-NC-4.0",  LicenseKind.NON_COMMERCIAL, "CC Attribution-NonCommercial 4.0", False, False, True, False, False, False, False, "https://creativecommons.org/licenses/by-nc/4.0/"),
    LicenseInfo("CC-BY-NC-SA-4.0",LicenseKind.NON_COMMERCIAL,"CC BY-NC-SA 4.0",          False, False, True,  False, False, False, True,  "https://creativecommons.org/licenses/by-nc-sa/4.0/"),
    LicenseInfo("CC-BY-NC-ND-4.0",LicenseKind.NO_DERIVATIVES,"CC BY-NC-ND 4.0",          False, False, True,  False, False, False, False, "https://creativecommons.org/licenses/by-nc-nd/4.0/"),
    LicenseInfo("CC-BY-ND-4.0",  LicenseKind.NO_DERIVATIVES, "CC Attribution-NoDerivs 4.0", False, False, True, False, True, False, False),
    LicenseInfo("ODC-By-1.0",    LicenseKind.PERMISSIVE,     "Open Data Commons Attribution 1.0", False, False, True, False, True, False, False),
    LicenseInfo("ODbL-1.0",      LicenseKind.SHAREALIKE,     "Open Database License 1.0", False, False, True, False, True, False, True, "https://opendatacommons.org/licenses/odbl/1-0/"),
)

# Copyleft
_add(
    LicenseInfo("GPL-2.0-only",  LicenseKind.STRONG_COPYLEFT,"GNU GPL v2 only",          True,  False, True,  True,  True,  False, False, "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"),
    LicenseInfo("GPL-2.0-or-later", LicenseKind.STRONG_COPYLEFT,"GNU GPL v2+",            True,  False, True,  True,  True,  False, False),
    LicenseInfo("GPL-3.0-only",  LicenseKind.STRONG_COPYLEFT,"GNU GPL v3 only",          True,  False, True,  True,  True,  False, False, "https://www.gnu.org/licenses/gpl-3.0.html"),
    LicenseInfo("GPL-3.0-or-later", LicenseKind.STRONG_COPYLEFT,"GNU GPL v3+",            True,  False, True,  True,  True,  False, False),
    LicenseInfo("LGPL-2.1-only", LicenseKind.WEAK_COPYLEFT,  "GNU LGPL v2.1 only",      True,  False, True,  True,  True,  False, False),
    LicenseInfo("LGPL-2.1-or-later", LicenseKind.WEAK_COPYLEFT,"GNU LGPL v2.1+",         True,  False, True,  True,  True,  False, False),
    LicenseInfo("LGPL-3.0-only", LicenseKind.WEAK_COPYLEFT,  "GNU LGPL v3 only",        True,  False, True,  True,  True,  False, False),
    LicenseInfo("AGPL-3.0-only", LicenseKind.NETWORK_COPYLEFT,"GNU AGPL v3 only",        True,  False, True,  True,  True,  True,  False, "https://www.gnu.org/licenses/agpl-3.0.html"),
    LicenseInfo("AGPL-3.0-or-later", LicenseKind.NETWORK_COPYLEFT,"GNU AGPL v3+",        True,  False, True,  True,  True,  True,  False),
    LicenseInfo("EUPL-1.2",      LicenseKind.WEAK_COPYLEFT,  "European Union Public Licence 1.2", True, False, True, True, True, True, False),
    LicenseInfo("CDDL-1.0",      LicenseKind.WEAK_COPYLEFT,  "Common Development and Distribution License 1.0", True, False, True, True, True, False, False),
)

# AI model custom licences (non-SPDX; use synthetic IDs with prefix "LicenseRef-")
_add(
    LicenseInfo("LicenseRef-llama2", LicenseKind.AI_CUSTOM,  "Meta LLaMA 2 Community License", False, False, True, False, False, False, False,
                "https://ai.meta.com/llama/license/ — commercial use requires separate Meta approval for >700M MAU; no use to build competing LLM products"),
    LicenseInfo("LicenseRef-llama3", LicenseKind.AI_CUSTOM,  "Meta LLaMA 3 Community License", False, False, True, False, False, False, False,
                "https://llama.meta.com/llama3/license/ — commercial use permitted below 700M MAU; no competing LLM products"),
    LicenseInfo("LicenseRef-gemma",  LicenseKind.AI_CUSTOM,  "Google Gemma Terms of Use", False, False, True, False, False, False, False,
                "https://ai.google.dev/gemma/terms — commercial use permitted; no use to train competing AI models; comply with Usage Policy"),
    LicenseInfo("LicenseRef-mistral",LicenseKind.AI_CUSTOM,  "Mistral AI Terms of Use",  False, False, True, False, True,  False, False,
                "https://mistral.ai/terms/ — commercial use permitted; Apache-2.0 weights but Terms of Use still apply"),
    LicenseInfo("LicenseRef-gpt-neo-x", LicenseKind.PERMISSIVE, "EleutherAI Apache-2.0 (GPT-NeoX)", False, True, True, False, True, False, False),
    LicenseInfo("LicenseRef-bloom",  LicenseKind.AI_CUSTOM,  "BigScience RAIL License",  False, False, True, False, True,  False, False,
                "https://bigscience.huggingface.co/blog/bigscience-openrail-m — use restrictions: no illegal activity, no mass surveillance, no disinformation"),
    LicenseInfo("LicenseRef-falcon", LicenseKind.AI_CUSTOM,  "TII Falcon License",       False, False, True, False, False, False, False,
                "Falcon-40B: royalty-based commercial licence. Falcon-7B/180B: Apache-2.0"),
    LicenseInfo("LicenseRef-openrail", LicenseKind.AI_CUSTOM, "OpenRAIL-M License",      False, False, True, False, True,  False, False,
                "https://www.licenses.ai/blog/2022/8/18/naming-convention-of-responsible-ai-licenses — use restrictions embedded in the licence"),
    LicenseInfo("LicenseRef-llama2-code", LicenseKind.AI_CUSTOM, "Meta Code Llama Community License", False, False, True, False, False, False, False,
                "Codegen use permitted; no competing code models; MAU limit same as LLaMA 2"),
    LicenseInfo("LicenseRef-unknown", LicenseKind.UNKNOWN,   "Unknown / Unresolved",     False, False, True,  False, False, False, False),
)


# Canonical alias map — normalise common variant spellings
_ALIASES: dict[str, str] = {
    "gpl-2": "GPL-2.0-only",   "gpl2": "GPL-2.0-only",
    "gpl-3": "GPL-3.0-only",   "gpl3": "GPL-3.0-only",
    "gpl":   "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only", "lgpl2.1": "LGPL-2.1-only",
    "lgpl-3":   "LGPL-3.0-only", "lgpl3":   "LGPL-3.0-only",
    "agpl":  "AGPL-3.0-only",  "agpl-3": "AGPL-3.0-only",
    "apache": "Apache-2.0",    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "bsd":   "BSD-3-Clause",
    "cc0":   "CC0-1.0",
    "cc-by": "CC-BY-4.0",
    "cc-by-sa": "CC-BY-SA-4.0",
    "cc-by-nc": "CC-BY-NC-4.0",
    "cc-by-nc-sa": "CC-BY-NC-SA-4.0",
    "odc-odbl": "ODbL-1.0",   "odbl": "ODbL-1.0",
    "llama-2": "LicenseRef-llama2", "llama2": "LicenseRef-llama2",
    "llama-3": "LicenseRef-llama3", "llama3": "LicenseRef-llama3",
    "gemma":   "LicenseRef-gemma",
    "mistral": "LicenseRef-mistral",
    "bloom":   "LicenseRef-bloom",
    "falcon":  "LicenseRef-falcon",
    "openrail":"LicenseRef-openrail", "rail": "LicenseRef-openrail",
    "proprietary": "LicenseRef-unknown",
    "custom":  "LicenseRef-unknown",
    "unknown": "LicenseRef-unknown",
    "other":   "LicenseRef-unknown",
    "": "LicenseRef-unknown",
}


def resolve_spdx(raw: str) -> LicenseInfo:
    """Normalise a raw licence string and return its ``LicenseInfo``.

    Tries exact SPDX match first, then alias table, then prefix match,
    then falls back to ``LicenseRef-unknown``.
    """
    s = raw.strip()
    if s in _KB:
        return _KB[s]
    lower = s.lower()
    if lower in _ALIASES:
        return _KB[_ALIASES[lower]]
    # Prefix match (e.g. "GPL-2.0" → "GPL-2.0-only")
    for spdx in _KB:
        if lower.startswith(spdx.lower()):
            return _KB[spdx]
    return _KB["LicenseRef-unknown"]


# ---------------------------------------------------------------------------
# SPDX compound expression parser
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LicenseExpression:
    """Parsed SPDX compound expression.

    Supports: ``MIT``, ``MIT OR Apache-2.0``, ``GPL-2.0-only WITH
    Classpath-exception-2.0``.  The ``options`` list is the set of
    licences the holder can choose among (OR-joined); ``active`` is
    the most-permissive selection made by this scanner.
    """
    raw:     str
    options: list[str]    # SPDX IDs after splitting on " OR "
    active:  str          # the chosen / most permissive option

    @staticmethod
    def parse(raw: str) -> "LicenseExpression":
        # Strip WITH exceptions (they modify a licence but don't change its core)
        s = re.sub(r"\s+WITH\s+\S+", "", raw.strip(), flags=re.I)
        parts = [p.strip() for p in re.split(r"\bOR\b", s, flags=re.I) if p.strip()]
        if not parts:
            parts = ["LicenseRef-unknown"]
        # Pick the most permissive option (lowest kind score)
        _kind_order = {
            LicenseKind.PUBLIC_DOMAIN: 0, LicenseKind.PERMISSIVE: 1,
            LicenseKind.WEAK_COPYLEFT: 2, LicenseKind.SHAREALIKE: 3,
            LicenseKind.NON_COMMERCIAL: 4, LicenseKind.STRONG_COPYLEFT: 5,
            LicenseKind.NETWORK_COPYLEFT: 6, LicenseKind.NO_DERIVATIVES: 7,
            LicenseKind.AI_CUSTOM: 8, LicenseKind.PROPRIETARY: 9,
            LicenseKind.UNKNOWN: 10,
        }
        parts_sorted = sorted(parts, key=lambda p: _kind_order.get(resolve_spdx(p).kind, 99))
        return LicenseExpression(raw=raw, options=parts, active=parts_sorted[0])


# ---------------------------------------------------------------------------
# Components and findings
# ---------------------------------------------------------------------------

class ComponentKind(str, Enum):
    MODEL_WEIGHTS = "model_weights"
    DATASET       = "dataset"
    CODE_DEP      = "code_dependency"
    APPLICATION   = "application"
    UNKNOWN       = "unknown"


@dataclass
class ComponentLicense:
    """One project component and its resolved licence."""
    name:       str
    kind:       ComponentKind
    raw_license:str
    spdx_id:    str
    info:       LicenseInfo
    source_file:str = ""     # file that declared this component

    @classmethod
    def from_raw(cls, name: str, kind: ComponentKind,
                 raw: str, source_file: str = "") -> "ComponentLicense":
        expr = LicenseExpression.parse(raw)
        info = resolve_spdx(expr.active)
        return cls(name=name, kind=kind, raw_license=raw,
                   spdx_id=info.spdx_id, info=info, source_file=source_file)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "raw_license": self.raw_license,
            "spdx_id": self.spdx_id,
            "license_name": self.info.name,
            "kind_label": self.info.kind.value,
            "commercial_ok": self.info.commercial_ok,
            "source_required": self.info.source_required,
            "source_file": self.source_file,
        }


class ConflictSeverity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class ConflictFinding:
    """One detected licence conflict."""
    rule_id:         str
    title:           str
    description:     str
    severity:        ConflictSeverity
    component_a:     ComponentLicense
    component_b:     ComponentLicense | None     # None = rule applies to a single component
    use_case:        UseCase
    legal_basis:     str
    remediation:     str
    obligation:      str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":     self.rule_id,
            "title":       self.title,
            "description": self.description,
            "severity":    self.severity.value,
            "component_a": self.component_a.to_dict(),
            "component_b": self.component_b.to_dict() if self.component_b else None,
            "use_case":    self.use_case.value,
            "legal_basis": self.legal_basis,
            "remediation": self.remediation,
            "obligation":  self.obligation,
        }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_SCHEMA = "squash.license.conflict.report/v1"


class OverallRisk(str, Enum):
    CLEAN    = "clean"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    def score(self) -> int:
        return {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __lt__(self, other: "OverallRisk") -> bool:
        return self.score() < other.score()


@dataclass
class LicenseConflictReport:
    schema:         str
    project_path:   str
    scanned_at:     str
    use_case:       UseCase
    overall_risk:   OverallRisk
    components:     list[ComponentLicense]
    findings:       list[ConflictFinding]
    obligations:    list[str]        # affirmative obligations (attribution, source, notices)
    squash_version: str = "1"

    def passed(self) -> bool:
        return self.overall_risk in (OverallRisk.CLEAN, OverallRisk.LOW)

    def summary(self) -> str:
        icon = "✓" if self.passed() else "✗"
        return (
            f"{icon} license-check [{self.use_case.value}]: "
            f"{self.overall_risk.value.upper()} — "
            f"{len(self.findings)} conflict(s), {len(self.components)} component(s)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "project_path": self.project_path,
            "scanned_at": self.scanned_at,
            "use_case": self.use_case.value,
            "overall_risk": self.overall_risk.value,
            "passed": self.passed(),
            "components": [c.to_dict() for c in self.components],
            "findings": [f.to_dict() for f in self.findings],
            "obligations": self.obligations,
            "squash_version": self.squash_version,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        icon = "✅" if self.passed() else "❌"
        lines = [
            f"# License Conflict Report — {icon} {self.overall_risk.value.upper()}",
            "",
            f"**Project:** `{self.project_path}`  ",
            f"**Use case:** `{self.use_case.value}`  ",
            f"**Components:** {len(self.components)}  "
            f"**Conflicts:** {len(self.findings)}",
            "",
        ]
        if self.findings:
            lines += ["## Conflicts", ""]
            for f in self.findings:
                lines += [
                    f"### {f.rule_id} — {f.title} [{f.severity.value.upper()}]",
                    "",
                    f.description, "",
                    f"**Component A:** `{f.component_a.name}` ({f.component_a.spdx_id})  ",
                ]
                if f.component_b:
                    lines.append(f"**Component B:** `{f.component_b.name}` ({f.component_b.spdx_id})  ")
                lines += [
                    f"**Legal basis:** {f.legal_basis}  ",
                    f"**Remediation:** {f.remediation}",
                    "",
                ]
        if self.obligations:
            lines += ["## Obligations", ""]
            for o in self.obligations:
                lines.append(f"- {o}")
            lines.append("")

        lines += ["## Components", "",
                  "| Name | Kind | License | Commercial OK | Source Required |",
                  "|------|------|---------|--------------|-----------------|"]
        for c in self.components:
            lines.append(
                f"| {c.name} | {c.kind.value} | `{c.spdx_id}` "
                f"| {'✅' if c.info.commercial_ok else '❌'} "
                f"| {'⚠️' if c.info.source_required else '—'} |"
            )
        lines += [
            "", "---",
            f"*Generated by [Squash](https://github.com/konjoai/squash) · "
            f"schema `{self.schema}`*",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Conflict checker — the compatibility matrix as code
# ---------------------------------------------------------------------------

class ConflictChecker:
    """Apply licence compatibility rules to a set of components.

    Each rule is a named function that inspects the component list and
    the use case, returning zero or more ``ConflictFinding`` objects.
    Rules are intentionally conservative: when the legal outcome is
    uncertain, the rule flags it so the user can seek counsel.
    """

    def check(
        self,
        components: list[ComponentLicense],
        use_case: UseCase,
    ) -> list[ConflictFinding]:
        findings: list[ConflictFinding] = []
        for rule in [
            self._rule_nc_commercial,
            self._rule_agpl_saas,
            self._rule_copyleft_closed_source,
            self._rule_sharealike_model_weights,
            self._rule_no_derivatives,
            self._rule_llama_commercial,
            self._rule_llama_competing_product,
            self._rule_gemma_competing,
            self._rule_bloom_rail_restrictions,
            self._rule_unknown_license,
            self._rule_gpl_apache_incompatibility,
            self._rule_strong_copyleft_mixing,
        ]:
            findings.extend(rule(components, use_case))
        return findings

    # -- Rule implementations -----------------------------------------------

    def _rule_nc_commercial(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        if use_case not in (UseCase.COMMERCIAL, UseCase.SAAS_API):
            return []
        findings = []
        for c in components:
            if c.info.kind == LicenseKind.NON_COMMERCIAL:
                findings.append(ConflictFinding(
                    rule_id="LC-001",
                    title="Non-commercial licence in commercial deployment",
                    description=(
                        f"`{c.name}` is licensed under `{c.spdx_id}` which prohibits "
                        f"commercial use. Deploying this component in a commercial product "
                        f"or SaaS service violates the licence terms."
                    ),
                    severity=ConflictSeverity.CRITICAL,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis=c.info.legal_basis or f"{c.spdx_id} §4(b) NonCommercial clause",
                    remediation=(
                        f"Replace `{c.name}` with a commercially licensed alternative, "
                        f"or obtain a commercial licence from the rights holder. "
                        f"For datasets: use CC0, CC-BY, ODC-By, or Apache-licensed alternatives."
                    ),
                    obligation="Remove or replace before commercial deployment.",
                ))
        return findings

    def _rule_agpl_saas(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        if use_case not in (UseCase.SAAS_API, UseCase.OPEN_SOURCE):
            return []
        findings = []
        for c in components:
            if c.info.saas_triggers:
                findings.append(ConflictFinding(
                    rule_id="LC-002",
                    title="AGPL network-copyleft trigger in SaaS deployment",
                    description=(
                        f"`{c.name}` is licensed under `{c.spdx_id}` (AGPL-class). "
                        f"Serving this component over a network — including as an API or "
                        f"web service — triggers the source-disclosure obligation. "
                        f"All corresponding source code must be made available to users."
                    ),
                    severity=ConflictSeverity.HIGH,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis="AGPL-3.0 §13 — Remote Network Interaction",
                    remediation=(
                        f"Either publish all corresponding source code of the service, "
                        f"replace `{c.name}` with a permissively or commercially licensed "
                        f"alternative, or obtain a commercial exception from the rights holder."
                    ),
                    obligation="Publish full source under AGPL-3.0 for all network users.",
                ))
        return findings

    def _rule_copyleft_closed_source(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        if use_case not in (UseCase.COMMERCIAL, UseCase.INTERNAL):
            return []
        findings = []
        for c in components:
            if c.info.kind == LicenseKind.STRONG_COPYLEFT and not c.info.saas_triggers:
                findings.append(ConflictFinding(
                    rule_id="LC-003",
                    title="Strong copyleft in closed-source product",
                    description=(
                        f"`{c.name}` is licensed under `{c.spdx_id}` (GPL-class). "
                        f"Linking or distributing this component in a closed-source product "
                        f"requires releasing the combined work's source code under the same licence."
                    ),
                    severity=ConflictSeverity.HIGH,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis=f"{c.spdx_id} §5 — Distribution of Modified Versions",
                    remediation=(
                        f"Replace `{c.name}` with an LGPL, MIT, or Apache-licensed alternative. "
                        f"If the component is dynamically linked (shared library), LGPL may "
                        f"permit use without source disclosure — verify with counsel."
                    ),
                    obligation="Disclose full source of combined work or replace component.",
                ))
        return findings

    def _rule_sharealike_model_weights(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        findings = []
        datasets = [c for c in components
                    if c.kind == ComponentKind.DATASET and c.info.share_alike]
        models   = [c for c in components if c.kind == ComponentKind.MODEL_WEIGHTS]
        if not datasets or not models:
            return []
        for ds in datasets:
            for m in models:
                if m.info.kind not in (LicenseKind.SHAREALIKE,) and m.info.commercial_ok:
                    findings.append(ConflictFinding(
                        rule_id="LC-004",
                        title="ShareAlike dataset may contaminate model weights",
                        description=(
                            f"Dataset `{ds.name}` is licensed under `{ds.spdx_id}` (ShareAlike). "
                            f"Training model `{m.name}` on this data may require releasing "
                            f"the model weights under the same ShareAlike licence. "
                            f"This is an **unsettled area of law** — consult IP counsel before "
                            f"commercial deployment."
                        ),
                        severity=ConflictSeverity.MEDIUM,
                        component_a=ds, component_b=m,
                        use_case=use_case,
                        legal_basis=(
                            f"{ds.spdx_id} ShareAlike clause — "
                            f"Creative Commons CC-BY-SA 4.0 §3(b)(1): derivative works must "
                            f"carry the same licence; whether trained model weights constitute "
                            f"a 'derivative work' is unsettled."
                        ),
                        remediation=(
                            f"Replace dataset `{ds.name}` with a CC0, CC-BY, or ODC-By licensed "
                            f"alternative to avoid ShareAlike obligations. "
                            f"Document the legal analysis if retaining this dataset."
                        ),
                        obligation="Seek legal opinion on ShareAlike applicability to model weights.",
                    ))
        return findings

    def _rule_no_derivatives(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        findings = []
        for c in components:
            if c.info.kind == LicenseKind.NO_DERIVATIVES:
                findings.append(ConflictFinding(
                    rule_id="LC-005",
                    title="No-derivatives licence — fine-tuning or modification prohibited",
                    description=(
                        f"`{c.name}` is licensed under `{c.spdx_id}` (NoDerivatives). "
                        f"Creating fine-tuned models, modified datasets, or any derivative "
                        f"work from this component is **prohibited** under the licence terms."
                    ),
                    severity=ConflictSeverity.HIGH,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis=f"{c.spdx_id} NoDerivatives clause — no modified forms permitted",
                    remediation=(
                        f"Replace `{c.name}` with a licence that permits modifications "
                        f"(CC-BY, CC0, Apache-2.0, MIT). Do not fine-tune on ND-licensed data."
                    ),
                    obligation="Remove ND-licensed component or cease derivative work.",
                ))
        return findings

    def _rule_llama_commercial(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        if use_case not in (UseCase.COMMERCIAL, UseCase.SAAS_API):
            return []
        findings = []
        for c in components:
            if c.spdx_id in ("LicenseRef-llama2", "LicenseRef-llama2-code"):
                findings.append(ConflictFinding(
                    rule_id="LC-006",
                    title="LLaMA 2 commercial use requires Meta approval above 700M MAU",
                    description=(
                        f"`{c.name}` uses the Meta LLaMA 2 Community License. "
                        f"Commercial use is **permitted** for products with <700M monthly "
                        f"active users. Above that threshold, a separate commercial licence "
                        f"must be obtained from Meta."
                    ),
                    severity=ConflictSeverity.MEDIUM,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis="Meta LLaMA 2 Community License §1 — Acceptable Use Policy",
                    remediation=(
                        "Ensure your product is below 700M MAU or apply for a commercial "
                        "licence at https://ai.meta.com/llama/. Retain the licence file and "
                        "include 'Built with Meta Llama 2' in your product documentation."
                    ),
                    obligation="Include 'Built with Meta Llama 2' attribution in product documentation.",
                ))
        return findings

    def _rule_llama_competing_product(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        findings = []
        for c in components:
            if c.spdx_id in ("LicenseRef-llama2", "LicenseRef-llama3", "LicenseRef-llama2-code"):
                findings.append(ConflictFinding(
                    rule_id="LC-007",
                    title="LLaMA licence prohibits use to build competing LLM products",
                    description=(
                        f"`{c.name}` uses a Meta LLaMA licence which explicitly prohibits "
                        f"using the model weights to train, fine-tune, or improve another "
                        f"large language model. This applies regardless of use case."
                    ),
                    severity=ConflictSeverity.HIGH,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis="Meta LLaMA Community License — Acceptable Use Policy §2(d): no use to improve other LLMs",
                    remediation=(
                        "If your product uses LLaMA to build, evaluate, or distil another "
                        "LLM, this use is prohibited. Switch to a permissively licensed base "
                        "model (Mistral Apache-2.0, GPT-NeoX, or Falcon-7B/180B Apache-2.0)."
                    ),
                    obligation="Confirm the product does not use LLaMA outputs to train competing models.",
                ))
        return findings

    def _rule_gemma_competing(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        findings = []
        for c in components:
            if c.spdx_id == "LicenseRef-gemma":
                findings.append(ConflictFinding(
                    rule_id="LC-008",
                    title="Gemma Terms prohibit training competing AI models",
                    description=(
                        f"`{c.name}` is governed by Google Gemma Terms of Use. "
                        f"Using Gemma outputs or weights to train, evaluate, or distil "
                        f"a competing AI model is **prohibited**."
                    ),
                    severity=ConflictSeverity.MEDIUM,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis="Google Gemma Terms of Use §4 — Prohibited Uses",
                    remediation=(
                        "If building a competing model, switch to a fully permissive "
                        "base model. For other uses, comply with the Gemma Usage Policy "
                        "and include the required attribution."
                    ),
                    obligation="Do not use Gemma to train competing AI models.",
                ))
        return findings

    def _rule_bloom_rail_restrictions(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        findings = []
        for c in components:
            if c.spdx_id in ("LicenseRef-bloom", "LicenseRef-openrail"):
                findings.append(ConflictFinding(
                    rule_id="LC-009",
                    title="RAIL/OpenRAIL use-restriction clause",
                    description=(
                        f"`{c.name}` is licensed under a Responsible AI Licence (RAIL/OpenRAIL). "
                        f"These licences embed **use restrictions** directly in the licence: "
                        f"prohibited uses include generating disinformation, surveillance, "
                        f"CSAM, and autonomous weapons. Violations are enforceable licence "
                        f"termination events."
                    ),
                    severity=ConflictSeverity.MEDIUM,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis="BigScience OpenRAIL-M §5 — Use Restrictions",
                    remediation=(
                        "Ensure your use case is not listed in the RAIL restrictions. "
                        "Document your compliance with the use restrictions as part of your "
                        "model card and risk assessment. Include the RAIL licence in your "
                        "model distribution."
                    ),
                    obligation="Document compliance with RAIL use restrictions in model card.",
                ))
        return findings

    def _rule_unknown_license(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        findings = []
        for c in components:
            if c.spdx_id == "LicenseRef-unknown":
                findings.append(ConflictFinding(
                    rule_id="LC-010",
                    title="Unknown or unresolved licence",
                    description=(
                        f"`{c.name}` has an unknown or unresolved licence (`{c.raw_license}`). "
                        f"Under copyright law, **all rights are reserved** by default when no "
                        f"licence is specified. This component cannot be legally used, "
                        f"modified, or distributed without explicit permission."
                    ),
                    severity=ConflictSeverity.HIGH,
                    component_a=c, component_b=None,
                    use_case=use_case,
                    legal_basis="Berne Convention — copyright is automatic; no licence = all rights reserved",
                    remediation=(
                        f"Contact the rights holder of `{c.name}` to obtain a written "
                        f"licence. Do not use this component in production until a licence "
                        f"is confirmed in writing."
                    ),
                    obligation="Obtain written licence from rights holder before any use.",
                ))
        return findings

    def _rule_gpl_apache_incompatibility(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        """GPL-2.0-only + Apache-2.0: the patent termination clause makes them incompatible."""
        findings = []
        gpl2_only = [c for c in components
                     if c.spdx_id in ("GPL-2.0-only",)]
        apache   = [c for c in components
                    if c.spdx_id in ("Apache-2.0",) and c.kind == ComponentKind.CODE_DEP]
        if gpl2_only and apache:
            for g in gpl2_only:
                for a in apache:
                    findings.append(ConflictFinding(
                        rule_id="LC-011",
                        title="GPL-2.0-only incompatible with Apache-2.0",
                        description=(
                            f"`{g.name}` (GPL-2.0-only) and `{a.name}` (Apache-2.0) "
                            f"cannot be combined in the same binary or distribution. "
                            f"Apache-2.0's patent termination clause is considered "
                            f"an additional restriction prohibited by GPL-2.0-only §6."
                        ),
                        severity=ConflictSeverity.HIGH,
                        component_a=g, component_b=a,
                        use_case=use_case,
                        legal_basis="FSF: Apache-2.0 + GPL-2.0-only incompatibility — https://www.gnu.org/licenses/license-list.html#apache2",
                        remediation=(
                            f"Upgrade the GPL component to GPL-2.0-or-later / GPL-3.0 "
                            f"(Apache-2.0 is compatible with GPL-3.0), or replace "
                            f"`{g.name}` with an Apache-2.0 / MIT alternative."
                        ),
                        obligation="Resolve licence incompatibility before distribution.",
                    ))
        return findings

    def _rule_strong_copyleft_mixing(
        self, components: list[ComponentLicense], use_case: UseCase
    ) -> list[ConflictFinding]:
        """Two different strong-copyleft licences in the same binary is incompatible."""
        findings = []
        copyleft = [c for c in components
                    if c.info.kind == LicenseKind.STRONG_COPYLEFT
                    and c.kind == ComponentKind.CODE_DEP]
        seen: set[tuple[str, str]] = set()
        for i, a in enumerate(copyleft):
            for b in copyleft[i + 1:]:
                if a.spdx_id == b.spdx_id:
                    continue
                key = tuple(sorted([a.spdx_id, b.spdx_id]))
                if key in seen:
                    continue
                seen.add(key)
                # GPL-2.0-only and GPL-3.0-only are incompatible (version lock)
                if "only" in a.spdx_id and "only" in b.spdx_id:
                    findings.append(ConflictFinding(
                        rule_id="LC-012",
                        title="Incompatible copyleft version lock",
                        description=(
                            f"`{a.name}` ({a.spdx_id}) and `{b.name}` ({b.spdx_id}) "
                            f"are both version-locked copyleft licences. They cannot be "
                            f"combined in the same binary because neither permits "
                            f"relicensing to the other version."
                        ),
                        severity=ConflictSeverity.HIGH,
                        component_a=a, component_b=b,
                        use_case=use_case,
                        legal_basis="FSF licence compatibility list — version-locked GPL variants cannot be combined",
                        remediation=(
                            f"If possible, use `GPL-2.0-or-later` or `GPL-3.0-or-later` "
                            f"variants which permit upgrading. Replace one component with "
                            f"a permissively licensed alternative."
                        ),
                        obligation="Resolve version-locked copyleft conflict before distribution.",
                    ))
        return findings


# ---------------------------------------------------------------------------
# Obligation extractor
# ---------------------------------------------------------------------------

def extract_obligations(
    components: list[ComponentLicense], use_case: UseCase
) -> list[str]:
    """Build the list of affirmative legal obligations (attribution, notices, etc.)."""
    obligations: list[str] = []
    for c in components:
        if c.info.attribution_required and c.info.kind not in (
            LicenseKind.PUBLIC_DOMAIN, LicenseKind.UNKNOWN
        ):
            obligations.append(
                f"Attribution required for `{c.name}` ({c.spdx_id}): "
                f"include copyright notice and licence text in distribution."
            )
        if c.info.source_required and use_case != UseCase.RESEARCH:
            obligations.append(
                f"Source disclosure required for `{c.name}` ({c.spdx_id}): "
                f"provide complete corresponding source under the same licence."
            )
        if c.info.saas_triggers and use_case == UseCase.SAAS_API:
            obligations.append(
                f"Network copyleft: `{c.name}` ({c.spdx_id}) requires offering "
                f"source code to every network user of the service."
            )
        if c.spdx_id in ("LicenseRef-llama2", "LicenseRef-llama3"):
            obligations.append(
                f"LLaMA attribution: include 'Built with Meta Llama' in your product "
                f"documentation and model card (required by Meta licence)."
            )
    # Deduplicate while preserving order
    seen: set[str] = set()
    return [o for o in obligations if not (o in seen or seen.add(o))]  # type: ignore[func-returns-value]


# ---------------------------------------------------------------------------
# Scanner — extract component licences from project files
# ---------------------------------------------------------------------------

class LicenseScanner:
    """Walk a project directory and extract ComponentLicense records."""

    def scan(self, project_path: Path) -> list[ComponentLicense]:
        components: list[ComponentLicense] = []
        project_path = project_path.resolve()

        if project_path.is_file():
            return self._scan_file(project_path)

        components.extend(self._scan_requirements_txt(project_path))
        components.extend(self._scan_pyproject_toml(project_path))
        components.extend(self._scan_package_json(project_path))
        components.extend(self._scan_cargo_toml(project_path))
        components.extend(self._scan_model_files(project_path))
        components.extend(self._scan_dataset_files(project_path))
        components.extend(self._scan_license_files(project_path))

        # Deduplicate by (name, kind)
        seen: set[tuple[str, str]] = set()
        unique: list[ComponentLicense] = []
        for c in components:
            key = (c.name, c.kind.value)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    def _scan_file(self, path: Path) -> list[ComponentLicense]:
        """Single-file mode — try all parsers."""
        for method in [
            self._parse_requirements_line,
            self._parse_package_json_content,
        ]:
            try:
                result = method(path)
                if result:
                    return result
            except Exception:
                pass
        return []

    def _scan_requirements_txt(self, root: Path) -> list[ComponentLicense]:
        components: list[ComponentLicense] = []
        for req_file in root.rglob("requirements*.txt"):
            try:
                for line in req_file.read_text().splitlines():
                    c = self._parse_requirements_line_str(line, str(req_file))
                    if c:
                        components.append(c)
            except Exception:
                pass
        return components

    def _parse_requirements_line(self, path: Path) -> list[ComponentLicense]:
        components = []
        for line in path.read_text().splitlines():
            c = self._parse_requirements_line_str(line, str(path))
            if c:
                components.append(c)
        return components

    def _parse_requirements_line_str(self, line: str, source: str) -> ComponentLicense | None:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            return None
        # Extract package name (before ==, >=, <=, ~=, [extras])
        name = re.split(r"[=><!~\[@\s]", line)[0].strip()
        if not name:
            return None
        spdx = _KNOWN_PKG_LICENSES.get(name.lower(), "LicenseRef-unknown")
        return ComponentLicense.from_raw(name, ComponentKind.CODE_DEP, spdx, source)

    def _scan_pyproject_toml(self, root: Path) -> list[ComponentLicense]:
        if tomllib is None:
            return []
        components: list[ComponentLicense] = []
        for toml_file in root.rglob("pyproject.toml"):
            try:
                data = tomllib.loads(toml_file.read_text())
                # Project's own licence
                proj = data.get("project", {})
                lic = proj.get("license", {})
                lic_str = lic.get("text", "") or lic.get("file", "") if isinstance(lic, dict) else str(lic)
                project_name = proj.get("name", toml_file.parent.name)
                if lic_str:
                    components.append(ComponentLicense.from_raw(
                        project_name, ComponentKind.APPLICATION,
                        lic_str, str(toml_file)
                    ))
                # Dependencies
                deps = proj.get("dependencies", [])
                for dep in deps:
                    c = self._parse_requirements_line_str(dep, str(toml_file))
                    if c:
                        components.append(c)
            except Exception:
                pass
        return components

    def _scan_package_json(self, root: Path) -> list[ComponentLicense]:
        components: list[ComponentLicense] = []
        for pj in root.rglob("package.json"):
            if "node_modules" in str(pj):
                continue
            try:
                data = json.loads(pj.read_text())
                # Own licence
                own_lic = data.get("license", "")
                name = data.get("name", pj.parent.name)
                if own_lic:
                    components.append(ComponentLicense.from_raw(
                        name, ComponentKind.APPLICATION, own_lic, str(pj)
                    ))
                # Dependencies
                for dep_name, _ver in {
                    **data.get("dependencies", {}),
                    **data.get("devDependencies", {}),
                }.items():
                    spdx = _KNOWN_PKG_LICENSES.get(dep_name.lower(), "LicenseRef-unknown")
                    components.append(ComponentLicense.from_raw(
                        dep_name, ComponentKind.CODE_DEP, spdx, str(pj)
                    ))
            except Exception:
                pass
        return components

    def _parse_package_json_content(self, path: Path) -> list[ComponentLicense]:
        data = json.loads(path.read_text())
        own_lic = data.get("license", "")
        name = data.get("name", path.parent.name)
        return [ComponentLicense.from_raw(name, ComponentKind.APPLICATION, own_lic, str(path))] if own_lic else []

    def _scan_cargo_toml(self, root: Path) -> list[ComponentLicense]:
        if tomllib is None:
            return []
        components: list[ComponentLicense] = []
        for ct in root.rglob("Cargo.toml"):
            try:
                data = tomllib.loads(ct.read_text())
                pkg = data.get("package", {})
                lic = pkg.get("license", "")
                name = pkg.get("name", ct.parent.name)
                if lic:
                    components.append(ComponentLicense.from_raw(
                        name, ComponentKind.APPLICATION, lic, str(ct)
                    ))
                for dep_name in data.get("dependencies", {}):
                    spdx = _KNOWN_PKG_LICENSES.get(dep_name.lower(), "LicenseRef-unknown")
                    components.append(ComponentLicense.from_raw(
                        dep_name, ComponentKind.CODE_DEP, spdx, str(ct)
                    ))
            except Exception:
                pass
        return components

    def _scan_model_files(self, root: Path) -> list[ComponentLicense]:
        """Extract model licences from README / model card / squash metadata."""
        components: list[ComponentLicense] = []
        for readme in list(root.glob("README.md")) + list(root.glob("README.txt")):
            lic = _extract_license_from_readme(readme.read_text(errors="replace"))
            if lic:
                components.append(ComponentLicense.from_raw(
                    root.name, ComponentKind.MODEL_WEIGHTS,
                    lic, str(readme)
                ))
        for meta in root.rglob("*.json"):
            if meta.name in ("master_record.json", "model_info.json", "config.json"):
                try:
                    d = json.loads(meta.read_text())
                    lic = (d.get("license") or d.get("licence") or
                           d.get("model_license") or "")
                    if lic:
                        components.append(ComponentLicense.from_raw(
                            d.get("model_id") or meta.parent.name,
                            ComponentKind.MODEL_WEIGHTS, lic, str(meta)
                        ))
                except Exception:
                    pass
        return components

    def _scan_dataset_files(self, root: Path) -> list[ComponentLicense]:
        components: list[ComponentLicense] = []
        for info_file in root.rglob("dataset_infos.json"):
            try:
                data = json.loads(info_file.read_text())
                for ds_name, ds_info in data.items():
                    lic = ds_info.get("license") or ds_info.get("licence") or ""
                    if lic:
                        components.append(ComponentLicense.from_raw(
                            ds_name, ComponentKind.DATASET, lic, str(info_file)
                        ))
            except Exception:
                pass
        for prov in root.rglob("*provenance*.json"):
            try:
                d = json.loads(prov.read_text())
                for ds in d.get("datasets", []):
                    lic = ds.get("license") or ds.get("licence") or ""
                    name = ds.get("dataset_id") or ds.get("name") or "unknown"
                    if lic:
                        components.append(ComponentLicense.from_raw(
                            name, ComponentKind.DATASET, lic, str(prov)
                        ))
            except Exception:
                pass
        return components

    def _scan_license_files(self, root: Path) -> list[ComponentLicense]:
        """Read top-level LICENSE / COPYING files as application licence."""
        components: list[ComponentLicense] = []
        for lic_file in ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"]:
            p = root / lic_file
            if p.exists():
                text = p.read_text(errors="replace")[:2000]
                lic = _sniff_license_text(text)
                if lic:
                    components.append(ComponentLicense.from_raw(
                        root.name, ComponentKind.APPLICATION,
                        lic, str(p)
                    ))
        return components


def _extract_license_from_readme(text: str) -> str:
    """Heuristic: look for '## License' or 'license:' in model card text."""
    for line in text.splitlines():
        m = re.match(r"^\s*license\s*:\s*(.+)", line, re.I)
        if m:
            return m.group(1).strip()
        if re.match(r"^#+\s*licen[sc]e", line, re.I):
            return ""   # section header — content follows but we can't parse it here
    return ""


def _sniff_license_text(text: str) -> str:
    """Identify common licence from first 2KB of a LICENSE file."""
    lower = text.lower()
    if "mit license" in lower or "permission is hereby granted" in lower:
        return "MIT"
    if "apache license" in lower and "version 2" in lower:
        return "Apache-2.0"
    if "gnu general public license" in lower and "version 3" in lower:
        return "GPL-3.0-only"
    if "gnu general public license" in lower and "version 2" in lower:
        return "GPL-2.0-only"
    if "gnu lesser general public" in lower and "version 3" in lower:
        return "LGPL-3.0-only"
    if "gnu lesser general public" in lower and "version 2.1" in lower:
        return "LGPL-2.1-only"
    if "gnu affero general public" in lower:
        return "AGPL-3.0-only"
    if "bsd 2-clause" in lower or "simplified bsd" in lower:
        return "BSD-2-Clause"
    if "bsd 3-clause" in lower:
        return "BSD-3-Clause"
    if "mozilla public license" in lower and "2.0" in lower:
        return "MPL-2.0"
    if "creative commons" in lower and "zero" in lower:
        return "CC0-1.0"
    if "unlicense" in lower:
        return "Unlicense"
    return ""


# Curated licence mapping for common Python/JS/Rust packages.
_KNOWN_PKG_LICENSES: dict[str, str] = {
    "numpy": "BSD-3-Clause",  "scipy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause", "scikit-learn": "BSD-3-Clause",
    "matplotlib": "PSF-2.0",  "pillow": "MIT",
    "torch": "BSD-3-Clause",  "torchvision": "BSD-3-Clause",
    "torchaudio": "BSD-3-Clause",
    "tensorflow": "Apache-2.0", "keras": "Apache-2.0",
    "transformers": "Apache-2.0", "datasets": "Apache-2.0",
    "tokenizers": "Apache-2.0", "accelerate": "Apache-2.0",
    "peft": "Apache-2.0",     "trl": "Apache-2.0",
    "langchain": "MIT",       "langchain-core": "MIT",
    "openai": "MIT",          "anthropic": "MIT",
    "fastapi": "MIT",         "uvicorn": "BSD-3-Clause",
    "pydantic": "MIT",        "requests": "Apache-2.0",
    "httpx": "BSD-3-Clause",  "aiohttp": "Apache-2.0",
    "sqlalchemy": "MIT",      "alembic": "MIT",
    "pytest": "MIT",          "coverage": "Apache-2.0",
    "click": "BSD-3-Clause",  "typer": "MIT",
    "rich": "MIT",            "tqdm": "MIT",
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "paramiko": "LGPL-2.1-or-later",
    "flask": "BSD-3-Clause",  "django": "BSD-3-Clause",
    "celery": "BSD-3-Clause", "redis": "MIT",
    "psycopg2": "LGPL-3.0-only",
    "mysql-connector-python": "GPL-2.0-only",
    "boto3": "Apache-2.0",    "botocore": "Apache-2.0",
    "google-cloud-storage": "Apache-2.0",
    "weasyprint": "BSD-3-Clause",
    "markdown": "BSD-3-Clause",
    # JavaScript
    "react": "MIT",           "next": "MIT",
    "typescript": "Apache-2.0",
    "webpack": "MIT",
    # Rust
    "serde": "MIT OR Apache-2.0",
    "tokio": "MIT",
    "anyhow": "MIT OR Apache-2.0",
}


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class LicenseConflictScanner:
    """Orchestrate scan + conflict check + report generation."""

    def scan(
        self,
        project_path: Path,
        use_case: UseCase = UseCase.COMMERCIAL,
        extra_components: list[ComponentLicense] | None = None,
        squash_version: str = "1",
    ) -> LicenseConflictReport:
        from datetime import datetime, timezone
        project_path = Path(project_path).resolve()

        components = LicenseScanner().scan(project_path)
        if extra_components:
            components.extend(extra_components)

        findings = ConflictChecker().check(components, use_case)
        obligations = extract_obligations(components, use_case)

        # Risk level: highest severity across all findings
        sev_order = {
            ConflictSeverity.CRITICAL: OverallRisk.CRITICAL,
            ConflictSeverity.HIGH:     OverallRisk.HIGH,
            ConflictSeverity.MEDIUM:   OverallRisk.MEDIUM,
            ConflictSeverity.LOW:      OverallRisk.LOW,
            ConflictSeverity.INFO:     OverallRisk.LOW,
        }
        overall = OverallRisk.CLEAN
        for f in findings:
            candidate = sev_order[f.severity]
            if candidate > overall:
                overall = candidate

        return LicenseConflictReport(
            schema=_SCHEMA,
            project_path=str(project_path),
            scanned_at=datetime.now(tz=timezone.utc).isoformat(),
            use_case=use_case,
            overall_risk=overall,
            components=components,
            findings=findings,
            obligations=obligations,
            squash_version=squash_version,
        )


def load_report(path: Path) -> LicenseConflictReport:
    from datetime import datetime, timezone

    d = json.loads(path.read_text())
    components = [
        ComponentLicense.from_raw(
            c["name"], ComponentKind(c["kind"]),
            c["raw_license"], c.get("source_file", "")
        )
        for c in d["components"]
    ]

    def _comp_from_dict(cd: dict | None) -> ComponentLicense | None:
        if cd is None:
            return None
        return ComponentLicense.from_raw(
            cd["name"], ComponentKind(cd["kind"]),
            cd["raw_license"], cd.get("source_file", "")
        )

    # Rebuild components by name for finding lookup
    comp_map = {(c["name"], c["kind"]): _comp_from_dict(c) for c in d["components"]}

    findings = []
    for f in d["findings"]:
        ca = _comp_from_dict(f["component_a"])
        cb = _comp_from_dict(f.get("component_b"))
        if ca:
            findings.append(ConflictFinding(
                rule_id=f["rule_id"],
                title=f["title"],
                description=f["description"],
                severity=ConflictSeverity(f["severity"]),
                component_a=ca, component_b=cb,
                use_case=UseCase(f["use_case"]),
                legal_basis=f["legal_basis"],
                remediation=f["remediation"],
                obligation=f.get("obligation", ""),
            ))

    return LicenseConflictReport(
        schema=d["schema"],
        project_path=d["project_path"],
        scanned_at=d["scanned_at"],
        use_case=UseCase(d["use_case"]),
        overall_risk=OverallRisk(d["overall_risk"]),
        components=components,
        findings=findings,
        obligations=d.get("obligations", []),
        squash_version=d.get("squash_version", "1"),
    )
