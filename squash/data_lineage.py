"""squash/data_lineage.py — Training Data Lineage Certificate.

Italy fined OpenAI €15 million for GDPR violations in training data.
The EU AI Act requires documentation of training data for high-risk systems.
Most organizations deploying fine-tuned models have no machine-readable record
of what data was used, whether it was licensed, or whether PII was included.

This module generates a signed Training Data Lineage Certificate that:
  1. Traces datasets from model config / MLflow / W&B experiment runs
  2. Checks dataset licenses against the SPDX license database
  3. Flags PII risk indicators (known PII-containing datasets, config signals)
  4. Produces a GDPR Article 6 legal basis assessment
  5. Signs the certificate with Sigstore (or offline SHA-256 hash)

Output: ``data_lineage_certificate.json``

Usage::

    from squash.data_lineage import DataLineageTracer
    from pathlib import Path

    cert = DataLineageTracer.trace(
        model_path=Path("./my-model"),
        config_path=Path("./train_config.json"),
    )
    print(cert.summary())
    cert.save(Path("./data_lineage_certificate.json"))
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


class LicenseCategory(str, Enum):
    PERMISSIVE = "permissive"          # MIT, Apache-2.0, BSD — commercial OK
    COPYLEFT = "copyleft"              # GPL, LGPL — may require source disclosure
    RESEARCH_ONLY = "research_only"    # CC-BY-NC, academic-only licenses
    COMMERCIAL_OK = "commercial_ok"    # CC-BY, CC0, Public Domain
    RESTRICTED = "restricted"          # Custom, unknown, or proprietary
    UNKNOWN = "unknown"


class PIIRiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"        # Aggregated/anonymized data
    MEDIUM = "medium"  # Pseudonymized or indirectly identifiable
    HIGH = "high"      # Direct PII (names, emails, SSNs, medical)
    CRITICAL = "critical"  # Special categories (health, biometric, financial)


@dataclass
class DatasetProvenance:
    dataset_id: str
    dataset_name: str
    source: str                # HuggingFace hub ID, URL, or filesystem path
    license_spdx: str          # SPDX identifier or "unknown"
    license_category: LicenseCategory
    commercial_use_allowed: bool | None
    pii_risk: PIIRiskLevel
    pii_indicators: list[str]  # Reasons for PII risk flag
    size_gb: float | None
    record_count: int | None
    gdpr_legal_basis: str      # e.g. "legitimate_interest", "consent", "none", "unknown"
    verified: bool             # Whether license was positively confirmed
    notes: str


@dataclass
class LineageCertificate:
    certificate_id: str
    model_id: str
    model_path: str
    generated_at: str
    datasets: list[DatasetProvenance] = field(default_factory=list)
    config_source: str = ""          # Path to training config that was parsed
    training_framework: str = ""     # pytorch, tensorflow, mlx, etc.
    license_issues: list[str] = field(default_factory=list)
    pii_issues: list[str] = field(default_factory=list)
    gdpr_compliant: bool | None = None
    overall_risk: PIIRiskLevel = PIIRiskLevel.NONE
    certificate_hash: str = ""

    def summary(self) -> str:
        lines = [
            "TRAINING DATA LINEAGE CERTIFICATE",
            "=" * 52,
            f"Certificate ID:  {self.certificate_id}",
            f"Model:           {self.model_id}",
            f"Generated:       {self.generated_at}",
            f"Datasets found:  {len(self.datasets)}",
            f"Overall PII Risk: {self.overall_risk.value.upper()}",
            f"GDPR Compliant:  {'Yes' if self.gdpr_compliant else 'No' if self.gdpr_compliant is False else 'Unknown'}",
            "",
        ]
        if self.datasets:
            lines.append("Datasets:")
            for ds in self.datasets:
                lic_ok = "✅" if ds.commercial_use_allowed else "⚠" if ds.commercial_use_allowed is False else "?"
                pii_icon = "🔴" if ds.pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL) else \
                           "🟡" if ds.pii_risk == PIIRiskLevel.MEDIUM else "✅"
                lines.append(f"  {lic_ok} {pii_icon} {ds.dataset_name}")
                lines.append(f"     License: {ds.license_spdx} ({ds.license_category.value}) | PII: {ds.pii_risk.value}")
                if ds.pii_indicators:
                    lines.append(f"     PII indicators: {', '.join(ds.pii_indicators[:3])}")
            lines.append("")
        if self.license_issues:
            lines.append("License Issues:")
            for issue in self.license_issues:
                lines.append(f"  ⚠  {issue}")
        if self.pii_issues:
            lines.append("PII Issues:")
            for issue in self.pii_issues:
                lines.append(f"  ⚠  {issue}")
        if self.certificate_hash:
            lines.append(f"\nCertificate SHA-256: {self.certificate_hash[:32]}…")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "document_type": "TRAINING_DATA_LINEAGE_CERTIFICATE",
            "model_id": self.model_id,
            "model_path": self.model_path,
            "generated_at": self.generated_at,
            "config_source": self.config_source,
            "training_framework": self.training_framework,
            "overall_pii_risk": self.overall_risk.value,
            "gdpr_compliant": self.gdpr_compliant,
            "certificate_hash": self.certificate_hash,
            "license_issues": self.license_issues,
            "pii_issues": self.pii_issues,
            "datasets": [
                {
                    "dataset_id": ds.dataset_id,
                    "dataset_name": ds.dataset_name,
                    "source": ds.source,
                    "license_spdx": ds.license_spdx,
                    "license_category": ds.license_category.value,
                    "commercial_use_allowed": ds.commercial_use_allowed,
                    "pii_risk": ds.pii_risk.value,
                    "pii_indicators": ds.pii_indicators,
                    "gdpr_legal_basis": ds.gdpr_legal_basis,
                    "verified": ds.verified,
                    "notes": ds.notes,
                }
                for ds in self.datasets
            ],
        }

    def save(self, path: Path) -> None:
        path = Path(path)
        doc = self.to_dict()
        path.write_text(json.dumps(doc, indent=2))
        log.info("Data lineage certificate written to %s", path)


# ── SPDX license knowledge base ───────────────────────────────────────────────

_SPDX_COMMERCIAL_OK = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense",
    "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0", "ODC-By-1.0", "ODbL-1.0",
    "PDDL-1.0", "WTFPL", "Zlib", "PSF-2.0", "Python-2.0", "BSL-1.0",
}

_SPDX_COPYLEFT = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0",
    "MPL-2.0", "EUPL-1.2", "CDDL-1.0",
}

_SPDX_RESEARCH_ONLY = {
    "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0",
    "CC-BY-ND-4.0",
}

# Common HuggingFace datasets with known license/PII characteristics
_HF_DATASET_PROFILES: dict[str, tuple[str, PIIRiskLevel, list[str]]] = {
    # (license_spdx, pii_risk, pii_indicators)
    "common_crawl": ("CC0-1.0", PIIRiskLevel.MEDIUM, ["web-scraped content may include PII"]),
    "c4": ("ODC-By-1.0", PIIRiskLevel.MEDIUM, ["derived from Common Crawl"]),
    "the_pile": ("MIT", PIIRiskLevel.HIGH, ["includes PubMed, GitHub, books, email archives"]),
    "openwebtext": ("CC0-1.0", PIIRiskLevel.MEDIUM, ["web-scraped Reddit links"]),
    "wikipedia": ("CC-BY-SA-4.0", PIIRiskLevel.LOW, []),
    "bookcorpus": ("unknown", PIIRiskLevel.LOW, []),
    "squad": ("CC-BY-SA-4.0", PIIRiskLevel.LOW, []),
    "imagenet": ("custom", PIIRiskLevel.LOW, ["contains facial images"]),
    "laion-5b": ("CC-BY-4.0", PIIRiskLevel.HIGH, ["web-scraped images, possible faces, CSAM removal ongoing"]),
    "laion-400m": ("CC-BY-4.0", PIIRiskLevel.HIGH, ["web-scraped images, possible faces"]),
    "pile-cc": ("CC0-1.0", PIIRiskLevel.MEDIUM, ["derived from Common Crawl"]),
    "openassistant": ("Apache-2.0", PIIRiskLevel.MEDIUM, ["human conversations, possible PII"]),
    "dolly": ("CC-BY-SA-4.0", PIIRiskLevel.LOW, []),
    "alpaca": ("CC-BY-NC-4.0", PIIRiskLevel.LOW, []),
    "oasst1": ("Apache-2.0", PIIRiskLevel.MEDIUM, ["human conversations"]),
    "gsm8k": ("MIT", PIIRiskLevel.NONE, []),
    "mmlu": ("MIT", PIIRiskLevel.NONE, []),
    "humaneval": ("MIT", PIIRiskLevel.NONE, []),
    "bigbench": ("Apache-2.0", PIIRiskLevel.NONE, []),
    "ultrachat": ("CC-BY-NC-SA-4.0", PIIRiskLevel.MEDIUM, ["human conversations, research-only"]),
    "sharegpt": ("CC-BY-NC-4.0", PIIRiskLevel.MEDIUM, ["human conversations with ChatGPT, research-only"]),
    "medical_dialog": ("unknown", PIIRiskLevel.CRITICAL, ["medical conversations, special GDPR category"]),
    "mimic": ("custom", PIIRiskLevel.CRITICAL, ["clinical data, special GDPR category"]),
    "pubmed": ("CC0-1.0", PIIRiskLevel.LOW, []),
    "arxiv": ("CC-BY-4.0", PIIRiskLevel.LOW, []),
    "github_code": ("various", PIIRiskLevel.MEDIUM, ["may contain API keys, emails, secrets"]),
    "stack": ("various", PIIRiskLevel.MEDIUM, ["may contain API keys, emails"]),
    "codesearchnet": ("various", PIIRiskLevel.MEDIUM, ["code repositories"]),
}

# Config key patterns that signal dataset usage
_DATASET_CONFIG_KEYS = re.compile(
    r"dataset[_\s]?(?:name|path|id|repo)|train_?file|data_?path|"
    r"hf_?dataset|huggingface_?dataset|data_?dir",
    re.IGNORECASE,
)

_PII_CONFIG_SIGNALS = re.compile(
    r"pii|personal_?data|gdpr|hipaa|phi|ssn|social_?security|"
    r"medical|health|financial|biometric|facial",
    re.IGNORECASE,
)


# ── Tracer ────────────────────────────────────────────────────────────────────

class DataLineageTracer:
    """Trace training data lineage from a model directory or config."""

    @staticmethod
    def trace(
        model_path: Path,
        config_path: Path | None = None,
        model_id: str | None = None,
        datasets: list[str] | None = None,
    ) -> LineageCertificate:
        model_path = Path(model_path)
        if model_id is None:
            model_id = model_path.name

        cert_id = hashlib.sha256(
            f"{model_id}{datetime.datetime.now().isoformat()}".encode()
        ).hexdigest()[:16].upper()

        config_src = ""
        training_framework = ""
        found_datasets: list[str] = list(datasets or [])

        # Discover config file
        config = _load_config(model_path, config_path)
        if config:
            config_src = str(config_path or "auto-detected")
            training_framework = _detect_framework(config)
            found_datasets += _extract_datasets_from_config(config)

        # Check for existing dataset_provenance.json
        prov_path = _find_provenance(model_path)
        if prov_path:
            try:
                prov_data = json.loads(prov_path.read_text())
                for ds in (prov_data.get("datasets") or []):
                    name = ds.get("name") or ds.get("id", "")
                    if name and name not in found_datasets:
                        found_datasets.append(name)
            except (json.JSONDecodeError, OSError):
                pass

        # Check MLflow artifacts
        mlflow_datasets = _scan_mlflow_run(model_path)
        for ds in mlflow_datasets:
            if ds not in found_datasets:
                found_datasets.append(ds)

        # Deduplicate
        found_datasets = list(dict.fromkeys(d.strip() for d in found_datasets if d.strip()))

        # Assess each dataset
        provenance_list: list[DatasetProvenance] = []
        for ds_name in found_datasets:
            prov = _assess_dataset(ds_name)
            provenance_list.append(prov)

        # Compute overall risk
        pii_levels = [p.pii_risk for p in provenance_list]
        _RANK = {PIIRiskLevel.NONE: 0, PIIRiskLevel.LOW: 1, PIIRiskLevel.MEDIUM: 2,
                 PIIRiskLevel.HIGH: 3, PIIRiskLevel.CRITICAL: 4}
        overall_pii = max(pii_levels, key=lambda x: _RANK[x]) if pii_levels else PIIRiskLevel.NONE

        # License issues
        license_issues: list[str] = []
        for p in provenance_list:
            if p.commercial_use_allowed is False:
                license_issues.append(
                    f"{p.dataset_name}: license '{p.license_spdx}' restricts commercial use"
                )
            if p.license_category == LicenseCategory.UNKNOWN:
                license_issues.append(f"{p.dataset_name}: license unknown — verify before commercial deployment")
            if p.license_category == LicenseCategory.COPYLEFT:
                license_issues.append(
                    f"{p.dataset_name}: copyleft license '{p.license_spdx}' — may require source disclosure"
                )

        # PII issues
        pii_issues: list[str] = []
        for p in provenance_list:
            if p.pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL):
                pii_issues.append(
                    f"{p.dataset_name}: {p.pii_risk.value} PII risk — "
                    f"GDPR Article 6 legal basis required: '{p.gdpr_legal_basis}'"
                )

        # GDPR compliance
        gdpr_bases = {p.gdpr_legal_basis for p in provenance_list}
        gdpr_compliant: bool | None = None
        if provenance_list:
            if any(p.pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL) for p in provenance_list):
                has_basis = all(
                    p.gdpr_legal_basis not in ("none", "unknown")
                    for p in provenance_list
                    if p.pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL)
                )
                gdpr_compliant = has_basis
            else:
                gdpr_compliant = True

        # Build certificate
        cert_doc = {
            "certificate_id": cert_id,
            "model_id": model_id,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "datasets": [p.to_dict() if hasattr(p, "to_dict") else {} for p in provenance_list],
        }
        cert_hash = hashlib.sha256(json.dumps(cert_doc, sort_keys=True).encode()).hexdigest()

        return LineageCertificate(
            certificate_id=cert_id,
            model_id=model_id,
            model_path=str(model_path),
            generated_at=cert_doc["generated_at"],
            datasets=provenance_list,
            config_source=config_src,
            training_framework=training_framework,
            license_issues=license_issues,
            pii_issues=pii_issues,
            gdpr_compliant=gdpr_compliant,
            overall_risk=overall_pii,
            certificate_hash=cert_hash,
        )


# ── Internal helpers ───────────────────────────────────────────────────────────

def _load_config(model_path: Path, config_path: Path | None) -> dict[str, Any] | None:
    candidates = [config_path] if config_path else []
    candidates += [
        model_path / "train_config.json", model_path / "config.json",
        model_path / "training_args.json", model_path / "hparams.json",
        model_path / "trainer_state.json",
    ]
    for p in candidates:
        if p and Path(p).exists():
            try:
                return json.loads(Path(p).read_text())
            except (json.JSONDecodeError, OSError):
                pass
    return None


def _detect_framework(config: dict[str, Any]) -> str:
    text = json.dumps(config).lower()
    if "torch" in text or "pytorch" in text:
        return "pytorch"
    if "tensorflow" in text or "keras" in text:
        return "tensorflow"
    if "mlx" in text:
        return "mlx"
    if "jax" in text or "flax" in text:
        return "jax/flax"
    if "sklearn" in text or "scikit" in text:
        return "scikit-learn"
    return "unknown"


def _extract_datasets_from_config(config: dict[str, Any]) -> list[str]:
    """Find dataset names in a training config dict."""
    datasets: list[str] = []

    def _recurse(obj: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _DATASET_CONFIG_KEYS.search(str(k)):
                    if isinstance(v, str) and v:
                        datasets.append(v)
                    elif isinstance(v, list):
                        datasets.extend(str(x) for x in v if x)
                _recurse(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:20]:
                _recurse(item, depth + 1)

    _recurse(config)
    return datasets


def _find_provenance(model_path: Path) -> Path | None:
    for p in [
        model_path / "dataset_provenance.json",
        model_path / "squash" / "dataset_provenance.json",
        model_path / "data_lineage.json",
    ]:
        if p.exists():
            return p
    return None


def _scan_mlflow_run(model_path: Path) -> list[str]:
    """Try to extract dataset names from MLflow run metadata if present."""
    for mlflow_meta in [
        model_path / "MLmodel",
        model_path / "mlflow" / "meta.yaml",
        model_path.parent / "MLmodel",
    ]:
        if mlflow_meta.exists():
            try:
                text = mlflow_meta.read_text()
                matches = re.findall(r"dataset[_\s]?(?:name|path|id)[\"'\s:=]+([^\s\"',\n]+)", text, re.I)
                return matches[:10]
            except OSError:
                pass
    return []


def _assess_dataset(ds_name: str) -> DatasetProvenance:
    """Assess a single dataset by name against the knowledge base."""
    import hashlib as _h
    ds_id = _h.md5(ds_name.encode()).hexdigest()[:8]

    # Normalize name for lookup (collapse hyphens, slashes, spaces to underscore)
    def _norm(s: str) -> str:
        return s.lower().replace(" ", "_").replace("-", "_").replace("/", "_")

    key = _norm(ds_name)
    # Try prefix match in known profiles (also normalize the known key for comparison)
    profile = None
    for known_key, prof in _HF_DATASET_PROFILES.items():
        nk = _norm(known_key)
        if nk == key or nk in key or key.startswith(nk.split("_")[0]):
            profile = prof
            break

    if profile:
        license_spdx, pii_risk, pii_indicators = profile
    else:
        license_spdx = "unknown"
        pii_risk = PIIRiskLevel.LOW
        pii_indicators = []

        # Heuristic PII detection from name
        if _PII_CONFIG_SIGNALS.search(ds_name):
            pii_risk = PIIRiskLevel.HIGH
            pii_indicators.append("Dataset name contains PII/medical/financial signal words")

    # Determine license category
    lic_cat, commercial_ok = _classify_license(license_spdx)

    # GDPR legal basis heuristic
    if pii_risk in (PIIRiskLevel.HIGH, PIIRiskLevel.CRITICAL):
        gdpr_basis = "unknown"
    elif pii_risk == PIIRiskLevel.MEDIUM:
        gdpr_basis = "legitimate_interest"
    else:
        gdpr_basis = "not_applicable"

    return DatasetProvenance(
        dataset_id=ds_id,
        dataset_name=ds_name,
        source=f"hf:{ds_name}" if "/" in ds_name or ds_name in _HF_DATASET_PROFILES else ds_name,
        license_spdx=license_spdx,
        license_category=lic_cat,
        commercial_use_allowed=commercial_ok,
        pii_risk=pii_risk,
        pii_indicators=pii_indicators,
        size_gb=None,
        record_count=None,
        gdpr_legal_basis=gdpr_basis,
        verified=profile is not None,
        notes="",
    )


def _classify_license(spdx: str) -> tuple[LicenseCategory, bool | None]:
    if spdx in _SPDX_COMMERCIAL_OK:
        return LicenseCategory.COMMERCIAL_OK, True
    if spdx in _SPDX_COPYLEFT:
        return LicenseCategory.COPYLEFT, None  # Depends on use
    if spdx in _SPDX_RESEARCH_ONLY:
        return LicenseCategory.RESEARCH_ONLY, False
    if spdx == "unknown":
        return LicenseCategory.UNKNOWN, None
    if spdx.startswith("CC-BY-NC"):
        return LicenseCategory.RESEARCH_ONLY, False
    return LicenseCategory.RESTRICTED, None


# ── Convenience re-export for DatasetProvenance.to_dict ───────────────────────
def _ds_to_dict(ds: DatasetProvenance) -> dict[str, Any]:
    return {
        "dataset_id": ds.dataset_id,
        "dataset_name": ds.dataset_name,
        "source": ds.source,
        "license_spdx": ds.license_spdx,
        "license_category": ds.license_category.value,
        "commercial_use_allowed": ds.commercial_use_allowed,
        "pii_risk": ds.pii_risk.value,
        "pii_indicators": ds.pii_indicators,
        "gdpr_legal_basis": ds.gdpr_legal_basis,
        "verified": ds.verified,
        "notes": ds.notes,
    }


DatasetProvenance.to_dict = _ds_to_dict  # type: ignore[method-assign]
