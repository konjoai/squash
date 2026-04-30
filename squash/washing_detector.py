"""squash/washing_detector.py — AI Washing Detection (C2 / W223-W225).

AI washing is the ML equivalent of greenwashing: making specific,
material claims about an AI system's capabilities, safety, compliance,
or fairness that are not supported by — or contradict — verifiable
attestation evidence.

Why this matters legally
------------------------
The SEC's 2026 examination priorities identified AI-related disclosure as
a top-tier enforcement focus. "Operation AI Comply" (2024) already produced
enforcement actions against firms that made material AI capability claims
without adequate basis. Under Rule 10b-5 and related guidance, capability
claims about AI systems in investor materials, product marketing, and
regulatory filings that overstate actual performance are securities fraud
exposure, not just marketing risk.

Key difference from generic false advertising: **specificity and
materiality**. "Our AI is better" is puffery. "Our AI achieves 99.2%
accuracy on MIMIC-III" is a specific factual claim — and if the model
card shows 67.4%, that divergence is a material misstatement.

What this module detects
------------------------
1. **Factual mismatch** — claim makes a specific, measurable assertion
   (accuracy, score, benchmark) that contradicts attestation evidence.

2. **Unsupported claim** — claim type has a known evidence requirement
   (e.g. "EU AI Act compliant" requires a squash attestation showing
   the eu-ai-act framework score ≥ 80 and passed=True) and no such
   evidence is found.

3. **Undocumented superlative** — absolute or comparative claim ("best",
   "world's first", "only solution", "outperforms GPT-4") with no
   verifiable grounding.

4. **Temporal mismatch** — claim about compliance or performance is
   supported by evidence that has expired (attestation older than 90 days
   for rapidly-changing systems).

5. **Scope mismatch** — claim applies to a broader scope than what the
   attestation covers (e.g. "our platform is HIPAA compliant" but the
   attestation covers only one model).

Claim taxonomy
--------------
Each pattern belongs to a ``ClaimType`` which determines what evidence
is required to resolve it. The taxonomy is drawn from:

* SEC AI examination guidance (2026)
* EU AI Act Art. 13 transparency / Art. 52 disclosure requirements
* FTC AI guidance on substantiation
* NIST AI RMF Govern 1.1 — accountability documentation

Architecture
------------
``ClaimExtractor``
    Regex-based pattern matcher over prose text. Returns a list of
    ``ExtractedClaim`` objects with type, raw text, extracted value,
    and confidence score.

``DivergenceEngine``
    Cross-references extracted claims against structured attestation
    evidence (master records, attestation registry, bias audit outputs,
    data lineage). Produces ``WashingFinding`` objects.

``WashingDetector``
    Orchestrate: load docs → extract → cross-reference → report.

Konjo notes
-----------
* 건조 — pure stdlib; no LLM required. Pattern-based extraction is
  deterministic, auditable, and reproducible. An LLM-based extractor
  might have higher recall but would be non-deterministic, unauditable,
  and impossible to test with fixed fixtures.
* ᨀᨚᨐᨚ — every finding names its evidence source. "Claim says X;
  attestation says Y; divergence is Z." An auditor can hand this
  directly to legal counsel.
* 康宙 — read-only; no network calls; works in air-gap environments.
  SEC examinations often happen in restricted network environments.
* 根性 — the claim patterns are conservative: when in doubt, flag as
  UNSUPPORTED rather than FACTUAL_MISMATCH. A false positive costs a
  legal review; a missed material misstatement costs enforcement action.
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Claim taxonomy
# ---------------------------------------------------------------------------

class ClaimType(str, Enum):
    ACCURACY_CLAIM      = "accuracy_claim"       # "achieves X% on Y benchmark"
    COMPLIANCE_CLAIM    = "compliance_claim"      # "EU AI Act compliant", "GDPR compliant"
    SAFETY_CLAIM        = "safety_claim"          # "safe", "no hallucinations", "tested for bias"
    FAIRNESS_CLAIM      = "fairness_claim"        # "unbiased", "fair", "equitable"
    DATA_CLAIM          = "data_claim"            # "trained on X data", "no PII"
    CAPABILITY_CLAIM    = "capability_claim"      # "can summarise", "understands code"
    SECURITY_CLAIM      = "security_claim"        # "secure", "penetration tested", "no backdoors"
    SUPERLATIVE_CLAIM   = "superlative_claim"     # "best", "world's first", "only solution"
    CERTIFICATION_CLAIM = "certification_claim"   # "ISO 42001 certified", "SOC 2 compliant"
    PERFORMANCE_CLAIM   = "performance_claim"     # latency, throughput, cost claims


class FindingType(str, Enum):
    FACTUAL_MISMATCH        = "factual_mismatch"         # claim contradicts evidence
    UNSUPPORTED_CLAIM       = "unsupported_claim"         # claim has no evidence backing
    UNDOCUMENTED_SUPERLATIVE= "undocumented_superlative"  # absolute claim without basis
    TEMPORAL_MISMATCH       = "temporal_mismatch"         # evidence is stale
    SCOPE_MISMATCH          = "scope_mismatch"            # claim scope exceeds evidence scope
    UNVERIFIABLE            = "unverifiable"              # cannot be checked with available data


class FindingSeverity(str, Enum):
    CRITICAL = "critical"   # material misstatement — immediate legal exposure
    HIGH     = "high"       # specific factual claim with no supporting evidence
    MEDIUM   = "medium"     # unsupported superlative or scope gap
    LOW      = "low"        # minor imprecision or unverifiable but plausible
    INFO     = "info"       # claim is supported; documenting for completeness


# ---------------------------------------------------------------------------
# Extracted claim
# ---------------------------------------------------------------------------

@dataclass
class ExtractedClaim:
    """One claim parsed from source prose."""
    claim_type:   ClaimType
    raw_text:     str           # exact text snippet containing the claim
    normalized:   str           # cleaned, lowercase claim text
    value:        str           # extracted quantitative or categorical value
    context:      str           # surrounding sentence for auditor review
    source_file:  str
    line_number:  int
    confidence:   float         # 0.0–1.0; pattern-based → deterministic 1.0 for exact matches

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_type":  self.claim_type.value,
            "raw_text":    self.raw_text,
            "normalized":  self.normalized,
            "value":       self.value,
            "context":     self.context,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "confidence":  self.confidence,
        }


# ---------------------------------------------------------------------------
# Washing finding
# ---------------------------------------------------------------------------

@dataclass
class WashingFinding:
    """One detected AI washing divergence."""
    finding_type:  FindingType
    severity:      FindingSeverity
    title:         str
    description:   str
    claim:         ExtractedClaim
    evidence:      str           # what evidence says (or "no evidence found")
    evidence_source: str         # file or registry entry that provided/lacked evidence
    remediation:   str
    legal_risk:    str           # regulatory/legal exposure summary
    rule_id:       str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":        self.rule_id,
            "finding_type":   self.finding_type.value,
            "severity":       self.severity.value,
            "title":          self.title,
            "description":    self.description,
            "claim":          self.claim.to_dict(),
            "evidence":       self.evidence,
            "evidence_source": self.evidence_source,
            "remediation":    self.remediation,
            "legal_risk":     self.legal_risk,
        }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_SCHEMA = "squash.washing.report/v1"


class OverallVerdict(str, Enum):
    CLEAN    = "clean"    # all claims supported
    LOW      = "low"      # minor issues only
    MEDIUM   = "medium"   # unsupported claims requiring attention
    HIGH     = "high"     # factual mismatches or major gaps
    CRITICAL = "critical" # material misstatements — legal exposure

    def score(self) -> int:
        return {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __lt__(self, other: "OverallVerdict") -> bool:
        return self.score() < other.score()


@dataclass
class WashingReport:
    """Aggregated AI washing detection report."""
    schema:          str
    scanned_at:      str
    doc_paths:       list[str]
    model_id:        str
    verdict:         OverallVerdict
    claims_extracted:int
    findings:        list[WashingFinding]
    supported_claims:list[ExtractedClaim]
    squash_version:  str = "1"

    def passed(self) -> bool:
        return self.verdict in (OverallVerdict.CLEAN, OverallVerdict.LOW)

    def summary(self) -> str:
        icon = "✓" if self.passed() else "✗"
        critical = sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
        high     = sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
        return (
            f"{icon} AI washing scan [{self.model_id}]: {self.verdict.value.upper()} — "
            f"{len(self.findings)} finding(s) ({critical} critical, {high} high), "
            f"{self.claims_extracted} claims extracted"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema":           self.schema,
            "scanned_at":       self.scanned_at,
            "doc_paths":        self.doc_paths,
            "model_id":         self.model_id,
            "verdict":          self.verdict.value,
            "passed":           self.passed(),
            "claims_extracted": self.claims_extracted,
            "findings":         [f.to_dict() for f in self.findings],
            "supported_claims": [c.to_dict() for c in self.supported_claims],
            "squash_version":   self.squash_version,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        icon = "✅" if self.passed() else "❌"
        lines = [
            f"# AI Washing Detection Report — {icon} {self.verdict.value.upper()}",
            "",
            f"**Model:** `{self.model_id}`  ",
            f"**Scanned:** {self.scanned_at[:19]}  ",
            f"**Documents:** {', '.join(Path(p).name for p in self.doc_paths)}  ",
            f"**Claims extracted:** {self.claims_extracted}  "
            f"**Findings:** {len(self.findings)}",
            "",
        ]
        if self.findings:
            lines += ["## Findings", ""]
            for f in self.findings:
                lines += [
                    f"### {f.rule_id} — {f.title} [{f.severity.value.upper()}]",
                    "",
                    f"**Type:** `{f.finding_type.value}`  ",
                    f"**Claim:** \"{f.claim.raw_text}\" *(source: {Path(f.claim.source_file).name}:{f.claim.line_number})*",
                    "",
                    f.description, "",
                    f"**Evidence:** {f.evidence}  ",
                    f"**Evidence source:** `{f.evidence_source}`  ",
                    f"**Legal risk:** {f.legal_risk}  ",
                    f"**Remediation:** {f.remediation}",
                    "",
                ]
        if self.supported_claims:
            lines += [
                "## Supported Claims",
                "",
                "These claims are substantiated by attestation evidence:",
                "",
            ]
            for c in self.supported_claims[:10]:
                lines.append(f"- ✅ `{c.claim_type.value}`: \"{c.raw_text}\"")
            lines.append("")

        lines += [
            "---",
            f"*Generated by [Squash](https://github.com/konjoai/squash) · "
            f"schema `{self.schema}`*",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Claim patterns — the extraction grammar
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClaimPattern:
    """A regex pattern that extracts one claim type from prose."""
    name:       str
    claim_type: ClaimType
    pattern:    re.Pattern
    value_group:int = 1       # capture group index for the extracted value
    confidence: float = 1.0

    def match(self, text: str) -> re.Match | None:
        return self.pattern.search(text)


# Compile once at module load.
# Each pattern is conservative — it targets *specific*, *measurable* claims,
# not vague phrasing. "Our AI is great" is not a testable claim.
_PATTERNS: list[ClaimPattern] = [
    # --- Accuracy / benchmark claims ---
    ClaimPattern("accuracy_percentage",  ClaimType.ACCURACY_CLAIM,
        re.compile(r"\b(\d{1,3}(?:\.\d+)?)\s*%\s+(?:accuracy|precision|recall|f1|auc|auroc)\b", re.I), 1),
    ClaimPattern("benchmark_score",      ClaimType.ACCURACY_CLAIM,
        re.compile(r"\b(?:scores?|achieves?|reaches?|attains?)\s+(\d{1,3}(?:\.\d+)?)\s*%?\s+on\s+([\w\-]+(?:\s+[\w\-]+){0,3})\b", re.I), 1),
    ClaimPattern("benchmark_named",      ClaimType.ACCURACY_CLAIM,
        re.compile(r"\b(?:BIG-bench|MMLU|HellaSwag|TruthfulQA|HumanEval|GSM8K|MATH|ARC|WinoGrande|LAMBADA|BoolQ|COPA|WiC|MultiRC|GLUE|SuperGLUE|SQuAD|TriviaQA|WebQuestions|NaturalQuestions|DROP|RACE|MIMIC|BLEU|ROUGE|METEOR)\b", re.I), 0, 0.9),
    ClaimPattern("error_rate",           ClaimType.ACCURACY_CLAIM,
        re.compile(r"\b(?:(?:error|false\s*positive|false\s*negative|hallucination)\s*rate\s+(?:of\s+|below\s+|under\s+)?(\d{1,3}(?:\.\d+)?)\s*%|(\d{1,3}(?:\.\d+)?)\s*%\s+(?:error\s*rate|false\s*positive|false\s*negative|hallucination\s*rate))\b", re.I), 0),

    # --- Compliance claims ---
    ClaimPattern("eu_ai_act",            ClaimType.COMPLIANCE_CLAIM,
        re.compile(r"\b(?:EU\s*AI\s*Act|European\s*AI\s*Act)\s+(?:compliant|compliance|complies|certified|approved)\b", re.I), 0),
    ClaimPattern("gdpr_compliant",       ClaimType.COMPLIANCE_CLAIM,
        re.compile(r"\bGDPR\s+(?:compliant|compliance|certified|approved)\b", re.I), 0),
    ClaimPattern("hipaa_compliant",      ClaimType.COMPLIANCE_CLAIM,
        re.compile(r"\bHIPAA\s+(?:compliant|compliance|certified|approved)\b", re.I), 0),
    ClaimPattern("sox_compliant",        ClaimType.COMPLIANCE_CLAIM,
        re.compile(r"\bSOX\s+(?:compliant|compliance|certified|approved)\b", re.I), 0),
    ClaimPattern("nist_rmf",             ClaimType.COMPLIANCE_CLAIM,
        re.compile(r"\bNIST\s+(?:AI\s*)?RMF\s+(?:compliant|aligned|certified)\b", re.I), 0),
    ClaimPattern("iso_42001",            ClaimType.CERTIFICATION_CLAIM,
        re.compile(r"\bISO\s*(?:/IEC\s*)?42001\s+(?:certified|compliant|aligned|approved)\b", re.I), 0),
    ClaimPattern("fedramp",              ClaimType.CERTIFICATION_CLAIM,
        re.compile(r"\bFedRAMP\s+(?:authorized|compliant|certified|in\s+process)\b", re.I), 0),
    ClaimPattern("soc2",                 ClaimType.CERTIFICATION_CLAIM,
        re.compile(r"\bSOC\s*2\s+(?:Type\s*II?\s+)?(?:certified|compliant|audited|attested)\b", re.I), 0),

    # --- Safety claims ---
    ClaimPattern("no_hallucinations",    ClaimType.SAFETY_CLAIM,
        re.compile(r"\b(?:no|zero|eliminates?|prevents?|free\s+(?:from|of))\s+hallucinations?\b", re.I), 0),
    ClaimPattern("safe_for_clinical",    ClaimType.SAFETY_CLAIM,
        re.compile(r"\bsafe\s+for\s+(?:clinical|medical|diagnostic|patient|surgical)\s+(?:use|deployment|workflow|application|diagnosis|context)\b", re.I), 0),
    ClaimPattern("bias_tested",          ClaimType.SAFETY_CLAIM,
        re.compile(r"\b(?:bias[- ]?(?:tested|free|mitigated|audited|checked)|tested\s+for\s+bias)\b", re.I), 0),
    ClaimPattern("safe_deployment",      ClaimType.SAFETY_CLAIM,
        re.compile(r"\b(?:safety[- ]?(?:tested|verified|assured|guaranteed)|guaranteed\s+(?:safe|safety))\b", re.I), 0),

    # --- Fairness claims ---
    ClaimPattern("unbiased",             ClaimType.FAIRNESS_CLAIM,
        re.compile(r"\b(?:unbiased|bias[- ]?free|free\s+from\s+bias|no\s+bias|fairness[- ]?(?:certified|tested|guaranteed))\b", re.I), 0),
    ClaimPattern("demographic_parity",   ClaimType.FAIRNESS_CLAIM,
        re.compile(r"\b(?:demographic\s+parity|equal\s+opportunity|equalized\s+odds|disparate\s+impact)\b", re.I), 0),

    # --- Data claims ---
    ClaimPattern("training_data_size",   ClaimType.DATA_CLAIM,
        re.compile(r"(?:trained|fine[- ]tuned|pre[- ]trained)\s+on\s+(\d[\d,.]*\s*(?:M|B|K|million|billion|thousand)?\s*(?:examples?|samples?|tokens?|prompts?|records?|documents?|images?|pairs?))\b", re.I), 1),
    ClaimPattern("no_pii",               ClaimType.DATA_CLAIM,
        re.compile(r"\bno\s+(?:PII|personally\s+identifiable|personal\s+data)\b", re.I), 0),
    ClaimPattern("data_source",          ClaimType.DATA_CLAIM,
        re.compile(r"\b(?:trained|fine[- ]tuned)\s+on\s+(?:only\s+)?([A-Z][A-Za-z0-9\-]+(?:\s+[A-Z][A-Za-z0-9\-]+){0,3})\s+(?:dataset|data|corpus)\b", re.I), 1),
    ClaimPattern("consent_data",         ClaimType.DATA_CLAIM,
        re.compile(r"\b(?:fully\s+)?(?:consented?|licensed|ethically\s+sourced|rights[- ]cleared)\s+(?:training\s+)?(?:data|content|corpus|dataset)\b", re.I), 0),

    # --- Security claims ---
    ClaimPattern("penetration_tested",   ClaimType.SECURITY_CLAIM,
        re.compile(r"\b(?:pen(?:etration)?[- ]?tested?|red[- ]team(?:ed|ing)|security[- ]audited?)\b", re.I), 0),
    ClaimPattern("no_backdoors",         ClaimType.SECURITY_CLAIM,
        re.compile(r"\b(?:no\s+backdoors?|backdoors?[- ]?free|free\s+from\s+backdoors?)\b", re.I), 0),
    ClaimPattern("secure_inference",     ClaimType.SECURITY_CLAIM,
        re.compile(r"\b(?:secure\s+(?:inference|deployment|model|AI)|enterprise[- ]grade\s+security)\b", re.I), 0),

    # --- Superlative claims ---
    ClaimPattern("best_in_class",        ClaimType.SUPERLATIVE_CLAIM,
        re.compile(r"\b(?:best[- ]in[- ]class|state[- ]of[- ]the[- ]art|SOTA|leading\s+model|world['’]?s\s+(?:first|best|only|leading)|industry[- ]leading|unmatched|unparalleled|unprecedented|outperforms?\s+(?:GPT|Claude|Gemini|LLaMA|PaLM|Llama))\b", re.I), 0),
    ClaimPattern("only_solution",        ClaimType.SUPERLATIVE_CLAIM,
        re.compile(r"\b(?:only\s+(?:solution|product|tool|platform|model)|first\s+(?:and\s+only|to\s+(?:achieve|offer|provide|deliver)))\b", re.I), 0),
    ClaimPattern("guaranteed_accuracy",  ClaimType.SUPERLATIVE_CLAIM,
        re.compile(r"\b(?:guaranteed|100\s*%|perfect)\s+(?:accuracy|precision|reliability|uptime|availability)\b", re.I), 0),

    # --- Capability claims (high-stakes domains) ---
    ClaimPattern("medical_diagnosis",    ClaimType.CAPABILITY_CLAIM,
        re.compile(r"\b(?:diagnos(?:es?|ing)|medical\s+(?:advice|diagnosis)|(?:detect|identifies?)\s+(?:cancer|disease|condition|illness))\b", re.I), 0),
    ClaimPattern("legal_advice",         ClaimType.CAPABILITY_CLAIM,
        re.compile(r"\b(?:provides?\s+legal\s+advice|legal\s+(?:guidance|counsel|opinions?))\b", re.I), 0),
    ClaimPattern("financial_advice",     ClaimType.CAPABILITY_CLAIM,
        re.compile(r"\b(?:provides?\s+financial\s+advice|investment\s+(?:recommendations?|guidance)|trading\s+(?:signals?|recommendations?))\b", re.I), 0),
]


# ---------------------------------------------------------------------------
# Claim extractor
# ---------------------------------------------------------------------------

class ClaimExtractor:
    """Extract structured claims from prose text.

    Deterministic, regex-based. Returns ``ExtractedClaim`` objects
    with source location for audit trail.

    Performance note: the pattern set is compiled once at module load;
    per-call cost is O(lines × patterns) ≈ O(n × 28). For a 200-page
    investor deck that is ~2s on a modern CPU — acceptable for a
    compliance tool that runs pre-release, not in hot paths.
    """

    def extract_from_text(self, text: str, source_file: str) -> list[ExtractedClaim]:
        claims: list[ExtractedClaim] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") and len(stripped) < 3:
                continue
            for pat in _PATTERNS:
                m = pat.match(stripped)
                if m:
                    if pat.value_group > 0 and pat.value_group <= len(m.groups()):
                        value = (m.group(pat.value_group) or "").strip()
                    else:
                        value = m.group(0).strip()
                    # Build context: 100 chars around the match
                    start = max(0, m.start() - 60)
                    end   = min(len(stripped), m.end() + 60)
                    context = ("…" if start else "") + stripped[start:end] + ("…" if end < len(stripped) else "")
                    claims.append(ExtractedClaim(
                        claim_type=pat.claim_type,
                        raw_text=m.group(0),
                        normalized=m.group(0).lower().strip(),
                        value=value,
                        context=context,
                        source_file=source_file,
                        line_number=lineno,
                        confidence=pat.confidence,
                    ))
        return claims

    def extract_from_file(self, path: Path) -> list[ExtractedClaim]:
        text = _read_document(path)
        return self.extract_from_text(text, str(path))


def _read_document(path: Path) -> str:
    """Read plain text from Markdown, HTML, or text files.

    PDF and DOCX reading: if pdfminer / python-docx are installed they
    are used; otherwise the file is read as bytes and non-ASCII stripped
    (produces partial but useful text for most PDF decks).
    """
    suffix = path.suffix.lower()
    if suffix in (".md", ".txt", ".rst", ".csv"):
        return path.read_text(errors="replace")
    if suffix == ".html" or suffix == ".htm":
        text = path.read_text(errors="replace")
        # Strip HTML tags
        return re.sub(r"<[^>]+>", " ", text)
    if suffix == ".json":
        try:
            d = json.loads(path.read_text())
            return json.dumps(d, indent=2)
        except Exception:
            return path.read_text(errors="replace")
    if suffix == ".pdf":
        try:
            from pdfminer.high_level import extract_text as pdf_extract  # type: ignore
            return pdf_extract(str(path))
        except ImportError:
            # Fallback: decode as latin-1, strip non-printable
            raw = path.read_bytes()
            return re.sub(r"[^\x20-\x7E\n\t]", " ", raw.decode("latin-1", errors="replace"))
    if suffix in (".docx",):
        try:
            import docx  # type: ignore
            doc = docx.Document(str(path))
            return "\n".join(p.text for p in doc.paragraphs)
        except ImportError:
            pass
    # Fallback: read as text
    return path.read_text(errors="replace")


# ---------------------------------------------------------------------------
# Evidence model
# ---------------------------------------------------------------------------

@dataclass
class AttestationEvidence:
    """Evidence loaded from attestation artefacts for one model."""
    model_id:           str
    overall_score:      float | None = None
    passed:             bool | None  = None
    framework_scores:   dict[str, float] = field(default_factory=dict)
    has_bias_audit:     bool = False
    bias_passed:        bool | None = None
    fairness_metrics:   dict[str, Any] = field(default_factory=dict)
    has_data_lineage:   bool = False
    datasets:           list[str] = field(default_factory=list)
    no_pii_confirmed:   bool | None = None
    has_security_scan:  bool = False
    scan_passed:        bool | None = None
    attestation_age_days: float | None = None   # days since last attestation
    certifications:     list[str] = field(default_factory=list)

    def framework_score(self, fw: str) -> float | None:
        """Return score for *fw* (or its common aliases)."""
        aliases = {
            "eu-ai-act": ["eu-ai-act", "eu_ai_act", "euaiact", "eu ai act"],
            "gdpr":      ["gdpr"],
            "hipaa":     ["hipaa"],
            "nist-ai-rmf": ["nist-ai-rmf", "nist_ai_rmf", "nist ai rmf", "nist-rmf"],
            "iso-42001": ["iso-42001", "iso42001", "iso_42001"],
            "fedramp":   ["fedramp", "fed-ramp"],
            "soc2":      ["soc2", "soc-2"],
        }
        fw_lower = fw.lower()
        for canonical, variants in aliases.items():
            if fw_lower in variants:
                return self.framework_scores.get(canonical) or self.framework_scores.get(fw_lower)
        return self.framework_scores.get(fw_lower)


def load_evidence(
    master_record_path: Path | None = None,
    bias_audit_path: Path | None = None,
    data_lineage_path: Path | None = None,
    model_id: str = "",
) -> AttestationEvidence:
    """Build an ``AttestationEvidence`` from squash output files."""
    ev = AttestationEvidence(model_id=model_id)

    if master_record_path and master_record_path.exists():
        try:
            rec = json.loads(master_record_path.read_text())
            ev.overall_score    = rec.get("overall_score")
            ev.passed           = rec.get("passed")
            ev.framework_scores = rec.get("framework_scores") or {}
            ev.has_security_scan = rec.get("scan_summary") is not None
            scan = rec.get("scan_summary") or {}
            ev.scan_passed      = scan.get("is_safe")
            if not model_id:
                ev.model_id = rec.get("model_id") or rec.get("attestation_id") or ""
            # Age
            gen_at = rec.get("generated_at")
            if gen_at:
                try:
                    dt = datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
                    ev.attestation_age_days = (datetime.now(tz=timezone.utc) - dt).days
                except (ValueError, TypeError):
                    pass
        except Exception as exc:
            log.debug("load_evidence master_record: %s", exc)

    if bias_audit_path and bias_audit_path.exists():
        try:
            d = json.loads(bias_audit_path.read_text())
            ev.has_bias_audit   = True
            ev.bias_passed      = d.get("passed") or d.get("overall_verdict") == "pass"
            ev.fairness_metrics = d.get("attributes") or {}
        except Exception as exc:
            log.debug("load_evidence bias_audit: %s", exc)

    if data_lineage_path and data_lineage_path.exists():
        try:
            d = json.loads(data_lineage_path.read_text())
            ev.has_data_lineage = True
            ev.datasets = [ds.get("dataset_id", "") for ds in d.get("datasets", [])]
            ev.no_pii_confirmed = d.get("pii_risk_level") in ("none", "low")
        except Exception as exc:
            log.debug("load_evidence data_lineage: %s", exc)

    return ev


# ---------------------------------------------------------------------------
# Divergence engine — 12 check rules
# ---------------------------------------------------------------------------

_STALE_ATTESTATION_DAYS = 90   # attestations older than this are considered stale


class DivergenceEngine:
    """Cross-reference extracted claims against attestation evidence."""

    def check(
        self,
        claims: list[ExtractedClaim],
        evidence: AttestationEvidence,
    ) -> tuple[list[WashingFinding], list[ExtractedClaim]]:
        """Return (findings, supported_claims)."""
        findings: list[WashingFinding] = []
        supported: list[ExtractedClaim] = []
        counter = [0]

        def rule_id() -> str:
            counter[0] += 1
            return f"AW-{counter[0]:03d}"

        for claim in claims:
            result = self._check_claim(claim, evidence, rule_id)
            if result is None:
                supported.append(claim)
            elif result is not False:
                findings.append(result)

        # Global staleness check: if any compliance claims present and evidence is stale
        compliance_claims = [c for c in claims if c.claim_type in (
            ClaimType.COMPLIANCE_CLAIM, ClaimType.CERTIFICATION_CLAIM)]
        if compliance_claims and evidence.attestation_age_days is not None:
            if evidence.attestation_age_days > _STALE_ATTESTATION_DAYS:
                for c in compliance_claims[:1]:  # one finding per document
                    findings.append(WashingFinding(
                        finding_type=FindingType.TEMPORAL_MISMATCH,
                        severity=FindingSeverity.HIGH,
                        title="Compliance claim supported by stale attestation",
                        description=(
                            f"The compliance claim \"{c.raw_text}\" is supported by an "
                            f"attestation that is {evidence.attestation_age_days:.0f} days old "
                            f"(threshold: {_STALE_ATTESTATION_DAYS} days). "
                            f"For rapidly evolving AI systems, stale attestations may not "
                            f"reflect current system behaviour."
                        ),
                        claim=c,
                        evidence=f"Attestation age: {evidence.attestation_age_days:.0f} days",
                        evidence_source=str(evidence.model_id),
                        remediation="Re-run `squash attest` to produce a fresh attestation before publishing compliance claims.",
                        legal_risk="SEC AI examination: stale compliance claims may constitute material misstatement if model has changed.",
                        rule_id=rule_id(),
                    ))

        return findings, supported

    def _check_claim(
        self,
        claim: ExtractedClaim,
        ev: AttestationEvidence,
        rule_id_fn,
    ) -> WashingFinding | None | bool:
        """Return:
        - ``WashingFinding`` — a detected divergence
        - ``None``           — claim is supported
        - ``False``          — claim is unverifiable (no evidence to check against)
        """
        ct = claim.claim_type

        # --- Compliance claims ---
        if ct == ClaimType.COMPLIANCE_CLAIM:
            return self._check_compliance(claim, ev, rule_id_fn)

        if ct == ClaimType.CERTIFICATION_CLAIM:
            return self._check_certification(claim, ev, rule_id_fn)

        # --- Accuracy / benchmark claims ---
        if ct == ClaimType.ACCURACY_CLAIM:
            return self._check_accuracy(claim, ev, rule_id_fn)

        # --- Safety claims ---
        if ct == ClaimType.SAFETY_CLAIM:
            return self._check_safety(claim, ev, rule_id_fn)

        # --- Fairness claims ---
        if ct == ClaimType.FAIRNESS_CLAIM:
            return self._check_fairness(claim, ev, rule_id_fn)

        # --- Data claims ---
        if ct == ClaimType.DATA_CLAIM:
            return self._check_data(claim, ev, rule_id_fn)

        # --- Superlative claims ---
        if ct == ClaimType.SUPERLATIVE_CLAIM:
            return self._check_superlative(claim, ev, rule_id_fn)

        # --- Security claims ---
        if ct == ClaimType.SECURITY_CLAIM:
            return self._check_security(claim, ev, rule_id_fn)

        # --- High-stakes capability claims ---
        if ct == ClaimType.CAPABILITY_CLAIM:
            return self._check_capability(claim, ev, rule_id_fn)

        return False   # unverifiable

    def _check_compliance(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        text = claim.normalized
        fw = _map_claim_to_framework(text)
        if fw is None:
            return False   # can't identify which framework

        score = ev.framework_score(fw)
        if score is None:
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.HIGH,
                title=f"Compliance claim without attestation evidence ({fw})",
                description=(
                    f"Claim: \"{claim.raw_text}\"\n"
                    f"No squash attestation found for framework `{fw}`. "
                    f"Compliance claims require a squash attestation with "
                    f"`{fw}` in the framework_scores and `passed=True`."
                ),
                claim=claim,
                evidence=f"No attestation found for framework `{fw}`",
                evidence_source="attestation registry",
                remediation=f"Run `squash attest --policy {fw}` and ensure the score ≥ 80 and passed=True before publishing this claim.",
                legal_risk=f"SEC/EU AI Act: compliance claims without supporting attestation evidence may constitute material misstatement.",
                rule_id=rule_id_fn(),
            )

        min_passing = 80.0
        if score < min_passing:
            return WashingFinding(
                finding_type=FindingType.FACTUAL_MISMATCH,
                severity=FindingSeverity.CRITICAL,
                title=f"Compliance claim contradicts attestation score ({fw}: {score:.1f}/100)",
                description=(
                    f"Claim: \"{claim.raw_text}\"\n"
                    f"Attestation score for `{fw}`: {score:.1f}/100 (minimum for compliance: {min_passing}).\n"
                    f"A score below {min_passing} does not meet the threshold for a compliance assertion."
                ),
                claim=claim,
                evidence=f"{fw} score: {score:.1f}/100 (below {min_passing} threshold)",
                evidence_source="master_record.json → framework_scores",
                remediation=f"Improve {fw} score to ≥{min_passing} and re-attest before publishing compliance claims. Current score: {score:.1f}.",
                legal_risk="CRITICAL: Specific compliance claim directly contradicted by signed attestation evidence. Material misstatement risk under SEC Rule 10b-5 and EU AI Act Art. 13.",
                rule_id=rule_id_fn(),
            )

        if ev.passed is False:
            return WashingFinding(
                finding_type=FindingType.FACTUAL_MISMATCH,
                severity=FindingSeverity.CRITICAL,
                title=f"Compliance claim contradicts attestation passed=False",
                description=(
                    f"Claim: \"{claim.raw_text}\"\n"
                    f"Attestation for model `{ev.model_id}` has `passed=False` despite "
                    f"a score of {score:.1f}. A failed attestation cannot support a compliance claim."
                ),
                claim=claim,
                evidence=f"passed=False (score={score:.1f})",
                evidence_source="master_record.json",
                remediation="Resolve policy violations in the attestation before publishing compliance claims.",
                legal_risk="Material misstatement: attestation explicitly marks this model as not passing compliance.",
                rule_id=rule_id_fn(),
            )

        return None   # supported

    def _check_certification(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        text = claim.normalized
        fw = _map_claim_to_framework(text)
        if fw is None:
            return False

        score = ev.framework_score(fw)
        if score is None:
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.HIGH,
                title=f"Certification claim without attestation evidence ({fw})",
                description=f"Claim: \"{claim.raw_text}\"\nNo {fw} attestation found.",
                claim=claim,
                evidence=f"No attestation found for {fw}",
                evidence_source="attestation registry",
                remediation=f"Run `squash attest --policy {fw}` to produce supporting evidence.",
                legal_risk="Certification claims without documented evidence may violate FTC substantiation standards.",
                rule_id=rule_id_fn(),
            )
        if score < 80.0:
            return WashingFinding(
                finding_type=FindingType.FACTUAL_MISMATCH,
                severity=FindingSeverity.CRITICAL,
                title=f"Certification claim contradicts score ({fw}: {score:.1f})",
                description=f"Claim: \"{claim.raw_text}\"\n{fw} score: {score:.1f}/100 (below 80 threshold for certification claim).",
                claim=claim,
                evidence=f"{fw} score: {score:.1f}/100",
                evidence_source="master_record.json",
                remediation=f"Score must reach ≥80 before certifying {fw} compliance.",
                legal_risk="Material misstatement: certification claim not supported by attestation evidence.",
                rule_id=rule_id_fn(),
            )
        return None   # supported

    def _check_accuracy(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        # If the claim names a specific number and we have an overall score,
        # flag if the claimed accuracy >> attested score (sanity check).
        num = re.search(r"\b(\d{2,3}(?:\.\d+)?)\s*%", claim.raw_text)
        if num and ev.overall_score is not None:
            claimed_pct = float(num.group(1))
            # Only flag if claimed >95% but attested score <60 — clearly misaligned
            if claimed_pct >= 95.0 and ev.overall_score < 60.0:
                return WashingFinding(
                    finding_type=FindingType.FACTUAL_MISMATCH,
                    severity=FindingSeverity.HIGH,
                    title=f"High accuracy claim vs. low overall compliance score ({ev.overall_score:.1f}/100)",
                    description=(
                        f"Claim: \"{claim.raw_text}\" asserts ≥{claimed_pct}% accuracy.\n"
                        f"Overall attestation score: {ev.overall_score:.1f}/100. "
                        f"A model with an overall compliance score of {ev.overall_score:.1f} "
                        f"is unlikely to achieve {claimed_pct}% on a rigorous benchmark. "
                        f"This divergence warrants further investigation."
                    ),
                    claim=claim,
                    evidence=f"Overall attestation score: {ev.overall_score:.1f}/100",
                    evidence_source="master_record.json",
                    remediation="Provide benchmark test results and methodology alongside the accuracy claim. Ensure claims are substantiated by reproducible evaluations.",
                    legal_risk="Specific benchmark claims without reproducible methodology may violate FTC substantiation rules and SEC AI disclosure guidance.",
                    rule_id=rule_id_fn(),
                )
        if ev.overall_score is None:
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.MEDIUM,
                title="Accuracy claim without attestation baseline",
                description=f"Claim: \"{claim.raw_text}\"\nNo squash attestation score found to cross-reference.",
                claim=claim,
                evidence="No attestation found",
                evidence_source="",
                remediation="Run `squash attest` to establish a performance baseline before publishing accuracy claims.",
                legal_risk="Accuracy claims without supporting evaluation methodology may not meet SEC or FTC substantiation standards.",
                rule_id=rule_id_fn(),
            )
        return None   # can't confirm but not clearly wrong either

    def _check_safety(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        text = claim.normalized
        if "no hallucination" in text or "hallucination-free" in text or "zero hallucination" in text:
            return WashingFinding(
                finding_type=FindingType.UNDOCUMENTED_SUPERLATIVE,
                severity=FindingSeverity.HIGH,
                title="Absolute no-hallucination claim — unsubstantiatable",
                description=(
                    f"Claim: \"{claim.raw_text}\"\n"
                    f"No AI system is hallucination-free in all contexts. "
                    f"This absolute claim is not supportable by any known evaluation methodology "
                    f"and exposes the publisher to material misstatement liability."
                ),
                claim=claim,
                evidence="No methodology can certify zero hallucination across all inputs.",
                evidence_source="known limitation of LLM evaluation science",
                remediation="Replace absolute claim with measured hallucination rate on a specific, named benchmark (e.g. 'TruthfulQA: 67.4%'). Document evaluation methodology.",
                legal_risk="CRITICAL: Absolute safety claims about AI systems with known failure modes are a top-tier SEC AI examination finding.",
                rule_id=rule_id_fn(),
            )
        if "bias" in text:
            if not ev.has_bias_audit:
                return WashingFinding(
                    finding_type=FindingType.UNSUPPORTED_CLAIM,
                    severity=FindingSeverity.HIGH,
                    title="Bias-related safety claim without bias audit evidence",
                    description=f"Claim: \"{claim.raw_text}\"\nNo `squash bias-audit` output found to support this claim.",
                    claim=claim,
                    evidence="No bias audit found",
                    evidence_source="",
                    remediation="Run `squash bias-audit` and reference the audit results in your documentation.",
                    legal_risk="EU AI Act Art. 10/9: bias claims require documented testing methodology and results.",
                    rule_id=rule_id_fn(),
                )
            if ev.bias_passed is False:
                return WashingFinding(
                    finding_type=FindingType.FACTUAL_MISMATCH,
                    severity=FindingSeverity.CRITICAL,
                    title="Bias safety claim contradicts failed bias audit",
                    description=f"Claim: \"{claim.raw_text}\"\nBias audit result: FAIL.",
                    claim=claim,
                    evidence="bias_audit: passed=False",
                    evidence_source="bias_audit.json",
                    remediation="Resolve bias audit findings before publishing bias-related safety claims.",
                    legal_risk="Material misstatement: claiming bias mitigation while bias audit fails.",
                    rule_id=rule_id_fn(),
                )
            return None  # supported by audit

        # Generic safety claim
        if ev.overall_score is not None and ev.overall_score < 60.0:
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.MEDIUM,
                title=f"Safety claim with low overall compliance score ({ev.overall_score:.1f}/100)",
                description=(
                    f"Claim: \"{claim.raw_text}\"\n"
                    f"Overall attestation score is {ev.overall_score:.1f}/100. "
                    f"Safety claims are difficult to substantiate when the overall compliance posture is below 60."
                ),
                claim=claim,
                evidence=f"Overall score: {ev.overall_score:.1f}/100",
                evidence_source="master_record.json",
                remediation="Improve overall compliance posture before making broad safety claims.",
                legal_risk="Broad safety claims with low attestation scores may not meet regulatory substantiation requirements.",
                rule_id=rule_id_fn(),
            )
        return False   # unverifiable generically

    def _check_fairness(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        if not ev.has_bias_audit:
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.HIGH,
                title="Fairness claim without bias audit evidence",
                description=f"Claim: \"{claim.raw_text}\"\nNo `squash bias-audit` output found.",
                claim=claim,
                evidence="No bias audit found",
                evidence_source="",
                remediation="Run `squash bias-audit --protected-attrs gender race age` and cite the results.",
                legal_risk="EU AI Act Art. 10: fairness requires documented testing. NYC Local Law 144: mandatory bias audit for employment AI.",
                rule_id=rule_id_fn(),
            )
        if ev.bias_passed is False:
            return WashingFinding(
                finding_type=FindingType.FACTUAL_MISMATCH,
                severity=FindingSeverity.CRITICAL,
                title="Fairness claim contradicts failed bias audit",
                description=f"Claim: \"{claim.raw_text}\"\nBias audit: FAIL.",
                claim=claim,
                evidence="bias_audit: passed=False",
                evidence_source="bias_audit.json",
                remediation="Resolve bias audit findings before publishing fairness claims.",
                legal_risk="Material misstatement: claiming fairness while bias audit fails.",
                rule_id=rule_id_fn(),
            )
        return None   # supported

    def _check_data(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        text = claim.normalized
        if "no pii" in text or "no personally" in text or "no personal data" in text:
            if not ev.has_data_lineage:
                return WashingFinding(
                    finding_type=FindingType.UNSUPPORTED_CLAIM,
                    severity=FindingSeverity.HIGH,
                    title="No-PII claim without data lineage evidence",
                    description=f"Claim: \"{claim.raw_text}\"\nNo `squash data-lineage` output found to support this claim.",
                    claim=claim,
                    evidence="No data lineage found",
                    evidence_source="",
                    remediation="Run `squash data-lineage` to establish a provenance record before making PII-related claims.",
                    legal_risk="GDPR Art. 13/14: data claims require documented basis. FTC: unsubstantiated PII claims are deceptive trade practice.",
                    rule_id=rule_id_fn(),
                )
            if ev.no_pii_confirmed is False:
                return WashingFinding(
                    finding_type=FindingType.FACTUAL_MISMATCH,
                    severity=FindingSeverity.CRITICAL,
                    title="No-PII claim contradicts data lineage risk assessment",
                    description=f"Claim: \"{claim.raw_text}\"\nData lineage shows PII risk: HIGH/MEDIUM.",
                    claim=claim,
                    evidence="data_lineage: pii_risk_level=HIGH or MEDIUM",
                    evidence_source="data_lineage.json",
                    remediation="Remediate PII risk in training data before publishing no-PII claims.",
                    legal_risk="Material misstatement: PII-absence claim contradicted by documented PII risk assessment.",
                    rule_id=rule_id_fn(),
                )
            return None   # supported
        return False   # other data claims — unverifiable without full lineage

    def _check_superlative(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        text = claim.normalized
        # "100% accuracy" / "guaranteed" are always findings
        if re.search(r"\b(100\s*%|perfect|guaranteed)\b", text, re.I):
            return WashingFinding(
                finding_type=FindingType.UNDOCUMENTED_SUPERLATIVE,
                severity=FindingSeverity.CRITICAL,
                title="Absolute performance guarantee claim",
                description=f"Claim: \"{claim.raw_text}\"\nNo AI system can provide absolute performance guarantees.",
                claim=claim,
                evidence="No evaluation methodology can certify absolute performance.",
                evidence_source="",
                remediation="Replace with measured performance on named benchmarks with documented methodology and confidence intervals.",
                legal_risk="CRITICAL: Absolute guarantee claims about AI systems are SEC examination priorities and FTC deceptive-practice violations.",
                rule_id=rule_id_fn(),
            )
        return WashingFinding(
            finding_type=FindingType.UNDOCUMENTED_SUPERLATIVE,
            severity=FindingSeverity.MEDIUM,
            title="Superlative claim without verifiable basis",
            description=(
                f"Claim: \"{claim.raw_text}\"\n"
                f"This absolute or comparative claim cannot be verified from attestation evidence. "
                f"Superlative claims in AI marketing are a documented FTC and SEC examination concern."
            ),
            claim=claim,
            evidence="No comparative evaluation found in attestation data.",
            evidence_source="",
            remediation="Replace with specific, measured comparisons on named benchmarks with documented test conditions and dates.",
            legal_risk="FTC: comparative claims require substantiation. SEC: superlative AI claims in investor materials require factual basis.",
            rule_id=rule_id_fn(),
        )

    def _check_security(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        if not ev.has_security_scan:
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.HIGH,
                title="Security claim without squash security scan evidence",
                description=f"Claim: \"{claim.raw_text}\"\nNo security scan found in attestation.",
                claim=claim,
                evidence="No security scan found",
                evidence_source="",
                remediation="Run `squash attest` (includes security scanner) or `squash scan` before publishing security claims.",
                legal_risk="Security claims without documented testing basis may violate FTC and SEC disclosure requirements.",
                rule_id=rule_id_fn(),
            )
        if ev.scan_passed is False:
            return WashingFinding(
                finding_type=FindingType.FACTUAL_MISMATCH,
                severity=FindingSeverity.CRITICAL,
                title="Security claim contradicts failed security scan",
                description=f"Claim: \"{claim.raw_text}\"\nSecurity scan: FAIL.",
                claim=claim,
                evidence="scan_summary: is_safe=False",
                evidence_source="master_record.json → scan_summary",
                remediation="Resolve security scan findings before publishing any security claims.",
                legal_risk="Material misstatement: security claim directly contradicted by scan evidence.",
                rule_id=rule_id_fn(),
            )
        return None   # supported

    def _check_capability(self, claim, ev, rule_id_fn) -> WashingFinding | None | bool:
        text = claim.normalized
        # High-stakes domains always flagged for substantiation
        if any(kw in text for kw in ("diagnos", "medical advice", "clinical", "legal advice", "financial advice")):
            return WashingFinding(
                finding_type=FindingType.UNSUPPORTED_CLAIM,
                severity=FindingSeverity.CRITICAL,
                title="High-stakes capability claim requires regulatory validation",
                description=(
                    f"Claim: \"{claim.raw_text}\"\n"
                    f"Capability claims in medical, legal, or financial domains require "
                    f"specific regulatory validation beyond a squash attestation. "
                    f"These claims carry independent regulatory liability."
                ),
                claim=claim,
                evidence="High-stakes domain capability claims are beyond squash's attestation scope.",
                evidence_source="",
                remediation="Obtain appropriate regulatory clearance (FDA 510(k)/De Novo for medical, state bar guidance for legal) before publishing these claims.",
                legal_risk="CRITICAL: Medical/legal/financial AI claims without regulatory clearance carry independent FDA, FTC, and SEC liability.",
                rule_id=rule_id_fn(),
            )
        return False   # other capability claims — unverifiable


def _map_claim_to_framework(text: str) -> str | None:
    """Map claim text to a squash framework key."""
    t = text.lower()
    if "eu ai act" in t or "european ai act" in t:
        return "eu-ai-act"
    if "gdpr" in t:
        return "gdpr"
    if "hipaa" in t:
        return "hipaa"
    if "nist" in t and "rmf" in t:
        return "nist-ai-rmf"
    if "iso" in t and "42001" in t:
        return "iso-42001"
    if "fedramp" in t:
        return "fedramp"
    if "soc" in t and "2" in t:
        return "soc2"
    return None


# ---------------------------------------------------------------------------
# Washing detector — orchestrator
# ---------------------------------------------------------------------------

class WashingDetector:
    """Orchestrate: load docs → extract claims → check against evidence → report."""

    def scan(
        self,
        doc_paths: list[Path],
        evidence: AttestationEvidence | None = None,
        model_id: str = "",
        squash_version: str = "1",
    ) -> WashingReport:
        if evidence is None:
            evidence = AttestationEvidence(model_id=model_id)

        extractor = ClaimExtractor()
        all_claims: list[ExtractedClaim] = []
        for p in doc_paths:
            if p.exists():
                all_claims.extend(extractor.extract_from_file(p))

        engine = DivergenceEngine()
        findings, supported = engine.check(all_claims, evidence)

        sev_map = {
            FindingSeverity.CRITICAL: OverallVerdict.CRITICAL,
            FindingSeverity.HIGH:     OverallVerdict.HIGH,
            FindingSeverity.MEDIUM:   OverallVerdict.MEDIUM,
            FindingSeverity.LOW:      OverallVerdict.LOW,
            FindingSeverity.INFO:     OverallVerdict.LOW,
        }
        verdict = OverallVerdict.CLEAN
        for f in findings:
            v = sev_map[f.severity]
            if v > verdict:
                verdict = v

        return WashingReport(
            schema=_SCHEMA,
            scanned_at=datetime.now(tz=timezone.utc).isoformat(),
            doc_paths=[str(p) for p in doc_paths],
            model_id=model_id or evidence.model_id,
            verdict=verdict,
            claims_extracted=len(all_claims),
            findings=findings,
            supported_claims=supported,
            squash_version=squash_version,
        )


def load_report(path: Path) -> WashingReport:
    d = json.loads(path.read_text())
    findings = []
    for f in d["findings"]:
        c = f["claim"]
        claim = ExtractedClaim(
            claim_type=ClaimType(c["claim_type"]),
            raw_text=c["raw_text"],
            normalized=c["normalized"],
            value=c["value"],
            context=c["context"],
            source_file=c["source_file"],
            line_number=c["line_number"],
            confidence=c["confidence"],
        )
        findings.append(WashingFinding(
            finding_type=FindingType(f["finding_type"]),
            severity=FindingSeverity(f["severity"]),
            title=f["title"],
            description=f["description"],
            claim=claim,
            evidence=f["evidence"],
            evidence_source=f["evidence_source"],
            remediation=f["remediation"],
            legal_risk=f["legal_risk"],
            rule_id=f["rule_id"],
        ))
    supported = []
    for c in d.get("supported_claims", []):
        supported.append(ExtractedClaim(
            claim_type=ClaimType(c["claim_type"]),
            raw_text=c["raw_text"], normalized=c["normalized"],
            value=c["value"], context=c["context"],
            source_file=c["source_file"], line_number=c["line_number"],
            confidence=c["confidence"],
        ))
    return WashingReport(
        schema=d["schema"], scanned_at=d["scanned_at"],
        doc_paths=d["doc_paths"], model_id=d["model_id"],
        verdict=OverallVerdict(d["verdict"]),
        claims_extracted=d["claims_extracted"],
        findings=findings, supported_claims=supported,
        squash_version=d.get("squash_version", "1"),
    )
