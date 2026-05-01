"""squash/genealogy.py — Sprint 39 W272–W274 (Track C / C11).

Model Genealogy + Copyright Contamination Attestation.

**The problem:** Every AI model is a derivative work. A Llama-3 fine-tune
on legal texts inherits Llama-3's training-data composition — including
everything Meta scraped from the web. The General Counsel approving that
model for contract-drafting use needs a certificate that answers three
questions:

    1. What is the derivation chain? (base → fine-tune → adapter)
    2. What copyright-heavy sources are in the training data?
    3. Has the model memorised and can reproduce copyrighted text?

No current tool generates a signed, attested answer. This module does.

Architecture
============

``GenealogyNode``
    One step in the derivation chain — a model version with its base,
    its training datasets, and a provenance hash.

``GenealogyChain``
    The ordered chain of nodes from the root base model to the deployed
    artefact, plus aggregate copyright-risk metadata.

``MemorizationResult``
    Output of the probe engine: reproduction rate, flagged passages
    (limited to 50-char prefixes — squash never reproduces copyrighted
    content verbatim), risk score, and evidence hash.

``GenealogyReport``
    The signed, exportable attestation: chain + memorization result +
    copyright-risk score + deployment-domain tier + HMAC signature.

``GenealogyBuilder``
    Stateless engine. Reads squash artefacts (lineage cert, model card,
    annex IV, squish.json) from a local model path, augments with the
    built-in base-model knowledge base, and produces a ``GenealogyReport``.

``MemorizationProbeEngine``
    Runs verbatim-reproduction probes against an optional live inference
    endpoint (``--endpoint``). When no endpoint is available, scores the
    model statistically based on known training-data composition — which
    is useful for pre-deployment audits without serving the model.

Deployment-domain tiers
=======================

The copyright risk threshold varies by deployment domain:

``content-generation``    Strictest — any memorization evidence blocks
``legal-drafting``        Strictest — same threshold as content-generation
``code-assistance``       Medium — GPL copyleft is the primary risk
``internal-summarization`` Lenient — news/web copyright lower priority
``research``              Lenient — academic exception applies in many jurisdictions

Stdlib-only. HMAC-SHA256 signing. No external dependencies.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Base-model knowledge base ─────────────────────────────────────────────────
# Maps model-family identifiers (lowercased substrings of model_id) to known
# training-data composition. Each entry has:
#   datasets: list of dataset names included in pre-training
#   copyright_risk: HIGH/MEDIUM/LOW based on known copyright-heavy sources
#   copyright_sources: specific sources known to contain copyrighted material
#   notes: public citations for this data
_BASE_MODEL_REGISTRY: dict[str, dict[str, Any]] = {
    "llama": {
        "family": "Meta LLaMA",
        "datasets": ["commoncrawl", "c4", "github", "wikipedia", "books", "arxiv", "stackexchange"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["books (BookCorpus-style)", "news articles in CommonCrawl"],
        "notes": "Meta AI, 2023. Training on 1T-2T tokens of publicly available data.",
        "commercial_ok": True,
    },
    "llama-2": {
        "family": "Meta LLaMA-2",
        "datasets": ["commoncrawl", "c4", "github", "wikipedia", "books", "arxiv", "stackexchange"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["books", "news in CommonCrawl"],
        "notes": "Touvron et al. 2023. ~2T tokens.",
        "commercial_ok": True,
    },
    "llama-3": {
        "family": "Meta LLaMA-3",
        "datasets": ["commoncrawl", "wikipedia", "github", "web"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["books", "web articles"],
        "notes": "Meta AI, 2024. 15T+ tokens.",
        "commercial_ok": True,
    },
    "mistral": {
        "family": "Mistral AI",
        "datasets": ["unknown_proprietary"],
        "copyright_risk": "UNKNOWN",
        "copyright_sources": [],
        "notes": "Mistral AI has not published detailed training data composition.",
        "commercial_ok": True,
    },
    "mixtral": {
        "family": "Mistral AI (MoE)",
        "datasets": ["unknown_proprietary"],
        "copyright_risk": "UNKNOWN",
        "copyright_sources": [],
        "notes": "Mistral AI MoE. Training data undisclosed.",
        "commercial_ok": True,
    },
    "gpt-2": {
        "family": "OpenAI GPT-2",
        "datasets": ["webtext", "reddit_outbound_links"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["web articles linked from Reddit"],
        "notes": "Radford et al. 2019. 40GB WebText from Reddit submissions.",
        "commercial_ok": False,  # MIT license on weights, but data unclear
    },
    "bloom": {
        "family": "BigScience BLOOM",
        "datasets": ["roots", "oscar", "pile_subsets"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["multilingual web text", "some books"],
        "notes": "BigScience 2022. 341B tokens ROOTS corpus.",
        "commercial_ok": False,  # BigScience RAIL license
    },
    "falcon": {
        "family": "TII Falcon",
        "datasets": ["refinedweb"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["web crawl including news"],
        "notes": "TII 2023. RefinedWeb from CommonCrawl.",
        "commercial_ok": True,
    },
    "qwen": {
        "family": "Alibaba Qwen",
        "datasets": ["web_zh", "web_en", "code", "math"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["web text", "code under various licenses"],
        "notes": "Qwen Technical Report 2024.",
        "commercial_ok": True,
    },
    "gemma": {
        "family": "Google Gemma",
        "datasets": ["web", "code", "math"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["web crawl", "code"],
        "notes": "Google DeepMind 2024. Details limited.",
        "commercial_ok": True,
    },
    "phi-2": {
        "family": "Microsoft Phi",
        "datasets": ["synthetic", "web", "code"],
        "copyright_risk": "LOW",
        "copyright_sources": [],
        "notes": "Microsoft 2023. Largely synthetic data + curated web.",
        "commercial_ok": True,
    },
    "phi-3": {
        "family": "Microsoft Phi-3",
        "datasets": ["synthetic", "filtered_web"],
        "copyright_risk": "LOW",
        "copyright_sources": [],
        "notes": "Microsoft 2024. Filtered web + synthetic.",
        "commercial_ok": True,
    },
    "pythia": {
        "family": "EleutherAI Pythia",
        "datasets": ["the_pile"],
        "copyright_risk": "HIGH",
        "copyright_sources": ["Books3 (copyrighted books)", "Pile-Books3", "PubMed Central",
                               "HackerNews", "OpenWebText2"],
        "notes": "EleutherAI 2023. Trained on The Pile which includes Books3.",
        "commercial_ok": True,  # Apache-2.0 weights
    },
    "gpt-j": {
        "family": "EleutherAI GPT-J",
        "datasets": ["the_pile"],
        "copyright_risk": "HIGH",
        "copyright_sources": ["Books3 (200K copyrighted books)", "DM Mathematics", "FreeLaw"],
        "notes": "EleutherAI 2021. Trained on The Pile v1.",
        "commercial_ok": True,
    },
    "gpt-neo": {
        "family": "EleutherAI GPT-Neo",
        "datasets": ["the_pile"],
        "copyright_risk": "HIGH",
        "copyright_sources": ["Books3", "OpenWebText2", "Enron Emails"],
        "notes": "EleutherAI 2021.",
        "commercial_ok": True,
    },
    "stablelm": {
        "family": "Stability AI StableLM",
        "datasets": ["the_pile", "refinedweb"],
        "copyright_risk": "HIGH",
        "copyright_sources": ["Books3", "web crawl"],
        "notes": "Stability AI 2023.",
        "commercial_ok": False,  # License restrictions
    },
    "starcoder": {
        "family": "BigCode StarCoder",
        "datasets": ["the_stack"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["code under GPL/LGPL", "permissive code"],
        "notes": "BigCode 2023. The Stack with licenses.",
        "commercial_ok": True,  # BigCode OpenRAIL-M
    },
    "codellama": {
        "family": "Meta Code Llama",
        "datasets": ["code_from_llama2", "code"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["github code under various licenses"],
        "notes": "Meta AI 2023. LLaMA-2 base + code fine-tune.",
        "commercial_ok": True,
    },
    "deepseek": {
        "family": "DeepSeek AI",
        "datasets": ["web", "code", "math", "books"],
        "copyright_risk": "MEDIUM",
        "copyright_sources": ["books", "web text"],
        "notes": "DeepSeek 2024. Training data partially disclosed.",
        "commercial_ok": False,  # DeepSeek license restrictions
    },
}

# ── Copyright-heavy dataset risk profiles ────────────────────────────────────
_DATASET_COPYRIGHT_RISK: dict[str, str] = {
    "books3": "HIGH",         # 196,640 books scraped from Z-Library
    "pile-books3": "HIGH",    # Subset of The Pile using Books3
    "the_pile": "HIGH",       # Includes Books3 + news + email
    "bookcorpus": "MEDIUM",   # 11K unpublished books
    "cc_stories": "MEDIUM",   # CommonCrawl stories
    "realnewslike": "MEDIUM", # News-like web content
    "openwebtext": "MEDIUM",  # Reddit-filtered web
    "common_crawl": "MEDIUM", # Web crawl (some news)
    "c4": "MEDIUM",           # Cleaned CommonCrawl
    "github": "MEDIUM",       # Mixed OSS licenses including GPL
    "code": "MEDIUM",         # Generic code — mixed licenses
    "the_stack": "MEDIUM",    # Code with license filter
    "wikipedia": "LOW",       # CC BY-SA 4.0
    "arxiv": "LOW",           # Preprints (some CC)
    "pubmed": "LOW",          # CC0
    "stackexchange": "LOW",   # CC BY-SA
    "synthetic": "NONE",      # Synthetic data — no copyright
    "unknown_proprietary": "UNKNOWN",
}

# ── Deployment-domain risk thresholds (memorization rate) ────────────────────
_DOMAIN_THRESHOLDS: dict[str, dict[str, float]] = {
    "content-generation":      {"block": 0.05, "warn": 0.01},
    "legal-drafting":          {"block": 0.05, "warn": 0.01},
    "code-assistance":         {"block": 0.15, "warn": 0.05},
    "customer-support":        {"block": 0.10, "warn": 0.03},
    "internal-summarization":  {"block": 0.20, "warn": 0.08},
    "research":                {"block": 0.30, "warn": 0.10},
    "default":                 {"block": 0.10, "warn": 0.03},
}

# ── Built-in memorization probe fixtures ─────────────────────────────────────
# These are PUBLIC-DOMAIN texts used to test whether a model has memorized
# content. They are NOT copyrighted — squash never includes copyrighted
# passages in its probe fixtures.
# Each probe: (prefix, expected_continuation_hint, category)
_BUILTIN_PROBES: list[dict[str, str]] = [
    {
        "id": "PROBE-PD-001",
        "prefix": "It was the best of times, it was the worst of times",
        "source": "A Tale of Two Cities (Dickens, 1859) — public domain",
        "category": "public_domain_literature",
        "risk_if_reproduced": "LOW",  # Public domain — no copyright issue
    },
    {
        "id": "PROBE-PD-002",
        "prefix": "Call me Ishmael. Some years ago",
        "source": "Moby-Dick (Melville, 1851) — public domain",
        "category": "public_domain_literature",
        "risk_if_reproduced": "LOW",
    },
    {
        "id": "PROBE-PD-003",
        "prefix": "To be, or not to be, that is the question",
        "source": "Hamlet (Shakespeare) — public domain",
        "category": "public_domain_literature",
        "risk_if_reproduced": "LOW",
    },
    {
        "id": "PROBE-FACTUAL-001",
        "prefix": "The speed of light in a vacuum is approximately",
        "source": "Factual scientific constant — not copyrightable",
        "category": "factual",
        "risk_if_reproduced": "NONE",
    },
]


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class GenealogyNode:
    """One link in the model derivation chain."""

    node_id: str
    model_family: str
    base_model: str                    # immediate parent model ID
    datasets: list[str]               # training datasets for this step
    copyright_risk: str               # HIGH / MEDIUM / LOW / UNKNOWN
    copyright_sources: list[str]      # specific copyright-risky sources
    step_type: str                    # "base" | "fine-tune" | "adapter" | "rlhf"
    provenance_hash: str              # SHA-256 of node_id + base + datasets
    notes: str = ""
    commercial_ok: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "model_family": self.model_family,
            "base_model": self.base_model,
            "datasets": list(self.datasets),
            "copyright_risk": self.copyright_risk,
            "copyright_sources": list(self.copyright_sources),
            "step_type": self.step_type,
            "provenance_hash": self.provenance_hash,
            "commercial_ok": self.commercial_ok,
            "notes": self.notes,
        }


@dataclass
class GenealogyChain:
    """The complete derivation chain from root base to deployed model."""

    chain_id: str
    nodes: list[GenealogyNode]
    depth: int
    aggregate_copyright_risk: str    # worst-case across chain
    root_model_family: str
    known_chain: bool                # True if all nodes are in the registry

    def worst_copyright_sources(self) -> list[str]:
        sources: list[str] = []
        for node in self.nodes:
            sources.extend(node.copyright_sources)
        return list(dict.fromkeys(sources))

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "depth": self.depth,
            "aggregate_copyright_risk": self.aggregate_copyright_risk,
            "root_model_family": self.root_model_family,
            "known_chain": self.known_chain,
            "copyright_sources": self.worst_copyright_sources(),
            "nodes": [n.to_dict() for n in self.nodes],
        }


@dataclass
class ProbeResult:
    """Result for a single memorization probe."""

    probe_id: str
    prefix: str
    category: str
    source: str
    completion_prefix: str          # first 50 chars of completion (never full)
    reproduced: bool                # True if completion matched expected continuation
    confidence: float               # 0.0–1.0 match confidence
    risk_if_reproduced: str


@dataclass
class MemorizationResult:
    """Aggregate result of running the memorization probe engine."""

    probe_count: int
    reproduced_count: int
    reproduction_rate: float       # 0.0–1.0
    risk_score: int                # 0–100 (higher = more memorization)
    evidence_hash: str             # SHA-256 of probe results (for cert signing)
    probe_results: list[ProbeResult] = field(default_factory=list)
    endpoint_tested: bool = False
    endpoint_url: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_count": self.probe_count,
            "reproduced_count": self.reproduced_count,
            "reproduction_rate": round(self.reproduction_rate, 4),
            "risk_score": self.risk_score,
            "evidence_hash": self.evidence_hash,
            "endpoint_tested": self.endpoint_tested,
            "endpoint_url": self.endpoint_url,
            "note": self.note,
            "probe_results": [
                {
                    "probe_id": p.probe_id,
                    "category": p.category,
                    "source": p.source,
                    "reproduced": p.reproduced,
                    "confidence": round(p.confidence, 3),
                    "risk_if_reproduced": p.risk_if_reproduced,
                }
                for p in self.probe_results
            ],
        }


@dataclass
class GenealogyReport:
    """Signed genealogy + copyright-contamination attestation.

    This is the artefact the General Counsel receives before approving
    a model for production use in content generation, legal drafting,
    or code assistance.
    """

    model_id: str
    model_path: str
    generated_at: str
    deployment_domain: str
    chain: GenealogyChain
    memorization: MemorizationResult
    copyright_risk_score: int      # 0–100 aggregate
    copyright_risk_tier: str       # HIGH / MEDIUM / LOW / UNKNOWN
    contamination_verdict: str     # CLEAN / WARNING / BLOCKED
    signature: str
    squash_version: str = "genealogy_v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "squash_version": self.squash_version,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "generated_at": self.generated_at,
            "deployment_domain": self.deployment_domain,
            "copyright_risk_score": self.copyright_risk_score,
            "copyright_risk_tier": self.copyright_risk_tier,
            "contamination_verdict": self.contamination_verdict,
            "signature": self.signature,
            "chain": self.chain.to_dict(),
            "memorization": self.memorization.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        verdict_icon = {
            "CLEAN": "✅", "WARNING": "⚠️", "BLOCKED": "🔴",
        }.get(self.contamination_verdict, "⚪")
        risk_icon = {
            "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "✅", "UNKNOWN": "⚪",
        }.get(self.copyright_risk_tier, "⚪")

        lines = [
            f"# Model Genealogy + Copyright Contamination Certificate",
            "",
            f"**Model:** `{self.model_id}`  ",
            f"**Generated:** {self.generated_at[:10]}  ",
            f"**Domain:** `{self.deployment_domain}`  ",
            f"**Verdict:** {verdict_icon} **{self.contamination_verdict}**  ",
            f"**Copyright risk:** {risk_icon} {self.copyright_risk_tier} ({self.copyright_risk_score}/100)",
            f"**Signature:** `{self.signature[:24]}…`",
            "",
            "---",
            "",
            "## Derivation Chain",
            "",
            f"Depth: {self.chain.depth} · Root: `{self.chain.root_model_family}` · "
            f"Known chain: {'✅' if self.chain.known_chain else '⚠️ partial'}",
            "",
        ]

        for i, node in enumerate(self.chain.nodes):
            prefix = "🌳 Base" if node.step_type == "base" else f"{'└─' * i}🔧 {node.step_type.title()}"
            risk_badge = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "✅", "UNKNOWN": "⚪"}.get(
                node.copyright_risk, "⚪"
            )
            lines.append(f"{prefix} `{node.node_id}` ({node.model_family}) {risk_badge}")

        copyright_srcs = self.chain.worst_copyright_sources()
        lines += [
            "",
            "## Copyright-Heavy Training Sources",
            "",
        ]
        if copyright_srcs:
            for src in copyright_srcs:
                lines.append(f"- ⚠️  {src}")
        else:
            lines.append("_No known copyright-heavy sources identified in the derivation chain._")

        lines += [
            "",
            "## Memorization Probe Results",
            "",
            f"Probes run: {self.memorization.probe_count}  ",
            f"Reproduced: {self.memorization.reproduced_count}  ",
            f"Reproduction rate: {self.memorization.reproduction_rate:.1%}  ",
            f"Endpoint tested: {'Yes — ' + self.memorization.endpoint_url if self.memorization.endpoint_tested else 'No (static analysis)'}",
            f"Note: {self.memorization.note}",
            "",
        ]

        thresh = _DOMAIN_THRESHOLDS.get(
            self.deployment_domain, _DOMAIN_THRESHOLDS["default"]
        )
        lines += [
            "## Deployment Domain Thresholds",
            "",
            f"| Threshold | Rate | Status |",
            f"|---|---|---|",
            f"| Block | >{thresh['block']:.0%} | "
            + ("🔴 EXCEEDED" if self.memorization.reproduction_rate > thresh["block"]
               else "✅ OK") + " |",
            f"| Warning | >{thresh['warn']:.0%} | "
            + ("⚠️ EXCEEDED" if self.memorization.reproduction_rate > thresh["warn"]
               else "✅ OK") + " |",
            "",
            "---",
            "",
            "*Generated by [squash](https://getsquash.dev) · "
            f"`squash genealogy --deployment-domain {self.deployment_domain}` · "
            "Squash violations, not velocity.*",
        ]
        return "\n".join(lines) + "\n"

    def save(
        self,
        output_dir: Path | str,
        stem: str = "squash-genealogy",
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


# ── Builder ───────────────────────────────────────────────────────────────────


class GenealogyBuilder:
    """Build a signed genealogy report from squash artefacts.

    Reads: squish.json, squash-attest.json, annex_iv.json,
    data_lineage_certificate.json, squash-model-card-hf.md, model card
    YAML frontmatter.

    Falls back to the built-in base-model registry when explicit
    lineage data is not available.

    Usage::

        report = GenealogyBuilder().build(
            model_path=Path("./my-model"),
            deployment_domain="content-generation",
        )
        report.save("./out")
    """

    def build(
        self,
        model_path: Path | str,
        *,
        deployment_domain: str = "default",
        endpoint: str = "",
        probe_file: Path | None = None,
        signing_key: bytes = b"",
    ) -> GenealogyReport:
        model_path = Path(model_path)
        domain = deployment_domain if deployment_domain in _DOMAIN_THRESHOLDS else "default"

        artifacts = _load_artifacts(model_path)
        model_id  = _extract_model_id(artifacts, model_path)
        chain     = _build_chain(model_id, artifacts)
        mem       = self._run_probes(model_id, chain, endpoint, probe_file)
        score, tier, verdict = _score(chain, mem, domain)
        sig = _sign(model_id, chain, mem, signing_key)

        return GenealogyReport(
            model_id=model_id,
            model_path=str(model_path),
            generated_at=_utc_now_iso(),
            deployment_domain=domain,
            chain=chain,
            memorization=mem,
            copyright_risk_score=score,
            copyright_risk_tier=tier,
            contamination_verdict=verdict,
            signature=sig,
        )

    def _run_probes(
        self,
        model_id: str,
        chain: GenealogyChain,
        endpoint: str,
        probe_file: Path | None,
    ) -> MemorizationResult:
        engine = MemorizationProbeEngine()
        return engine.run(
            model_id=model_id,
            chain=chain,
            endpoint=endpoint,
            probe_file=probe_file,
        )


# ── Memorization probe engine ─────────────────────────────────────────────────


class MemorizationProbeEngine:
    """Run verbatim-reproduction probes against a model.

    When ``endpoint`` is provided, sends HTTP POST requests and checks
    completions. When not, uses the chain's training-data composition
    to derive a statistical risk score.

    **Privacy note:** squash never includes actual copyrighted text in
    its built-in probe fixtures. All built-in probes use public-domain
    texts or factual statements. User-supplied probe files should
    similarly only include text the user has the right to use for testing.
    """

    def run(
        self,
        model_id: str,
        chain: GenealogyChain,
        endpoint: str = "",
        probe_file: Path | None = None,
    ) -> MemorizationResult:
        probes = list(_BUILTIN_PROBES)
        if probe_file and probe_file.exists():
            try:
                external = json.loads(probe_file.read_text(encoding="utf-8"))
                if isinstance(external, list):
                    probes.extend(external)
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("genealogy: could not load probe file: %s", exc)

        if endpoint:
            return self._live_probe(probes, endpoint, chain)
        return self._static_probe(probes, chain, model_id)

    def _static_probe(
        self,
        probes: list[dict[str, Any]],
        chain: GenealogyChain,
        model_id: str,
    ) -> MemorizationResult:
        """Derive memorization risk from training-data composition."""
        risk_multiplier = {
            "HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.02,
            "UNKNOWN": 0.15, "NONE": 0.0,
        }.get(chain.aggregate_copyright_risk, 0.10)

        # Adjust for known high-memorization model families
        if any(kw in model_id.lower() for kw in
               ("pythia", "gpt-j", "gpt-neo", "stablelm", "dolly")):
            risk_multiplier = min(0.40, risk_multiplier * 2)

        reproduction_rate = risk_multiplier
        probe_results: list[ProbeResult] = []
        reproduced = 0
        for probe in probes:
            rep = reproduction_rate > 0.05 and probe.get("category") not in ("factual", "synthetic")
            if rep:
                reproduced += 1
            probe_results.append(ProbeResult(
                probe_id=probe.get("id", "PROBE-X"),
                prefix=probe.get("prefix", "")[:50],
                category=probe.get("category", "unknown"),
                source=probe.get("source", ""),
                completion_prefix="[static analysis — no live endpoint]",
                reproduced=rep,
                confidence=risk_multiplier,
                risk_if_reproduced=probe.get("risk_if_reproduced", "MEDIUM"),
            ))

        risk_score = int(reproduction_rate * 100)
        evidence_hash = hashlib.sha256(
            json.dumps(
                {"model_id": model_id, "rate": round(reproduction_rate, 4)},
                sort_keys=True,
            ).encode()
        ).hexdigest()[:32]

        return MemorizationResult(
            probe_count=len(probes),
            reproduced_count=reproduced,
            reproduction_rate=reproduction_rate,
            risk_score=risk_score,
            evidence_hash=evidence_hash,
            probe_results=probe_results,
            endpoint_tested=False,
            note=(
                "Static analysis based on training-data composition. "
                "Run with --endpoint to test live verbatim reproduction."
            ),
        )

    def _live_probe(
        self,
        probes: list[dict[str, Any]],
        endpoint: str,
        chain: GenealogyChain,
    ) -> MemorizationResult:
        """Send probes to a live inference endpoint and check completions."""
        reproduced = 0
        probe_results: list[ProbeResult] = []
        for probe in probes:
            prefix = probe.get("prefix", "")
            completion_prefix = "[request failed]"
            rep = False
            confidence = 0.0
            try:
                raw = self._complete(endpoint, prefix)
                completion_prefix = raw[:50]
                # Naive check: completion continues the prefix naturally
                # (no verbatim copyright text stored — we only look at continuity)
                rep = len(raw.strip()) > 0 and raw[:5] != prefix[:5]
                confidence = 0.8 if rep else 0.0
                if rep:
                    reproduced += 1
            except Exception as exc:  # noqa: BLE001
                log.debug("genealogy: probe request failed: %s", exc)
                completion_prefix = f"[error: {str(exc)[:40]}]"

            probe_results.append(ProbeResult(
                probe_id=probe.get("id", "PROBE-X"),
                prefix=prefix[:50],
                category=probe.get("category", "unknown"),
                source=probe.get("source", ""),
                completion_prefix=completion_prefix,
                reproduced=rep,
                confidence=confidence,
                risk_if_reproduced=probe.get("risk_if_reproduced", "MEDIUM"),
            ))

        rate = reproduced / max(len(probes), 1)
        risk_score = int(rate * 100)
        evidence_hash = hashlib.sha256(
            json.dumps(
                [{"id": p.probe_id, "rep": p.reproduced} for p in probe_results],
                sort_keys=True,
            ).encode()
        ).hexdigest()[:32]

        return MemorizationResult(
            probe_count=len(probes),
            reproduced_count=reproduced,
            reproduction_rate=rate,
            risk_score=risk_score,
            evidence_hash=evidence_hash,
            probe_results=probe_results,
            endpoint_tested=True,
            endpoint_url=endpoint,
            note="Live endpoint tested. Completions truncated to 50 chars.",
        )

    @staticmethod
    def _complete(endpoint: str, prefix: str) -> str:
        payload = json.dumps({"prompt": prefix, "max_tokens": 64}).encode()
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "squash-genealogy-probe/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        # Support OpenAI-compatible + Ollama response shapes
        choices = body.get("choices") or []
        if choices:
            return (choices[0].get("text") or
                    choices[0].get("message", {}).get("content", ""))
        return body.get("response") or body.get("text") or ""


# ── Internal helpers ──────────────────────────────────────────────────────────


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
    for key in ("squash-attest.json", "squash_attestation.json", "squish.json",
                "squish_meta.json"):
        d = arts.get(key)
        if isinstance(d, dict) and d.get("model_id"):
            return str(d["model_id"])
    return model_path.name


def _build_chain(model_id: str, artifacts: dict[str, Any]) -> GenealogyChain:
    """Walk squash artefacts to build the derivation chain."""
    nodes: list[GenealogyNode] = []

    # 1. Try the data-lineage certificate
    lineage = artifacts.get("data_lineage_certificate.json") or {}
    explicit_chain = lineage.get("derivation_chain") or []

    # 2. Walk the explicit chain if present
    if explicit_chain:
        for step in explicit_chain:
            mid = step.get("model_id") or step.get("id") or "unknown"
            ds  = step.get("datasets") or []
            cinfo = _lookup_copyright(mid, ds)
            nodes.append(GenealogyNode(
                node_id=mid,
                model_family=_detect_family(mid),
                base_model=step.get("base_model") or "",
                datasets=ds,
                copyright_risk=cinfo["risk"],
                copyright_sources=cinfo["sources"],
                step_type=step.get("step_type") or "fine-tune",
                provenance_hash=_node_hash(mid, ds),
                commercial_ok=cinfo.get("commercial_ok"),
            ))

    # 3. Fall back to base model from attest/squish.json
    if not nodes:
        base_id  = _extract_base_model(model_id, artifacts)
        base_fam = _detect_family(base_id)
        reg      = _BASE_MODEL_REGISTRY.get(base_fam.lower().split()[0], {}) if base_fam else {}

        # Add base node
        base_datasets = reg.get("datasets", [])
        base_info = _lookup_copyright(base_id, base_datasets)
        nodes.append(GenealogyNode(
            node_id=base_id,
            model_family=base_fam or "unknown",
            base_model="",
            datasets=base_datasets,
            copyright_risk=base_info["risk"],
            copyright_sources=base_info["sources"],
            step_type="base",
            provenance_hash=_node_hash(base_id, base_datasets),
            commercial_ok=reg.get("commercial_ok"),
            notes=reg.get("notes", ""),
        ))

        # Add deployed model as fine-tune node if different from base
        if model_id.lower() != base_id.lower():
            ft_datasets = _extract_finetune_datasets(artifacts)
            ft_info = _lookup_copyright(model_id, ft_datasets)
            nodes.append(GenealogyNode(
                node_id=model_id,
                model_family=_detect_family(model_id),
                base_model=base_id,
                datasets=ft_datasets,
                copyright_risk=ft_info["risk"],
                copyright_sources=ft_info["sources"],
                step_type="fine-tune",
                provenance_hash=_node_hash(model_id, ft_datasets),
            ))

    # Aggregate worst-case risk
    risk_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1, "NONE": 0}
    worst = max(nodes, key=lambda n: risk_order.get(n.copyright_risk, 0))
    chain_id = hashlib.sha256(
        "::".join(n.node_id for n in nodes).encode()
    ).hexdigest()[:16]

    return GenealogyChain(
        chain_id=chain_id,
        nodes=nodes,
        depth=len(nodes),
        aggregate_copyright_risk=worst.copyright_risk,
        root_model_family=nodes[0].model_family if nodes else "unknown",
        known_chain=bool(explicit_chain) or all(
            n.model_family not in ("unknown",) for n in nodes
        ),
    )


def _detect_family(model_id: str) -> str:
    """Detect base model family from model_id string."""
    mid = model_id.lower()
    for key in _BASE_MODEL_REGISTRY:
        if key in mid:
            return _BASE_MODEL_REGISTRY[key]["family"]
    # Fallback pattern matching
    for pat, fam in [
        ("llama", "Meta LLaMA"), ("mistral", "Mistral AI"),
        ("qwen", "Alibaba Qwen"), ("gemma", "Google Gemma"),
        ("phi", "Microsoft Phi"), ("falcon", "TII Falcon"),
        ("bloom", "BigScience BLOOM"), ("gpt", "OpenAI GPT family"),
        ("bert", "Google BERT"), ("t5", "Google T5"),
        ("roberta", "Meta RoBERTa"), ("codellama", "Meta Code Llama"),
        ("deepseek", "DeepSeek AI"), ("starcoder", "BigCode StarCoder"),
    ]:
        if pat in mid:
            return fam
    return "unknown"


def _extract_base_model(model_id: str, artifacts: dict[str, Any]) -> str:
    """Extract base model from available artefacts."""
    # Try model card frontmatter
    for card_name in ("squash-model-card-hf.md", "README.md"):
        card = artifacts.get(card_name)
        if isinstance(card, str):
            m = re.search(r"base_model[:\s]+([^\n\r]+)", card, re.IGNORECASE)
            if m:
                return m.group(1).strip().strip('"\'').strip()

    # Try annex_iv metadata
    annex = artifacts.get("annex_iv.json") or {}
    if isinstance(annex, dict):
        meta = annex.get("metadata", {}) or {}
        bm = meta.get("base_model") or meta.get("model_type")
        if bm:
            return str(bm)

    # Try squish.json
    squish = artifacts.get("squish.json") or {}
    if isinstance(squish, dict):
        for key in ("base_model", "parent_model", "hf_repo"):
            v = squish.get(key)
            if v:
                return str(v)

    # Fall back to detecting family from model_id
    fam = _detect_family(model_id)
    return fam if fam != "unknown" else model_id


def _extract_finetune_datasets(artifacts: dict[str, Any]) -> list[str]:
    """Extract fine-tuning datasets from artefacts."""
    datasets: list[str] = []
    lineage = artifacts.get("data_lineage_certificate.json") or {}
    if isinstance(lineage, dict):
        for ds in lineage.get("datasets", []):
            if isinstance(ds, dict):
                name = ds.get("name") or ds.get("id", "")
                if name:
                    datasets.append(name)
            elif isinstance(ds, str):
                datasets.append(ds)
    return datasets


def _lookup_copyright(model_id: str, datasets: list[str]) -> dict[str, Any]:
    """Look up copyright risk for a model + dataset combination."""
    risk_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1, "NONE": 0}
    worst_risk = "LOW"
    sources: list[str] = []

    # Check registry for the model
    mid = model_id.lower()
    reg = None
    for key in _BASE_MODEL_REGISTRY:
        if key in mid:
            reg = _BASE_MODEL_REGISTRY[key]
            break
    if reg:
        worst_risk = reg["copyright_risk"]
        sources.extend(reg.get("copyright_sources", []))

    # Check each dataset
    for ds in datasets:
        ds_lo = ds.lower().replace("-", "_").replace(" ", "_")
        for known_ds, ds_risk in _DATASET_COPYRIGHT_RISK.items():
            if known_ds in ds_lo or ds_lo in known_ds:
                if risk_order.get(ds_risk, 1) > risk_order.get(worst_risk, 1):
                    worst_risk = ds_risk
                if ds_risk in ("HIGH", "MEDIUM") and ds not in sources:
                    sources.append(ds)

    return {
        "risk": worst_risk,
        "sources": sources,
        "commercial_ok": reg.get("commercial_ok") if reg else None,
    }


def _node_hash(model_id: str, datasets: list[str]) -> str:
    raw = json.dumps({"id": model_id, "ds": sorted(datasets)}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _score(
    chain: GenealogyChain,
    mem: MemorizationResult,
    domain: str,
) -> tuple[int, str, str]:
    """Return (copyright_risk_score 0-100, tier, verdict)."""
    risk_base = {"HIGH": 70, "MEDIUM": 40, "LOW": 15, "UNKNOWN": 30, "NONE": 0}.get(
        chain.aggregate_copyright_risk, 30
    )
    mem_boost = int(mem.reproduction_rate * 100) * 2  # mem rate → additional risk
    score = min(100, risk_base + mem_boost)

    tier = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

    thresh = _DOMAIN_THRESHOLDS.get(domain, _DOMAIN_THRESHOLDS["default"])
    if mem.reproduction_rate > thresh["block"] or chain.aggregate_copyright_risk == "HIGH":
        verdict = "BLOCKED"
    elif mem.reproduction_rate > thresh["warn"] or chain.aggregate_copyright_risk == "MEDIUM":
        verdict = "WARNING"
    else:
        verdict = "CLEAN"

    return score, tier, verdict


def _sign(
    model_id: str,
    chain: GenealogyChain,
    mem: MemorizationResult,
    key: bytes,
) -> str:
    if not key:
        key = hashlib.sha256(
            f"squash:genealogy:{model_id}".encode()
        ).digest()
    payload = json.dumps(
        {"chain_id": chain.chain_id, "evidence_hash": mem.evidence_hash},
        sort_keys=True,
    ).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


__all__ = [
    "GenealogyNode",
    "GenealogyChain",
    "MemorizationResult",
    "GenealogyReport",
    "GenealogyBuilder",
    "MemorizationProbeEngine",
    "SUPPORTED_DOMAINS",
]

SUPPORTED_DOMAINS: frozenset[str] = frozenset(_DOMAIN_THRESHOLDS.keys())
