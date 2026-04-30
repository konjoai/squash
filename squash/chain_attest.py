"""squash/chain_attest.py — Composite chain / pipeline attestation engine.

The EU AI Act regulates the deployed system, not individual model weights.
A modern AI system is a *chain* — a RAG pipeline (retriever → embedder →
LLM), a tool-using agent (LLM + tools), or a multi-LLM ensemble (parallel
branches → aggregator). Squash must attest the whole chain as a single
unit and roll up policy posture worst-case across components.

This module is the core composite engine. Per-component attestation
delegates to :class:`squash.attest.AttestPipeline`; this module sequences
the work, aggregates results, computes the worst-case composite score,
and produces a single signed ``ChainAttestation`` record.

Composite score semantics
-------------------------
- Each attestable component contributes a score in [0, 100] derived from
  the per-policy ``error_count`` (0 errors → 100; cap drops 25 points per
  error policy and 5 points per warning policy).
- ``composite_score`` is the **minimum** of all attestable component
  scores. Worst-case roll-up is the only honest answer for compliance:
  a chain is no more compliant than its weakest link.
- ``composite_passed`` is ``True`` iff every attestable component passed.
  External (non-attestable) components are recorded but excluded from
  the pass/fail roll-up — they show up in the report so reviewers can
  apply their own judgement.

Signing
-------
``ChainAttestation`` is signed with HMAC-SHA256 over its canonical JSON
serialisation. The signing key defaults to a deterministic local key
derived from the chain_id; callers in production should pass an
explicit ``signing_key`` (e.g. a secret read from KMS or env). The
signature roots the composite record so downstream consumers can detect
tampering of any component result without re-running attestation.

Stdlib-only — no external dependencies. PyYAML is used opportunistically
in :func:`load_chain_spec` when present; JSON is the always-supported
input format.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ── Vocabulary ───────────────────────────────────────────────────────────────


class ChainKind(str, Enum):
    """Topology of the chain. Strings match LangChain / LlamaIndex idioms."""

    SEQUENCE = "sequence"   # Linear LLM chain (prompt → LLM → parser)
    RAG = "rag"             # Retriever + embedder + LLM
    AGENT = "agent"         # LLM + tool-belt
    ENSEMBLE = "ensemble"   # Parallel LLMs whose outputs are merged
    CUSTOM = "custom"       # Anything else


class ComponentRole(str, Enum):
    """The functional role of a component in the chain."""

    LLM = "llm"
    EMBEDDING = "embedding"
    RETRIEVER = "retriever"
    TOOL = "tool"
    GUARDRAIL = "guardrail"
    EXTERNAL = "external"   # Third-party API (OpenAI, Anthropic) — non-attestable


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class ChainComponent:
    """Description of one element of a chain.

    Attributes
    ----------
    name:
        Unique identifier within the chain (used for edges & rollup).
    role:
        :class:`ComponentRole` value as a string.
    model_path:
        Filesystem path to the model artefact. ``None`` for external
        components (third-party APIs) and pure-tool components.
    model_id:
        Display identifier (e.g. ``"meta-llama/Llama-3.1-8B"``).
        Defaults to the basename of ``model_path`` when not provided.
    metadata:
        Free-form dict for component-specific data — vector store kind,
        tool description, LangChain class name, etc.
    external:
        ``True`` for components that cannot be attested locally
        (third-party API endpoints). Recorded in the chain attestation
        but skipped during per-component attestation.
    """

    name: str
    role: str
    model_path: Path | None = None
    model_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    external: bool = False

    def __post_init__(self) -> None:
        if self.model_path is not None and not isinstance(self.model_path, Path):
            self.model_path = Path(self.model_path)
        if not self.model_id:
            if self.model_path is not None:
                self.model_id = self.model_path.name
            else:
                self.model_id = self.name

    @property
    def attestable(self) -> bool:
        """A component is attestable iff it has a model_path and is not external."""
        return self.model_path is not None and not self.external

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "model_path": str(self.model_path) if self.model_path else None,
            "model_id": self.model_id,
            "metadata": self.metadata,
            "external": self.external,
        }


@dataclass
class ChainSpec:
    """Declarative description of a chain — components + topology."""

    chain_id: str
    kind: str = ChainKind.CUSTOM.value
    components: list[ChainComponent] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.chain_id:
            raise ValueError("chain_id is required")
        names = [c.name for c in self.components]
        if len(set(names)) != len(names):
            raise ValueError(f"Duplicate component names in chain {self.chain_id}")
        # Edges must reference known components
        valid = set(names)
        for a, b in self.edges:
            if a not in valid or b not in valid:
                raise ValueError(f"Edge ({a},{b}) references unknown component")

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "kind": self.kind,
            "components": [c.to_dict() for c in self.components],
            "edges": [list(e) for e in self.edges],
            "metadata": self.metadata,
        }


@dataclass
class ComponentAttestation:
    """Per-component result wrapped with its role / skip context."""

    component: ChainComponent
    passed: bool = False
    score: int = 0
    error_count: int = 0
    warning_count: int = 0
    policy_results: dict[str, str] = field(default_factory=dict)  # policy → "PASS"/"FAIL"
    attestation_id: str = ""
    skipped: bool = False
    skipped_reason: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component.to_dict(),
            "passed": self.passed,
            "score": self.score,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "policy_results": self.policy_results,
            "attestation_id": self.attestation_id,
            "skipped": self.skipped,
            "skipped_reason": self.skipped_reason,
            "error": self.error,
        }


@dataclass
class ChainAttestation:
    """Composite signed chain attestation record.

    The single source of truth for the compliance posture of the *whole*
    pipeline. ``composite_score`` is the worst-case roll-up across
    attestable components; ``composite_passed`` is ``True`` only when
    every attestable component passed.
    """

    chain_id: str
    kind: str
    generated_at: str
    spec: ChainSpec
    components: list[ComponentAttestation]
    composite_score: int
    composite_passed: bool
    policy_rollup: dict[str, str] = field(default_factory=dict)
    external_components: list[str] = field(default_factory=list)
    signature: str = ""
    signature_alg: str = "HMAC-SHA256"
    squash_version: str = "chain_attest_v1"

    # ── Serialisation ─────────────────────────────────────────────────────

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "squash_version": self.squash_version,
            "chain_id": self.chain_id,
            "kind": self.kind,
            "generated_at": self.generated_at,
            "spec": self.spec.to_dict(),
            "components": [c.to_dict() for c in self.components],
            "composite_score": self.composite_score,
            "composite_passed": self.composite_passed,
            "policy_rollup": self.policy_rollup,
            "external_components": self.external_components,
        }
        if include_signature:
            d["signature"] = self.signature
            d["signature_alg"] = self.signature_alg
        return d

    def canonical_json(self) -> str:
        """Deterministic JSON serialisation used for signing."""
        return json.dumps(self.to_dict(include_signature=False), sort_keys=True)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        """Human-readable executive summary."""
        status = "✅ PASS" if self.composite_passed else "❌ FAIL"
        lines = [
            f"# Chain Attestation — {self.chain_id}",
            "",
            f"**Status:** {status}  ",
            f"**Kind:** `{self.kind}`  ",
            f"**Composite score:** {self.composite_score}/100  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Signature ({self.signature_alg}):** `{self.signature[:24]}…`",
            "",
            "## Components",
            "",
            "| Name | Role | Model | Status | Score | Errors | Warnings |",
            "|---|---|---|---|---|---|---|",
        ]
        for c in self.components:
            comp = c.component
            if c.skipped:
                status_cell = f"⊘ {c.skipped_reason or 'skipped'}"
                score_cell = "—"
                err_cell = "—"
                warn_cell = "—"
            else:
                status_cell = "✅" if c.passed else "❌"
                score_cell = str(c.score)
                err_cell = str(c.error_count)
                warn_cell = str(c.warning_count)
            lines.append(
                f"| `{comp.name}` | {comp.role} | `{comp.model_id}` | "
                f"{status_cell} | {score_cell} | {err_cell} | {warn_cell} |"
            )

        if self.policy_rollup:
            lines.extend(["", "## Policy Roll-up (worst-case)", ""])
            lines.append("| Policy | Status |")
            lines.append("|---|---|")
            for pol in sorted(self.policy_rollup.keys()):
                emoji = "✅" if self.policy_rollup[pol] == "PASS" else "❌"
                lines.append(f"| `{pol}` | {emoji} {self.policy_rollup[pol]} |")

        if self.external_components:
            lines.extend(["", "## External (non-attestable) components", ""])
            for name in self.external_components:
                lines.append(f"- `{name}`")
            lines.append(
                "\n*External components are excluded from the composite score. "
                "Apply your own vendor risk review.*"
            )

        return "\n".join(lines) + "\n"

    def save(
        self,
        output_dir: Path | str,
        formats: tuple[str, ...] = ("json", "md"),
        stem: str = "chain-attest",
    ) -> dict[str, Path]:
        """Write the attestation in JSON and/or Markdown form.

        Returns a dict mapping format to written Path.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}

        if "json" in formats:
            p = output_dir / f"{stem}.json"
            p.write_text(self.to_json(), encoding="utf-8")
            written["json"] = p
        if "md" in formats:
            p = output_dir / f"{stem}.md"
            p.write_text(self.to_markdown(), encoding="utf-8")
            written["md"] = p
        return written


# ── Pipeline ─────────────────────────────────────────────────────────────────


@dataclass
class ChainAttestConfig:
    """Configuration for a chain attestation run."""

    spec: ChainSpec
    policies: list[str] = field(default_factory=lambda: ["enterprise-strict"])
    output_dir: Path | None = None
    signing_key: bytes = b""
    fail_on_component_violation: bool = False
    sign_components: bool = False
    """Whether to Sigstore-sign each component BOM during per-component attest."""


class ChainAttestPipeline:
    """Run composite chain attestation.

    Stateless — every call to :meth:`run` produces a fresh
    :class:`ChainAttestation`.
    """

    @staticmethod
    def run(config: ChainAttestConfig) -> ChainAttestation:
        spec = config.spec
        components: list[ComponentAttestation] = []
        external_names: list[str] = []

        for comp in spec.components:
            if not comp.attestable:
                reason = (
                    "external (third-party API)" if comp.external
                    else f"no model_path for role={comp.role}"
                )
                components.append(ComponentAttestation(
                    component=comp,
                    skipped=True,
                    skipped_reason=reason,
                ))
                if comp.external:
                    external_names.append(comp.name)
                continue

            comp_result = _attest_component(comp, config)
            components.append(comp_result)
            if config.fail_on_component_violation and not comp_result.passed:
                # We still finish the report so the user has full diagnostic
                # info — the failure surfaces via composite_passed.
                log.warning(
                    "chain_attest: component %s failed and "
                    "fail_on_component_violation=True", comp.name,
                )

        composite_score = _composite_score(components)
        composite_passed = _composite_passed(components)
        policy_rollup = _policy_rollup(components, config.policies)

        attestation = ChainAttestation(
            chain_id=spec.chain_id,
            kind=spec.kind,
            generated_at=_utc_now_iso(),
            spec=spec,
            components=components,
            composite_score=composite_score,
            composite_passed=composite_passed,
            policy_rollup=policy_rollup,
            external_components=external_names,
        )

        # Sign the attestation
        attestation.signature = _sign(attestation, config.signing_key)

        # Persist if requested
        if config.output_dir:
            attestation.save(config.output_dir)

        return attestation


# ── Helpers ──────────────────────────────────────────────────────────────────


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _attest_component(
    comp: ChainComponent,
    config: ChainAttestConfig,
) -> ComponentAttestation:
    """Run AttestPipeline for one component and convert to ComponentAttestation."""
    # Lazy import to keep chain_attest importable in environments where
    # the heavyweight attest pipeline is missing some optional deps.
    from squash.attest import AttestConfig, AttestPipeline

    if comp.model_path is None:
        return ComponentAttestation(
            component=comp, skipped=True, skipped_reason="no model_path",
        )

    if not comp.model_path.exists():
        return ComponentAttestation(
            component=comp, skipped=True,
            skipped_reason=f"model_path does not exist: {comp.model_path}",
            error=f"model_path does not exist: {comp.model_path}",
        )

    attest_out = (
        config.output_dir / "components" / comp.name
        if config.output_dir else None
    )
    cfg = AttestConfig(
        model_path=comp.model_path,
        output_dir=attest_out,
        model_id=comp.model_id,
        policies=list(config.policies),
        sign=config.sign_components,
        fail_on_violation=False,  # never bail mid-chain
    )

    try:
        result = AttestPipeline.run(cfg)
    except Exception as exc:  # noqa: BLE001 — surface attestation errors verbatim
        log.warning("chain_attest: attestation failed for %s — %s", comp.name, exc)
        return ComponentAttestation(
            component=comp, skipped=False, passed=False,
            error=str(exc),
        )

    err_count = sum(p.error_count for p in result.policy_results.values())
    warn_count = sum(p.warning_count for p in result.policy_results.values())
    score = _component_score(result.policy_results, scan_passed=result.passed)
    policy_results = {
        name: ("PASS" if r.passed else "FAIL")
        for name, r in result.policy_results.items()
    }

    return ComponentAttestation(
        component=comp,
        passed=result.passed,
        score=score,
        error_count=err_count,
        warning_count=warn_count,
        policy_results=policy_results,
        attestation_id=result.model_id,
    )


def _component_score(
    policy_results: dict[str, Any],
    scan_passed: bool,
) -> int:
    """Convert per-policy results into a 0–100 score.

    Mathematical formulation:
        score = 100
              − 25 × Σ(error_findings, error policies)
              −  5 × Σ(warning_findings, all policies)
              − 50 × (1 if scan failed)
        clipped to [0, 100]
    """
    score = 100
    for r in policy_results.values():
        score -= 25 * r.error_count
        score -= 5 * r.warning_count
    if not scan_passed:
        score -= 50
    return max(0, min(100, score))


def _composite_score(components: list[ComponentAttestation]) -> int:
    """Worst-case roll-up. Skipped components do not contribute."""
    scores = [c.score for c in components if not c.skipped]
    if not scores:
        return 0
    return min(scores)


def _composite_passed(components: list[ComponentAttestation]) -> bool:
    """Composite passes only when every attestable component passed."""
    attestable = [c for c in components if not c.skipped]
    if not attestable:
        return False  # No verifiable attestation = not passed
    return all(c.passed for c in attestable)


def _policy_rollup(
    components: list[ComponentAttestation],
    policies: list[str],
) -> dict[str, str]:
    """For each policy, return PASS iff every attestable component passed it."""
    out: dict[str, str] = {}
    attestable = [c for c in components if not c.skipped]
    for pol in policies:
        if not attestable:
            out[pol] = "FAIL"
            continue
        all_pass = all(c.policy_results.get(pol) == "PASS" for c in attestable)
        out[pol] = "PASS" if all_pass else "FAIL"
    return out


def _sign(attestation: ChainAttestation, key: bytes) -> str:
    """HMAC-SHA256 over the canonical JSON form of the attestation.

    When *key* is empty, a deterministic per-chain key is derived from
    ``chain_id`` so the signature is still stable across runs and
    detects tampering. Production deployments should pass an explicit
    signing key from KMS / env.
    """
    if not key:
        key = hashlib.sha256(
            f"squash:chain:{attestation.chain_id}".encode("utf-8")
        ).digest()
    msg = attestation.canonical_json().encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_signature(
    attestation: ChainAttestation, key: bytes = b"",
) -> bool:
    """Recompute and constant-time compare the HMAC signature.

    Returns ``True`` iff the stored signature matches what we'd compute
    now over the same payload — i.e. nothing in the record has been
    tampered with.
    """
    expected = _sign(attestation, key)
    return hmac.compare_digest(expected, attestation.signature or "")


# ── Spec loaders ─────────────────────────────────────────────────────────────


def load_chain_spec(path: Path | str) -> ChainSpec:
    """Load a :class:`ChainSpec` from JSON or YAML.

    YAML is parsed via PyYAML when available; otherwise the file must be
    JSON. The expected schema is::

        {
          "chain_id": "rag-prod-v1",
          "kind": "rag",
          "components": [
            {"name": "embedder", "role": "embedding",
             "model_path": "./bge-small"},
            {"name": "llm", "role": "llm",
             "model_path": "./llama-3.1-8b"}
          ],
          "edges": [["embedder", "llm"]],
          "metadata": {}
        }
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    raw = _parse_spec_text(text, path.suffix.lower())
    return _spec_from_dict(raw)


def _parse_spec_text(text: str, suffix: str) -> dict[str, Any]:
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "YAML chain spec requires PyYAML. Install with: pip install pyyaml. "
                "Alternatively, convert to JSON."
            ) from exc
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _spec_from_dict(raw: dict[str, Any]) -> ChainSpec:
    if not isinstance(raw, dict):
        raise ValueError("Chain spec must be a mapping")
    components = []
    for c in raw.get("components", []):
        if not isinstance(c, dict):
            raise ValueError(f"Component entry must be a mapping: {c!r}")
        components.append(ChainComponent(
            name=c["name"],
            role=c["role"],
            model_path=Path(c["model_path"]) if c.get("model_path") else None,
            model_id=c.get("model_id", ""),
            metadata=c.get("metadata", {}) or {},
            external=bool(c.get("external", False)),
        ))
    edges_raw = raw.get("edges", []) or []
    edges = [tuple(e) for e in edges_raw if isinstance(e, (list, tuple)) and len(e) == 2]
    return ChainSpec(
        chain_id=raw.get("chain_id") or raw.get("id") or "",
        kind=raw.get("kind", ChainKind.CUSTOM.value),
        components=components,
        edges=edges,
        metadata=raw.get("metadata", {}) or {},
    )


def attestation_from_dict(raw: dict[str, Any]) -> ChainAttestation:
    """Re-hydrate a :class:`ChainAttestation` from its JSON form.

    Used by ``squash chain-attest --verify`` and by downstream consumers
    that want to verify a stored attestation without re-running it.
    """
    spec = _spec_from_dict(raw["spec"])
    components: list[ComponentAttestation] = []
    for c in raw.get("components", []):
        comp_raw = c.get("component", c)
        comp = ChainComponent(
            name=comp_raw["name"],
            role=comp_raw["role"],
            model_path=(
                Path(comp_raw["model_path"]) if comp_raw.get("model_path") else None
            ),
            model_id=comp_raw.get("model_id", ""),
            metadata=comp_raw.get("metadata", {}) or {},
            external=bool(comp_raw.get("external", False)),
        )
        components.append(ComponentAttestation(
            component=comp,
            passed=bool(c.get("passed", False)),
            score=int(c.get("score", 0)),
            error_count=int(c.get("error_count", 0)),
            warning_count=int(c.get("warning_count", 0)),
            policy_results=dict(c.get("policy_results", {}) or {}),
            attestation_id=c.get("attestation_id", ""),
            skipped=bool(c.get("skipped", False)),
            skipped_reason=c.get("skipped_reason", ""),
            error=c.get("error", ""),
        ))
    return ChainAttestation(
        chain_id=raw["chain_id"],
        kind=raw.get("kind", ChainKind.CUSTOM.value),
        generated_at=raw.get("generated_at", ""),
        spec=spec,
        components=components,
        composite_score=int(raw.get("composite_score", 0)),
        composite_passed=bool(raw.get("composite_passed", False)),
        policy_rollup=dict(raw.get("policy_rollup", {}) or {}),
        external_components=list(raw.get("external_components", []) or []),
        signature=raw.get("signature", ""),
        signature_alg=raw.get("signature_alg", "HMAC-SHA256"),
        squash_version=raw.get("squash_version", "chain_attest_v1"),
    )


__all__ = [
    "ChainKind",
    "ComponentRole",
    "ChainComponent",
    "ChainSpec",
    "ComponentAttestation",
    "ChainAttestation",
    "ChainAttestConfig",
    "ChainAttestPipeline",
    "load_chain_spec",
    "attestation_from_dict",
    "verify_signature",
]
