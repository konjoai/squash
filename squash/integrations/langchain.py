"""squish.squash.integrations.langchain — LangChain callback for Squash.

Attests the underlying model whenever a LangChain :class:`~langchain.llms.base.LLM`
or :class:`~langchain.chat_models.base.BaseChatModel` is first loaded, then
re-evaluates policy on every generation if ``continuous_audit=True``.

Usage::

    from langchain_community.llms import LlamaCpp
    from squash.integrations.langchain import SquashCallback

    callback = SquashCallback(
        model_path=Path("./llama-3.1-8b.gguf"),
        policies=["eu-ai-act"],
        fail_on_violation=True,
    )

    llm = LlamaCpp(
        model_path="./llama-3.1-8b.gguf",
        callbacks=[callback],
    )
    # First call triggers attestation; subsequent calls are no-ops unless
    # continuous_audit=True.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from squash.attest import AttestConfig, AttestPipeline, AttestResult

log = logging.getLogger(__name__)


class SquashCallback:
    """LangChain callback that attests a model on first use.

    Implements the minimal LangChain callback interface (``on_llm_start``,
    ``on_chat_model_start``) without inheriting from LangChain base classes so
    that squish does not take a hard dependency on the LangChain SDK version.
    When LangChain *is* installed, the callback duck-types as a valid
    :class:`~langchain.callbacks.base.BaseCallbackHandler`.

    Parameters
    ----------
    model_path:
        Path to the model file or directory.
    policies:
        Policies to evaluate on attestation.
    fail_on_violation:
        If ``True``, raises :class:`~squish.squash.attest.AttestationViolationError`
        on policy failure.
    continuous_audit:
        If ``True``, re-runs policy evaluation on every ``on_llm_end`` call
        (expensive; intended for compliance-sensitive pipelines).
    """

    def __init__(
        self,
        model_path: Path,
        *,
        policies: list[str] | None = None,
        fail_on_violation: bool = True,
        continuous_audit: bool = False,
        **attest_kwargs,
    ) -> None:
        self._model_path = model_path
        self._policies = policies or ["enterprise-strict"]
        self._fail_on_violation = fail_on_violation
        self._continuous_audit = continuous_audit
        self._attest_kwargs = attest_kwargs
        self._result: AttestResult | None = None
        self._attested = False

    # ── LangChain callback interface (duck-typed) ─────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Attest on first LLM invocation."""
        self._maybe_attest()

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[Any],
        **kwargs: Any,
    ) -> None:
        """Attest on first chat model invocation."""
        self._maybe_attest()

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Re-attest after generation if continuous_audit is enabled."""
        if self._continuous_audit and self._attested:
            log.debug("Squash continuous audit: re-evaluating policy …")
            self._run_attestation()

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:  # noqa: D401
        """No-op — let LangChain handle LLM errors normally."""

    # ── Property access ───────────────────────────────────────────────────

    @property
    def last_result(self) -> AttestResult | None:
        """The most recent :class:`~squish.squash.attest.AttestResult`, or None."""
        return self._result

    # ── Private ───────────────────────────────────────────────────────────

    def _maybe_attest(self) -> None:
        if not self._attested:
            self._run_attestation()
            self._attested = True

    def _run_attestation(self) -> None:
        config = AttestConfig(
            model_path=self._model_path,
            policies=self._policies,
            fail_on_violation=self._fail_on_violation,
            **self._attest_kwargs,
        )
        self._result = AttestPipeline.run(config)
        log.info(
            "SquashCallback: attestation %s for %s",
            "passed" if self._result.passed else "FAILED",
            self._model_path,
        )


# ── Wave 46 — SquashAuditCallback ─────────────────────────────────────────────

import time as _time  # noqa: E402


class SquashAuditCallback(SquashCallback):
    """LangChain callback that attests *and* writes an audit trail.

    Extends :class:`SquashCallback` by routing every LLM invocation through
    :class:`~squish.squash.governor.AgentAuditLogger`.  Each ``llm_start``
    and ``llm_end`` event is written as an :class:`~squish.squash.governor.AuditEntry`
    with SHA-256 hashes of the prompt / response payload and the measured
    first-token latency.

    The logger defaults to the process-level singleton but callers may supply
    their own ``AgentAuditLogger`` instance for test isolation or custom log
    paths::

        from squash.governor import AgentAuditLogger
        from squash.integrations.langchain import SquashAuditCallback

        logger = AgentAuditLogger(log_path="/var/log/squash/audit.jsonl")
        callback = SquashAuditCallback(
            model_path=Path("./qwen3-8b-q4"),
            session_id="req-abc-123",
            audit_logger=logger,
        )
        llm = LlamaCpp(model_path="...", callbacks=[callback])

    Parameters
    ----------
    session_id:
        A stable identifier for this conversation / request.  Defaults to an
        empty string if not provided.
    audit_logger:
        Supply a custom :class:`~squish.squash.governor.AgentAuditLogger`
        instance.  If *None*, the process-level singleton is used.
    All other parameters are forwarded to :class:`SquashCallback`.
    """

    def __init__(
        self,
        model_path: Path,
        *,
        session_id: str = "",
        audit_logger: "Any | None" = None,
        **kwargs,
    ) -> None:
        super().__init__(model_path, **kwargs)
        self._session_id = session_id
        self._audit_logger = audit_logger
        self._start_ts: float = 0.0

    def _get_logger(self):
        if self._audit_logger is not None:
            return self._audit_logger
        from squash.governor import get_audit_logger, _hash_text  # noqa: F401
        return get_audit_logger()

    # ── LangChain callback overrides ──────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Attest (first call) and log llm_start with hashed prompt."""
        self._start_ts = _time.monotonic()
        self._maybe_attest()
        try:
            from squash.governor import _hash_text
            combined = "\n".join(prompts)
            self._get_logger().append(
                session_id=self._session_id,
                event_type="llm_start",
                model_id=str(self._model_path),
                input_hash=_hash_text(combined),
                metadata={"prompt_count": len(prompts)},
            )
        except Exception as exc:
            log.debug("SquashAuditCallback: llm_start log failed: %s", exc)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[Any],
        **kwargs: Any,
    ) -> None:
        """Attest (first call) and log llm_start for chat model."""
        self._start_ts = _time.monotonic()
        self._maybe_attest()
        try:
            from squash.governor import _hash_text
            combined = str(messages)
            self._get_logger().append(
                session_id=self._session_id,
                event_type="llm_start",
                model_id=str(self._model_path),
                input_hash=_hash_text(combined),
                metadata={"message_count": len(messages)},
            )
        except Exception as exc:
            log.debug("SquashAuditCallback: chat_start log failed: %s", exc)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Log llm_end with hashed output and measured latency."""
        latency_ms = (_time.monotonic() - self._start_ts) * 1000 if self._start_ts else -1.0
        if self._continuous_audit and self._attested:
            log.debug("Squash continuous audit: re-evaluating policy …")
            self._run_attestation()
        try:
            from squash.governor import _hash_text
            output_text = str(getattr(response, "generations", response))
            self._get_logger().append(
                session_id=self._session_id,
                event_type="llm_end",
                model_id=str(self._model_path),
                output_hash=_hash_text(output_text),
                latency_ms=round(latency_ms, 2),
                metadata={
                    "attestation_passed": (
                        self._result.passed if self._result else None
                    ),
                },
            )
        except Exception as exc:
            log.debug("SquashAuditCallback: llm_end log failed: %s", exc)


# ── W196 (Sprint 11) — attest_chain: Runnable graph walker ───────────────────


def attest_chain(
    chain: Any,
    *,
    chain_id: str = "",
    policies: list[str] | None = None,
    output_dir: Path | None = None,
    fail_on_component_violation: bool = False,
    sign_components: bool = False,
    signing_key: bytes = b"",
) -> "Any":
    """Walk a LangChain Runnable graph and produce a composite ChainAttestation.

    The walker introspects the chain duck-style — squash never imports
    LangChain. Detected component shapes:

    * ``RunnableSequence`` (``chain.steps`` or chained via ``|``) →
      ChainKind.SEQUENCE; each step inspected recursively.
    * ``RunnableParallel`` (``chain.steps__`` dict) → ChainKind.ENSEMBLE;
      each branch inspected recursively.
    * RAG retrievers (attribute name contains ``retriever`` or class
      name ends with ``Retriever``) → ComponentRole.RETRIEVER.
    * Embedders (class name ends with ``Embeddings``) →
      ComponentRole.EMBEDDING.
    * LLMs / chat models (has ``model_path`` or ``model_name`` /
      ``model``) → ComponentRole.LLM. ``model_path`` set → attestable;
      otherwise marked ``external=True``.
    * Tool-using agents (``chain.tools`` is iterable) →
      ChainKind.AGENT; each tool a ComponentRole.TOOL component.

    Parameters
    ----------
    chain:
        A LangChain ``Runnable``-like object. Duck-typing only — no
        hard dependency on the LangChain SDK version.
    chain_id:
        Stable identifier; defaults to ``chain.__class__.__name__``.
    policies:
        Policies to evaluate per component.
    output_dir:
        Where to write ``chain-attest.json`` / ``chain-attest.md``.
    fail_on_component_violation:
        Forwarded to :class:`ChainAttestPipeline`.
    sign_components:
        Sigstore-sign each component BOM during attest.
    signing_key:
        HMAC key for the composite signature; defaults to a deterministic
        per-chain key derived from ``chain_id``.

    Returns
    -------
    ChainAttestation
        Composite signed attestation record.
    """
    from squash.chain_attest import (
        ChainAttestConfig,
        ChainAttestPipeline,
        ChainComponent,
        ChainKind,
        ChainSpec,
    )

    chain_id = chain_id or getattr(
        chain, "name", chain.__class__.__name__
    )
    components, edges, kind = _walk_runnable(chain)

    # Make component names unique by suffixing duplicates. Track per-occurrence
    # rename so edges (which reference original names) can be retargeted onto
    # the new unique names.
    seen: dict[str, int] = {}
    deduped: list[ChainComponent] = []
    occurrence: dict[str, list[str]] = {}  # original name → ordered new names
    for idx, c in enumerate(components):
        base = c.name or f"component_{idx}"
        if base in seen:
            seen[base] += 1
            new_name = f"{base}_{seen[base]}"
        else:
            seen[base] = 0
            new_name = base
        occurrence.setdefault(base, []).append(new_name)
        c.name = new_name
        deduped.append(c)

    def _retarget(name: str) -> str | None:
        # Pop the next available rename for this base name (FIFO so edges
        # land on consecutive components in walker-emit order).
        bucket = occurrence.get(name)
        if not bucket:
            # Already an unrenamed name — pass through if it still exists
            return name if any(c.name == name for c in deduped) else None
        return bucket[0]  # peek; reusing names across multiple edges is fine

    fixed_edges: list[tuple[str, str]] = []
    for a, b in edges:
        ra = _retarget(a)
        rb = _retarget(b)
        if ra and rb:
            fixed_edges.append((ra, rb))

    spec = ChainSpec(
        chain_id=chain_id,
        kind=kind.value if hasattr(kind, "value") else str(kind),
        components=deduped,
        edges=fixed_edges,
        metadata={"langchain_class": chain.__class__.__name__},
    )

    cfg = ChainAttestConfig(
        spec=spec,
        policies=policies or ["enterprise-strict"],
        output_dir=output_dir,
        signing_key=signing_key,
        fail_on_component_violation=fail_on_component_violation,
        sign_components=sign_components,
    )
    return ChainAttestPipeline.run(cfg)


def _walk_runnable(chain: Any) -> tuple[list, list, Any]:
    """Recursively walk *chain* and return (components, edges, kind).

    Returns a top-level kind that best describes *chain*. Components are
    flattened — edges describe topology between flattened component
    indices (resolved to names later by the caller).
    """
    from squash.chain_attest import ChainComponent, ChainKind, ComponentRole

    components: list[ChainComponent] = []

    def _add_llm(node: Any, name_hint: str) -> str:
        """Add an LLM component; return its assigned name."""
        model_path = _llm_model_path(node)
        is_external = model_path is None and _looks_like_remote_llm(node)
        comp = ChainComponent(
            name=_first_nonempty(getattr(node, "name", None), name_hint),
            role=ComponentRole.LLM.value,
            model_path=model_path,
            model_id=_llm_model_id(node),
            metadata={"langchain_class": node.__class__.__name__},
            external=is_external,
        )
        components.append(comp)
        return comp.name

    def _add_retriever(node: Any, name_hint: str) -> str:
        comp = ChainComponent(
            name=_first_nonempty(getattr(node, "name", None), name_hint),
            role=ComponentRole.RETRIEVER.value,
            metadata={"langchain_class": node.__class__.__name__},
        )
        components.append(comp)
        return comp.name

    def _add_embedding(node: Any, name_hint: str) -> str:
        model_path = _llm_model_path(node)  # embeddings often expose model_name
        comp = ChainComponent(
            name=_first_nonempty(getattr(node, "name", None), name_hint),
            role=ComponentRole.EMBEDDING.value,
            model_path=model_path,
            model_id=_llm_model_id(node),
            metadata={"langchain_class": node.__class__.__name__},
            external=(model_path is None and _looks_like_remote_llm(node)),
        )
        components.append(comp)
        return comp.name

    def _add_tool(node: Any, name_hint: str) -> str:
        comp = ChainComponent(
            name=_first_nonempty(getattr(node, "name", None), name_hint),
            role=ComponentRole.TOOL.value,
            metadata={
                "langchain_class": node.__class__.__name__,
                "description": getattr(node, "description", "") or "",
            },
        )
        components.append(comp)
        return comp.name

    def _classify_and_add(node: Any, name_hint: str) -> str:
        """Identify the role of *node* and add as component."""
        if _is_retriever(node):
            return _add_retriever(node, name_hint)
        if _is_embedding(node):
            return _add_embedding(node, name_hint)
        if _is_llm(node):
            return _add_llm(node, name_hint)
        if _is_tool(node):
            return _add_tool(node, name_hint)
        # Unknown node — record as guardrail/custom so it shows in the report
        comp = ChainComponent(
            name=_first_nonempty(getattr(node, "name", None), name_hint),
            role="custom",
            metadata={"langchain_class": node.__class__.__name__},
        )
        components.append(comp)
        return comp.name

    edges: list[tuple[str, str]] = []
    kind = _detect_kind(chain)

    # Tool-using agent: chain has .tools and .llm/.agent.llm
    if _is_agent_with_tools(chain):
        llm_node = _agent_llm(chain)
        if llm_node is not None:
            llm_name = _classify_and_add(llm_node, "llm")
        else:
            llm_name = ""
        for i, t in enumerate(getattr(chain, "tools", []) or []):
            tname = _add_tool(t, f"tool_{i}")
            if llm_name:
                edges.append((llm_name, tname))
        return components, edges, ChainKind.AGENT

    # RunnableSequence — chain.steps is a list of runnables
    steps = _runnable_steps(chain)
    if steps:
        prev_name: str | None = None
        for i, step in enumerate(steps):
            sub_comps, sub_edges, _ = _walk_runnable(step)
            offset = len(components)
            components.extend(sub_comps)
            for a, b in sub_edges:
                edges.append((a, b))
            if sub_comps:
                first_name = sub_comps[0].name
                last_name = sub_comps[-1].name
                if prev_name is not None:
                    edges.append((prev_name, first_name))
                prev_name = last_name
        return components, edges, kind

    # RunnableParallel — chain.steps__ is a dict
    branches = _runnable_branches(chain)
    if branches:
        for branch_name, branch in branches.items():
            sub_comps, sub_edges, _ = _walk_runnable(branch)
            for c in sub_comps:
                if not c.name.startswith(branch_name):
                    c.name = f"{branch_name}__{c.name}" if c.name else branch_name
            components.extend(sub_comps)
            edges.extend(sub_edges)
        return components, edges, ChainKind.ENSEMBLE

    # Single node — just classify it
    name_hint = chain.__class__.__name__.lower()
    _classify_and_add(chain, name_hint)
    return components, edges, kind


# ── Duck-type predicates ─────────────────────────────────────────────────────


def _is_llm(node: Any) -> bool:
    cls = node.__class__.__name__
    if cls.endswith("Embeddings") or cls.endswith("Retriever"):
        return False
    if cls.endswith("LLM") or cls.endswith("ChatModel"):
        return True
    if any(cls.startswith(p) for p in ("Chat", "LlamaCpp", "Ollama", "OpenAI", "Anthropic")):
        return True
    if cls.endswith("Tool"):
        return False
    return any(hasattr(node, a) for a in ("model_path", "model_name", "model"))


def _is_retriever(node: Any) -> bool:
    cls = node.__class__.__name__
    if cls.endswith("Retriever"):
        return True
    return hasattr(node, "vectorstore") or hasattr(node, "search_kwargs")


def _is_embedding(node: Any) -> bool:
    cls = node.__class__.__name__
    if cls.endswith("Embeddings"):
        return True
    return hasattr(node, "embed_query") and hasattr(node, "embed_documents")


def _is_tool(node: Any) -> bool:
    cls = node.__class__.__name__
    if cls.endswith("Tool"):
        return True
    if hasattr(node, "name") and hasattr(node, "description") and (
        hasattr(node, "_run") or hasattr(node, "func") or callable(node)
    ):
        return True
    return False


def _is_agent_with_tools(chain: Any) -> bool:
    return bool(getattr(chain, "tools", None)) and (
        getattr(chain, "llm", None) is not None
        or getattr(chain, "agent", None) is not None
    )


def _agent_llm(chain: Any) -> Any:
    if hasattr(chain, "llm") and chain.llm is not None:
        return chain.llm
    agent = getattr(chain, "agent", None)
    if agent is not None and hasattr(agent, "llm"):
        return agent.llm
    return None


def _runnable_steps(chain: Any) -> list:
    """Return the ordered child steps of a RunnableSequence-shaped chain."""
    steps = getattr(chain, "steps", None)
    if isinstance(steps, list) and steps:
        return list(steps)
    # LangChain v0.1+: middle/first/last
    parts: list = []
    if hasattr(chain, "first") and chain.first is not None:
        parts.append(chain.first)
    middle = getattr(chain, "middle", None)
    if isinstance(middle, list):
        parts.extend(middle)
    if hasattr(chain, "last") and getattr(chain, "last") is not None:
        parts.append(chain.last)
    if len(parts) >= 2:
        return parts
    return []


def _runnable_branches(chain: Any) -> dict:
    """Return the dict of branches for a RunnableParallel-shaped chain."""
    for attr in ("steps__", "branches", "runnables"):
        v = getattr(chain, attr, None)
        if isinstance(v, dict) and v:
            return dict(v)
    return {}


def _detect_kind(chain: Any) -> Any:
    from squash.chain_attest import ChainKind
    cls = chain.__class__.__name__
    if "Parallel" in cls or "Ensemble" in cls:
        return ChainKind.ENSEMBLE
    if "Sequence" in cls or "Pipeline" in cls:
        return ChainKind.SEQUENCE
    if "Agent" in cls:
        return ChainKind.AGENT
    if "RAG" in cls.upper() or "Retrieval" in cls:
        return ChainKind.RAG
    return ChainKind.CUSTOM


def _llm_model_path(node: Any) -> Path | None:
    """Extract a filesystem model_path from an LLM-like node, if any."""
    for attr in ("model_path", "model_file", "weights_path"):
        v = getattr(node, attr, None)
        if v:
            p = Path(str(v))
            if p.exists():
                return p
    return None


def _llm_model_id(node: Any) -> str:
    for attr in ("model_id", "model_name", "model"):
        v = getattr(node, attr, None)
        if v:
            return str(v)
    return node.__class__.__name__


def _looks_like_remote_llm(node: Any) -> bool:
    """A node that's clearly a hosted-API LLM (no model_path)."""
    cls = node.__class__.__name__
    return any(
        cls.startswith(p) for p in (
            "ChatOpenAI", "ChatAnthropic", "ChatGoogle", "ChatCohere",
            "ChatBedrock", "OpenAI", "Anthropic", "AzureOpenAI",
            "AzureChatOpenAI", "Bedrock", "Cohere",
        )
    )


def _first_nonempty(*vals: Any) -> str:
    for v in vals:
        if v:
            return str(v)
    return ""
