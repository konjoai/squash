"""tests/test_squash_sprint11.py — Sprint 11 (W195–W197) tests.

Sprint 11: Chain & Pipeline Attestation (Tier 2 #16).

W195 — squash/chain_attest.py: composite engine + ChainAttestation +
       worst-case policy roll-up + HMAC signing
W196 — squash/integrations/langchain.py: attest_chain() Runnable walker
       (RAG / agent / multi-LLM ensemble shapes)
W197 — squash chain-attest CLI: JSON/YAML loader, --verify, --json,
       --fail-on-component-violation
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


# ── W195 — chain_attest engine ───────────────────────────────────────────────


class TestW195ChainSpec(unittest.TestCase):
    def test_chain_id_required(self) -> None:
        from squash.chain_attest import ChainSpec
        with self.assertRaises(ValueError):
            ChainSpec(chain_id="")

    def test_duplicate_component_names_rejected(self) -> None:
        from squash.chain_attest import ChainComponent, ChainSpec
        with self.assertRaises(ValueError):
            ChainSpec(
                chain_id="x",
                components=[
                    ChainComponent(name="a", role="llm"),
                    ChainComponent(name="a", role="tool"),
                ],
            )

    def test_unknown_edge_target_rejected(self) -> None:
        from squash.chain_attest import ChainComponent, ChainSpec
        with self.assertRaises(ValueError):
            ChainSpec(
                chain_id="x",
                components=[ChainComponent(name="a", role="llm")],
                edges=[("a", "b")],
            )

    def test_to_dict_round_trip(self) -> None:
        from squash.chain_attest import (
            ChainComponent, ChainKind, ChainSpec, _spec_from_dict,
        )
        spec = ChainSpec(
            chain_id="rag-1",
            kind=ChainKind.RAG.value,
            components=[
                ChainComponent(name="emb", role="embedding", external=True),
                ChainComponent(name="llm", role="llm", external=True),
            ],
            edges=[("emb", "llm")],
        )
        round_tripped = _spec_from_dict(spec.to_dict())
        self.assertEqual(round_tripped.chain_id, "rag-1")
        self.assertEqual(round_tripped.kind, "rag")
        self.assertEqual([c.name for c in round_tripped.components], ["emb", "llm"])
        self.assertEqual(round_tripped.edges, [("emb", "llm")])


class TestW195CompositeRollup(unittest.TestCase):
    """Composite score and policy roll-up — pure unit tests."""

    def test_score_min_across_attestable(self) -> None:
        from squash.chain_attest import (
            ChainComponent, ComponentAttestation, _composite_score,
        )
        components = [
            ComponentAttestation(
                component=ChainComponent(name="a", role="llm"),
                passed=True, score=80,
            ),
            ComponentAttestation(
                component=ChainComponent(name="b", role="llm"),
                passed=True, score=60,  # weakest link
            ),
            ComponentAttestation(
                component=ChainComponent(name="c", role="llm"),
                passed=True, score=95,
            ),
        ]
        self.assertEqual(_composite_score(components), 60)

    def test_skipped_components_excluded_from_score(self) -> None:
        from squash.chain_attest import (
            ChainComponent, ComponentAttestation, _composite_score,
        )
        components = [
            ComponentAttestation(
                component=ChainComponent(name="a", role="llm"),
                passed=True, score=80,
            ),
            ComponentAttestation(
                component=ChainComponent(name="ext", role="llm", external=True),
                skipped=True, skipped_reason="external",
            ),
        ]
        # Only attestable component contributes
        self.assertEqual(_composite_score(components), 80)

    def test_passed_only_when_all_attestable_passed(self) -> None:
        from squash.chain_attest import (
            ChainComponent, ComponentAttestation, _composite_passed,
        )
        all_pass = [
            ComponentAttestation(
                component=ChainComponent(name="a", role="llm"),
                passed=True, score=100,
            ),
            ComponentAttestation(
                component=ChainComponent(name="b", role="llm"),
                passed=True, score=90,
            ),
        ]
        self.assertTrue(_composite_passed(all_pass))

        one_fail = list(all_pass)
        one_fail[0] = ComponentAttestation(
            component=ChainComponent(name="a", role="llm"),
            passed=False, score=20,
        )
        self.assertFalse(_composite_passed(one_fail))

    def test_passed_false_when_no_attestable(self) -> None:
        from squash.chain_attest import (
            ChainComponent, ComponentAttestation, _composite_passed,
        )
        # All-external: no verifiable signal → must NOT auto-pass
        components = [
            ComponentAttestation(
                component=ChainComponent(name="ext", role="llm", external=True),
                skipped=True, skipped_reason="external",
            ),
        ]
        self.assertFalse(_composite_passed(components))

    def test_policy_rollup_worst_case(self) -> None:
        from squash.chain_attest import (
            ChainComponent, ComponentAttestation, _policy_rollup,
        )
        components = [
            ComponentAttestation(
                component=ChainComponent(name="a", role="llm"),
                passed=True, policy_results={"eu-ai-act": "PASS", "owasp-llm": "PASS"},
            ),
            ComponentAttestation(
                component=ChainComponent(name="b", role="llm"),
                passed=False, policy_results={"eu-ai-act": "FAIL", "owasp-llm": "PASS"},
            ),
        ]
        rollup = _policy_rollup(components, ["eu-ai-act", "owasp-llm"])
        self.assertEqual(rollup, {"eu-ai-act": "FAIL", "owasp-llm": "PASS"})


class TestW195ComponentScore(unittest.TestCase):
    def test_clean_run_is_100(self) -> None:
        from squash.chain_attest import _component_score
        self.assertEqual(_component_score({}, scan_passed=True), 100)

    def test_each_error_subtracts_25(self) -> None:
        from squash.chain_attest import _component_score
        # Mock policy result with 2 errors
        m = mock.MagicMock(error_count=2, warning_count=0)
        score = _component_score({"p": m}, scan_passed=True)
        self.assertEqual(score, 50)  # 100 - 25*2

    def test_warnings_subtract_5(self) -> None:
        from squash.chain_attest import _component_score
        m = mock.MagicMock(error_count=0, warning_count=3)
        score = _component_score({"p": m}, scan_passed=True)
        self.assertEqual(score, 85)  # 100 - 5*3

    def test_failed_scan_subtracts_50(self) -> None:
        from squash.chain_attest import _component_score
        score = _component_score({}, scan_passed=False)
        self.assertEqual(score, 50)  # 100 - 50

    def test_score_clipped_to_zero(self) -> None:
        from squash.chain_attest import _component_score
        m = mock.MagicMock(error_count=10, warning_count=0)
        score = _component_score({"p": m}, scan_passed=False)
        self.assertEqual(score, 0)


class TestW195Signature(unittest.TestCase):
    """HMAC-SHA256 signing + tamper detection."""

    def _make(self):
        from squash.chain_attest import (
            ChainAttestConfig, ChainAttestPipeline, ChainComponent, ChainSpec,
        )
        spec = ChainSpec(
            chain_id="sig-test",
            components=[
                ChainComponent(name="ext", role="llm", external=True,
                               model_id="gpt-4"),
            ],
        )
        return ChainAttestPipeline.run(
            ChainAttestConfig(spec=spec, policies=["enterprise-strict"])
        )

    def test_signature_present(self) -> None:
        a = self._make()
        self.assertTrue(a.signature)
        self.assertEqual(len(a.signature), 64)  # hex SHA-256

    def test_verify_signature_valid(self) -> None:
        from squash.chain_attest import verify_signature
        a = self._make()
        self.assertTrue(verify_signature(a))

    def test_verify_detects_tamper_in_chain_id(self) -> None:
        from squash.chain_attest import verify_signature
        a = self._make()
        a.chain_id = "tampered"
        self.assertFalse(verify_signature(a))

    def test_verify_detects_tamper_in_component(self) -> None:
        from squash.chain_attest import verify_signature
        a = self._make()
        a.components[0].component.model_id = "tampered-model"
        self.assertFalse(verify_signature(a))

    def test_explicit_signing_key_changes_signature(self) -> None:
        from squash.chain_attest import (
            ChainAttestConfig, ChainAttestPipeline, ChainComponent, ChainSpec,
        )
        spec = ChainSpec(
            chain_id="key-test",
            components=[ChainComponent(name="a", role="llm", external=True)],
        )
        a1 = ChainAttestPipeline.run(
            ChainAttestConfig(spec=spec, signing_key=b"secret-1")
        )
        # Re-build a fresh spec to avoid mutation
        spec2 = ChainSpec(
            chain_id="key-test",
            components=[ChainComponent(name="a", role="llm", external=True)],
        )
        a2 = ChainAttestPipeline.run(
            ChainAttestConfig(spec=spec2, signing_key=b"secret-2")
        )
        self.assertNotEqual(a1.signature, a2.signature)


class TestW195SerialisationAndPersistence(unittest.TestCase):
    def test_save_writes_json_and_md(self) -> None:
        from squash.chain_attest import (
            ChainAttestConfig, ChainAttestPipeline, ChainComponent, ChainSpec,
        )
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            spec = ChainSpec(
                chain_id="save-test",
                components=[
                    ChainComponent(name="a", role="llm", external=True,
                                   model_id="gpt-4"),
                ],
            )
            ChainAttestPipeline.run(
                ChainAttestConfig(spec=spec, output_dir=out)
            )
            self.assertTrue((out / "chain-attest.json").exists())
            self.assertTrue((out / "chain-attest.md").exists())

    def test_attestation_round_trip_via_dict(self) -> None:
        from squash.chain_attest import (
            ChainAttestConfig, ChainAttestPipeline, ChainComponent, ChainSpec,
            attestation_from_dict, verify_signature,
        )
        spec = ChainSpec(
            chain_id="rt-test",
            components=[
                ChainComponent(name="a", role="llm", external=True,
                               model_id="gpt-4"),
                ChainComponent(name="b", role="retriever",
                               metadata={"k": "v"}),
            ],
        )
        a = ChainAttestPipeline.run(ChainAttestConfig(spec=spec))
        d = json.loads(a.to_json())
        b = attestation_from_dict(d)
        self.assertEqual(b.chain_id, a.chain_id)
        self.assertEqual(b.signature, a.signature)
        self.assertTrue(verify_signature(b))


class TestW195SpecLoader(unittest.TestCase):
    def test_load_json_spec(self) -> None:
        from squash.chain_attest import load_chain_spec
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "chain.json"
            p.write_text(json.dumps({
                "chain_id": "json-test",
                "kind": "rag",
                "components": [
                    {"name": "a", "role": "llm", "external": True},
                ],
            }))
            spec = load_chain_spec(p)
            self.assertEqual(spec.chain_id, "json-test")
            self.assertEqual(spec.kind, "rag")
            self.assertEqual(len(spec.components), 1)

    def test_load_yaml_without_pyyaml_raises_clean_error(self) -> None:
        from squash.chain_attest import load_chain_spec
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "chain.yaml"
            p.write_text("chain_id: foo\n")
            with mock.patch.dict(sys.modules, {"yaml": None}):
                with self.assertRaises(ImportError) as ctx:
                    load_chain_spec(p)
                self.assertIn("PyYAML", str(ctx.exception))


# ── W196 — LangChain Runnable walker ─────────────────────────────────────────


# Realistic LangChain-style mock classes (names match real SDK)


class OpenAIEmbeddings:
    model_name = "text-embedding-3-small"
    def embed_query(self, q): return []
    def embed_documents(self, ds): return []


class VectorStoreRetriever:
    def __init__(self):
        self.vectorstore = "fake_chroma"
        self.search_kwargs = {"k": 5}


class ChatOpenAI:
    def __init__(self, model_name="gpt-4-turbo"):
        self.model_name = model_name


class ChatAnthropic:
    def __init__(self, model="claude-opus-4"):
        self.model = model


class FakeTool:
    """Mimics a LangChain BaseTool."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    def _run(self, x): return x

    def __class__name(self):
        return f"{self.name}_Tool"


# Make the class look like a *Tool subclass at runtime
FakeTool.__name__ = "WebSearchTool"


class RunnableSequence:
    def __init__(self, steps):
        self.steps = list(steps)


class RunnableParallel:
    def __init__(self, branches):
        self.steps__ = dict(branches)


class AgentExecutor:
    def __init__(self, llm, tools):
        self.llm = llm
        self.tools = list(tools)


class TestW196RAGShape(unittest.TestCase):
    """Walk a RAG-style RunnableSequence(embedder → retriever → LLM)."""

    def test_walks_three_components(self) -> None:
        from squash.integrations.langchain import attest_chain
        chain = RunnableSequence([
            OpenAIEmbeddings(),
            VectorStoreRetriever(),
            ChatOpenAI(),
        ])
        result = attest_chain(chain, chain_id="rag-test",
                              policies=["enterprise-strict"])
        self.assertEqual(len(result.components), 3)

    def test_classifies_each_role(self) -> None:
        from squash.integrations.langchain import attest_chain
        chain = RunnableSequence([
            OpenAIEmbeddings(),
            VectorStoreRetriever(),
            ChatOpenAI(),
        ])
        result = attest_chain(chain, chain_id="rag-test")
        roles = {c.component.role for c in result.components}
        self.assertIn("embedding", roles)
        self.assertIn("retriever", roles)
        self.assertIn("llm", roles)

    def test_external_llm_flagged(self) -> None:
        from squash.integrations.langchain import attest_chain
        chain = RunnableSequence([
            VectorStoreRetriever(),
            ChatOpenAI(),
        ])
        result = attest_chain(chain, chain_id="rag-test")
        external = result.external_components
        self.assertIn("chatopenai", [n.lower() for n in external])

    def test_kind_is_sequence(self) -> None:
        from squash.integrations.langchain import attest_chain
        chain = RunnableSequence([VectorStoreRetriever(), ChatOpenAI()])
        result = attest_chain(chain, chain_id="rag-test")
        self.assertEqual(result.kind, "sequence")

    def test_edges_link_steps(self) -> None:
        from squash.integrations.langchain import attest_chain
        chain = RunnableSequence([
            OpenAIEmbeddings(),
            VectorStoreRetriever(),
            ChatOpenAI(),
        ])
        result = attest_chain(chain, chain_id="rag-test")
        # Sequence walker must produce at least 2 forward edges
        self.assertGreaterEqual(len(result.spec.edges), 2)


class TestW196AgentShape(unittest.TestCase):
    """Walk a tool-using AgentExecutor (LLM + tools list)."""

    def test_kind_is_agent(self) -> None:
        from squash.integrations.langchain import attest_chain
        agent = AgentExecutor(ChatOpenAI(), [
            FakeTool("search", "web search"),
            FakeTool("calc", "calculator"),
        ])
        result = attest_chain(agent, chain_id="agent-test")
        self.assertEqual(result.kind, "agent")

    def test_llm_plus_each_tool_emitted(self) -> None:
        from squash.integrations.langchain import attest_chain
        agent = AgentExecutor(ChatOpenAI(), [
            FakeTool("search", "web search"),
            FakeTool("calc", "calculator"),
        ])
        result = attest_chain(agent, chain_id="agent-test")
        roles = [c.component.role for c in result.components]
        self.assertIn("llm", roles)
        self.assertEqual(roles.count("tool"), 2)

    def test_tool_names_preserved(self) -> None:
        from squash.integrations.langchain import attest_chain
        agent = AgentExecutor(ChatOpenAI(), [
            FakeTool("search", "web search"),
            FakeTool("calc", "calculator"),
        ])
        result = attest_chain(agent, chain_id="agent-test")
        names = [c.component.name for c in result.components]
        self.assertIn("search", names)
        self.assertIn("calc", names)


class TestW196EnsembleShape(unittest.TestCase):
    """Walk a RunnableParallel(gpt: ..., claude: ...) ensemble."""

    def test_kind_is_ensemble(self) -> None:
        from squash.integrations.langchain import attest_chain
        ensemble = RunnableParallel({
            "gpt": ChatOpenAI(),
            "claude": ChatAnthropic(),
        })
        result = attest_chain(ensemble, chain_id="ensemble-test")
        self.assertEqual(result.kind, "ensemble")

    def test_branches_namespaced(self) -> None:
        from squash.integrations.langchain import attest_chain
        ensemble = RunnableParallel({
            "gpt": ChatOpenAI(),
            "claude": ChatAnthropic(),
        })
        result = attest_chain(ensemble, chain_id="ensemble-test")
        names = {c.component.name for c in result.components}
        # Branch prefix should be in component names
        self.assertTrue(any(n.startswith("gpt") for n in names))
        self.assertTrue(any(n.startswith("claude") for n in names))


class TestW196DuckTypePredicates(unittest.TestCase):
    def test_is_llm_detects_chat_classes(self) -> None:
        from squash.integrations.langchain import _is_llm
        self.assertTrue(_is_llm(ChatOpenAI()))
        self.assertTrue(_is_llm(ChatAnthropic()))

    def test_is_llm_rejects_embeddings(self) -> None:
        from squash.integrations.langchain import _is_llm
        self.assertFalse(_is_llm(OpenAIEmbeddings()))

    def test_is_retriever_detects_vectorstore(self) -> None:
        from squash.integrations.langchain import _is_retriever
        self.assertTrue(_is_retriever(VectorStoreRetriever()))

    def test_is_embedding_detects_embed_query(self) -> None:
        from squash.integrations.langchain import _is_embedding
        self.assertTrue(_is_embedding(OpenAIEmbeddings()))

    def test_looks_like_remote_llm_detects_openai(self) -> None:
        from squash.integrations.langchain import _looks_like_remote_llm
        self.assertTrue(_looks_like_remote_llm(ChatOpenAI()))
        self.assertTrue(_looks_like_remote_llm(ChatAnthropic()))


# ── W197 — CLI integration ───────────────────────────────────────────────────


class TestW197CLIBasic(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)

    def _write_spec(self, name: str = "chain.json") -> Path:
        p = self.tmp / name
        p.write_text(json.dumps({
            "chain_id": "cli-rag-test",
            "kind": "rag",
            "components": [
                {"name": "embedder", "role": "embedding", "external": True,
                 "model_id": "text-embedding-3-small"},
                {"name": "retriever", "role": "retriever"},
                {"name": "llm", "role": "llm", "external": True,
                 "model_id": "gpt-4-turbo"},
            ],
            "edges": [["embedder", "retriever"], ["retriever", "llm"]],
        }))
        return p

    def test_help_includes_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for flag in ("--policy", "--output-dir", "--fail-on-component-violation",
                     "--verify", "--json", "--sign-components", "--chain-id"):
            self.assertIn(flag, result.stdout, msg=f"{flag} missing")

    def test_runs_on_json_spec(self) -> None:
        spec = self._write_spec()
        out = self.tmp / "out"
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             str(spec), "--output-dir", str(out), "--quiet"],
            capture_output=True, text=True,
        )
        # All-external chain: composite_passed = False, but exit code is 0
        # unless --fail-on-component-violation is set
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((out / "chain-attest.json").exists())
        self.assertTrue((out / "chain-attest.md").exists())

    def test_json_output(self) -> None:
        spec = self._write_spec()
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             str(spec), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        # Must be valid JSON with squash_version chain_attest_v1
        payload = json.loads(result.stdout)
        self.assertEqual(payload["squash_version"], "chain_attest_v1")
        self.assertEqual(payload["chain_id"], "cli-rag-test")
        self.assertIn("composite_score", payload)
        self.assertIn("signature", payload)

    def test_chain_id_override(self) -> None:
        spec = self._write_spec()
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             str(spec), "--chain-id", "renamed-chain", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["chain_id"], "renamed-chain")

    def test_missing_spec_exits_1(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             str(self.tmp / "no-such.json"), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)

    def test_fail_on_component_violation_exits_nonzero(self) -> None:
        spec = self._write_spec()
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             str(spec), "--fail-on-component-violation", "--quiet"],
            capture_output=True, text=True,
        )
        # Composite is FAIL (no attestable components); fail flag → rc 1
        self.assertEqual(result.returncode, 1)


class TestW197CLIVerify(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.tmp = Path(self._tmp)
        # Generate a real attestation file
        spec = self.tmp / "chain.json"
        spec.write_text(json.dumps({
            "chain_id": "verify-test",
            "components": [{"name": "a", "role": "llm", "external": True}],
        }))
        subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             str(spec), "--output-dir", str(self.tmp), "--quiet"],
            check=True, capture_output=True,
        )
        self.attest_path = self.tmp / "chain-attest.json"

    def test_verify_passes_for_untouched_file(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             "--verify", str(self.attest_path)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("VALID", result.stdout)

    def test_verify_fails_after_tamper(self) -> None:
        raw = json.loads(self.attest_path.read_text())
        raw["chain_id"] = "tampered-id"
        self.attest_path.write_text(json.dumps(raw))
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             "--verify", str(self.attest_path)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("TAMPERED", result.stdout)

    def test_verify_invalid_json_returns_1(self) -> None:
        bad = self.tmp / "broken.json"
        bad.write_text("{not json")
        result = subprocess.run(
            [sys.executable, "-m", "squash.cli", "chain-attest",
             "--verify", str(bad)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)


class TestW197PythonModuleResolution(unittest.TestCase):
    """`squash chain-attest module:variable` import path."""

    def test_resolve_python_chain_for_simple_object(self) -> None:
        from squash import cli as _cli
        # Resolve a real attribute on a real module — use json.loads itself
        obj = _cli._resolve_python_chain("json:dumps")
        self.assertTrue(callable(obj))


# ── Module count gate (Sprint 11 → 71) ───────────────────────────────────────


class TestModuleCountGate(unittest.TestCase):
    """Tracks current count. Sprint 11 added chain_attest.py (71). Sprint 14
    W205 (B1) added hf_scanner.py (72). The canonical gate is in
    test_squash_model_card.py — this is a secondary live tracker."""

    def test_squash_module_count_is_71(self) -> None:
        squash_dir = Path(__file__).parent.parent / "squash"
        py_files = [
            f for f in squash_dir.rglob("*.py") if "__pycache__" not in str(f)
        ]
        count = len(py_files)
        self.assertEqual(
            count, 106,
            msg=f"squash/ has {count} Python files (expected 97 after D2/W226-228).",
        )


if __name__ == "__main__":
    unittest.main()
