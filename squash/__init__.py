"""squash — Automated EU AI Act compliance for ML teams.

Squash generates Annex IV technical documentation, runs policy checks against 10+
regulatory frameworks, and produces cryptographically signed audit records — all
inside your CI/CD pipeline.

Quick start::

    pip install squash-ai
    squash attest ./my-model --policy eu-ai-act

For the REST microservice::

    pip install "squash-ai[api]"
    uvicorn squash.api:app --host 0.0.0.0 --port 4444

Frameworks covered: EU AI Act · NIST AI RMF · ISO 42001 · OWASP LLM Top 10 ·
FedRAMP · CMMC · SOC 2-AI · HITRUST · GDPR-AI · DORA
"""

__version__ = "0.9.14"

from squash.sbom_builder import CompressRunMeta, CycloneDXBuilder, SbomDiff, SbomRegistry, EvalBinder
from squash.oms_signer import OmsSigner, OmsVerifier
from squash.governor import SquashGovernor

# Phase 7 exports — lazy-guarded; raise ImportError at access time if cyclonedx absent
from squash.spdx_builder import SpdxArtifacts, SpdxBuilder, SpdxOptions
from squash.policy import (
    AVAILABLE_POLICIES,
    PolicyEngine,
    PolicyFinding,
    PolicyHistory,
    PolicyResult,
    PolicyRegistry,
    PolicyWebhook,
)
from squash.scanner import ModelScanner, ScanFinding, ScanResult
from squash.vex import (
    ModelInventory,
    ModelInventoryEntry,
    VexCache,
    VexDocument,
    VexEvaluator,
    VexFeed,
    VexReport,
    VexStatement,
)
from squash.provenance import (
    DatasetRecord,
    ProvenanceCollector,
    ProvenanceManifest,
)
from squash.attest import (
    AttestConfig,
    AttestPipeline,
    AttestResult,
    AttestationViolationError,
    CompositeAttestConfig,
    CompositeAttestPipeline,
    CompositeAttestResult,
)
from squash.sarif import SarifBuilder
from squash.report import ComplianceReporter
from squash.policy import NtiaResult, NtiaValidator  # noqa: F401 (Wave 20)
from squash.slsa import SlsaLevel, SlsaAttestation, SlsaProvenanceBuilder  # noqa: F401 (Wave 21)
from squash.sbom_builder import BomMerger  # noqa: F401 (Wave 22)
from squash.risk import (  # noqa: F401 (Wave 23)
    RiskCategory,
    EuAiActCategory,
    NistRmfCategory,
    RiskAssessmentResult,
    AiRiskAssessor,
)
from squash.governor import DriftEvent, DriftMonitor  # noqa: F401 (Wave 24)
from squash.cicd import CiEnvironment, CicdAdapter, CicdReport  # noqa: F401 (Wave 25)
from squash.integrations.sagemaker import SageMakerSquash  # noqa: F401 (Wave 26)
from squash.sbom_builder import OrasAdapter  # noqa: F401 (Wave 26)
from squash.vex import VexFeedManifest, SQUASH_VEX_FEED_URL, SQUASH_VEX_FEED_FALLBACK_URL  # noqa: F401 (Wave 26)
from squash.integrations.ray import (  # noqa: F401 (Wave 28)
    SquashServeConfig,
    SquashServeDeployment,
    squash_serve,
)
from squash.integrations.kubernetes import (  # noqa: F401 (Wave 27)
    KubernetesWebhookHandler,
    WebhookConfig,
)
from squash.remediate import (  # noqa: F401 (Wave 54)
    Remediator,
    RemediateResult,
    ConvertedFile,
    FailedFile,
)
from squash.evaluator import (  # noqa: F401 (Wave 55)
    EvalEngine,
    EvalReport,
    ProbeResult,
)
from squash.edge_formats import (  # noqa: F401 (Wave 56)
    TFLiteParser,
    TFLiteMetadata,
    CoreMLParser,
    CoreMLMetadata,
    EdgeSecurityScanner,
    EdgeFinding,
    TensorDescriptor,
)
from squash.chat import ChatSession  # noqa: F401 (Wave 56)
from squash.model_card import (  # noqa: F401 (Wave 57)
    ModelCard,
    ModelCardConfig,
    ModelCardGenerator,
    ModelCardSection,
    KNOWN_FORMATS as MODEL_CARD_KNOWN_FORMATS,
)
from squash.artifact_extractor import (  # noqa: F401 (Wave 128-131)
    ArtifactExtractor,
    ArtifactExtractionResult,
    DatasetProvenance,
    MetricSeries,
    TrainingConfig,
    TrainingMetrics,
)
from squash.code_scanner_ast import (  # noqa: F401 (Wave 132)
    CodeArtifacts,
    CodeScanner,
    ImportRecord,
    OptimizerCall,
)
from squash.nist_rmf import (  # noqa: F401 (Wave 83)
    NistRmfFunction,
    NistControlStatus,
    NistRmfControl,
    NistRmfPosture,
    NistRmfReport,
    NistRmfScanner,
)

__all__ = [
    # Core
    "CycloneDXBuilder",
    "CompressRunMeta",
    "EvalBinder",
    "OmsSigner",
    "OmsVerifier",
    "SquashGovernor",
    # SPDX
    "SpdxBuilder",
    "SpdxOptions",
    "SpdxArtifacts",
    # Policy
    "PolicyEngine",
    "PolicyResult",
    "PolicyFinding",
    "AVAILABLE_POLICIES",
    # Scanner
    "ModelScanner",
    "ScanResult",
    "ScanFinding",
    # VEX
    "VexFeed",
    "VexEvaluator",
    "VexReport",
    "ModelInventory",
    "ModelInventoryEntry",
    "VexDocument",
    "VexStatement",
    # Provenance
    "ProvenanceCollector",
    "ProvenanceManifest",
    "DatasetRecord",
    # Attestation pipeline
    "AttestPipeline",
    "AttestConfig",
    "AttestResult",
    "AttestationViolationError",
    # SARIF export
    "SarifBuilder",
    # SBOM diff + policy history
    "SbomDiff",
    "PolicyHistory",
    # HTML compliance report
    "ComplianceReporter",
    # VEX cache
    "VexCache",
    # Policy webhooks
    "PolicyWebhook",
    # Composite attestation
    "CompositeAttestConfig",
    "CompositeAttestPipeline",
    "CompositeAttestResult",
    # SBOM registry push
    "SbomRegistry",
    # NTIA minimum elements
    "NtiaResult",
    "NtiaValidator",
    # SLSA provenance
    "SlsaLevel",
    "SlsaAttestation",
    "SlsaProvenanceBuilder",
    # BOM merge
    "BomMerger",
    # AI risk assessment
    "RiskCategory",
    "EuAiActCategory",
    "NistRmfCategory",
    "RiskAssessmentResult",
    "AiRiskAssessor",
    # Drift detection
    "DriftEvent",
    "DriftMonitor",
    # CI/CD integration
    "CiEnvironment",
    "CicdAdapter",
    "CicdReport",
    # SageMaker, ORAS, VEX feed
    "SageMakerSquash",
    "OrasAdapter",
    "VexFeedManifest",
    "SQUASH_VEX_FEED_URL",
    "SQUASH_VEX_FEED_FALLBACK_URL",
    # Kubernetes Admission Webhook
    "KubernetesWebhookHandler",
    "WebhookConfig",
    # Ray Serve decorator
    "SquashServeConfig",
    "SquashServeDeployment",
    "squash_serve",
    # Remediate (pickle → safetensors)
    "Remediator",
    "RemediateResult",
    "ConvertedFile",
    "FailedFile",
    # Dynamic evaluation / red-teaming
    "EvalEngine",
    "EvalReport",
    "ProbeResult",
    # Edge AI format support
    "TFLiteParser",
    "TFLiteMetadata",
    "CoreMLParser",
    "CoreMLMetadata",
    "EdgeSecurityScanner",
    "EdgeFinding",
    "TensorDescriptor",
    # RAG compliance chat
    "ChatSession",
    # Model card generator
    "ModelCard",
    "ModelCardConfig",
    "ModelCardGenerator",
    "ModelCardSection",
    "MODEL_CARD_KNOWN_FORMATS",
    # Wave 132: Python AST code scanner
    "CodeArtifacts",
    "CodeScanner",
    "ImportRecord",
    "OptimizerCall",
    # Wave 128–131: Annex IV artifact extraction
    "ArtifactExtractor",
    "ArtifactExtractionResult",
    "DatasetProvenance",
    "MetricSeries",
    "TrainingConfig",
    "TrainingMetrics",
    # NIST AI RMF 1.0 controls scanner
    "NistRmfFunction",
    "NistControlStatus",
    "NistRmfControl",
    "NistRmfPosture",
    "NistRmfReport",
    "NistRmfScanner",
]
