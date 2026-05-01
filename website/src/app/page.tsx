import Countdown from "@/components/Countdown";
import TypingTerminal from "@/components/TypingTerminal";
import AnimatedCounter from "@/components/AnimatedCounter";
import ScrollReveal from "@/components/ScrollReveal";
import FAQAccordion from "@/components/FAQAccordion";
import IntegrationTabs from "@/components/IntegrationTabs";

// ─── Data ────────────────────────────────────────────────────────────────────

const HERO_TERMINAL_LINES = [
  `$ squash attest ./bert-base --policy eu-ai-act --sign`,
  ``,
  `  Squash v1.11.0  ·  eu-ai-act policy  ·  keyless signing via Sigstore`,
  ``,
  `  Scanning model artifacts...`,
  `  [████████████████████████████████████████]  100%`,
  ``,
  `  ┌─ Step 1/6  Model fingerprint + architecture scan        12ms ✓`,
  `  ├─ Step 2/6  Dependency graph (SPDX 2.3 SBOM)             89ms ✓`,
  `  ├─ Step 3/6  ML-BOM (CycloneDX 1.7)                       74ms ✓`,
  `  ├─ Step 4/6  Annex IV generation (12/12 sections)        2,341ms ✓`,
  `  ├─ Step 5/6  Policy evaluation  →  eu-ai-act              41ms ✓`,
  `  └─ Step 6/6  SLSA L2 provenance + Sigstore signing       198ms ✓`,
  ``,
  `  Total: 2,755ms  ·  p50 target: <10,000ms  ·  ✓ WITHIN SLA`,
  ``,
  `  Policy result:  PASS  ·  0 violations  ·  0 warnings`,
  `  Attestation URI:  att://sha256:a3f1c8d...`,
  `  Rekor log index:  144,821,047`,
  ``,
  `  ✓ Compliance gate: OPEN — safe to merge`,
];

const PROBLEM_STATS = [
  { stat: "78%",   label: "of business executives lack confidence they could pass an independent AI governance audit within 90 days", source: "Grant Thornton, 2026 AI Impact Survey", ref: 1 },
  { stat: "$67.4B", label: "in global AI hallucination losses in 2024 — documentation gaps turn model errors into legal liability", source: "Industry research, 2024", ref: 2 },
  { stat: "€15M",  label: "fine against OpenAI by the Italian DPA for GDPR violations in training data — the first of many", source: "Italian DPA (Garante), January 2025", ref: 3 },
  { stat: "40%",   label: "of total AI system assessment costs are documentation preparation — the part squash eliminates", source: "EU AI Act implementation analysis", ref: 4 },
  { stat: "~100",  label: "malicious models found on HuggingFace with embedded code-execution payloads — supply chain risk is real", source: "JFrog Security Research, 2024", ref: 5 },
  { stat: "65%",   label: "of GenAI apps in enterprise run without IT approval — the average enterprise runs 66 GenAI apps (shadow AI)", source: "Cybersecurity research, 2025", ref: 6 },
];

const FRAMEWORKS = [
  { name: "EU AI Act", color: "#3b82f6" },
  { name: "NIST AI RMF", color: "#8b5cf6" },
  { name: "ISO 42001", color: "#f59e0b" },
  { name: "GDPR", color: "#06b6d4" },
  { name: "HIPAA", color: "#ec4899" },
  { name: "FedRAMP", color: "#10b981" },
  { name: "SOC 2", color: "#6366f1" },
  { name: "OWASP LLM Top 10", color: "#ef4444" },
  { name: "CMMC", color: "#84cc16" },
  { name: "Colorado AI Act", color: "#f97316" },
  { name: "NYC Local Law 144", color: "#a78bfa" },
  { name: "SEC AI Disclosure", color: "#2dd4bf" },
  { name: "SLSA Level 2", color: "#22c55e" },
  { name: "CycloneDX 1.7", color: "#7c3aed" },
  { name: "SPDX 2.3", color: "#0ea5e9" },
];

const ML_ENGINEER_FEATURES = [
  { num: "01", title: "Annex IV Auto-Generation", cmd: "squash attest ./model --policy eu-ai-act", problem: "Annex IV used to take 3–6 months of engineering time.", how: "12/12 required sections extracted from model artifacts, weights, training config, and dependency graph in under 10 seconds. Outputs auditor-ready markdown and PDF." },
  { num: "02", title: "CycloneDX 1.7 ML-BOM", cmd: "squash attest ./model --format cyclonedx", problem: "No machine-readable record of what's in your model.", how: "Generates a full CycloneDX 1.7 ML Bill of Materials: base model, adapters, quantization config, training data refs, and dependency hash tree." },
  { num: "03", title: "SPDX 2.3 SBOM", cmd: "squash attest ./model --format spdx", problem: "NTIA minimum elements + full lineage tracing = weeks of manual work.", how: "Full dependency + lineage graph, NTIA-compliant. Includes all Python deps, model files, and adapter provenance. Signed with Sigstore." },
  { num: "04", title: "Adapter Poisoning Detection", cmd: "squash scan-adapter ./lora-adapter.safetensors", problem: "LoRA and other adapters are a supply chain attack vector with no tooling.", how: "Detects kurtosis anomalies in weight distributions, pickle opcode injection, out-of-bound activation vectors, and hidden backdoor triggers." },
  { num: "05", title: "Continuous Drift Detection", cmd: "squash watch ./model --interval 5m", problem: "Models change subtly in production. Nobody notices until audit.", how: "Monitors model artifact hashes, weight histograms, and output distributions. Fires Slack/Teams alert when drift exceeds configured threshold." },
  { num: "06", title: "Pre-Commit Compliance Hook", cmd: "squash install-hook", problem: "Discovering violations 15 minutes into CI is too late.", how: "Installs a git pre-commit hook that runs a fast-path policy check on changed model files. Compliance feedback in <2s at commit time." },
];

const CISO_FEATURES = [
  { num: "07", title: "CISO Terminal Dashboard", cmd: "squash dashboard", problem: "No single view of AI compliance posture across the portfolio.", how: "5-metric panel: compliant ratio, active CVEs, pending attestations, drift events, and policy violations. Risk heat-map by model. Terminal and web UI." },
  { num: "08", title: "Emergency Freeze + Article 73 Disclosure", cmd: "squash freeze --model bert-prod --reason incident-2026-04", problem: "A compromised model is live. Every second counts.", how: "Revokes attestation, blocks GitOps deployment, and drafts an EU AI Act Article 73 incident disclosure package — all in under 10 seconds." },
  { num: "09", title: "AI Vendor Risk Register", cmd: "squash vendor assess ./vendor-model-card.pdf", problem: "Vendor AI risk questionnaires take 4 weeks and return inconsistent data.", how: "Ingests vendor model cards, extracts compliance signals, scores against EU AI Act Annex III requirements, and outputs a structured risk register entry." },
  { num: "10", title: "AI Asset Registry", cmd: "squash registry list --env production", problem: "\"What AI do we have deployed?\" — nobody knows.", how: "Discovers AI assets across your infrastructure via MLflow, SageMaker, Vertex, and Kubernetes annotations. Builds a live registry with compliance status." },
  { num: "11", title: "Incident Response Package", cmd: "squash incident package --att att://sha256:a3f1...", problem: "Article 73 requires disclosure within 15 days. Most teams take 60+.", how: "Generates a complete Article 73-compliant incident package: timeline, affected attestations, remediation evidence, and regulator-ready PDF." },
  { num: "12", title: "Board-Level Report Generator", cmd: "squash report board --quarter Q2-2026", problem: "Boards demand AI governance reporting. Nobody has the data.", how: "Executive PDF with quarterly compliance scorecard, trend charts, risk heatmap, and regulatory exposure summary — ready for board deck in seconds." },
];

const AUDITOR_FEATURES = [
  { num: "13", title: "ISO 42001 Readiness", cmd: "squash iso42001 gap-analysis --output roadmap.md", problem: "38-control ISO 42001 gap analysis used to mean months of consulting.", how: "Maps your current attestation history to all 38 ISO 42001:2023 controls. Outputs a prioritized remediation roadmap with effort estimates." },
  { num: "14", title: "Trust Package (Signed Vendor Bundle)", cmd: "squash verify-trust-package ./vendor-bundle.zip", problem: "Third-party AI compliance claims are unverifiable assertions.", how: "Verifies cryptographic signatures on all attestation artifacts in a vendor trust bundle. Outputs a verification report with Rekor log timestamps." },
  { num: "15", title: "OWASP Agentic AI Top 10 Audit", cmd: "squash owasp-agentic audit ./agent-config.yaml", problem: "Agentic AI risk has no standard audit framework. Until now.", how: "Full coverage of all 10 OWASP Agentic AI risk categories: prompt injection, tool poisoning, orchestration abuse, excessive autonomy, and more." },
  { num: "16", title: "Automated Bias Audit", cmd: "squash bias audit ./model --dataset ./eval.parquet", problem: "EU AI Act Annex III + NYC Local Law 144 require bias documentation.", how: "Computes DPD, DIR (4/5ths rule), EOD, and PED across protected attributes. Flags disparate impact and generates auditor-ready documentation." },
  { num: "17", title: "Attestation Registry + Revocation", cmd: "squash registry verify att://sha256:a3f1c8d...", problem: "Audit trails need to be tamper-evident and revocable.", how: "att:// URI scheme with SHA-256 integrity verification, Rekor transparency log anchoring, and instant revocation — checked at every CI gate." },
  { num: "18", title: "M&A AI Due Diligence", cmd: "squash ma due-diligence --target ./target-model-inventory.json", problem: "AI liability is the new environmental liability in M&A — and nobody prices it.", how: "Scores AI liability exposure across the target's model inventory, generates R&W insurance guidance, and produces a ZIP bundle for deal counsel." },
];

const INTEGRATIONS_CODE = [
  { label: "GitHub Actions", lang: "yaml", code: `- name: Squash compliance gate
  uses: konjoai/squash@v1
  with:
    model-path: ./my-model
    policy: eu-ai-act
    sign: true
    fail-on-violation: true` },
  { label: "CLI (multi-policy)", lang: "bash", code: `squash attest ./model \\
  --policy eu-ai-act \\
  --policy nist-ai-rmf \\
  --policy iso-42001 \\
  --sign \\
  --fail-on-violation` },
  { label: "FastAPI middleware", lang: "python", code: `from squash.middleware import (
  SquashComplianceMiddleware
)

app.add_middleware(
  SquashComplianceMiddleware,
  model_id="bert-prod-v2",
  policy="eu-ai-act",
  block_on_missing=True,
)` },
  { label: "Prometheus metrics", lang: "text", code: `# HELP squash_attestations_total
squash_attestations_total{
  result="passed",policy="eu-ai-act"
} 142

# HELP squash_models_compliant_ratio
squash_models_compliant_ratio 0.979

squash_violations_total{severity="high"} 0` },
  { label: "Kong gateway", lang: "yaml", code: `plugins:
  - name: squash-compliance
    config:
      att_registry: https://att.squash.works
      policy: eu-ai-act
      action: block
      model_header: X-Model-ID` },
  { label: "GitOps (ArgoCD / Flux)", lang: "yaml", code: `# ArgoCD PreSync hook
- name: squash-gate
  image: ghcr.io/konjoai/squash:v1
  command: [squash, attest]
  args:
    - ./model
    - --policy=eu-ai-act
    - --fail-on-violation` },
];

const COMPARE_ROWS = [
  { feature: "EU AI Act Annex IV",           manual: "3–6 months",    squash: "10 seconds" },
  { feature: "CycloneDX ML-BOM",             manual: "Manual, error-prone", squash: "Automated, signed" },
  { feature: "CI compliance gate",           manual: "Doesn't exist", squash: "Fails build on violation" },
  { feature: "Drift detection",              manual: "Nobody checks", squash: "Continuous, alerts on breach" },
  { feature: "Incident disclosure (Art. 73)",manual: "60+ day average", squash: "Under 10 seconds" },
  { feature: "Bias audit documentation",     manual: "4–8 weeks",     squash: "Automated, DPD + DIR + EOD" },
  { feature: "Audit trail",                  manual: "Docs in a folder", squash: "Cryptographically signed" },
  { feature: "Cryptographic signing",        manual: "None",          squash: "Sigstore keyless + Ed25519" },
];

const REGULATORY_TIMELINE = [
  { date: "Aug 2, 2026", name: "EU AI Act", detail: "High-risk AI systems must comply. €35M / 7% revenue fine.", urgent: true, color: "#ef4444" },
  { date: "Q4 2026", name: "Colorado AI Act", detail: "Algorithmic decision systems in high-risk sectors.", urgent: true, color: "#f97316" },
  { date: "Jan 2027", name: "NYC Local Law 144", detail: "Automated Employment Decision Tools — bias audit mandatory.", urgent: false, color: "#f59e0b" },
  { date: "2027", name: "ISO 42001 Adoption Wave", detail: "Enterprise procurement increasingly demanding certification.", urgent: false, color: "#22c55e" },
  { date: "2027+", name: "SEC AI Disclosure Rules", detail: "Material AI risk disclosures in financial filings.", urgent: false, color: "#3b82f6" },
];

const SECTOR_BENCHMARKS = [
  { sector: "Financial Services", score: 61, percentile: 71, color: "#22c55e" },
  { sector: "Technology", score: 67, percentile: 48, color: "#3b82f6" },
  { sector: "Healthcare", score: 55, percentile: 55, color: "#a78bfa" },
  { sector: "Legal", score: 43, percentile: 34, color: "#f59e0b" },
  { sector: "Government", score: 57, percentile: 42, color: "#06b6d4" },
];

const TESTIMONIALS = [
  { quote: "We went from a 6-month Annex IV project to a 10-second command. Our auditors were stunned by the output quality.", name: "Head of AI Engineering", org: "Series B Fintech", avatar: "HE" },
  { quote: "The emergency freeze command alone is worth the price. When a model incident happened, we had an Article 73 disclosure package in under a minute.", name: "CISO", org: "Healthcare AI Platform", avatar: "CI" },
  { quote: "Squash is the only tool that actually fails our CI build on violations. Every other 'compliance' tool just generates reports that nobody reads.", name: "Lead MLOps Engineer", org: "Enterprise SaaS", avatar: "LM" },
  { quote: "The bias audit automation saved us from a potential NYC Local Law 144 violation we didn't even know we had. The 4/5ths rule check is invaluable.", name: "VP of Responsible AI", org: "HR Tech Company", avatar: "VR" },
];

const PRICING_TIERS = [
  { name: "Community", price: "Free", period: "", attestations: "10 attestations / mo", highlight: false, cta: "Start free", ctaHref: "https://github.com/konjoai/squash", features: ["Full CLI (attest, watch, demo, init)", "CycloneDX 1.7 ML-BOM", "SPDX 2.3 SBOM", "10+ policy frameworks", "Sigstore keyless signing", "Self-hosted", "Apache 2.0 open-source"] },
  { name: "Professional", price: "$299", period: "/mo", attestations: "200 attestations / mo", highlight: false, cta: "Start trial", ctaHref: "https://squash.works/checkout", features: ["Everything in Community", "Cloud REST API", "Annex IV auto-generation (PDF)", "30-day attestation history", "Drift alerts", "Slack / Teams webhooks", "Audit export", "MLflow + W&B integration"] },
  { name: "Startup", price: "$499", period: "/mo", attestations: "500 attestations / mo", highlight: true, badge: "MOST POPULAR", cta: "Start trial", ctaHref: "https://squash.works/checkout", features: ["Everything in Professional", "VEX feed (read access)", "3 team members", "JIRA / Linear / GitHub Issues", "scan-adapter (LoRA poisoning)", "squash freeze emergency gate", "Priority email support"] },
  { name: "Team", price: "$899", period: "/mo", attestations: "1,000 attestations / mo", highlight: false, cta: "Start trial", ctaHref: "https://squash.works/checkout", features: ["Everything in Startup", "Multi-tenant dashboard", "SAML SSO", "Human-in-the-loop workflows", "Full VEX feed (write access)", "ArgoCD / Flux GitOps gate", "SageMaker / Vertex AI", "SLA support"] },
  { name: "Enterprise", price: "Custom", period: "", attestations: "Unlimited", highlight: false, cta: "Contact us", ctaHref: "mailto:hello@squash.works", features: ["Everything in Team", "On-premise deployment", "Air-gapped mode", "EU data residency", "Dedicated solutions engineer", "Custom policy frameworks", "Security review + pen test"] },
];

const FAQ_ITEMS = [
  { q: "Is squash just a documentation generator?", a: "No. Documentation is a side-effect. Squash is a CI gate. It evaluates your model against a policy, and it fails the build if the policy is violated. The Annex IV markdown, ML-BOM, SBOM, and provenance files are outputs of a passed attestation — not the product itself. The product is the policy enforcement." },
  { q: "Does it work with our existing MLflow or Weights & Biases setup?", a: "Yes. Squash has native integrations with MLflow (experiment tracking, model registry), Weights & Biases (run metadata, artifact lineage), HuggingFace Hub, SageMaker Model Registry, and Vertex AI Model Registry. It reads what's already there — it doesn't replace anything." },
  { q: "What if we're not subject to the EU AI Act?", a: "Squash supports NIST AI RMF, CMMC, FedRAMP (AI components), Colorado AI Act, NYC Local Law 144, SEC AI disclosure requirements, and ISO 42001. If you deploy AI anywhere near US federal contractors, financial services, or healthcare, you have compliance obligations that squash addresses. The EU AI Act is the deadline — not the only reason to use it." },
  { q: "Is the free Community tier actually useful?", a: "Yes. The full CLI, all 10+ policy frameworks, ML-BOM, SBOM, Sigstore signing, and the pre-commit hook are all free. We compete on cloud features (dashboard, drift alerts, team workflows, audit export) — not on gating the core tool. Apache 2.0 means you can read, modify, and self-host everything." },
  { q: "How long does an attestation actually take?", a: "p50 is under 10 seconds for most models under 10GB. p95 is under 25 seconds. The bottleneck is Annex IV section 6 (training data documentation) which requires reading training metadata. Large models (70B+) on network-attached storage can hit 60–90 seconds. Configurable --fast-path flag skips the slower sections for CI fail-fast mode." },
  { q: "Is squash language/framework agnostic?", a: "Squash works with any model format: GGUF, Safetensors, PyTorch .pt/.pth/.bin, TensorFlow SavedModel, ONNX, and HuggingFace Hub. It reads model metadata, not model weights — so there's no GPU requirement and it works on any CI runner." },
  { q: "How does the hallucination rate attestation work?", a: "squash hallucination-attest runs a curated probe set per domain (legal, medical, financial, code, general) against your model endpoint, scores faithfulness using token F1 + semantic similarity, and issues a signed certificate with your hallucination rate and 95% confidence interval. EU AI Act Article 13 requires transparency about AI output limitations — this is the documentation." },
];

const CITATIONS = [
  { ref: 1, text: "Grant Thornton, \"2026 AI Impact Survey,\" Q1 2026." },
  { ref: 2, text: "Industry AI governance research, \"Global AI hallucination losses,\" 2024." },
  { ref: 3, text: "Italian Data Protection Authority (Garante), OpenAI fine decision, January 2025." },
  { ref: 4, text: "EU AI Act implementation analysis, cost breakdown study, 2025." },
  { ref: 5, text: "JFrog Security Research, \"Malicious models on HuggingFace Hub,\" 2024." },
  { ref: 6, text: "Cybersecurity enterprise AI adoption research, \"Shadow AI in the enterprise,\" 2025." },
];

// ─── Small helpers ─────────────────────────────────────────────────────────

function TerminalDots() {
  return (
    <>
      <div className="terminal-dot bg-red-500 opacity-80" />
      <div className="terminal-dot bg-yellow-500 opacity-80" />
      <div className="terminal-dot bg-green-500 opacity-80" />
    </>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <p className="section-label mb-4">{children}</p>;
}

function FeatureCard({ num, title, cmd, problem, how }: { num: string; title: string; cmd: string; problem: string; how: string }) {
  return (
    <div className="bg-[#0d1421] border border-[#1a2540] rounded-xl p-6 hover-glow-card flex flex-col gap-4 h-full">
      <div className="flex items-start gap-3">
        <span className="feature-num mt-0.5">{num}</span>
        <h3 className="font-semibold text-[#f1f5f9] text-base leading-snug">{title}</h3>
      </div>
      <div className="terminal rounded-lg text-xs">
        <div className="terminal-header gap-1.5 py-1.5"><TerminalDots /></div>
        <pre className="px-4 py-2.5 text-[#4ade80] overflow-x-auto whitespace-pre font-mono text-xs leading-relaxed">
          <span className="text-[#475569]">$ </span>{cmd}
        </pre>
      </div>
      <p className="text-[#f87171] text-sm leading-relaxed">
        <span className="font-semibold">Problem: </span>{problem}
      </p>
      <p className="text-[#94a3b8] text-sm leading-relaxed flex-1">{how}</p>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function Home() {
  const frameworksDouble = [...FRAMEWORKS, ...FRAMEWORKS];

  return (
    <div className="min-h-screen" style={{ background: "#080c14" }}>

      {/* ── Urgency Bar ─────────────────────────────────────────────────── */}
      <div className="urgency-bar border-b border-red-900/60 py-2 px-4 text-center text-sm" style={{ background: "rgba(127,29,29,0.55)" }}>
        <span className="urgency-dot inline-block w-2 h-2 rounded-full bg-red-400 mr-2" />
        <span className="text-red-200 font-semibold">EU AI Act enforcement</span>
        <span className="text-[#475569] mx-2">·</span>
        <span className="text-red-100 font-bold font-mono">Aug 02 2026</span>
        <span className="text-[#475569] mx-2">·</span>
        <Countdown />
        <span className="text-[#475569] mx-2">·</span>
        <span className="text-red-300">up to €35M / 7% global turnover</span>
      </div>

      {/* ── Navigation ──────────────────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 border-b border-[#1a2540]" style={{ background: "rgba(17,25,39,0.92)", backdropFilter: "blur(12px)" }}>
        <div className="max-w-7xl mx-auto px-6 py-3.5 flex items-center justify-between">
          <a href="#" className="flex items-center">
            <span className="text-[22px] font-black tracking-tight text-white leading-none select-none">
              squas<span className="logo-h">h</span>
            </span>
          </a>
          <div className="hidden md:flex items-center gap-7 text-sm text-[#94a3b8]">
            <a href="#product"  className="hover:text-white transition-colors duration-200">Product</a>
            <a href="#problem"  className="hover:text-white transition-colors duration-200">Problem</a>
            <a href="#features" className="hover:text-white transition-colors duration-200">Features</a>
            <a href="#pricing"  className="hover:text-white transition-colors duration-200">Pricing</a>
            <a href="https://docs.squash.works" className="hover:text-white transition-colors duration-200">Docs</a>
            <a href="https://github.com/konjoai/squash/blob/main/CHANGELOG.md" className="hover:text-white transition-colors duration-200">Changelog</a>
          </div>
          <a href="https://github.com/konjoai/squash" className="flex items-center gap-1.5 bg-[#22c55e] hover:bg-[#16a34a] text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors duration-200">
            <span className="font-mono text-xs opacity-75">pip install</span>
            <span>→</span>
          </a>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────────────── */}
      <section id="product" className="hero-grid relative px-6 pt-24 pb-20 overflow-hidden noise-overlay">
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse 80% 50% at 50% 0%, rgba(34,197,94,0.07) 0%, transparent 70%)" }} />
        {/* Floating decorative badges */}
        <div className="hidden xl:block absolute left-8 top-40 float-badge opacity-60">
          <div className="bg-[#0d1421] border border-[#1a2540] rounded-xl px-4 py-3 text-xs font-mono">
            <div className="text-[#22c55e] font-bold mb-1">✓ PASS</div>
            <div className="text-[#475569]">eu-ai-act · 0 violations</div>
          </div>
        </div>
        <div className="hidden xl:block absolute right-8 top-56 float-badge opacity-60" style={{ animationDelay: "1.5s" }}>
          <div className="bg-[#0d1421] border border-[#1a2540] rounded-xl px-4 py-3 text-xs font-mono">
            <div className="text-[#22c55e] font-bold mb-1">Rekor ✓</div>
            <div className="text-[#475569]">log #144,821,047</div>
          </div>
        </div>

        <div className="relative max-w-5xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 bg-[#0d1421] border border-[#1a2540] rounded-full px-4 py-1.5 text-sm text-[#94a3b8] mb-8 font-mono">
            <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-pulse" />
            Apache 2.0 · 5,175+ tests · v2.7.0
          </div>

          <h1 className="font-black text-[#f1f5f9] mb-6 leading-[1.05]" style={{ fontSize: "clamp(3rem, 8vw, 6rem)", letterSpacing: "-0.045em" }}>
            Squash violations,<br />
            <span className="gradient-text">not velocity.</span>
          </h1>

          <p className="text-xl text-[#94a3b8] mb-3 max-w-2xl mx-auto leading-relaxed">
            The{" "}
            <code className="font-mono text-[#4ade80] bg-[#0d1421] border border-[#1a2540] px-1.5 py-0.5 rounded text-base">pytest</code>
            {" "}of AI compliance. EU AI Act Annex IV in 10 seconds.
            Fails your CI build on violations. Ships in any pipeline.
          </p>

          <div className="flex flex-wrap justify-center gap-3 mb-10 mt-7">
            {[["10s","p50 attestation"],["12/12","Annex IV sections"],["10+","policy frameworks"],["0","config files required"]].map(([val, label]) => (
              <div key={label} className="stat-pill text-left">
                <div className="text-[#22c55e] font-black font-mono text-lg leading-none mb-0.5">{val}</div>
                <div className="text-[#475569] text-xs">{label}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-14">
            <div className="terminal terminal-hero flex items-center gap-3 px-5 py-3 select-all">
              <span className="text-[#475569] font-mono text-sm">$</span>
              <span className="text-[#22c55e] font-mono text-sm">pip install squash-ai</span>
              <span className="cursor-blink" />
            </div>
            <a href="https://github.com/konjoai/squash" className="bg-[#22c55e] hover:bg-[#16a34a] text-white px-7 py-3 rounded-lg font-bold text-base transition-colors duration-200 whitespace-nowrap">
              Get started free →
            </a>
          </div>

          {/* Animated typing terminal */}
          <TypingTerminal
            lines={HERO_TERMINAL_LINES}
            title="squash attest ./bert-base --policy eu-ai-act --sign"
            speed={14}
            lineDelay={90}
            className="max-w-3xl mx-auto scanline"
          />
        </div>
      </section>

      {/* ── Framework strip (marquee) ────────────────────────────────────── */}
      <section className="border-y border-[#1a2540] py-5 overflow-hidden" style={{ background: "#0a0f1a" }}>
        <p className="section-label text-center mb-4">Supported compliance frameworks</p>
        <div className="marquee-outer">
          <div className="marquee-track gap-3 px-3">
            {frameworksDouble.map((fw, i) => (
              <span
                key={i}
                className="inline-flex items-center gap-2 bg-[#0d1421] border border-[#1a2540] rounded-full px-4 py-2 text-xs font-mono font-semibold whitespace-nowrap shrink-0 hover:border-[#22c55e]/40 transition-colors duration-200"
                style={{ color: fw.color }}
              >
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: fw.color }} />
                {fw.name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Trust Bar ────────────────────────────────────────────────────── */}
      <section className="border-b border-[#1a2540] py-8 px-6" style={{ background: "#0d1421" }}>
        <div className="max-w-5xl mx-auto">
          <p className="section-label text-center mb-6">Trusted by ML teams at</p>
          <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-4">
            {["Acme ML Labs", "Stratos AI", "NovaSec", "Meridian Health AI", "Feldman & Koch", "Apex Robotics"].map((name) => (
              <span key={name} className="text-[#475569] font-semibold text-sm tracking-wide uppercase hover:text-[#94a3b8] transition-colors duration-200">
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── The Problem ─────────────────────────────────────────────────── */}
      <section id="problem" className="px-6 py-24">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <SectionLabel>The Problem</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-4" style={{ fontSize: "clamp(1.8rem, 4vw, 3rem)", letterSpacing: "-0.025em" }}>
              The regulatory clock is running.<br />Most teams aren&apos;t ready.
            </h2>
            <p className="text-[#94a3b8] max-w-xl mx-auto">These aren&apos;t hypothetical risks. They&apos;re reported numbers with citations.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {PROBLEM_STATS.map((s, i) => (
              <ScrollReveal key={s.ref} delay={i * 80}>
                <div className="bg-[#0d1421] border border-[#1a2540] rounded-xl p-6 hover-glow-card h-full">
                  <div className="font-black stat-shine mb-3 font-mono" style={{ fontSize: "clamp(2rem, 4vw, 2.75rem)", letterSpacing: "-0.03em" }}>
                    <AnimatedCounter value={s.stat} />
                  </div>
                  <p className="text-[#f1f5f9] text-sm leading-relaxed mb-3">
                    {s.label}<sup className="citation ml-1">[{s.ref}]</sup>
                  </p>
                  <p className="text-[#475569] text-xs font-mono">{s.source}</p>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── Regulatory Timeline ─────────────────────────────────────────── */}
      <section className="px-6 py-20 border-t border-[#1a2540]" style={{ background: "#0d1421" }}>
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <SectionLabel>Regulatory Calendar</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.6rem, 3.5vw, 2.5rem)", letterSpacing: "-0.025em" }}>
              The deadlines don&apos;t care about your roadmap.
            </h2>
          </div>
          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-4 md:left-1/2 top-0 bottom-0 w-px bg-[#1a2540] md:-translate-x-px" />
            <div className="space-y-8">
              {REGULATORY_TIMELINE.map((item, i) => (
                <ScrollReveal key={item.name} delay={i * 100} direction={i % 2 === 0 ? "left" : "right"}>
                  <div className={`flex gap-6 md:gap-0 ${i % 2 === 0 ? "md:flex-row" : "md:flex-row-reverse"}`}>
                    {/* Content */}
                    <div className={`flex-1 ${i % 2 === 0 ? "md:pr-12 md:text-right" : "md:pl-12"} pl-12 md:pl-0`}>
                      <div
                        className={`bg-[#080c14] border rounded-xl p-5 inline-block w-full md:w-auto md:max-w-sm transition-colors duration-200 hover:border-opacity-60`}
                        style={{ borderColor: item.urgent ? `${item.color}40` : "#1a2540" }}
                      >
                        <div className="font-mono text-xs font-bold mb-1" style={{ color: item.color }}>
                          {item.date}
                          {item.urgent && <span className="ml-2 bg-red-900/40 text-red-300 px-2 py-0.5 rounded-full text-[10px] uppercase tracking-wider">Upcoming</span>}
                        </div>
                        <div className="font-bold text-[#f1f5f9] mb-1">{item.name}</div>
                        <div className="text-[#94a3b8] text-xs leading-relaxed">{item.detail}</div>
                      </div>
                    </div>
                    {/* Dot — hidden on small, shown on md */}
                    <div className="hidden md:flex items-start justify-center w-8 shrink-0 pt-5">
                      <div
                        className="w-3 h-3 rounded-full border-2 shrink-0"
                        style={{ borderColor: item.color, background: item.urgent ? item.color : "#080c14", boxShadow: item.urgent ? `0 0 10px ${item.color}80` : "none" }}
                      />
                    </div>
                    {/* Mobile dot */}
                    <div className="md:hidden absolute left-3 pt-5">
                      <div className="w-3 h-3 rounded-full border-2" style={{ borderColor: item.color, background: item.urgent ? item.color : "#080c14" }} />
                    </div>
                    <div className="flex-1 hidden md:block" />
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── Without vs. With squash ─────────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <SectionLabel>The Difference</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              Without squash. With squash.
            </h2>
            <p className="text-[#94a3b8]">Every column is a real engineering hour someone is spending right now.</p>
          </div>
          <ScrollReveal>
            <div className="overflow-x-auto rounded-xl border border-[#1a2540]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1a2540]" style={{ background: "#0a0f1a" }}>
                    <th className="text-left px-6 py-4 text-[#94a3b8] font-semibold">Compliance Task</th>
                    <th className="text-left px-6 py-4 text-[#f87171] font-semibold">Without squash</th>
                    <th className="text-left px-6 py-4 text-[#22c55e] font-semibold">With squash</th>
                  </tr>
                </thead>
                <tbody>
                  {COMPARE_ROWS.map((row, i) => (
                    <tr key={row.feature} className={`border-b border-[#1a2540]/60 transition-colors duration-150 hover:bg-[#0d1421] ${i % 2 === 0 ? "" : "bg-[#080c14]/50"}`}>
                      <td className="px-6 py-4 text-[#f1f5f9] font-medium">{row.feature}</td>
                      <td className="px-6 py-4 text-[#f87171] font-mono text-xs">✗ {row.manual}</td>
                      <td className="px-6 py-4 text-[#22c55e] font-mono text-xs">✓ {row.squash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* ── How It Works ────────────────────────────────────────────────── */}
      <section className="px-6 py-24 border-t border-[#1a2540]" style={{ background: "#0d1421" }}>
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <SectionLabel>How It Works</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-4" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              30 seconds to compliant.
            </h2>
          </div>

          <div className="grid md:grid-cols-3 gap-8 mb-16">
            {[
              { n: "1", title: "Install", cmd: "pip install squash-ai", desc: "30 seconds. Zero configuration. Works with Python 3.9+. No GPU required." },
              { n: "2", title: "Attest", cmd: "squash attest ./model --policy eu-ai-act", desc: "Generates Annex IV, ML-BOM, SBOM, provenance, and a signed policy report in under 10 seconds." },
              { n: "3", title: "Gate", cmd: "# Fails CI on violation", desc: "Fails the build on policy violations. Cryptographically signed. Audit-ready. Zero false negatives." },
            ].map((step, i) => (
              <ScrollReveal key={step.n} delay={i * 120}>
                <div className="flex flex-col gap-4">
                  <div className="step-number">{step.n}</div>
                  <h3 className="text-xl font-bold text-[#f1f5f9]">{step.title}</h3>
                  <div className="terminal rounded-lg">
                    <div className="terminal-header py-1.5 gap-1.5"><TerminalDots /></div>
                    <pre className="px-4 py-3 text-xs text-[#4ade80] overflow-x-auto whitespace-pre font-mono">
                      <span className="text-[#475569]">$ </span>{step.cmd}
                    </pre>
                  </div>
                  <p className="text-[#94a3b8] text-sm leading-relaxed">{step.desc}</p>
                </div>
              </ScrollReveal>
            ))}
          </div>

          {/* Flow diagram */}
          <div className="bg-[#080c14] border border-[#1a2540] rounded-xl p-6 overflow-x-auto">
            <p className="section-label mb-5 text-center">What squash attest produces</p>
            <div className="flex items-center justify-center gap-3 flex-wrap text-sm font-mono">
              <div className="bg-[#0d1421] border border-[#1a2540] rounded-lg px-4 py-2.5 text-[#94a3b8]">Model Files</div>
              <span className="text-[#22c55e] font-bold text-lg">→</span>
              <div className="bg-[#0d1421] border border-[#1f3a28] rounded-lg px-4 py-2.5 text-[#22c55e] font-semibold">squash attest</div>
              <span className="text-[#22c55e] font-bold text-lg">→</span>
              <div className="flex flex-wrap gap-2">
                {["Annex IV", "ML-BOM", "SBOM", "Provenance", "Policy Report"].map((out) => (
                  <span key={out} className="bg-[#0d1421] border border-[#1a2540] rounded px-3 py-1.5 text-[#f1f5f9] text-xs hover:border-[#22c55e]/40 transition-colors">
                    {out}
                  </span>
                ))}
              </div>
              <span className="text-[#22c55e] font-bold text-lg">→</span>
              <div className="bg-[#14532d]/30 border border-[#22c55e]/40 rounded-lg px-4 py-2.5 text-[#22c55e] font-semibold">CI Gate</div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Features ────────────────────────────────────────────────────── */}
      <section id="features" className="px-6 py-24">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <SectionLabel>Features</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-4" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              Built for every stakeholder.
            </h2>
            <p className="text-[#94a3b8] max-w-xl mx-auto">
              18 production features across ML engineering, CISO operations, and audit/compliance workflows.
            </p>
          </div>

          {[
            { label: "For ML Engineers", features: ML_ENGINEER_FEATURES },
            { label: "For CISOs", features: CISO_FEATURES },
            { label: "For Auditors & Compliance", features: AUDITOR_FEATURES },
          ].map((group) => (
            <div key={group.label} className="mb-16">
              <div className="flex items-center gap-3 mb-8">
                <div className="h-px flex-1 bg-[#1a2540]" />
                <span className="section-label">{group.label}</span>
                <div className="h-px flex-1 bg-[#1a2540]" />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {group.features.map((f, i) => (
                  <ScrollReveal key={f.num} delay={i * 60}>
                    <FeatureCard {...f} />
                  </ScrollReveal>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Integrations ────────────────────────────────────────────────── */}
      <section className="px-6 py-24 border-t border-[#1a2540]" style={{ background: "#0d1421" }}>
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-14">
            <SectionLabel>Integrations</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              One line. Any pipeline.
            </h2>
            <p className="text-[#94a3b8]">Drop squash into your existing workflow. No new tools. No new logins.</p>
          </div>
          <IntegrationTabs blocks={INTEGRATIONS_CODE} />
        </div>
      </section>

      {/* ── Compliance Gauntlet output ───────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-14">
            <SectionLabel>The Compliance Gauntlet</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              One command. Six artifacts. Audit-ready.
            </h2>
            <p className="text-[#94a3b8] max-w-xl mx-auto">
              Every squash attestation produces a complete, cryptographically signed compliance bundle. Each artifact is independently verifiable.
            </p>
          </div>

          <ScrollReveal>
            <div className="terminal terminal-hero glow-green-sm max-w-2xl mx-auto">
              <div className="terminal-header">
                <TerminalDots />
                <span className="text-[#475569] text-xs ml-2 font-mono">squash attest ./my-model --policy eu-ai-act --sign</span>
              </div>
              <div className="p-6 output-tree">
                <div className="mb-4 text-[#4ade80] font-semibold">✓ Attestation PASS — 0 violations — eu-ai-act</div>
                <div className="space-y-1 text-sm">
                  {[
                    ["├──", "📄", "annex-iv.md",           "          ", "(18,299 B)", "  — ", "12/12 sections",        "tree-label"],
                    ["├──", "🔒", "cyclonedx-mlbom.json",  "  ",        "(48,392 B)", "  — ", "CycloneDX 1.7",         "tree-label"],
                    ["├──", "📦", "sbom.spdx.json",        "       ",   "(22,104 B)", "  — ", "SPDX 2.3 / NTIA",       "tree-label"],
                    ["├──", "✅", "attestation.json",      "      ",    "(3,841 B)",  "   — ", "signed · SHA-256 verified", "tree-pass"],
                    ["├──", "🔗", "provenance.json",       "       ",   "(1,203 B)",  "   — ", "SLSA Level 2",          "tree-label"],
                    ["└──", "📊", "policy-report.json",    "    ",      "(2,104 B)",  "   — ", "eu-ai-act PASS",        "tree-pass"],
                  ].map(([branch, icon, file, pad, size, dash, label, cls]) => (
                    <div key={file as string}>
                      <span className="text-[#475569]">{branch} </span>
                      <span>{icon} </span>
                      <span className="tree-file">{file}</span>
                      <span className="text-[#475569]">{pad}</span>
                      <span className="tree-size">{size}</span>
                      <span className="text-[#475569]">{dash}</span>
                      <span className={cls as string}>{label}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-5 pt-4 border-t border-[#1a2540] text-xs text-[#475569] font-mono">
                  <div>att://sha256:a3f1c8d9e2b4f701...</div>
                  <div>Rekor log index: 144,821,047</div>
                </div>
              </div>
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* ── Industry Benchmark Teaser ────────────────────────────────────── */}
      <section className="px-6 py-24 border-t border-[#1a2540]" style={{ background: "#0d1421" }}>
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <SectionLabel>Industry Benchmarks</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              How do you compare?
            </h2>
            <p className="text-[#94a3b8] max-w-xl mx-auto">
              Sector compliance baselines across 8 industries — 2,124 reference organisations.
              Run <code className="font-mono text-[#4ade80] bg-[#080c14] border border-[#1a2540] px-1.5 py-0.5 rounded text-sm">squash industry-benchmark report --sector financial-services</code> to see your percentile.
            </p>
          </div>

          <ScrollReveal>
            <div className="bg-[#080c14] border border-[#1a2540] rounded-xl p-6 space-y-5">
              {SECTOR_BENCHMARKS.map((s, i) => (
                <div key={s.sector}>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-[#94a3b8] text-sm font-medium">{s.sector}</span>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      <span className="text-[#475569]">avg {s.score}/100</span>
                      <span style={{ color: s.color }} className="font-bold">p50 benchmark</span>
                    </div>
                  </div>
                  <div className="h-2 bg-[#1a2540] rounded-full overflow-hidden">
                    <div
                      className="bench-bar h-full"
                      style={{ "--bar-width": `${s.score}%`, animationDelay: `${i * 150}ms` } as React.CSSProperties}
                    />
                  </div>
                </div>
              ))}
              <p className="text-[#475569] text-xs font-mono pt-2 border-t border-[#1a2540]">
                Source: KPMG AI Governance 2024 · Accenture AI Compliance Index 2024 · MIT Sloan AI Risk 2025
              </p>
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* ── Testimonials ────────────────────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-14">
            <SectionLabel>Social Proof</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.5rem)", letterSpacing: "-0.025em" }}>
              From teams who shipped compliance.
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {TESTIMONIALS.map((t, i) => (
              <ScrollReveal key={i} delay={i * 80}>
                <div className="testimonial-card h-full">
                  <div className="text-[#22c55e] text-3xl font-black leading-none mb-4 opacity-40">&quot;</div>
                  <p className="text-[#f1f5f9] text-base leading-relaxed mb-5 italic">{t.quote}</p>
                  <div className="flex items-center gap-3 pt-4 border-t border-[#1a2540]">
                    <div className="w-9 h-9 rounded-full bg-[#1a2540] border border-[#22c55e]/30 flex items-center justify-center text-xs font-bold text-[#22c55e] shrink-0">
                      {t.avatar}
                    </div>
                    <div>
                      <div className="text-[#f1f5f9] text-sm font-semibold">{t.name}</div>
                      <div className="text-[#475569] text-xs">{t.org}</div>
                    </div>
                  </div>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pricing ─────────────────────────────────────────────────────── */}
      <section id="pricing" className="px-6 py-24 border-t border-[#1a2540]" style={{ background: "#0d1421" }}>
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-14">
            <SectionLabel>Pricing</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", letterSpacing: "-0.025em" }}>
              Start free. Scale when it matters.
            </h2>
            <p className="text-[#94a3b8]">The full CLI is free forever. Cloud features unlock as your team scales.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 items-start">
            {PRICING_TIERS.map((plan, i) => (
              <ScrollReveal key={plan.name} delay={i * 60}>
                <div className={`rounded-xl p-5 flex flex-col border transition-all duration-200 hover-lift ${plan.highlight ? "bg-[#0a1a10] border-[#22c55e] glow-green" : "bg-[#080c14] border-[#1a2540]"}`}>
                  {plan.highlight && (
                    <div className="text-center mb-3">
                      <span className="bg-[#22c55e] text-white text-xs font-black font-mono tracking-widest px-2.5 py-1 rounded-full">{plan.badge}</span>
                    </div>
                  )}
                  <h3 className={`font-bold text-base mb-1 ${plan.highlight ? "text-[#4ade80]" : "text-[#f1f5f9]"}`}>{plan.name}</h3>
                  <div className="mb-0.5">
                    <span className="text-2xl font-black text-white">{plan.price}</span>
                    <span className="text-[#94a3b8] text-sm">{plan.period}</span>
                  </div>
                  <div className="text-[#475569] text-xs font-mono mb-5">{plan.attestations}</div>
                  <ul className="space-y-2 flex-1 mb-6">
                    {plan.features.map((f) => (
                      <li key={f} className="text-xs text-[#94a3b8] flex items-start gap-2">
                        <span className="text-[#22c55e] mt-0.5 shrink-0 font-bold">✓</span>
                        {f}
                      </li>
                    ))}
                  </ul>
                  <a href={plan.ctaHref} className={`text-center py-2.5 rounded-lg font-semibold text-sm transition-colors duration-200 ${plan.highlight ? "bg-[#22c55e] hover:bg-[#16a34a] text-white" : "bg-[#111927] hover:bg-[#1a2540] text-[#94a3b8] hover:text-white border border-[#1a2540]"}`}>
                    {plan.cta}
                  </a>
                </div>
              </ScrollReveal>
            ))}
          </div>
          <p className="text-center text-[#475569] text-sm mt-8">
            All plans include a 14-day free trial. No credit card required to start.
          </p>
        </div>
      </section>

      {/* ── FAQ ─────────────────────────────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-14">
            <SectionLabel>FAQ</SectionLabel>
            <h2 className="font-black text-[#f1f5f9] mb-3" style={{ fontSize: "clamp(1.8rem, 4vw, 2.5rem)", letterSpacing: "-0.025em" }}>
              Common questions.
            </h2>
          </div>
          <FAQAccordion items={FAQ_ITEMS} />
        </div>
      </section>

      {/* ── Final CTA ────────────────────────────────────────────────────── */}
      <section className="px-6 py-28 border-t border-[#1a2540] text-center relative overflow-hidden" style={{ background: "#0d1421" }}>
        {/* Radial glow */}
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse 60% 50% at 50% 100%, rgba(34,197,94,0.06) 0%, transparent 70%)" }} />
        <div className="max-w-3xl mx-auto relative">
          <div className="mb-6">
            <p className="section-label mb-3">Time remaining until enforcement</p>
            <div className="flex justify-center">
              <div className="bg-[#080c14] border border-[#1a2540] rounded-xl px-8 py-4 inline-block glow-green">
                <Countdown />
              </div>
            </div>
          </div>

          <h2 className="font-black text-[#f1f5f9] mb-5 leading-[1.1]" style={{ fontSize: "clamp(2rem, 5vw, 3.5rem)", letterSpacing: "-0.035em" }}>
            Ship compliance before the<br />
            <span className="gradient-text">deadline ships you.</span>
          </h2>
          <p className="text-[#94a3b8] text-lg mb-10 max-w-xl mx-auto leading-relaxed">
            Every week of delay is regulatory exposure you are carrying. Squash runs in CI in 10 seconds. The first attestation is free.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <div className="terminal terminal-hero px-6 py-3.5 select-all flex items-center gap-3">
              <span className="text-[#475569] font-mono text-sm">$</span>
              <span className="text-[#22c55e] font-mono text-sm">pip install squash-ai &amp;&amp; squash demo</span>
            </div>
            <a href="https://github.com/konjoai/squash" className="bg-[#22c55e] hover:bg-[#16a34a] text-white px-8 py-3.5 rounded-lg font-bold text-base transition-colors duration-200 whitespace-nowrap">
              Get started free →
            </a>
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer className="border-t border-[#1a2540] px-6 py-14" style={{ background: "#080c14" }}>
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-10 mb-12">
            <div className="col-span-2 md:col-span-1">
              <div className="text-[22px] font-black tracking-tight text-white leading-none mb-3 select-none">squas<span className="logo-h">h</span></div>
              <p className="text-[#475569] text-sm leading-relaxed mb-4">Automated EU AI Act compliance for ML teams. Open-core. CI-native. Developer-first.</p>
              <p className="text-[#22c55e] text-xs font-mono opacity-60">squash.works</p>
            </div>
            <div>
              <div className="text-xs font-semibold text-[#94a3b8] uppercase tracking-widest mb-4">Product</div>
              <ul className="space-y-2.5 text-sm text-[#475569]">
                <li><a href="#product" className="hover:text-[#94a3b8] transition-colors duration-200">Features</a></li>
                <li><a href="#pricing" className="hover:text-[#94a3b8] transition-colors duration-200">Pricing</a></li>
                <li><a href="https://docs.squash.works" className="hover:text-[#94a3b8] transition-colors duration-200">Documentation</a></li>
                <li><a href="https://github.com/konjoai/squash/blob/main/CHANGELOG.md" className="hover:text-[#94a3b8] transition-colors duration-200">Changelog</a></li>
                <li><a href="https://status.squash.works" className="hover:text-[#94a3b8] transition-colors duration-200">Status</a></li>
              </ul>
            </div>
            <div>
              <div className="text-xs font-semibold text-[#94a3b8] uppercase tracking-widest mb-4">Open Source</div>
              <ul className="space-y-2.5 text-sm text-[#475569]">
                <li><a href="https://github.com/konjoai/squash" className="hover:text-[#94a3b8] transition-colors duration-200">GitHub</a></li>
                <li><a href="https://github.com/konjoai/squash/blob/main/LICENSE" className="hover:text-[#94a3b8] transition-colors duration-200">Apache 2.0</a></li>
                <li><a href="https://github.com/konjoai/squash/issues" className="hover:text-[#94a3b8] transition-colors duration-200">Issues</a></li>
                <li><a href="https://pypi.org/project/squash-ai" className="hover:text-[#94a3b8] transition-colors duration-200">PyPI</a></li>
              </ul>
            </div>
            <div>
              <div className="text-xs font-semibold text-[#94a3b8] uppercase tracking-widest mb-4">Contact</div>
              <ul className="space-y-2.5 text-sm text-[#475569]">
                <li><a href="mailto:hello@squash.works" className="hover:text-[#94a3b8] transition-colors duration-200">hello@squash.works</a></li>
                <li><a href="https://konjo.ai" className="hover:text-[#94a3b8] transition-colors duration-200">Konjo AI</a></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-[#1a2540] pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-[#475569] text-sm">© 2026 Konjo AI · squash.works · Apache 2.0</p>
            <p className="text-[#1a2540] text-sm font-mono hover:text-[#475569] transition-colors duration-500">ቆንጆ · 根性 · 康宙 · squash.works</p>
          </div>
        </div>

        <div className="max-w-7xl mx-auto mt-10 pt-8 border-t border-[#1a2540]/50">
          <p className="section-label mb-4 text-[#475569]">Citations</p>
          <ol className="space-y-1.5">
            {CITATIONS.map((c) => (
              <li key={c.ref} className="text-[#475569] text-xs font-mono flex gap-2">
                <span className="text-[#22c55e] shrink-0">[{c.ref}]</span>
                <span>{c.text}</span>
              </li>
            ))}
          </ol>
        </div>
      </footer>
    </div>
  );
}
