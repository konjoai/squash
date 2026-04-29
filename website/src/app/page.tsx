import Countdown from "@/components/Countdown";

const DEMO_OUTPUT = `────────────────────────────────────────────────────
  Squash violations, not velocity.
  Running demo attestation on sample BERT model…
────────────────────────────────────────────────────

  Model:   bert-base-uncased (sample)
  Policy:  eu-ai-act

✅ Attestation PASSED

  Artifacts generated:
    cyclonedx-mlbom.json            48,392 bytes
    sbom.spdx.json                  22,104 bytes
    attestation.json                 3,841 bytes
    annex-iv-documentation.md       18,299 bytes
    provenance.json                  1,203 bytes

────────────────────────────────────────────────────
  This is squash. It runs in CI in <10 seconds.
  pip install squash-ai && squash attest ./your-model
────────────────────────────────────────────────────`;

const FEATURES = [
  {
    icon: "📄",
    title: "EU AI Act Annex IV",
    desc: "All 12 required technical documentation sections, auto-generated from your model artifacts.",
  },
  {
    icon: "🔒",
    title: "Cryptographic signing",
    desc: "Keyless Sigstore signing via Rekor transparency log. SLSA Level 1–3 provenance.",
  },
  {
    icon: "📦",
    title: "ML-BOM + SBOM",
    desc: "CycloneDX 1.7 ML Bill of Materials and SPDX 2.3 Software Bill of Materials.",
  },
  {
    icon: "🛡️",
    title: "10+ Policy Frameworks",
    desc: "EU AI Act · NIST AI RMF · ISO 42001 · OWASP LLM Top 10 · FedRAMP · CMMC",
  },
  {
    icon: "🔍",
    title: "ModelScan Security",
    desc: "Detects pickle exploits, serialization attacks, and unsafe ops before deployment.",
  },
  {
    icon: "⚡",
    title: "VEX + Drift Detection",
    desc: "Live CVE tracking and behavioral drift alerts when models deviate from baseline.",
  },
  {
    icon: "📊",
    title: "Prometheus Metrics",
    desc: "Grafana-compatible /metrics endpoint. Attestation counts, violations, and latency.",
  },
  {
    icon: "🔔",
    title: "Slack / Teams Alerts",
    desc: "Webhook notifications on violations, drift events, and CVE hits.",
  },
  {
    icon: "🎫",
    title: "Auto-ticketing",
    desc: "Policy violations auto-create JIRA, Linear, or GitHub Issues. No manual triage.",
  },
  {
    icon: "🔗",
    title: "CI/CD Native",
    desc: "GitHub Actions, GitLab CI, Jenkins, Azure DevOps. One line to add to any pipeline.",
  },
  {
    icon: "🏷️",
    title: "Compliance Badges",
    desc: "shields.io-compatible SVG badges. Paste in any README. Zero auth required.",
  },
  {
    icon: "🔌",
    title: "Framework Middleware",
    desc: "FastAPI / Django middleware. X-Squash-Compliant header on every inference response.",
  },
];

const PRICING = [
  {
    name: "Community",
    price: "Free",
    period: "",
    attestations: "10/month",
    highlight: false,
    cta: "Start free",
    ctaHref: "https://github.com/konjoai/squash",
    features: [
      "Full CLI (squash attest, demo, init, watch)",
      "CycloneDX 1.7 ML-BOM",
      "SPDX 2.3 SBOM",
      "10+ policy frameworks",
      "Sigstore signing",
      "Self-hosted",
      "Apache 2.0 license",
    ],
  },
  {
    name: "Professional",
    price: "$299",
    period: "/month",
    attestations: "200/month",
    highlight: false,
    cta: "Start trial",
    ctaHref: "https://api.getsquash.dev/billing/checkout",
    features: [
      "Everything in Community",
      "Cloud REST API",
      "Annex IV auto-generation (PDF)",
      "Drift alerts",
      "Slack / Teams webhooks",
      "Audit export",
      "Email support",
    ],
  },
  {
    name: "Startup",
    price: "$499",
    period: "/month",
    attestations: "500/month",
    highlight: true,
    badge: "Most Popular",
    cta: "Start trial",
    ctaHref: "https://api.getsquash.dev/billing/checkout",
    features: [
      "Everything in Professional",
      "VEX feed (read access)",
      "3 team members",
      "GitHub Issues auto-ticketing",
      "JIRA / Linear integration",
      "Priority email support",
    ],
  },
  {
    name: "Team",
    price: "$899",
    period: "/month",
    attestations: "1,000/month",
    highlight: false,
    cta: "Start trial",
    ctaHref: "https://api.getsquash.dev/billing/checkout",
    features: [
      "Everything in Startup",
      "Multi-tenant dashboard",
      "SAML SSO",
      "Human-in-the-loop workflows",
      "Full VEX feed",
      "Unlimited team members",
      "SLA support",
    ],
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    attestations: "Unlimited",
    highlight: false,
    cta: "Contact us",
    ctaHref: "mailto:wesleyscholl@gmail.com",
    features: [
      "Everything in Team",
      "On-premise deployment",
      "Air-gapped mode",
      "EU data residency",
      "Dedicated support",
      "Custom policy frameworks",
      "Security review",
    ],
  },
];

const INTEGRATIONS = [
  "GitHub Actions", "GitLab CI", "Jenkins", "Azure DevOps",
  "MLflow", "Weights & Biases", "HuggingFace", "LangChain",
  "SageMaker", "Vertex AI", "Ray Serve", "Kubernetes",
  "Slack", "Microsoft Teams", "JIRA", "Linear",
  "Prometheus", "Grafana", "FastAPI", "Django",
];

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Urgency banner */}
      <div className="urgency-bar bg-red-950 border-b border-red-900 py-2 px-4 text-center text-sm">
        <span className="text-red-300 font-medium">⏰ EU AI Act high-risk enforcement</span>
        <span className="text-slate-400 mx-2">·</span>
        <span className="text-red-200 font-bold">August 2, 2026</span>
        <span className="text-slate-400 mx-2">·</span>
        <Countdown />
        <span className="text-slate-400 mx-2">·</span>
        <span className="text-red-300">Non-compliance: up to €35M or 7% of global turnover</span>
      </div>

      {/* Nav */}
      <nav className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-2xl font-bold text-white">squash</span>
            <span className="text-xs bg-brand-600 text-white px-2 py-0.5 rounded-full font-mono">v1.0</span>
          </div>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <a href="#features" className="hover:text-white transition-colors">Features</a>
            <a href="#pricing" className="hover:text-white transition-colors">Pricing</a>
            <a href="https://docs.getsquash.dev" className="hover:text-white transition-colors">Docs</a>
            <a href="https://github.com/konjoai/squash" className="hover:text-white transition-colors">GitHub</a>
            <a
              href="https://github.com/konjoai/squash"
              className="bg-brand-600 hover:bg-brand-500 text-white px-4 py-2 rounded-lg font-medium transition-colors"
            >
              Get started free
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="px-6 py-24 text-center">
        <div className="max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-full px-4 py-2 text-sm text-slate-400 mb-8">
            <span className="w-2 h-2 rounded-full bg-brand-500 animate-pulse"></span>
            Open-core · Apache 2.0 · 2,299 tests passing
          </div>

          <h1 className="text-5xl md:text-7xl font-bold mb-6 leading-tight">
            <span className="gradient-text">Squash violations,</span>
            <br />
            <span className="text-white">not velocity.</span>
          </h1>

          <p className="text-xl text-slate-400 mb-4 max-w-2xl mx-auto">
            The <code className="text-brand-400 bg-slate-900 px-1 rounded">pytest</code> of AI compliance.
            EU AI Act Annex IV documentation in 10 seconds.
            Ships inside your CI/CD pipeline.
          </p>

          <p className="text-slate-500 mb-10 text-sm">
            51 modules · 10+ policy frameworks · GitHub Actions · GitLab CI · Jenkins · Kubernetes
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
            <div className="terminal px-4 py-3 text-brand-400 text-base font-mono select-all">
              pip install squash-ai
            </div>
            <a
              href="https://github.com/konjoai/squash"
              className="bg-brand-600 hover:bg-brand-500 text-white px-8 py-3 rounded-lg font-semibold text-lg transition-colors"
            >
              Start free →
            </a>
          </div>

          {/* Terminal demo */}
          <div className="terminal glow-green text-left max-w-3xl mx-auto">
            <div className="terminal-header">
              <div className="terminal-dot bg-red-500"></div>
              <div className="terminal-dot bg-yellow-500"></div>
              <div className="terminal-dot bg-green-500"></div>
              <span className="text-slate-500 text-xs ml-2 font-mono">squash demo</span>
            </div>
            <pre className="p-6 text-sm leading-relaxed text-slate-300 overflow-x-auto whitespace-pre">
              {DEMO_OUTPUT}
            </pre>
          </div>
        </div>
      </section>

      {/* Why Squash */}
      <section className="px-6 py-16 bg-slate-900/50">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">
            The math is simple
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Without Squash</th>
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">With Squash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {[
                  ["Annex IV documentation: 3–6 months engineering", "Annex IV documentation: 10 seconds"],
                  ["Compliance consultant: €150K–€400K/year", "Squash Professional: $299/month"],
                  ["Violation discovered in audit (€35M fine risk)", "Violation blocked in CI before merge"],
                  ["Manual risk assessment per model", "squash attest ./model --policy eu-ai-act"],
                  ["Zero observability on compliance posture", "squash_models_compliant_ratio 0.979 in Grafana"],
                ].map(([bad, good], i) => (
                  <tr key={i}>
                    <td className="py-3 px-4 text-red-400/80">{bad}</td>
                    <td className="py-3 px-4 text-brand-400">{good}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="px-6 py-24">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-4">
            Everything your AI compliance team needs
          </h2>
          <p className="text-slate-400 text-center mb-16 max-w-2xl mx-auto">
            From Annex IV generation to drift detection to Grafana dashboards — all in one pip install.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="bg-slate-900 border border-slate-800 rounded-xl p-6 hover:border-slate-600 transition-colors"
              >
                <div className="text-2xl mb-3">{f.icon}</div>
                <h3 className="font-semibold text-white mb-2">{f.title}</h3>
                <p className="text-slate-400 text-sm leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CI/CD code samples */}
      <section className="px-6 py-16 bg-slate-900/50">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">
            One line in any pipeline
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="terminal">
              <div className="terminal-header">
                <div className="terminal-dot bg-red-500"></div>
                <div className="terminal-dot bg-yellow-500"></div>
                <div className="terminal-dot bg-green-500"></div>
                <span className="text-slate-500 text-xs ml-2">GitHub Actions</span>
              </div>
              <pre className="p-5 text-sm text-slate-300 overflow-x-auto">{`- uses: konjoai/squash@v1
  with:
    model-path: ./my-model
    policy: eu-ai-act
    fail-on-violation: true`}</pre>
            </div>
            <div className="terminal">
              <div className="terminal-header">
                <div className="terminal-dot bg-red-500"></div>
                <div className="terminal-dot bg-yellow-500"></div>
                <div className="terminal-dot bg-green-500"></div>
                <span className="text-slate-500 text-xs ml-2">CLI / Python API</span>
              </div>
              <pre className="p-5 text-sm text-slate-300 overflow-x-auto">{`squash attest ./model \\
  --policy eu-ai-act \\
  --policy nist-ai-rmf \\
  --sign \\
  --fail-on-violation`}</pre>
            </div>
            <div className="terminal">
              <div className="terminal-header">
                <div className="terminal-dot bg-red-500"></div>
                <div className="terminal-dot bg-yellow-500"></div>
                <div className="terminal-dot bg-green-500"></div>
                <span className="text-slate-500 text-xs ml-2">FastAPI middleware</span>
              </div>
              <pre className="p-5 text-sm text-slate-300 overflow-x-auto">{`from squash.middleware import (
  SquashComplianceMiddleware
)

app.add_middleware(
  SquashComplianceMiddleware,
  model_id="my-model-v2",
  block_on_missing=True,
)`}</pre>
            </div>
            <div className="terminal">
              <div className="terminal-header">
                <div className="terminal-dot bg-red-500"></div>
                <div className="terminal-dot bg-yellow-500"></div>
                <div className="terminal-dot bg-green-500"></div>
                <span className="text-slate-500 text-xs ml-2">Prometheus metrics</span>
              </div>
              <pre className="p-5 text-sm text-slate-300 overflow-x-auto">{`# HELP squash_attestations_total
squash_attestations_total{
  result="passed",
  policy="eu-ai-act"
} 142

squash_models_compliant_ratio 0.979`}</pre>
            </div>
          </div>
        </div>
      </section>

      {/* Integrations */}
      <section className="px-6 py-16">
        <div className="max-w-5xl mx-auto text-center">
          <h2 className="text-3xl font-bold mb-4">Works with your entire stack</h2>
          <p className="text-slate-400 mb-12">20+ integrations — no new tools, no new logins.</p>
          <div className="flex flex-wrap justify-center gap-3">
            {INTEGRATIONS.map((name) => (
              <span
                key={name}
                className="bg-slate-900 border border-slate-700 text-slate-300 text-sm px-4 py-2 rounded-full"
              >
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="px-6 py-24 bg-slate-900/50">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-4">Simple, transparent pricing</h2>
          <p className="text-slate-400 text-center mb-16">
            Start free. Upgrade when you need more attestations or team features.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            {PRICING.map((plan) => (
              <div
                key={plan.name}
                className={`rounded-xl p-6 flex flex-col border ${
                  plan.highlight
                    ? "bg-brand-900/30 border-brand-600 glow-green"
                    : "bg-slate-900 border-slate-800"
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className={`font-bold text-lg ${plan.highlight ? "text-brand-400" : "text-white"}`}>
                    {plan.name}
                  </h3>
                  {plan.badge && (
                    <span className="text-xs bg-brand-600 text-white px-2 py-0.5 rounded-full">
                      {plan.badge}
                    </span>
                  )}
                </div>
                <div className="mb-1">
                  <span className="text-3xl font-bold text-white">{plan.price}</span>
                  <span className="text-slate-400 text-sm">{plan.period}</span>
                </div>
                <div className="text-slate-500 text-xs mb-6">{plan.attestations}</div>
                <ul className="space-y-2 flex-1 mb-8">
                  {plan.features.map((f) => (
                    <li key={f} className="text-sm text-slate-300 flex items-start gap-2">
                      <span className="text-brand-500 mt-0.5 shrink-0">✓</span>
                      {f}
                    </li>
                  ))}
                </ul>
                <a
                  href={plan.ctaHref}
                  className={`text-center py-2.5 rounded-lg font-medium text-sm transition-colors ${
                    plan.highlight
                      ? "bg-brand-600 hover:bg-brand-500 text-white"
                      : "bg-slate-800 hover:bg-slate-700 text-slate-200"
                  }`}
                >
                  {plan.cta}
                </a>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="px-6 py-24">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-4">
            96 days to enforcement. <span className="gradient-text">Ship compliance today.</span>
          </h2>
          <p className="text-slate-400 mb-10 text-lg">
            Every week of delay is regulatory risk you're carrying. Squash runs in CI in 10 seconds.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <div className="terminal px-6 py-3 text-brand-400 font-mono text-sm">
              pip install squash-ai &amp;&amp; squash demo
            </div>
            <a
              href="https://github.com/konjoai/squash"
              className="bg-brand-600 hover:bg-brand-500 text-white px-8 py-3 rounded-lg font-semibold transition-colors"
            >
              Get started free →
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 px-6 py-12">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="font-bold text-white mb-3">squash</div>
              <p className="text-slate-500 text-sm">
                Automated EU AI Act compliance. Open-core, developer-first.
              </p>
            </div>
            <div>
              <div className="font-semibold text-slate-300 mb-3 text-sm">Product</div>
              <ul className="space-y-2 text-sm text-slate-500">
                <li><a href="#features" className="hover:text-slate-300 transition-colors">Features</a></li>
                <li><a href="#pricing" className="hover:text-slate-300 transition-colors">Pricing</a></li>
                <li><a href="https://docs.getsquash.dev" className="hover:text-slate-300 transition-colors">Documentation</a></li>
                <li><a href="https://github.com/konjoai/squash/blob/main/CHANGELOG.md" className="hover:text-slate-300 transition-colors">Changelog</a></li>
              </ul>
            </div>
            <div>
              <div className="font-semibold text-slate-300 mb-3 text-sm">Integrations</div>
              <ul className="space-y-2 text-sm text-slate-500">
                <li><a href="https://github.com/konjoai/squash" className="hover:text-slate-300 transition-colors">GitHub Actions</a></li>
                <li><a href="https://github.com/konjoai/squash" className="hover:text-slate-300 transition-colors">GitLab CI</a></li>
                <li><a href="https://github.com/konjoai/squash" className="hover:text-slate-300 transition-colors">Jenkins</a></li>
                <li><a href="https://github.com/konjoai/squash" className="hover:text-slate-300 transition-colors">Kubernetes / Helm</a></li>
              </ul>
            </div>
            <div>
              <div className="font-semibold text-slate-300 mb-3 text-sm">Company</div>
              <ul className="space-y-2 text-sm text-slate-500">
                <li><a href="https://konjo.ai" className="hover:text-slate-300 transition-colors">Konjo AI</a></li>
                <li><a href="https://github.com/konjoai/squash" className="hover:text-slate-300 transition-colors">GitHub</a></li>
                <li><a href="mailto:wesleyscholl@gmail.com" className="hover:text-slate-300 transition-colors">Contact</a></li>
                <li><a href="https://github.com/konjoai/squash/blob/main/LICENSE" className="hover:text-slate-300 transition-colors">Apache 2.0</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-slate-800 pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-slate-600 text-sm">
              © 2026 Konjo AI · "Squash violations, not velocity."
            </p>
            <p className="text-slate-600 text-sm">
              Built with fighting spirit · <span className="text-brand-700">ቆንጆ · 根性 · 康宙</span>
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
