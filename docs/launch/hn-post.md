# Show HN: Squash — automated EU AI Act compliance for ML teams (open-source)

**Post date target:** Tuesday, July 14, 2026 · 9:00 AM ET

---

## Title options (pick one)

1. **Show HN: Squash – EU AI Act compliance automation that runs in CI/CD (open-source)**
2. **Show HN: I built the "pytest of AI compliance" because August 2 is coming fast**
3. **Show HN: Squash – automated Annex IV documentation for ML teams (10 seconds, Apache 2.0)**

**Recommended:** Option 1 — concrete, testable claim, open-source signal immediately visible.

---

## Body

```
Hi HN,

I built Squash — an open-source tool that automates EU AI Act compliance for ML teams.

The problem: EU AI Act enforcement for high-risk AI systems starts August 2, 2026.
Annex IV (the technical documentation requirement) alone takes 3–6 months to produce manually
per AI system. Companies are going to miss the deadline.

The solution: `pip install squash-ai && squash attest ./my-model`

In 10 seconds you get:
- CycloneDX 1.7 ML Bill of Materials
- SPDX 2.3 SBOM
- All 12 Annex IV documentation sections (as Markdown, HTML, or PDF)
- SLSA Level 2 provenance
- Policy evaluation: EU AI Act, NIST AI RMF, OWASP LLM Top 10, ISO 42001, FedRAMP, CMMC
- Cryptographic signing via Sigstore Rekor
- ModelScan security scan (pickle exploits, serialization attacks)

It integrates with GitHub Actions in one line:

  uses: konjoai/squash@v1
  with:
    model-path: ./my-model
    policy: eu-ai-act
    fail-on-violation: true

Other features:
- Prometheus /metrics endpoint (attestation counts, violation rates, latency)
- Slack/Teams webhook notifications on violations
- JIRA/Linear/GitHub Issues auto-ticketing
- FastAPI/Django compliance middleware (X-Squash-Compliant header)
- squash watch — re-attests on model file change
- GitLab CI, Jenkins, Kubernetes/Helm support
- 51 Python modules, 2,299 tests passing, Apache 2.0

I'm not a lawyer and this isn't legal advice — squash generates the *technical artifacts*
that documentation requires, not legal opinions. But it's the difference between spending
6 months and spending 10 seconds.

GitHub: https://github.com/konjoai/squash
Docs: https://docs.getsquash.dev
Try it: pip install squash-ai && squash demo

Happy to answer questions about the implementation — particularly around CycloneDX 1.7
ML-BOM format, SLSA provenance generation, or the EU AI Act Article 11 / Annex IV
technical documentation structure.
```

---

## Anticipated questions + answers

**Q: Does this actually make you EU AI Act compliant?**
A: Squash generates the technical artifacts that Annex IV documentation requires (model cards, risk assessments, data governance docs, monitoring documentation, etc.) and validates them against EU AI Act criteria. Whether a specific deployment is compliant requires legal review. Squash eliminates the engineering burden so you're not starting from scratch.

**Q: How does it know what's in my model?**
A: It reads model artifacts (safetensors, ONNX, PyTorch state dicts), training configs, requirements.txt, and code structure. For HuggingFace models it uses the hub API. It integrates with MLflow/W&B run metadata if present.

**Q: What's the business model?**
A: Open-core. Community tier is Apache 2.0, free forever. Paid tiers add the cloud REST API, multi-tenant dashboard, VEX (live CVE feed), SAML SSO, and SLA support. $299–$899/month.

**Q: EU AI Act only? What about other markets?**
A: NIST AI RMF for US federal contractors (FedRAMP, CMMC), ISO 42001 (international), OWASP LLM Top 10. The US executive orders on AI are also pointing toward similar documentation requirements.

**Q: Why not just use an existing compliance platform?**
A: Credo AI is $30K–$150K/year and requires a 3-month implementation. OneTrust is similar. Neither is developer-native. Squash is a CLI tool that runs in 10 seconds in CI/CD. Different buyer, different use case.

---

## Timing note

Post on Tuesday morning at 9am ET. EU AI Act angle creates natural urgency. The "Show HN" format is correct because we have a working product (not just an announcement).

Target: front page for 4–6 hours. 200+ upvotes. 50+ comments.

Follow-up comment at hour 2 with metrics from the demo run (output screenshot).
```
