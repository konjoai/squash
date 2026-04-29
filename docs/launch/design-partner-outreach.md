# Design Partner Outreach Templates

**Goal:** Lock in 1 named design partner in closed beta before public launch (July 11).

**Ideal profile:** Boutique AI consulting firms that:
- Build AI/ML models for BFSI, healthcare, insurance, or government clients
- Currently charge clients for compliance documentation
- Face EU AI Act pressure from their clients
- Have 5–50 engineers

**The value prop to them:** Squash turns 6 weeks of billable compliance work into a 15-minute CLI run.
They either (a) pass the savings to the client and win deals on price, or (b) keep the billable rate and 
improve their own margin dramatically. Either way, they win.

---

## Email Template A — Cold outreach to AI consulting firm

**Subject:** EU AI Act compliance — you're probably charging clients 6 weeks for this

**To:** Head of AI / CTO / Founder at boutique AI consultancy

---

Hi [Name],

I'm building Squash — a tool that generates EU AI Act Annex IV compliance documentation for AI systems in 10 seconds instead of 6 months.

I'm reaching out because firms like yours are in an interesting position: you're already being asked by BFSI/healthcare clients to produce Annex IV documentation, and right now that's expensive billable work. Squash can either:

1. Cut your costs dramatically (better margins), or
2. Make you faster than competitors and win deals on delivery speed

The tool generates: CycloneDX ML-BOM, SPDX SBOM, all 12 Annex IV sections (as PDF), SLSA provenance, policy evaluation against EU AI Act + NIST AI RMF, and cryptographic signing via Sigstore.

It runs in CI/CD:
```
pip install squash-ai
squash attest ./my-model --policy eu-ai-act --annex-iv
```

I'm looking for 3–5 design partners to use it in production before the August 2 enforcement deadline. In exchange, I'll give you:
- Free Team tier access (normally $899/month)
- Direct access to me for implementation support
- Your logo on the website if you want it

Would a 20-minute call this week make sense?

Wesley Scholl
Founder, Konjo AI
[wesleyscholl@gmail.com](mailto:wesleyscholl@gmail.com)
[github.com/konjoai/squash](https://github.com/konjoai/squash)

---

## Email Template B — Warm intro / mutual connection

**Subject:** Intro: Squash — EU AI Act compliance automation (think pytest for your models)

---

Hi [Name],

[Mutual connection] suggested I reach out — you've been dealing with EU AI Act compliance questions from clients and I just shipped something that might be directly relevant.

Squash (github.com/konjoai/squash) automates EU AI Act Annex IV documentation. What your team currently spends 6 weeks on becomes a 15-minute CLI run. It produces signed, machine-verifiable compliance artifacts that satisfy Article 11 requirements.

Open-source, Apache 2.0. The paid tier adds a cloud API and multi-tenant dashboard.

I'm onboarding a few design partners before the August 2 deadline — would love your feedback on whether this fits your client workflow.

Happy to do a quick demo on your actual model stack if useful.

Wesley

---

## Email Template C — LinkedIn connection request

(150 characters max)

```
Building open-source EU AI Act compliance automation. Squash = pip install + 10 seconds → Annex IV docs. Would love your feedback — enforcement is 96 days out.
```

---

## Follow-up sequence

**Day 0:** Send initial email  
**Day 3:** Follow-up if no response — "Sending a quick follow-up. I shipped a demo command yesterday that shows the full output in 10 seconds: pip install squash-ai && squash demo. Would this help your team?"  
**Day 7:** Final follow-up — "Last reach-out on this. Happy to connect if timing is right for Q3. Either way, the tool is open-source at github.com/konjoai/squash."

---

## Target company list

### Tier 1 — Boutique AI/ML consulting (BFSI + healthcare focus)

Research and compile 20 firms that:
- Build custom AI for regulated industries
- Are EU-based or serve EU clients
- Have 5–50 engineers
- Are active on LinkedIn

Search terms:
- "AI consulting BFSI EU" on LinkedIn
- "machine learning compliance healthcare" 
- "custom AI financial services Europe"
- "responsible AI consulting EU"

### Tier 2 — MLOps consultancies

Firms that implement MLflow, Kubeflow, or Vertex AI for enterprise clients. They have:
- Direct access to client model pipelines
- Existing CI/CD relationships
- Billing relationships that make adding Squash easy

### Tier 3 — Independent ML engineers / freelancers

Individuals on Toptal, Upwork, or LinkedIn who do AI/ML for regulated industry clients.
Lower ARR but higher volume and faster to close.

---

## Design partner terms (verbal / email commitment is fine)

1. **Free Team tier** ($899/month value) for 12 months
2. **Weekly 30-minute check-in** during beta period
3. **Written feedback** on what works and what doesn't
4. **One quote** we can use in marketing (opt-in, they can review first)
5. **Optional:** logo on getsquash.dev/customers

We need from them:
- Test squash on at least one real model/project
- Give us honest feedback within 30 days
- Tell us what would make them pay for the Enterprise tier

---

## Pitch call script (20 minutes)

**Minutes 1–3:** The problem
"When did your clients first ask you about EU AI Act Annex IV? What's your current process for producing that documentation?"

**Minutes 4–8:** The demo
"Let me show you what squash does. I'm going to run it live on a sample model — this takes about 10 seconds."
→ Run `squash demo` in terminal share

**Minutes 9–14:** Their workflow
"How does this map to your current client delivery workflow? Where would this slot in?"
"What would you need to see for this to replace your current manual process?"

**Minutes 15–18:** Pricing conversation
"Right now I'm onboarding design partners at no cost — Team tier, free for 12 months. In exchange I want your honest feedback and a quote if the tool delivers value. Does that work?"

**Minutes 19–20:** Next step
"Can we do a live test on one of your actual models next week? I'll handle the setup."

---

## Success criteria

1 named company actively using squash by July 4, 2026.  
"Named" = they've agreed to a quote and are okay being referenced (even as "a leading AI consulting firm in Germany").

The quote to aim for:
> "Squash reduced our Annex IV documentation from 6 weeks to 15 minutes. 
> We're now including compliance automation in every client proposal."
