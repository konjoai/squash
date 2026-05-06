# Changelog

All notable changes to `@squash/dashboard` are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/).

## [0.1.0] — 2026-05-06

### Added — Sprint 1: Compliance Bridge

The cinematic dashboard for squash. First slice — six views, full mock-fallback story, ready to demo with or without a live backend.

- **Repository scaffold** — Vite 8 + React 19 + TypeScript + Tailwind v4 + Vitest 4. Consumes `@konjoai/ui` via `file:../../konjoai-ui`. Reacts and motion are deduped at the resolver to share one singleton.
- **Six views**:
  - [`<Hero>`](./src/App.tsx) — violet/cyan/green Konjo tri-color statement.
  - [`<ExecutiveSummary>`](./src/views/ExecutiveSummary.tsx) — tri-ring `<RiskRing>` (Headline · EU AI Act · NIST AI RMF · OWASP LLM) + four pills (days-to-Aug-2, findings count, score, insurance readiness).
  - [`<ScanFlow>`](./src/views/ScanFlow.tsx) — six-stage animated pipeline (Canonicalize → Manifest → SBOM → Policy → Sign → Verify) with locking Run button, decoupled from API latency so the cadence is always cinematic.
  - [`<FindingsList>`](./src/views/FindingsList.tsx) — cinematic cascade reveal · severity-tinted cards · expand to show why + how-to-fix + citation link.
  - [`<CertificateBadge>`](./src/views/CertificateBadge.tsx) — SVG "Squash Verified" badge in compact (280×280) and full (720×260) forms · downloadable as `.svg`.
  - [`<InsurancePreview>`](./src/views/InsurancePreview.tsx) — Munich Re / Coalition / Generic underwriter formats · animated bars · maturity dial.
  - [`<RegulatoryTimeline>`](./src/views/RegulatoryTimeline.tsx) — horizontal timeline of EU AI Act 2026-08-02 (89 days), ISO/IEC 42001, Colorado AI Act, NYC LL 144, EU AI Act high-risk 2027-08-02.
- **API client** ([`src/lib/api.ts`](./src/lib/api.ts)) — typed wrapper for `/api/ollama-scan` and `/api/health`; transparent fallback to mocks when the server is unreachable.
- **Mock fixtures** ([`src/lib/mock.ts`](./src/lib/mock.ts)) — full `ScanResult` (two competing models with findings + remediations), `InsurancePackage` with all three underwriter formats, `frameworkScoresFromScan` for deriving 4-framework compliance scores from a model scan's findings.
- **Tests** — 30 Vitest cases covering: date arithmetic and milestone ordering, mock-fixture invariants, framework score derivation (clamping + per-framework attribution), and behavioral tests for `<ExecutiveSummary>`, `<ScanFlow>`, `<FindingsList>`, `<RegulatoryTimeline>`. All green.
- **Docs** — README, CLAUDE.md (operating rules), this changelog.

### Backend integration

- Vite dev server proxies `/api` → `http://localhost:8002` (the demo server). CORS is open on the demo server, so direct fetches also work.
- Set `VITE_SQUASH_API` to point at a remote API for production builds.

### Notes

- Sprint 1 is calendar-critical: **89 days** to EU AI Act GPAI enforcement (2026-08-02). The Bridge ships independent of Track A items A1/A3/A4 (Fly deploy, domain + Stripe, public website).
- All animation respects `prefers-reduced-motion`.
- The visual scan duration (6 × 480ms) is decoupled from the API call so a fast cached scan still feels intentional.
