# squash · Compliance Bridge

The cinematic dashboard for **squash** — the pytest of AI compliance.

> EU AI Act · NIST AI RMF · ISO/IEC 42001 · OWASP LLM Top-10 · SLSA Build L3

A live, signed, board-room-ready view onto every model in your portfolio. Tri-ring risk gauge, animated scan pipeline, severity-tinted findings cascade, underwriter-ready insurance preview, certificate badges, and the regulatory horizon you're racing.

## Quick start

```bash
npm install
npm run dev      # → http://localhost:5174
npm test         # vitest (30 tests)
npm run build    # production build → dist/
```

To wire the dashboard to a live squash backend:

```bash
# In one terminal — start the demo server
cd /Users/wesleyscholl/squash
python demo/server.py        # binds 0.0.0.0:8002

# In another terminal — start the dashboard (proxies /api → :8002)
cd dashboard
npm run dev
```

When the server is unreachable the dashboard falls back to mock fixtures so the story is always whole.

## Stack

`React 19` · `TypeScript` · `Vite 8` · `Tailwind CSS v4` · `motion` · `Vitest`
Built on top of [`@konjoai/ui`](../../konjoai-ui) — the shared design system for the KonjoAI portfolio.

## What you'll see

| Section              | What it shows                                                           |
|----------------------|-------------------------------------------------------------------------|
| **Hero**             | The squash promise · violet/cyan/green tri-color statement              |
| **Executive Summary**| Tri-ring `<RiskRing>` + four pills: days-to-Aug-2 · findings · score · insurance |
| **Scan Flow**        | Six-stage `<StagePipeline>` (canonicalize → manifest → SBOM → policy → sign → verify) |
| **Findings**         | Cinematic cascade · severity-tinted cards · click to expand remediation |
| **Certificate**      | SVG-rendered "Squash Verified" badge · downloadable                     |
| **Insurance**        | Munich Re · Coalition · Generic underwriter formats                     |
| **Regulatory**       | Horizontal timeline · EU AI Act · ISO 42001 · Colorado · NYC LL 144     |

## Configuration

- `VITE_SQUASH_API` — base URL of the squash API (default: `""`, which leans on the Vite dev proxy or relative paths in production).
- The dev server proxies `/api` → `http://localhost:8002` (see [`vite.config.ts`](./vite.config.ts)).

## Tests

```bash
npm test
```

Covers: date arithmetic, framework score derivation, mock-fixture invariants, and behavioral tests for `<ExecutiveSummary>`, `<ScanFlow>`, `<FindingsList>`, `<RegulatoryTimeline>`. 30 tests, all green.

## Architecture notes

- **No state library** — `useState` + a single state machine in `App.tsx`. Konjo principle: 건조 (strip to essence).
- **No UI dependency on the live backend** — every endpoint has a typed mock so the dashboard is demo-able offline.
- **Single source of truth for tokens** — every color, every easing, every glass surface comes from `@konjoai/ui`. Squash extends with severity-specific overlays (`--color-sev-*`).
- **Animation is decoupled from network** — the scan pipeline runs on a 6-phase visual cadence regardless of API latency, so the user never sees a "stuck" or "instant" scan.

See [`CLAUDE.md`](./CLAUDE.md) for operating rules.
