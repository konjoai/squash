# squash/dashboard

The Compliance Bridge — a Vite + React frontend for the squash compliance engine. Built on `@konjoai/ui`. Sprint 1 of the Konjo UI Initiative.

## Stack
React 19 · TypeScript · Vite 8 · Tailwind v4 (`@theme` config) · motion · Vitest 4 · `@konjoai/ui` (file: dep)

## Commands
```bash
npm install
npm run dev          # → http://localhost:5174 (proxies /api → :8002)
npm test             # vitest (30 tests)
npm run build        # tsc -b && vite build
npm run typecheck    # tsc -b --noEmit
```

## Critical Constraints
- React, react-dom, motion are **deduped** in [vite.config.ts](./vite.config.ts) so the package and the app share one singleton. Don't break that.
- `@konjoai/ui` is consumed via `file:../../konjoai-ui`. Tokens come from `@konjoai/ui/styles` — don't redefine.
- Mock data is the truth-floor. Every API call must have a mock fallback so the demo is always shippable.
- Severity levels match the Python backend: `info` · `warn` · `error` · `critical`. Don't invent new ones.
- Date math goes through [src/lib/dates.ts](./src/lib/dates.ts). Don't reach for `Date.now()` in views — pass `now` so tests can fix the clock.
- `npm test` and `npm run build` must stay green.

## File Map
| Path | Role |
|------|------|
| `src/App.tsx`                          | Composition + scan state machine |
| `src/views/ExecutiveSummary.tsx`       | Tri-ring + pills (CISO at-a-glance) |
| `src/views/ScanFlow.tsx`               | 6-stage animated pipeline + Run button |
| `src/views/FindingsList.tsx`           | Cinematic findings cascade |
| `src/views/CertificateBadge.tsx`       | SVG "Squash Verified" badge |
| `src/views/InsurancePreview.tsx`       | Munich Re / Coalition / Generic toggle |
| `src/views/RegulatoryTimeline.tsx`     | Horizontal regulatory horizon |
| `src/lib/types.ts`                     | TS mirrors of Python response shapes |
| `src/lib/api.ts`                       | Real API client (with auto-fallback to mocks) |
| `src/lib/mock.ts`                      | Mock fixtures + `frameworkScoresFromScan` |
| `src/lib/dates.ts`                     | Day-counting + relative time formatting |
| `src/index.css`                        | Imports `@konjoai/ui/styles`, adds severity tokens |

## Backend integration
- `/api/ollama-scan` — drives the scan + findings flow. Falls back to `MOCK_SCAN_RESULT` when unreachable.
- `/api/health` — surfaced via the status pill in the header.
- Future: `/api/attest`, `/api/verify`, `/api/genealogy`, `/api/copyright`, `/api/pdf-report`.
- Demo server CORS is wide-open (`*`); the Vite dev proxy is for ergonomic relative paths.

## When extending
- New view? Lives in `src/views/`, imported in `App.tsx`. Always ship a Vitest test.
- New backend shape? Mirror types in [src/lib/types.ts](./src/lib/types.ts), add a mock fixture, then add the API method to [src/lib/api.ts](./src/lib/api.ts) with a mock fallback.
- New severity? Don't. Map onto the four canonical levels.
- New design token? Add to `@konjoai/ui` (so all flagships inherit), not here.

## Sprint context
This is **Sprint 1** of the 10-sprint Konjo UI Initiative. Sprint 0 = `@konjoai/ui` foundation. Sprint 2 = miru "Mind of the Machine". This Bridge is calendar-critical: 89 days to EU AI Act enforcement (2026-08-02). Track A items A1 (Fly deploy), A3 (domain + Stripe), A4 (website live) gate full launch but the Bridge itself is shippable today.
