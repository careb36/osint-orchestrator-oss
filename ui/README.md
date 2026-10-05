# Operator dashboard

React + TypeScript + Vite single-page app served by the orchestrator at
`/console`. It reads the public API only; the backend owns every rule.

## UI2 planning and scope docs

- [Scope and boundaries](./docs/scope.md)
- [KPI baseline and targets](./docs/kpis.md)
- [Phased definition of done](./docs/dod.md)

## Local development

```bash
cd ui
npm install
npm run dev
```

## Quality gates

```bash
cd ui
npm run lint
npm run test:run
npm run build
```

## How it is served

The orchestrator serves the production build under `/console`
(`orchestrator/api.py`): Vite builds with `base: '/console/'`, the router uses
that prefix as its basename, and the Dockerfiles copy `ui/dist` to
`orchestrator/static/ui-dist`. Without that directory `/console` answers `503`
with the build steps.

The page is served with `script-src 'self'; style-src 'self'`: nothing inline,
nothing from another origin. CI fails the build if `index.html` gains an inline
script.

## Languages

Operator-facing text lives in `src/i18n.tsx`, Spanish and English side by
side; `src/i18n.test.ts` fails when a key misses a language or the two
languages disagree on placeholders. The locale is the stored choice
(`osint-operator-locale` in localStorage), else a supported browser language,
else Spanish. Persisted identifiers (run status, risk, relevance) keep their
English value in the data and are only labelled for display, as ADR-004 asks.

## Accessibility

`src/a11y.test.tsx` runs axe-core over every main view (WCAG 2.1 A/AA and
best-practice rules; colour contrast is skipped because jsdom has no layout
engine) and fails on any violation. Tables carry sortable headers with
`aria-sort`, filters are labelled search regions, live counts use
`aria-live="polite"`, failures use `role="alert"`, and the run tabs follow the
tablist pattern.

## Access

Access follows ADR-005: one static API key, the same one every API client uses.
There are no users or roles. On load the app probes `/targets`; a `401` shows
the key prompt, and a `401` on any later call clears the stored key and shows it
again. The key lives in `sessionStorage` under `osint-operator-api-key`, and in
`localStorage` too when the operator ticks "Remember on this browser". Every
request sends it as `X-API-Key`.

The API is same-origin by default. `npm run dev` keeps that: the Vite server
proxies `/health`, `/targets`, `/runs` and `/analytics` to the orchestrator at
`http://localhost:8000` (`VITE_DEV_API_TARGET` changes the target). Start the
orchestrator first (`uvicorn orchestrator.api:app --reload`), then
`npm run dev` and open `http://localhost:5173/console/`. `VITE_API_BASE_URL`
remains for calling another origin directly, which needs CORS on that origin.
