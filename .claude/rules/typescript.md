---
paths:
  - "ui/**/*.ts"
  - "ui/**/*.tsx"
  - "ui/package.json"
---
# TypeScript (operator dashboard, `ui/`)

> Extends `workflow.md` for the React + Vite dashboard served at `/console`
> (ADR-010). Run `npm run lint`, `npm run test:run` and `npm run build` from
> `ui/` before a PR; lint runs with `--max-warnings 0` and the build runs
> `tsc`, so a warning or a type error is a red PR.

## Types

- Explicit parameter and return types on exported functions and on component
  props; let locals infer. Props are a named `type` or `interface`; no
  `React.FC`.
- No `any`. External or untrusted input is `unknown` and narrowed.
- String-literal unions over `enum`.
- API shapes live in `ui/src/types.ts` and mirror the backend's field names
  in snake_case (`orchestrator/api.py`, `orchestrator/models.py`). Keep the
  comment that says where a field comes from.

## Where things go

- Every request to the backend is a function in `ui/src/lib/api.ts`; every
  backend path is listed in `ui/src/lib/apiPaths.ts` (the dev proxy and its
  test read that list). No `fetch` in a component.
- Pure logic (filtering, sorting, formatting, tone mapping) lives in
  `ui/src/lib/*.ts` with a sibling `*.test.ts`. Components render; they do
  not compute.
- Reuse before writing: `PageLayout` and the loading / error / empty states
  in `components/PageState.tsx`, `StatusPill`, `SortableHeader`,
  `SearchField`, `useListControls` for URL-backed filters and sort,
  `useStartRun`. A new page copies the shape of `pages/RunsPage.tsx`.
- Routes are declared in `ui/src/routes.ts` and lazy-loaded in `App.tsx`;
  a new route is documented in `ui/docs/routes.md`.

## Operator text

- Every visible string goes through `t()` / `tv()` from `ui/src/i18n.tsx`,
  with the key present in both `en` and `es`; `i18n.test.ts` fails on a
  missing key. Persisted identifiers (`risk_level`, run status) are shown
  through `tv()`, never translated in place.
- Dates and durations go through `ui/src/lib/format.ts` with the active
  locale.

## State and effects

- Server state is `@tanstack/react-query` (`useQuery` / `useMutation`) with
  the existing query keys; no hand-rolled caches or `useEffect` fetches.
- Treat data as immutable: spread into new objects and arrays, never mutate
  a query result or a prop.
- The API key is stored only through the helpers in `ui/src/lib/api.ts`
  (`sessionStorage`, or `localStorage` when the operator asks to be
  remembered; ADR-005). Any other browser storage is a per-viewer convenience
  and every access is wrapped in try/catch, as those helpers are.
- No `console.log` in shipped code. The error boundary and
  `ui/src/lib/telemetry.ts` are the only places that write to the console.

## Accessibility

- Every control has a label; tables use `<th scope="col">`; live counts use
  `role="status"` with `aria-live="polite"`; filters sit in a landmark with
  `role="search"`. `a11y.test.tsx` runs axe over each page: a new page gets
  a case there.

## Tests

- Vitest with Testing Library. Backend responses come from
  `ui/src/test/mockApi.ts` (add a sample and a route there rather than
  mocking `fetch` in a test). Page tests in `App.test.tsx`, the end-to-end
  flow in `App.e2e.test.tsx`, pure logic next to its module.
- Test names state the behaviour; assert on what the operator sees (text,
  roles), not on implementation details.
