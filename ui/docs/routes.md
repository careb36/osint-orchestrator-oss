# Route map and shell conventions

This document captures the top-level route map for the UI2 super-app shell so contributors can add features without creating a second navigation model.

## Shell structure

- The app is wrapped in a single `AppShell` layout.
- Top-level navigation is defined in `src/routes.ts` and is rendered from the same source of truth.
- Shared page layout/state primitives live in `src/components/PageState.tsx` and are expected to be reused by every major route.
- Global runtime errors are caught by `src/components/ErrorBoundary.tsx` and show a fallback state instead of crashing the shell.

## Route map

| Path | View | Navigation | Notes |
| --- | --- | --- | --- |
| `/` | Overview | Yes | Key figures, targets by attention, active runs, recent findings, service health. |
| `/targets` | Targets | Yes | Inventory with search, filters and sortable columns; Start run per row. |
| `/targets/:targetId` | Target detail | No | Target settings, risk trend, Start run, run history oldest first (timeline) with risk and change per run. |
| `/targets/:targetId/runs/:runId` | Run detail | No | Same view as `/runs/:runId`, reached from a target. |
| `/runs` | Runs | Yes | Recent execution history with search, filters and sortable columns, the risk of each run and what changed since the target's previous run. |
| `/runs/:runId` | Run detail | No | Finding, evidence (searchable, sortable), delta, report and manifest tabs; artefact download. |
| `*` | Not found | No | Fallback empty-state view within the shell. |

Search, filter and sort state lives in the URL query string (`useListControls`):
`?q=…`, one key per filter, and `sort=<column>:<asc|desc>`. A value equal to
its default is dropped from the URL, so a plain route stays plain.

## Contributor rules

1. Add a route once to the centralized route list in `src/routes.ts`.
2. Reuse `PageLayout`, `LoadingState`, `EmptyState`, and `ErrorState` for major views.
3. Keep navigation labels short and consistent with the existing shell.
4. If a new route is added, update the route list and tests before shipping.
