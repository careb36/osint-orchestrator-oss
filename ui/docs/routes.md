# Route map and shell conventions

This document captures the top-level route map for the UI2 super-app shell so contributors can add features without creating a second navigation model.

## Shell structure

- The app is wrapped in a single `AppShell` layout.
- Top-level navigation is defined in `src/routes.ts` and is rendered from the same source of truth.
- Shared page layout/state primitives live in `src/components/PageState.tsx` and are expected to be reused by every major route.
- Runtime errors are caught by `src/components/ErrorBoundary.tsx`: one boundary around the whole app, and one around the routed views keyed by the route path, so a crashed view shows a fallback with *Try again* and *Back to the overview* while the shell keeps working, and changing route renders views again.
- Views are lazy-loaded (`React.lazy` in `src/App.tsx`, one chunk each); the libraries build into two vendor chunks (`vite.config.ts`).

## Route map

| Path | View | Navigation | Notes |
| --- | --- | --- | --- |
| `/` | Overview | Yes | Key figures, targets by attention, active runs, recent findings, service health. |
| `/targets` | Targets | Yes | Inventory with search, filters and sortable columns; Start run per row. |
| `/targets/:targetId` | Target detail | No | Target settings, risk trend, Start run, run history oldest first (timeline) with risk and change per run. |
| `/targets/:targetId/runs/:runId` | Run detail | No | Same view as `/runs/:runId`, reached from a target. |
| `/runs` | Runs | Yes | Recent execution history with search, filters and sortable columns, the risk of each run and what changed since the target's previous run. |
| `/alerts` | Alerts | Yes | Alert cases (one per run that met an alert rule) with target and state filters, sortable columns, and Acknowledge / Resolve actions recorded with the operator's name. |
| `/runs/:runId` | Run detail | No | Finding, evidence (searchable, sortable), delta, report and manifest tabs; artefact download. Handoff block: verify the target's evidence chain, download the signed bundle (`.zip`) or the PDF report, copy a plain-text handoff summary, start a follow-up run, and see the alerts the run dispatched. |
| `/cases` | Dossiers | Personal accounts | Create and browse shared-practice dossiers with identity and scope. |
| `/cases/:caseId` | Professional review | No | Source stages, reasoned evidence decisions, conclusion, immutable report versions and audit history. |
| `/account` | My account | Personal accounts | Own-password change; administrators also manage accountant access and resets. |
| `*` | Not found | No | Fallback empty-state view within the shell. |

Search, filter and sort state lives in the URL query string (`useListControls`):
`?q=…`, one key per filter, and `sort=<column>:<asc|desc>`. A value equal to
its default is dropped from the URL, so a plain route stays plain.

## Navigation conventions

The order of the route map above is the order of the rail, and it is
authoritative: `/` leads because it is the landing route, day-to-day views
follow in the order an operator uses them, and the personal destinations — the
only conditional ones — close the list (`Serial Position Effect`). A route that
asks to be in the navigation also needs a glyph in `RAIL_ICONS` (`src/App.tsx`);
the icon column has a fixed width so a missing glyph leaves a blank slot rather
than a label that jumps left of its neighbours.

`src/navigation.test.tsx` parses this document and compares it with
`APP_ROUTES`, so editing the order or the `personalOnly` flag here without
editing `src/routes.ts` (or the other way round) fails the suite.

## Contributor rules

1. Add a route once to the centralized route list in `src/routes.ts`, and a row
   to the route map above with the same path and navigation column.
2. Reuse `PageLayout`, `LoadingState`, `EmptyState`, and `ErrorState` for major views.
3. Keep navigation labels short and consistent with the existing shell.
4. If a new route is added, update the route list and tests before shipping.
5. A route in the navigation needs an entry in `RAIL_ICONS`, or the rail breaks
   its own alignment.
