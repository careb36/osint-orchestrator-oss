# Route map and shell conventions

This document captures the top-level route map for the UI super-app shell so contributors can add features without creating a second navigation model.

## Shell structure

- The app is wrapped in a single `AppShell` layout.
- Top-level navigation is defined in `src/routes.ts` and is rendered from the same source of truth.
- Global quick actions are defined in `src/routes.ts` and link directly to `/console` and `/docs`.
- Shared page layout/state primitives live in `src/components/PageState.tsx` and are expected to be reused by every major route.
- Global runtime errors are caught by `src/components/ErrorBoundary.tsx` and show a fallback state instead of crashing the shell.

## Route map

| Path | View | Navigation | Notes |
| --- | --- | --- | --- |
| `/` | Overview | Yes | Dashboard health and status snapshot. |
| `/targets` | Targets | Yes | Inventory and current target state. |
| `/runs` | Runs | Yes | Recent execution history. |
| `*` | Not found | No | Fallback empty-state view within the shell. |

## Contributor rules

1. Add a route once to the centralized route list in `src/routes.ts`.
2. Reuse `PageLayout`, `LoadingState`, `EmptyState`, and `ErrorState` for major views.
3. Keep navigation labels short and consistent with the existing shell.
4. If a new route is added, update the route list and tests before shipping.
