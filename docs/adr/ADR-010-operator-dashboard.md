# ADR-010: Operator dashboard as a React SPA served by the API

**Date:** 2026-10-15
**Status:** Accepted

## Context

Operators monitored targets, runs and evidence through the REST API, the
reports on disk and a minimal server-rendered console (ADR-005). As the run
output grew (qualified evidence, the signed manifest, the handoff bundle, the
run history) the console could not show it without becoming an application of
its own, and the public demo page duplicated part of it with a different
security model. The dashboard was built in pull requests #67 to #77; this ADR
records the decisions those changes made so they are not revisited by
accident.

## Decision

- The dashboard is a **React + TypeScript single-page application** in `ui/`,
  built with Vite and tested with Vitest and axe. It is the only operator
  interface: the server-rendered console and the public demo mode were retired.
- The **API serves the build** under `/console` from
  `orchestrator/static/ui-dist`, copied in by the `Dockerfile`. There is no
  second process, port or image: one deployment artefact (ADR-001, ADR-005).
- The dashboard is **a client of the public REST API and nothing else**. It
  holds no state the backend does not have; every view reads the same routes a
  script would (ADR-003: the backend stays the source of truth).
- **Access follows ADR-005.** The shell is public; every data route needs the
  static API key, kept by the browser in `sessionStorage` (or `localStorage` on
  request) and sent as `X-API-Key`. No users, sessions or roles exist in the
  backend, so none exist in the UI. The optional OIDC front door (ADR-006)
  stays in front of the whole API.
- **Hardening:** the shell is served with `default-src 'none'; script-src
  'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src
  'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` (the
  constants in `orchestrator/api.py`) and no inline script; CI rejects a build
  that violates it. Assets are immutable-cached; client routes that look like
  files answer 404.
- **Language follows ADR-004:** Spanish by default, English switch, one
  catalogue with parity enforced by a unit test; persisted identifiers (run
  status, risk level) are shown through `value.*` labels and never changed.
- **Scope:** a front door to existing capabilities. A feature that needs a new
  backend contract, a new collector or a change to the report-signing model is
  a backend decision first (`ui/docs/scope.md`).

## Consequences

- One image and one port to deploy and to protect; the compose and Helm shapes
  did not change.
- Operator identity (adoption KPIs, per-user audit) is deliberately out of
  scope until ADR-005 is revisited; `ui/docs/kpis.md` records which targets wait
  on it.
- A dashboard change that adds a route needs the backend route first and the
  dev-proxy prefix list (`ui/src/lib/apiPaths.ts`) updated.
