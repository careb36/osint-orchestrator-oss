# Frontend scaffold

This directory contains the React + TypeScript baseline for the OSINT Orchestrator UI.

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

## Auth and compatibility

The shell now uses a lightweight session model for protected routes and role-aware navigation. Operators sign in with mock demo credentials (viewer, operator, admin), while legacy API-key clients can continue working by storing the shared key in `sessionStorage` under `osint-operator-api-key`. The typed client reads this value and attaches it to requests as `X-API-Key` during the transition window.

The app expects the backend API at `/api` by default, which can be overridden with `VITE_API_BASE_URL`.
