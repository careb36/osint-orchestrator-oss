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

The app expects the backend API at `/api` by default, which can be overridden with `VITE_API_BASE_URL`.
