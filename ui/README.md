# Frontend scaffold

This directory contains the React + TypeScript baseline for the OSINT Orchestrator UI.

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
