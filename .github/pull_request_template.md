# Summary

<!-- What changed and why? -->

This PR adds the initial UI shell for the OSINT Orchestrator: a React + TypeScript app, router, error boundary, typed API client and baseline query setup. It also adds the product brief and UX acceptance checklist plus frontend lint/test/build jobs in CI.

## Validation

<!-- Commands executed and key output -->

```bash
cd ui
npm install --no-fund --no-audit
npm run lint
npm run test:run
npm run build
```

## Documentation impact (required)

- [x] docs were updated.
- [ ] API or operator-facing changes were reflected in `docs/` (and in both READMEs when the overview changes).
- [ ] New/changed settings were reflected in `.env.example`.

### Documentation notes

- Added `ui/PRODUCT_BRIEF.md` and `ui/UX_CHECKLIST.md` documenting the phase-one product and UX baselines.
- Added `ui/README.md` with local development and quality-gate instructions.
