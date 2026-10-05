# Summary

This change adds a minimal locale layer to the React UI with Spanish as the default language and an English toggle. It also hardens the main shell for accessibility by adding skip links, visible focus styles, labeled navigation, and a basic Axe-based smoke test to enforce a zero-violation baseline.

## Validation

- `cd ui && npm run test:run -- --run src/App.test.tsx`
- `cd ui && npm run lint && npm run build`

## Documentation impact (required)

- [x] No documentation change needed (explain why below), **or** docs were updated.
- [ ] API or operator-facing changes were reflected in `docs/` (and in both READMEs when the overview changes).
- [ ] New/changed settings were reflected in `.env.example`.

### Documentation notes

Updated `ui/README.md` to document the default Spanish locale, English switch, and the Axe accessibility smoke test threshold.
