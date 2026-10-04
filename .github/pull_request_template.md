# Summary

This PR adds the UI production-readiness pieces for the operator console: bounded browser-side telemetry for API/auth and JS failures, plus a focused runbook/SOP in `docs/operations.md` covering smoke checks, incident triage, and rollback. The change stays within the Phase 6 acceptance criteria and does not alter unrelated backend behavior.

## Validation

```bash
cd /home/runner/work/osint-orchestrator-oss/osint-orchestrator-oss
ruff check orchestrator/ tests/unit/
ruff format --check orchestrator/ tests/unit/
python3 -m pytest tests/unit/test_operator_console.py -v
```

Output summary:
- `ruff check orchestrator/ tests/unit/` -> All checks passed
- `ruff format --check orchestrator/ tests/unit/` -> 94 files already formatted
- `python3 -m pytest tests/unit/test_operator_console.py -v` -> 8 passed in 0.79s

## Documentation impact (required)

- [x] No documentation change needed (explain why below), **or** docs were updated.
- [x] API or operator-facing changes were reflected in `docs/` (and in both READMEs when the overview changes).
- [ ] New/changed settings were reflected in `.env.example`.

### Documentation notes

- Updated `docs/operations.md` with UI smoke checks, frontend telemetry notes, incident triage, rollback, and release checklist/SOP.
- No new settings or environment variables were introduced for this phase, so `.env.example` changes were not required.
