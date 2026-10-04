---
name: context-aware-code-review
description: Perform repository-aware code reviews that prioritize correctness, security, tests, and project constraints.
---

# Context-aware code review

Use this skill when reviewing pull requests or proposed patches in this repository.

## Review goals

1. Find high-confidence correctness bugs, security risks, and regression risks.
2. Verify changes follow repository guardrails from `AGENTS.md`.
3. Confirm tests and checks match the touched areas.
4. Keep feedback actionable, minimal, and prioritized by risk.

## Repository-specific checks

- Read `AGENTS.md` first and enforce its constraints.
- Keep architecture aligned with ADR decisions in `docs/adr/`.
- Ensure language policy is respected:
  - Developer-facing code/comments/logs/docs in English.
  - Operator-facing text localized via `orchestrator/i18n.py` with both `es` and `en` keys.
- Reject changes that add secrets or sensitive values to code, docs, fixtures, or examples.
- If new settings are introduced, require updates to:
  - `orchestrator/config.py`
  - `.env.example`
  - config tables in `README.md` and `README.es.md`
- If metrics are introduced, require updates to:
  - `orchestrator/metrics.py`
  - metrics tables in `README.md` and `README.es.md`

## Expected validation evidence

Ask for or verify output for:

- `ruff check orchestrator/ tests/unit/`
- `ruff format --check orchestrator/ tests/unit/`
- `pytest tests/unit/ -v -m "not integration"`
- If `deploy/helm/` changed:
  - `helm lint deploy/helm/osint-orchestrator --strict`
  - `helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0`

## Review output format

Return findings as a short list:

- **Severity**: High / Medium / Low
- **Location**: file and line(s)
- **Issue**: what is wrong and why it matters
- **Fix direction**: concise remediation guidance

If no material issues are found, explicitly say so and mention what was checked.
