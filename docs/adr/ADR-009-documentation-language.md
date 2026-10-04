# ADR-009: Documentation in English, README in English and Spanish

**Date:** 2026-10-04
**Status:** Accepted

## Context

ADR-004 separates operator-facing output (Spanish by default, through
`orchestrator/i18n.py`) from developer-facing text (English). In practice every
README, ADR, contributing and security document had also grown a Spanish
companion. Each companion doubled the cost of a documentation change, and
translations that lag behind the canonical file are worse than none: a reader
cannot tell which version describes the running system.

## Decision

- Documentation is written in **English**: `docs/`, the ADRs, `CONTRIBUTING.md`,
  `SECURITY.md`, `CHANGELOG.md` and `AGENTS.md`.
- The **README** is the only translated document: `README.md` is canonical and
  `README.es.md` is its Spanish companion, updated in the same pull request and
  with the same sections.
- Reference material (settings, metrics, endpoints, operations) lives under
  `docs/` and is linked from both READMEs; it is not copied into them.
- Operator-facing output of the running system is unchanged: reports, alerts,
  API error details and model output follow ADR-004.

## Consequences

- One place to update per fact. The settings and metrics tables checked by the
  unit tests are in `docs/configuration.md` and `docs/operations.md`.
- A Spanish-reading operator gets the project overview in Spanish and the
  reference in English. The product itself still speaks Spanish to operators.
- The Spanish companions of the ADRs, `CONTRIBUTING` and `SECURITY` were
  removed rather than left to drift.
