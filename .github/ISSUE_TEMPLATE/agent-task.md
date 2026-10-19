---
name: Agent task
about: A self-contained task to delegate to the coding agent (assign it to Copilot to start it)
title: ""
labels: agent-task
assignees: ""
---

<!--
Write the issue so that a reviewer can check every line against the code.
The agent reads AGENTS.md first; do not repeat its rules here, only what is
specific to this task. Assign the issue to Copilot once it is complete.
-->

## Problem

<!-- What is wrong or missing today, with file paths and line references. -->

## What to do

<!-- Numbered steps in execution order. Name the module, function and
     behaviour for each one. Each step is an acceptance criterion. -->

1.

## Tests

<!-- Test file, test names and what each one asserts. -->

- `tests/unit/test_<module>.py::test_<name>` — asserts …

## Constraints

- Do not touch: <!-- files or directories that stay untouched -->
- No new dependencies.
- ADR-004: code, comments, logs and commits in English; operator-facing text
  through `orchestrator/i18n.py` with both `es` and `en`.
- Documentation in English under `docs/`; `README.es.md` mirrors `README.md` (ADR-009).

## Definition of done

- [ ] Every item under *What to do* is implemented as written.
- [ ] Every test under *Tests* exists and passes.
- [ ] PR body follows `.github/pull_request_template.md` and pastes the output of:
      `ruff check orchestrator/ tests/unit/`,
      `ruff format --check orchestrator/ tests/unit/`,
      `pytest tests/unit/ -q -m "not integration"`,
      `alembic upgrade head && alembic check` (temporary SQLite DB).
- [ ] Documentation impact checklist filled in.
