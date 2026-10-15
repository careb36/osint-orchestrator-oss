# Project rules for Claude Code

`AGENTS.md` is the contract every agent and contributor works to. The files in
this directory restate the parts of it that matter while editing a given kind
of file, so they are in front of the agent at the moment it writes Python,
TypeScript or a pull request. They add no rule `AGENTS.md` does not already
imply; where the two disagree, `AGENTS.md` wins and this directory is wrong.

- `workflow.md`: always loaded. The quality gates, the review checklist and
  the git conventions.
- `python.md`: loaded for `orchestrator/`, `tests/` and the migrations.
- `typescript.md`: loaded for `ui/`.

The layout and the checklists are adapted from the `rules/common`,
`rules/python` and `rules/typescript` packs of
[ECC](https://github.com/affaan-m/ECC) (MIT License, Copyright (c) 2026 Affaan
Mustafa), rewritten against this repository's conventions: ECC's defaults that
this project does not use (a coverage threshold, black and isort, Zod, a
generic API envelope, its agent roster) were dropped rather than kept as
aspirations.
