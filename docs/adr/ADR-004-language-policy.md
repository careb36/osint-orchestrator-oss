# ADR-004: Spanish for Operators, English for Code

> 🇪🇸 [Español](ADR-004-language-policy-es.md)

**Date:** 2026-09-04
**Status:** Accepted

## Context

The operators of this deployment work in Spanish. Reports and LLM synthesis are read by them, so producing that text in English imposes a translation step on every reading of every daily report.

At the same time the project has no stated language rule, and it has already drifted because of it: commit `e51aa1a` shipped a fix labelled "README language" whose actual content was reverting a Spanish fragment (`conector oficial`) that had leaked into the architecture diagram. A correction without a rule only postpones the next drift, and there are now two agents writing in this repository.

Three constraints bound the decision:

1. **The dependency is English.** The collector imports `openosint`, whose fork is being upstreamed to `OpenOSINT/OpenOSINT`, a public English-language project. Its vocabulary — `EntityGraph`, `Entity`, `budget` — reaches our call sites regardless of what we do.
2. **The domain vocabulary is English.** STIX 2.1 and OpenCTI define `domain-name`, `observable`, `relationship_type`, `x_opencti_score`. These are identifiers, not prose, and translating them would produce invalid data.
3. **Some strings are data, not text.** `Finding.risk_level` is persisted, compared and filtered on. Localising it at rest would silently break every comparison against it.

## Decision

Language is chosen by **audience**, not by file or repository.

**Spanish — anything a person reads as prose:**

- Daily reports (Markdown and PDF)
- LLM synthesis: `summary`, `risk_justification`, `suggested_pivots`
- API error details (`HTTPException.detail`)
- Operator-facing comments in `targets.example.yaml` — the file an operator edits by hand
  (`.env.example` stays English: it is a deployment file whose content is OpenCTI,
  Elasticsearch and RabbitMQ variables named in English)

**English — anything a developer or a machine reads:**

- Source code: identifiers, comments, docstrings
- Log messages — they sit next to English tracebacks and library output, and are read while debugging, not while operating
- Commit messages, PR descriptions, ADRs, README
- Enum values and any identifier persisted or compared: `RunStatus`, `CollectorName`, `Finding.risk_level`, STIX types and property names

### Mechanism

`orchestrator/i18n.py` holds a message catalogue keyed by message id, then language. `t(key, language=..., **kwargs)` renders one; `resolve_language()` picks the language from the most specific source available:

```text
target.language  →  settings.orchestrator_language (ORCHESTRATOR_LANGUAGE)  →  "es"
```

The setting is named `orchestrator_language`, not `language`, and the prefix is
load-bearing rather than cosmetic: pydantic-settings derives the environment
variable from the field name, so a bare `language` field would bind to
`LANGUAGE` — a standard GNU gettext variable exported on most Linux hosts and
inside many container images. Report language would then follow the host
locale, silently and only in some deployments. `test_setting_ignores_the_hosts_gettext_language`
holds that shut.

Per-target override mirrors the existing `llm:` field, for the case where one target's reports go to a different reader.

Supported languages are `es` and `en`. An unrecognised value is logged and skipped rather than raised: a typo in `targets.yaml` should degrade to another language, never take a scheduled collection down.

## Consequences

**Good.** Operators read reports in their own language without a per-report translation step. Code stays contributable and diffable against upstream, and anything we send there needs no language rewrite. The rule is written down, so the `e51aa1a` drift has a place to be settled rather than re-litigated per review.

**Bad.** Operator-facing strings must go through `t()` rather than being written inline, which is a small tax on every new message and one more thing a reviewer has to catch. Two languages in the catalogue is two chances to update only one — mitigated by `test_catalogue_is_complete`, which fails CI on any key missing a translation.

**Deferred.** Date and number localisation is not addressed; it becomes relevant when reports exist (Phase 2) and should be decided there, alongside the template engine. Adding a third language means auditing the catalogue, not changing the mechanism.

## Alternatives considered

**gettext / `.po` files.** The standard answer, and the right one at a scale this project does not have. It adds a compile step and tooling for a catalogue currently holding four keys. Revisit if the catalogue passes roughly fifty.

**Spanish throughout, including code.** Rejected on constraint 1: it creates a language boundary exactly where the orchestrator calls into OpenOSINT, and any code later contributed upstream would need rewriting. Tracebacks and STIX vocabulary stay English regardless, so the result is mixed anyway — the worst of both.

**English throughout, translate at the reader.** Rejected as the status quo that prompted this: it pushes recurring manual work onto the people the reports exist for.

## Amendment (2026-09-17): bilingual companions

Practice went further than the original rule: this README and these ADRs now
ship Spanish companions (`README.es.md`, `*-es.md`) and the business runbooks
under `docs/business/` are authored in Spanish. That is not a violation of
"English for developers" but its consequence — the *audience* test decides:

- The **English file is canonical** for READMEs and ADRs. A companion
  (`README.es.md`, `-es.md`) is a translation for Spanish-reading operators,
  stakeholders and reviewers, cross-linked from the canonical file's header.
- **Business/operator manuals** (`docs/business/*`) may be authored in
  Spanish first, with an English companion when the audience requires it.
- Companions must be updated in the same PR that changes the canonical file
  so both languages describe the same behavior.
- Everything the original rule assigns to English — code, comments,
  docstrings, logs, commits, persisted identifiers — stays English without
  exception.
