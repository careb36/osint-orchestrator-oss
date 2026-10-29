# Documentation

Reference material for operators and maintainers. Everything here is in
English ([ADR-009](adr/ADR-009-documentation-language.md)); the only Spanish
translation is the top-level [README](../README.es.md).

New to the project? Start with the [README](../README.md), then read
[architecture](architecture.md).

## Guides

| Document | Read it when |
| --- | --- |
| [Architecture](architecture.md) | You need the pipeline, the module map or the reasons behind a design decision |
| [Configuration](configuration.md) | You are filling `.env` or `targets.yaml` and want every key and its default |
| [Operations](operations.md) | You run it: metrics, logs, alerts, retention, backups, troubleshooting |
| [Deploy](deploy.md) | You are taking it to production, with Compose or the Helm chart |
| [Compliance review workflow](compliance-workflow.md) | You use the professional identity, dossier and review features, or you are upgrading an automation-only install |
| [Threat model](threat-model.md) | You are reviewing the security posture or assessing a change against it |

## Decisions

Architecture decisions live in [`adr/`](adr/) and are the record of why the
system is shaped the way it is. Read the relevant one before proposing a change
that contradicts it.

| ADR | Decision |
| --- | --- |
| [001](adr/ADR-001-modular-monolith.md) | Modular monolith |
| [002](adr/ADR-002-stix-as-contract.md) | STIX 2.1 as the internal data contract |
| [003](adr/ADR-003-opencti-as-store.md) | OpenCTI as the single source of truth |
| [004](adr/ADR-004-language-policy.md) | Spanish for operators, English for code |
| [005](adr/ADR-005-api-auth-and-single-instance.md) | Static API keys, structured observability, single instance |
| [006](adr/ADR-006-oidc-proxy.md) | Optional OIDC proxy as a perimeter layer |
| [007](adr/ADR-007-evidence-chain.md) | Signed per-run evidence manifests, chained per target |
| [008](adr/ADR-008-optional-opencti-sink.md) | Optional OpenCTI sink via `OPENCTI_ENABLED` |
| [009](adr/ADR-009-documentation-language.md) | Documentation in English, README in English and Spanish |
| [010](adr/ADR-010-operator-dashboard.md) | Operator dashboard as a React SPA served by the API |
| [011](adr/ADR-011-external-stix-producers.md) | External STIX 2.1 producers as an intake path |
| [012](adr/ADR-012-personal-compliance-workflow.md) | Personal identities and professional dossiers |

## Other

| Document | Content |
| --- | --- |
| [Hackathon history](HACKATHON.md) | Build log and per-PR record, in English and Spanish |
| [`img/`](img/) | Dashboard screenshots used by both READMEs |

Contributing rules, the language policy and the commands CI runs are in
[CONTRIBUTING](../CONTRIBUTING.md) and [AGENTS](../AGENTS.md).
