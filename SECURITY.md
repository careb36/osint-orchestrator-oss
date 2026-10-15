# Security Policy

## 1. Authorised use (the most important rule)

This orchestrator drives **live reconnaissance** (DNS, TLS, HTTP requests via
SpiderFoot; public-source pivoting via OpenOSINT; and, opt-in per target, web
search via Tavily, subdomain enumeration via Amass and social media analysis
via SocialOSINT) against whatever is listed in `targets.yaml`.

- Only add targets you **own** or hold **written authorisation** to assess.
- `authorization` and `purpose` are mandatory per target and are written into
  every run report as the audit trail for why the collection happened.
- The repository ships nothing that exploits, authenticates against, or
  otherwise interacts with a target beyond public-source collection. Do not
  add such code, even in tests or fixtures.
- Collection is bounded by design: OpenOSINT budgets (`max_depth`,
  `max_entities`, `max_tool_calls`), per-collector `timeout_seconds` and the
  Tavily call budget (`max_calls_per_run`) prevent runaway scans and spend.
- Amass `active` and `brute` modes send traffic to the target's own servers;
  they are off by default and need an authorisation that covers active probing.

## 2. Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately via GitHub's *Report a vulnerability* form (Security →
Advisories → "Report a vulnerability" on
`careb36/osint-orchestrator-oss`), or by e-mail to the repository owner. Include:

- affected version / commit SHA,
- reproduction steps or proof of concept,
- impact assessment,
- whether the issue is already public.

We aim to acknowledge reports within **5 business days** and to publish an
advisory with any fix. Security fixes are released and back-referenced in
[CHANGELOG.md](CHANGELOG.md).

## 3. Security model and hardening checklist

| Layer | Mechanism | Reference |
| --- | --- | --- |
| API access | Shared static API key (`X-API-Key` / `Bearer`), constant-time comparison, rotation by listing two keys | [ADR-005](docs/adr/ADR-005-api-auth-and-single-instance.md) |
| Human login (optional) | Keycloak + oauth2-proxy OIDC front door (`--profile auth`) | [ADR-006](docs/adr/ADR-006-oidc-proxy.md) |
| Webhook alerts | HMAC-SHA256 payload signature (`X-Orchestrator-Signature`) when `ALERT_WEBHOOK_SECRET` is set | [Operations → Alerts](docs/operations.md#alerts) |
| Evidence integrity | Per-run manifest with the SHA-256 of every artefact, HMAC-signed with `ORCHESTRATOR_SECRET_KEY` and chained per target; verifiable through the API or offline | [ADR-007](docs/adr/ADR-007-evidence-chain.md) |
| Untrusted content | Text collected from the internet reaches the LLM flattened and delimited as data; every value a model returns is validated before it is stored | `orchestrator/textsafe.py`, `orchestrator/synthesizer/` |
| Metrics | Label values are bounded; never an observable value, run id or error string | [Operations → Observability](docs/operations.md#observability) |
| Logs | JSON logs with request ids; no secret material is logged | `orchestrator/logging_config.py` |
| Retention | Nightly purge of runs/reports after `ORCHESTRATOR_RETENTION_DAYS` (default 90) | [Operations → Retention](docs/operations.md#retention) |
| Main branch | Ruleset requiring green CI (lint, unit tests, Helm chart, public-release guard) and forbidding force pushes | repository settings |

The 90-day default is operational. It is not a legal retention period: when
artifacts form part of AML/CFT evidence, configure the period your regulation
requires or use controlled external archival storage.

Before any deployment beyond a laptop:

- [ ] `ORCHESTRATOR_API_KEY` set (an empty key leaves the API **open**; a
      warning is logged at startup).
- [ ] `OPENCTI_ADMIN_PASSWORD`, `OPENCTI_ADMIN_TOKEN`, `MINIO_ROOT_PASSWORD`,
      `RABBITMQ_DEFAULT_PASS` and `KEYCLOAK_ADMIN_PASSWORD` set to generated
      values (`.env.example` ships them blank).
- [ ] `ORCHESTRATOR_SECRET_KEY` generated (`openssl rand -hex 32`) and backed
      up: it signs the evidence manifests, and a lost key means earlier runs
      can no longer be verified. An empty or default key logs a warning.
- [ ] `ALERT_WEBHOOK_SECRET` set if webhooks are used (payloads are unsigned
      without it).
- [ ] Host port 8000 firewalled or unpublished when the auth front door
      (8002) is the intended entry point.
- [ ] TLS terminated at a real proxy/ingress in production; the auth overlay
      defaults are development conveniences (`OAUTH2_PROXY_COOKIE_SECURE=false`,
      Keycloak in `start-dev` mode).
- [ ] The Keycloak client secret replaced (`AUTH_CLIENT_SECRET` must match the
      client in the realm; `auth/keycloak/realm.json` ships a placeholder).
- [ ] `.env` never committed; `targets.yaml` contains no credentials (it is
      not encrypted and not a secret store).

## 4. Data protection and privacy

- Alert payloads carry observable values (domains, IPs, e-mail addresses)
  unless `include_values: false` is set per target — consider where the
  receiving channel stores them.
- SocialOSINT data is subject to each platform's developer terms; X/Twitter
  in particular restricts storing and redistributing user data. The collector
  is opt-in for this reason, and its LLM analysis is stored in OpenCTI
  labelled *not verified*.
- LLM calls with `LLM_PROVIDER=ollama` keep data on-premises; cloud providers
  (`nebius`, `openai`, `anthropic`) receive the run's observables and the web
  evidence being qualified — make that an explicit, documented decision in
  your jurisdiction.
- Tavily receives the search terms configured for a target (entity names or
  the domain).
- Model output (qualification and risk synthesis) is decision support for an
  analyst. It is stored with the provider and model that produced it and is
  not a determination about any person or entity.

## 5. Supported versions

Only the current `main` branch and the latest `vX.Y.Z` tag receive security
fixes, as a new tag. The project is pre-1.0; deployments pin the tag or the
exact commit SHA they run.
