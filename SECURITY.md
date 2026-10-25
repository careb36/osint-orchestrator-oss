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
| Container | The orchestrator image runs as uid 1000, never root; images are pinned to a patch release or a commit; compose publishes every port on `127.0.0.1` only | `Dockerfile`, `docker-compose*.yml`, `tests/unit/test_compose_hardening.py` |
| Retention | No purge by default (`ORCHESTRATOR_RETENTION_DAYS=0`); an opt-in nightly purge never deletes runs that opened an alert case | [Operations → Retention](docs/operations.md#retention) |
| Main branch | Ruleset requiring green CI (lint, unit tests, Helm chart, public-release guard) and forbidding force pushes | repository settings |

Retention is disabled by default because the artifacts form part of AML/CFT
evidence and record-keeping rules measure their retention in years. If you
enable a period, make it the one your regulation requires, not an operational
one, and archive the run directories you must keep before the first purge.

Before any deployment beyond a laptop:

- [ ] `ORCHESTRATOR_API_KEY` set (an empty key leaves the API **open**; a
      warning is logged at startup).
- [ ] `OPENCTI_ADMIN_PASSWORD`, `OPENCTI_ADMIN_TOKEN`, `OPENCTI_ENCRYPTION_KEY`,
      `MINIO_ROOT_PASSWORD`, `RABBITMQ_DEFAULT_PASS` and `KEYCLOAK_ADMIN_PASSWORD`
      set to generated values (`.env.example` ships them blank).
- [ ] `ORCHESTRATOR_SECRET_KEY` generated (`openssl rand -hex 32`) and backed
      up: it signs the evidence manifests, and a lost key means earlier runs
      can no longer be verified. An empty or default key logs a warning.
- [ ] `ALERT_WEBHOOK_SECRET` set if webhooks are used (payloads are unsigned
      without it).
- [ ] Every compose port stays on the loopback interface (the shipped files
      bind `127.0.0.1` for the API, OpenCTI, SpiderFoot and the overlays);
      only your TLS proxy, or the auth front door (8002) behind it, is
      reachable from outside.
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
- Where the LLM prompts go is decided per target by its `llm` field. The
  global `LLM_PROVIDER` is not a default provider; it changes the destination
  in exactly two cases: `LLM_PROVIDER=none` makes no LLM call for any target,
  and `LLM_PROVIDER=nebius` sends the targets with `llm: openai` to Nebius
  Token Factory instead of OpenAI. Otherwise a target with `llm: local` (the
  default) sends the prompts to the Ollama server at `LLM_BASE_URL`, and they
  stay on-premises only if that server does; a target with `llm: nebius`,
  `openai` or `anthropic` sends the run's observables and the web evidence
  being qualified to that cloud provider. Make each cloud opt-in, and the
  `LLM_PROVIDER` value, an explicit, documented decision in your jurisdiction.
- Tavily receives the search terms configured for a target (entity names or
  the domain).
- Model output (qualification and risk synthesis) is decision support for an
  analyst. It is stored with the provider and model that produced it and is
  not a determination about any person or entity.

## 5. Supported versions

Only the current `main` branch and the latest `vX.Y.Z` tag receive security
fixes, as a new tag. The project is pre-1.0; deployments pin the tag or the
exact commit SHA they run.
