# Security Policy

> 🇪🇸 [Español](SECURITY.es.md)

## 1. Authorised use (the most important rule)

This orchestrator drives **live reconnaissance** (DNS, TLS, HTTP requests via
SpiderFoot; public-source pivoting via OpenOSINT; opt-in social media analysis
via SocialOSINT) against whatever is listed in `targets.yaml`.

- Only add targets you **own** or hold **written authorisation** to assess.
- `authorization` and `purpose` are mandatory per target and are written into
  every run report as the audit trail for why the collection happened.
- The repository ships nothing that exploits, authenticates against, or
  otherwise interacts with a target beyond public-source collection. Do not
  add such code, even in tests or fixtures.
- Collection is bounded by design: OpenOSINT budgets (`max_depth`,
  `max_entities`, `max_tool_calls`) and SpiderFoot `timeout_seconds` prevent
  runaway scans against third-party infrastructure.

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
| Webhook alerts | HMAC-SHA256 payload signature (`X-Orchestrator-Signature`) when `ALERT_WEBHOOK_SECRET` is set | README → Alerts |
| Metrics | Label values are bounded; never an observable value, run id or error string | README → Observability |
| Logs | JSON logs with request ids; no secret material is logged | `orchestrator/logging_config.py` |
| Retention | Nightly purge of runs/reports after `ORCHESTRATOR_RETENTION_DAYS` (default 90) | README → Retention |

The 90-day default is operational. It is not a legal retention period: when
artifacts form part of AML/CTF evidence, configure the applicable period or
use controlled external archival storage (see article 15 of Decree 379/018
and the README Retention section).

Before any deployment beyond a laptop:

- [ ] `ORCHESTRATOR_API_KEY` set (an empty key leaves the API **open**; a
      warning is logged at startup).
- [ ] `OPENCTI_ADMIN_PASSWORD`, `MINIO_ROOT_PASSWORD`, `RABBITMQ_DEFAULT_PASS`,
      `ORCHESTRATOR_SECRET_KEY`, `KEYCLOAK_ADMIN_PASSWORD` changed from
      placeholders.
- [ ] `ALERT_WEBHOOK_SECRET` set if webhooks are used (payloads are unsigned
      without it).
- [ ] Host port 8000 firewalled or unpublished when the auth front door
      (8002) is the intended entry point.
- [ ] TLS terminated at a real proxy/ingress in production; the auth overlay
      defaults are development conveniences (`COOKIE_SECURE=false`,
      `network_mode: host`).
- [ ] Demo accounts (Keycloak `analyst`/`change-me`) removed or disabled.
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
- LLM synthesis with `LLM_PROVIDER=ollama` keeps data on-premises; cloud
  providers (`anthropic`, `openai`) send observables to a third party — make
  that an explicit, documented decision in your jurisdiction.

## 5. Supported versions

Only the current `main` branch (and tagged releases once published) receives
security fixes. The project is pre-1.0; deployments pin the exact commit SHA
they run.
