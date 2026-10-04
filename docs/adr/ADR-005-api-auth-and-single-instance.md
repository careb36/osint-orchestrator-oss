# ADR-005: Static API Keys, Structured Observability and a Single-Instance Deployment

**Status:** Accepted
**Date:** 2026-09-08
**Phase:** 5

> **Amended by:** [ADR-006](ADR-006-oidc-proxy.md) — the rejected
> "OAuth 2 / OIDC" alternative materialised as an *optional* compose overlay
> for human operators; API-key authentication for machine callers is unchanged.

## Context

Phases 0–4 produced an orchestrator that can trigger collections against
authorised targets, read their findings and ship alerts — all over an HTTP
API with no authentication, plain-text logs and no metrics. That is fine on
a laptop behind `docker compose`; it is not fine on a shared network or a
cluster. Phase 5 has to make the service deployable by an operations team
without changing what it does.

Three questions had to be settled:

1. **How do callers authenticate?** The callers are operators and automation
   (a cron job, a CI pipeline, a SOAR playbook) — not end users. The platform
   of record, OpenCTI, already has its own users, roles and tokens.
2. **What do logs and metrics look like?** A log shipper needs a stable shape;
   an on-call engineer needs to answer "is it running, is it late, is it
   failing" from a dashboard, not from `grep`.
3. **How does it run on Kubernetes?** The operational state is SQLite and the
   scheduler is APScheduler in-process. Both were deliberate (ADR-001:
   modular monolith, no extra infrastructure) and both assume one process.

## Decision

### Authentication: shared static API keys

- `ORCHESTRATOR_API_KEY` holds one or more keys (comma-separated). A request
  presents one as `X-API-Key: <key>` or `Authorization: Bearer <key>`.
- Every data endpoint requires a key. `GET /health` and `GET /metrics` do not:
  probes and scrapers are not API clients and neither endpoint returns target
  data.
- An empty `ORCHESTRATOR_API_KEY` disables authentication and logs a warning
  once at startup. The default stays open so `docker compose up` on a laptop
  keeps working; production deployments must set a key, and the Helm chart's
  install notes say so loudly.
- Keys are compared in constant time and every configured key is checked, so
  a rejected request takes the same time whichever slot would have matched.
- Error details are localised like every other API error (ADR-004).

Rejected alternatives:

- **OAuth 2 / OIDC.** Right answer for browsers and humans; wrong shape for
  cron and playbooks, and it adds an identity provider to a stack that
  already has five services. Revisit if a UI is ever built on this API.
  *(Revisited: a minimal operator console shipped, and ADR-006 adds OIDC as an
  optional front-door overlay — the API-key contract for machine callers is
  untouched.)*
- **Per-user accounts in the orchestrator.** Would duplicate OpenCTI's RBAC
  with less of it. Authorisation for *targets* is not an access-control
  problem at all: it is the `authorization` field in `targets.yaml`, logged
  with every run.
- **mTLS.** Excellent between services, painful for a human with `curl`.
  Nothing here prevents putting it in front (an ingress or a mesh).

### Observability: JSON logs, request ids, Prometheus

- `ORCHESTRATOR_LOG_FORMAT=json` emits one JSON object per line (`ts`,
  `level`, `logger`, `msg`, plus any `extra=` fields such as `target_id`,
  `run_id`, `collector`). `text` remains the default for a terminal.
- Every HTTP request gets an id (caller-supplied `X-Request-ID` or generated),
  echoed in the response and stamped on every log line emitted while handling
  it. Background runs from the scheduler log `-`.
- `GET /metrics` serves Prometheus metrics: HTTP requests and latency by
  *route template*, runs by final status, collector outcomes and durations,
  OpenCTI ingest outcomes, synthesis status, alert dispatches and the number
  of scheduled jobs. Label values are bounded on purpose — never an
  observable value, a run id or an error string.
- No logging library and no OpenTelemetry SDK: the formatter is forty lines,
  and `prometheus_client` is the one dependency added. Traces can come later
  through an OTel collector without touching the application if the request
  id is propagated.

### Deployment: a Helm chart for one replica

- `deploy/helm/osint-orchestrator` deploys the orchestrator only. OpenCTI,
  SpiderFoot and Ollama have their own charts and are referenced by URL.
- **`replicaCount` is 1 and the strategy is `Recreate`.** SQLite on a
  `ReadWriteOnce` volume and an in-process scheduler cannot be scaled
  horizontally: two replicas would double-run every cron and corrupt the
  database. This is the honest consequence of ADR-001 and ADR-003 — the
  orchestrator is a thin coordinator, the heavy state lives in OpenCTI — and
  a single pod is sufficient for the workload (a handful of targets, a few
  runs a day).
- Secrets come from a Secret (ideally an existing one managed by External
  Secrets / Sealed Secrets), configuration from a ConfigMap, `targets.yaml`
  from a ConfigMap, and a checksum annotation rolls the pod on change.

## Consequences

- The API is safe to expose behind an ingress once a key is set; the
  default remains developer-friendly. Operators must treat the key like any
  other credential (rotation is supported by listing old and new keys
  together during the switch).
- Dashboards and alerts can be built on `osint_orchestrator_*` metrics
  without parsing logs. The metric names are part of the operator contract:
  renaming one is a breaking change and gets a note in the README.
- Horizontal scaling is explicitly out of scope. The trigger for revisiting
  this ADR is concrete: more targets than one pod can collect within its
  schedule window. At that point the path is a shared database (PostgreSQL,
  already supported by SQLModel) and moving the scheduler to a leader-elected
  or external trigger — not a rewrite.
- CI validates the chart with `helm lint` and `helm template` when the
  toolchain is available; the chart follows the `helm create` conventions so
  it stays readable to anyone who has seen one.
