# Deploying to production

How to run the orchestrator for real users. [operations.md](operations.md)
covers day-to-day running; [configuration.md](configuration.md) describes every
setting; the hardening checklist is in
[SECURITY.md](../SECURITY.md#3-security-model-and-hardening-checklist).

There are two supported shapes:

| Shape | When | Guide |
| --- | --- | --- |
| Docker Compose, full stack | One server; OpenCTI, SpiderFoot and the orchestrator together | This page |
| Kubernetes, Helm chart | Existing cluster with OpenCTI and SpiderFoot deployed separately | [`deploy/helm/osint-orchestrator`](../deploy/helm/osint-orchestrator/README.md) |

## Server requirements

Docker Engine 24+ with Compose v2, 16 GB of RAM (OpenCTI and Elasticsearch
take most of it; 32 GB is comfortable), 4 cores, 50 GB of disk and
`vm.max_map_count=262144` on the host.

## Configuration

```bash
git clone <repository> osint-orchestrator && cd osint-orchestrator
cp .env.example .env
cp targets.example.yaml targets.yaml
```

Generate every secret `.env` asks for with `openssl rand -hex 32`. The ones a
production deployment cannot leave at their default:

| Variable | Why |
| --- | --- |
| `ORCHESTRATOR_API_KEY` | Empty leaves the API open to anyone who can reach it (ADR-005). |
| `ORCHESTRATOR_SECRET_KEY` | Signs the evidence manifests (ADR-007); the default key makes every signature forgeable. |
| `OPENCTI_ADMIN_TOKEN`, the OpenCTI, MinIO and RabbitMQ passwords | Shared between the OpenCTI services and the orchestrator. |
| `ALERT_WEBHOOK_SECRET`, SMTP credentials | Only if alerts are delivered. |
| `TAVILY_API_KEY`, `NEBIUS_API_KEY` (or the key of the provider chosen in `LLM_PROVIDER`) | Web research and synthesis. |

`targets.yaml` is the audit trail: `authorization` and `purpose` are mandatory
per target and are written into every report. List only entities you are
authorised in writing to assess.

## Start and verify

```bash
docker compose up -d --build
docker compose ps                     # every service healthy (OpenCTI takes 2-3 minutes)
curl -s http://127.0.0.1:8000/health  # {"status": "ok", ...}
```

Every published port binds the loopback interface only: the orchestrator
(`127.0.0.1:${ORCHESTRATOR_PORT:-8000}`), OpenCTI (`127.0.0.1:8080`),
SpiderFoot (`127.0.0.1:5001`, no authentication of its own) and the optional
overlays (SocialOSINT `8001`, Keycloak `8085`, oauth2-proxy `8002`, MISP
`8443`). Reach OpenCTI or SpiderFoot from your workstation through an SSH
tunnel (`ssh -L 8080:127.0.0.1:8080 <server>`) or put them behind the same
reverse proxy as the API. Database migrations run at startup; a fresh install
reaches the latest schema and an upgrade applies what is missing, so no manual
migration step exists.

The compose file always starts OpenCTI: the orchestrator service waits for it
to be healthy. `OPENCTI_ENABLED=false` ([ADR-008](adr/ADR-008-optional-opencti-sink.md))
stops the ingest, not the containers; a stack without OpenCTI is a Helm or a
hand-written compose deployment, not this file.

The orchestrator container runs as uid 1000. The `./daily_reports` bind mount
must be writable by that uid before the first start, or every run fails at the
report step:

```bash
mkdir -p daily_reports && sudo chown -R 1000:1000 daily_reports
```

The `orchestrator-db` and `amass-data` volumes are initialised from the image
with the right owner and need nothing.

## Exposing the API and the dashboard

Never publish port 8000 directly. Two options:

- **Your own reverse proxy** (nginx, Caddy, Traefik) terminating TLS in front
  of `127.0.0.1:8000`. The dashboard at `/console` asks for the API key in the
  browser; every data route requires it as `X-API-Key` or a bearer token.
- **The OIDC overlay**: `docker compose -f docker-compose.yml -f docker-compose.auth.yml --profile auth up -d`
  starts Keycloak and oauth2-proxy in front of the dashboard
  ([ADR-006](adr/ADR-006-oidc-proxy.md)). Its defaults are for development
  (`start-dev` Keycloak, insecure cookie flag, a placeholder client secret):
  replace them and terminate TLS at the proxy before exposing it.

## Persistence and backups

| Data | Where | Back up |
| --- | --- | --- |
| Runs, findings, queues (SQLite) | volume `orchestrator-db` (`/app/data/orchestrator.db`) | Copy the file while the orchestrator is stopped, or use `sqlite3 .backup` |
| Reports, STIX bundles, signed manifests | `./daily_reports` on the host | File-level backup; the manifest chain detects any later change |
| OpenCTI knowledge graph | volumes `elasticsearch-data`, `minio-data`, `redis-data`, `rabbitmq-data` | Follow the OpenCTI backup guidance |
| Collector state | `spiderfoot-data`, `amass-data` | Optional; rebuilt by later runs |

`ORCHESTRATOR_RETENTION_DAYS` (default 90) purges old runs and report
directories; the evidence chain stays verifiable across the purge.

## Upgrading

```bash
git pull
docker compose build orchestrator
docker compose up -d orchestrator
```

The image builds the dashboard and applies the database migrations itself.
Read the [changelog](../CHANGELOG.md) for removed settings before upgrading;
`.env` keys that no longer exist are ignored, but a renamed one would silently
fall back to its default.

## Observability

`GET /health` (component checks with hints) and `GET /metrics` (Prometheus)
need no API key. With `ORCHESTRATOR_LOG_FORMAT=json` every log line is one
object with `request_id`, `target_id`, `run_id` and `collector` fields for a
log shipper. Details and the alert runbook: [operations.md](operations.md#observability).
