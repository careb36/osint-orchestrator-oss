# Deploying to production

How to run the orchestrator for real users. [operations.md](operations.md)
covers day-to-day running; [configuration.md](configuration.md) describes every
setting; the hardening checklist is in
[SECURITY.md](../SECURITY.md#3-security-model-and-hardening-checklist).

There are two supported shapes:

| Shape | When | Guide |
| --- | --- | --- |
| Docker Compose | One server; SpiderFoot and the orchestrator, optionally with OpenCTI | This page |
| Kubernetes, Helm chart | Existing cluster with OpenCTI and SpiderFoot deployed separately | [`deploy/helm/osint-orchestrator`](../deploy/helm/osint-orchestrator/README.md) |

## Server requirements

Docker Engine 24+ with Compose v2.20+ (`depends_on.required` support).
With the optional `opencti` profile: 16 GB of RAM (OpenCTI and Elasticsearch
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
| `OPENCTI_ENCRYPTION_KEY` | Mandatory since OpenCTI 7.260224.0: the platform encrypts its secrets with it and does not start without one (`openssl rand -base64 32`). Back it up with the OpenCTI volumes. |
| `ALERT_WEBHOOK_SECRET`, SMTP credentials | Only if alerts are delivered. |
| `TAVILY_API_KEY`, `NEBIUS_API_KEY` (or the key of the provider chosen in `LLM_PROVIDER`) | Web research and synthesis. |

Compose validates required variables even in inactive profiles: fill the
OpenCTI credentials and `OPENCTI_ENCRYPTION_KEY`, and the MinIO and RabbitMQ
passwords, even for a sink-off install.

`targets.yaml` is the audit trail: `authorization` and `purpose` are mandatory
per target and are written into every report. List only entities you are
authorised in writing to assess.

## Start and verify

```bash
docker compose build orchestrator spiderfoot
docker compose up -d                 # sink off: OPENCTI_ENABLED=false, the .env.example default
```

For the OpenCTI knowledge graph, set `OPENCTI_ENABLED=true` in `.env` and use:

```bash
docker compose --profile opencti up -d
```

Existing sink-on installs must also add this profile on upgrades, or set
`COMPOSE_PROFILES=opencti` in `.env` to enable it for every Compose command.
With the profile active, the orchestrator waits for OpenCTI to become healthy;
without it, only SpiderFoot and the orchestrator start
([ADR-008](adr/ADR-008-optional-opencti-sink.md)).

```bash
docker compose ps                     # every enabled service healthy (OpenCTI takes 2-3 minutes)
curl -s http://127.0.0.1:8000/health  # {"status": "ok", ...}; "opencti": "disabled" with OPENCTI_ENABLED=false
curl -si http://127.0.0.1:8000/ready  # HTTP 200; 503 while the database or the scheduler is down
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

The OpenCTI images are pinned to the long-term line `7.260811.0-lts.1`. To
upgrade a deployment that ran `6.8.11`: back up the four OpenCTI volumes, add
`OPENCTI_ENCRYPTION_KEY` to `.env`, then `docker compose --profile opencti pull
&& docker compose --profile opencti up -d`. OpenCTI migrates its data on first
start; existing API tokens move to the hashed token store and can no longer be
displayed afterwards, so keep `OPENCTI_ADMIN_TOKEN` in `.env`. The platform's
own list is its
[breaking-changes page](https://docs.opencti.io/latest/deployment/breaking-changes/).

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
| OpenCTI knowledge graph | volumes `elasticsearch-data`, `minio-data`, `redis-data`, `rabbitmq-data` | Follow the OpenCTI backup guidance, and keep `OPENCTI_ENCRYPTION_KEY` with the backup |
| Collector state | `spiderfoot-data`, `amass-data` | Optional; rebuilt by later runs |

`ORCHESTRATOR_RETENTION_DAYS` (default 90) purges old runs and report
directories; the evidence chain stays verifiable across the purge.

## Upgrading

```bash
git pull
docker compose build orchestrator
docker compose up -d orchestrator
```

For sink-on installs, add `--profile opencti` to the `up` command unless
`COMPOSE_PROFILES=opencti` is set in `.env`.

The image builds the dashboard and applies the database migrations itself.
Read the [changelog](../CHANGELOG.md) for removed settings before upgrading;
`.env` keys that no longer exist are ignored, but a renamed one would silently
fall back to its default.

## Observability

`GET /health` (component checks with hints), `GET /ready` (503 until the
service can work; what the compose healthcheck polls) and `GET /metrics`
(Prometheus) need no API key. With `ORCHESTRATOR_LOG_FORMAT=json` every log line is one
object with `request_id`, `target_id`, `run_id` and `collector` fields for a
log shipper. Details and the alert runbook: [operations.md](operations.md#observability).
