# OSINT Orchestrator

> 🇪🇸 [Español](README.es.md)

Orchestrates open-source OSINT tools — **OpenOSINT**, **SpiderFoot**, and, opt-in, **OWASP SocialOSINT** and **OWASP Amass** — normalises findings to **STIX 2.1**, and ingests them into **OpenCTI** as the single source of truth.

> **Architecture decision:** modular monolith → microservices only when a module needs to scale independently. See [`docs/adr/`](docs/adr/).

**Contents** — [Authorised use](#authorised-use) · [Architecture](#architecture) · [Hardware](#hardware-requirements) · [Quick start](#quick-start) · [MISP](#misp) · [SocialOSINT](#socialosint) · [Amass](#amass) · [Configuration](#configuration) · [API](#api) · [Targets](#target-configuration) · [Language](#language) · [Reports](#reports-phase-2) · [Alerts](#alerts-phase-4a) · [Retention](#retention) · [Auth](#api-authentication-phase-5) · [Observability](#observability-phase-5) · [Business guides](#business-guides) · [Kubernetes](#kubernetes-phase-5) · [Development](#development) · [Migrations](#database-migrations) · [Troubleshooting](#troubleshooting) · [Phases](#phases) · [ADRs](#architecture-decisions)

---

## Authorised use

This orchestrator drives reconnaissance against whatever you list in
`targets.yaml`. SpiderFoot in particular makes live DNS, TLS and HTTP requests
to the target; this is not a passive-only tool.

- Add only targets you own or hold **written authorisation** to assess.
- `authorization` and `purpose` are **required** on every target. They are not
  decoration: both are written into each run's report and kept as the audit
  trail for why that collection happened.
- `targets.yaml` is not encrypted and is not a secret store — credentials
  belong in `.env`.
- Alert payloads carry observable values (domains, IP addresses, e-mail
  addresses) unless you set `include_values: false` on the target. Consider
  where the receiving channel stores them.

The repository ships nothing that exploits, authenticates against, or
otherwise interacts with a target beyond public-source collection.

---

## Architecture

```text
              targets.yaml  ·  REST API  ·  cron (APScheduler)
                                │
   ┌────────────────────────────▼─────────────────────────────┐
   │                  orchestrator  (FastAPI)                 │
   │  collectors/ → normalizer/ → sinks/ → reports/ → alerts/ │
   └───┬──────────────┬───────────────┬────────────┬──────────┘
       │              │               │            │
       ▼              ▼               ▼            │  pycti
┌─────────────┐ ┌────────────┐ ┌─────────────┐     │  (STIX 2.1 bundles)
│  OpenOSINT  │ │ SpiderFoot │ │ SocialOSINT │     ▼
│(in-process) │ │ (HTTP API) │ │ Amass (opt) │  ┌───────────┐  connector  ┌──────┐
└─────────────┘ └────────────┘ └─────────────┘  │  OpenCTI  │◄───────────►│ MISP │
                                                │ ES·Redis· │  (Phase 4b) └──────┘
                                                │ RabbitMQ· │
                                                │   MinIO   │
                                                └───────────┘
```

One run, end to end: the scheduler (or `POST /targets/{id}/run`) fans out to the
enabled collectors, each returning raw findings; `normalizer/` turns them into a
single STIX 2.1 bundle with deterministic ids; `sinks/opencti.py` pushes the
bundle through pycti; observables not seen before for that target are marked new;
`synthesizer/` asks an LLM for a risk read; `reports/` writes the day's Markdown
and STIX artifacts; `alerts/` dispatches if the target's rules match.

**MISP** integrates via the [official OpenCTI↔MISP connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp), not custom code.

---

## Hardware Requirements

> ⚠️ **OpenCTI is resource-intensive.** Verify your host meets these requirements before deploying.

Sourced from [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker):

| Component | Minimum RAM |
| --- | --- |
| Elasticsearch heap (`ELASTIC_MEMORY_SIZE`) | **4 GB** (default) |
| OpenCTI platform (Node.js, `--max-old-space-size=8096`) | **8 GB** |
| Redis | ~256 MB |
| RabbitMQ | ~256 MB |
| MinIO | ~256 MB |
| Workers (×2) | ~512 MB |
| SpiderFoot | ~512 MB |
| Orchestrator | ~256 MB |
| **Total (core)** | **≥ 16 GB** (32 GB comfortable) |
| MISP stack (`-f docker-compose.misp.yml --profile misp`) | +1.6 GB additional |
| SocialOSINT service (`--profile socialosint`) | +512 MB additional |
| Amass engine (`--profile amass`) | +256 MB additional (more with brute forcing) |

Additional OS requirements:

```bash
# Elasticsearch requires vm.max_map_count ≥ 262144
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

**CPU:** ≥ 4 cores (Elasticsearch is CPU-bound during indexing).  
**Disk:** ≥ 50 GB (Elasticsearch data + MinIO objects).

---

## Quick Start

### Prerequisites

- Docker Engine ≥ 24 and Docker Compose v2
- Host RAM ≥ 16 GB (see above)
- `vm.max_map_count=262144` set on the host

### 1. Clone & configure

```bash
git clone https://github.com/careb36/osint-orchestrator-oss.git
cd osint-orchestrator

cp .env.example .env
# Edit .env — set passwords, generate OPENCTI_ADMIN_TOKEN:
#   python -c "import uuid; print(uuid.uuid4())"

cp targets.example.yaml targets.yaml
# Edit targets.yaml — add your authorised targets
```

### 2. Start the stack

```bash
docker compose up -d
```

Services started:

- OpenCTI at <http://localhost:8080> (use credentials from `.env`), plus its
  `worker` (×2) and the built-in `connector-import-file-stix` /
  `connector-opencti` connectors, backed by Elasticsearch, Redis, RabbitMQ and MinIO
- SpiderFoot at <http://localhost:5001> (built locally from source, `spiderfoot:local`)
- Orchestrator API at <http://localhost:8000> (`orchestrator:8000` on the Docker network)

> **No LLM service is included.** The default `LLM_PROVIDER=ollama` /
> `LLM_BASE_URL=http://ollama:11434` expects an Ollama endpoint on the Docker
> network. Without one, synthesis is skipped or recorded as failed
> (`synthesis_total{status="skipped"|"failed"}`) and the run continues normally —
> reports just carry no finding. Point `LLM_BASE_URL` at your own Ollama, or set
> `LLM_PROVIDER=anthropic|openai` with the matching API key.

### 3. Verify

```bash
# Orchestrator health
curl http://localhost:8000/health

# OpenCTI (may take 2–3 min to fully start)
curl http://localhost:8080/health

# Open the minimal operator console (the page asks for the API key when auth is enabled)
xdg-open http://localhost:8000/console
```

#### Console API-key security flow

- Default mode is session-only: the key stays in JS memory and is cleared from the input after you click **Use key**.
- **Remember in this browser** is explicit opt-in and stores the key in `sessionStorage` (cleared when the tab closes).
- The console shell (`/console`, `/console/i18n.json`) is public because it holds no data; every request it makes carries the key and is rejected without it. See [ADR-006 — Browser access model](docs/adr/ADR-006-oidc-proxy.md#browser-access-model).
- The console never places the key in URLs and shows an actionable 401 message when the key is invalid/rotated.

### 4. First run

```bash
export KEY="$(grep '^ORCHESTRATOR_API_KEY=' .env | cut -d= -f2)"

# Trigger a collection — returns 202 immediately, the run happens in background
curl -X POST -H "X-API-Key: $KEY" \
  http://localhost:8000/targets/example-domain/run
# {"run_id": 1, "status": "accepted", "target_id": "example-domain"}

# Poll until status leaves pending/running
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1

# What is new since the previous run for this target
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1/delta

# The operator report (Markdown, also on disk under daily_reports/)
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1/report
```

### 5. Optional: MISP profile

```bash
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d
```

> ⚠️ **MISP takes 5–10 minutes to initialise on first run.** Wait for the
> `misp` container to report healthy before starting the `connector-misp`.

See [MISP](#misp) below for full startup order and configuration.

### Optional authenticated front door

If you want a production-shaped operator login, start the OIDC overlay on top of the base stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.auth.yml --profile auth up -d
curl http://localhost:8002/health
```

This adds Keycloak at `http://localhost:8085` and an oauth2-proxy front door at
`http://localhost:8002` (`AUTH_PROXY_PORT`; 8002 is also the value shipped in
`.env.example` — do not use 8001, it collides with the `socialosint` service).
`auth-proxy` waits for Keycloak and the orchestrator to become healthy before
starting.

**Create an operator account** (no demo credentials are shipped — see [ADR-006](docs/adr/ADR-006-oidc-proxy.md)):

1. Open `http://localhost:8085` and log in with the `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` credentials from your `.env`.
2. Select the **orchestrator** realm → **Users** → **Add user**.
3. Fill in username / e-mail, set a password under **Credentials**, and mark it as permanent.

The front door reverse-proxies to `http://orchestrator:8000` on the compose
network. The base stack still publishes port 8000 on loopback, so hand browser
operators the `8002` URL. The full decision record is
[ADR-006](docs/adr/ADR-006-oidc-proxy.md).

> **Architecture note:** the OIDC proxy is an *optional* perimeter layer — it does not replace the `X-API-Key` mechanism (ADR-005). Automation clients that already send an API key continue to work unchanged.  See [ADR-006](docs/adr/ADR-006-oidc-proxy.md).

---

## MISP

MISP runs from the optional overlay `docker-compose.misp.yml` (`--profile misp`) with its own
**MariaDB** and **Redis** (not shared with OpenCTI's infrastructure).
OpenCTI ↔ MISP synchronisation is handled by the official
[`opencti/connector-misp`](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp)
connector (version **6.8.11**, pinned to match the platform).

### Startup order

```bash
# 1. Start MISP stack and wait for initialisation (5–10 min on first run)
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d misp-db misp-redis misp-modules misp
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp logs -f misp   # wait until "MISP is ready"

# 2. Once MISP is healthy, start the OpenCTI connector
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d connector-misp
```

### Obtaining the MISP API key

1. Open `https://localhost:8443` in your browser (accept the self-signed cert).
2. Log in with `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` from `.env`.
3. Go to **Administration → List Auth Keys → Add Authentication Key**.
4. Copy the 40-character hex key into `MISP_KEY` in `.env`.
5. Restart the connector: `docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp restart connector-misp`.

### Verifying connector registration

In OpenCTI, go to **Data → Connectors**. The connector named **MISP** should
appear with status "Connected" within a minute of starting. If it shows as
disconnected, check `docker compose logs connector-misp` for authentication
errors.

### Hardware requirements (additional)

| Additional component | RAM |
| --- | --- |
| MariaDB (MISP) | ~256 MB |
| Redis (MISP) | ~128 MB |
| MISP core (PHP-FPM + nginx) | ~1 GB |
| `connector-misp` | ~256 MB |
| **Total additional** | **~1.6 GB** |

---

## SocialOSINT

The SocialOSINT collector integrates the
[OWASP SocialOSINT Agent](https://github.com/bm-github/owasp-social-osint-agent)
(MIT) for LLM-powered analysis of social media accounts associated with a target.
Integration design and rationale: [`docs/socialosint.md`](docs/socialosint.md).

**This collector is disabled by default** (`collectors.socialosint.enabled: false`).
It must be explicitly enabled per target in `targets.yaml`.

### Platforms

| Platform | Credentials needed | Notes |
| --- | --- | --- |
| Twitter/X | `SOCIALOSINT_TWITTER_BEARER_TOKEN` | v2 bearer token |
| Reddit | `SOCIALOSINT_REDDIT_CLIENT_ID`, `SOCIALOSINT_REDDIT_CLIENT_SECRET` | PRAW credentials |
| GitHub | `SOCIALOSINT_GITHUB_TOKEN` | Optional (lower rate limit without) |
| Bluesky | `SOCIALOSINT_BLUESKY_IDENTIFIER`, `SOCIALOSINT_BLUESKY_APP_SECRET` | app password (format: `<xxxx-xxxx-xxxx-xxxx>`) |
| Mastodon | `SOCIALOSINT_MASTODON_INSTANCE_1_URL`, `SOCIALOSINT_MASTODON_INSTANCE_1_TOKEN` | one entry per instance |
| HackerNews | *(none)* | Public Algolia API |

A platform whose credentials are absent is silently skipped with a warning — it
does **not** fail the collector.

### LLM requirements

SocialOSINT requires its own LLM (OpenAI-compatible, with vision support).
Set `SOCIALOSINT_LLM_BASE_URL`, `SOCIALOSINT_LLM_API_KEY`, `SOCIALOSINT_LLM_MODEL`,
and `SOCIALOSINT_LLM_VISION_MODEL` in `.env`. These are independent of the
orchestrator's `LLM_PROVIDER` setting.

### Usage

```bash
# Build and start the SocialOSINT service
docker compose --profile socialosint up -d socialosint

# Enable for a specific target in targets.yaml:
# collectors:
#   socialosint:
#     enabled: true
#     usernames: [brandhandle]
#     platforms: [twitter, github, hackernews]
```

### APIs and data use

The collector uses **official platform APIs** (not scraping). However, use
of collected data is subject to each platform's developer terms:

> ⚠️ **X/Twitter** in particular restricts storing and redistributing user data
> under its developer agreement. Ensure your use-case complies before enabling
> Twitter collection. This is why the collector is **opt-in**.

The LLM analysis report is stored as a Note in OpenCTI labelled
*"análisis de SocialOSINT, no verificado"* and is not treated as verified fact.
The configured timeout is a total wall-clock bound for the complete workflow,
not a per-request allowance. After a session has been created in SocialOSINT,
the orchestrator deletes it on a best-effort basis after success, failure, or
timeout.

---

## Amass

The Amass collector integrates [OWASP Amass v5](https://github.com/owasp-amass/amass)
(Apache-2.0) for in-depth subdomain enumeration of the target's root domain:
certificate transparency, passive DNS, dozens of public data sources and
optional brute forcing, with every name resolved to its addresses. It
complements SpiderFoot (broad, module-driven) with the deepest attack-surface
mapping the open-source ecosystem offers.

**This collector is disabled by default** (`collectors.amass.enabled: false`).
It must be explicitly enabled per target in `targets.yaml`.

### How it runs

Amass v5 splits into a long-running **engine** and thin CLI clients. The engine
runs as the `amass` compose service (official image, profile `amass`); the
orchestrator image carries the `oam_enum` and `oam_subs` clients. Per run the
collector:

1. checks `GET /api/v1/health` on `AMASS_ENGINE_URL`;
2. runs `oam_enum -engine … -d <fqdn>` — the engine enumerates until no new
   finding has appeared for `progress_timeout_minutes`;
3. runs `oam_subs -d <fqdn> -names -ip` against the asset database on the volume
   shared with the engine (`AMASS_DATA_DIR`) and maps each line to STIX:
   `domain-name` per discovered name, `ipv4-addr` / `ipv6-addr` per address,
   `resolves-to` (name → address) and `related-to` (name → target root).

Engine down, missing binaries, non-zero exit or the wall-clock
`timeout_seconds` return `success=False`, so the run is recorded partial or
failed instead of reporting zero findings.

### Data sources and credentials

Data-source API keys never reach the orchestrator: they live in
`amass/datasources.yaml`, git-ignored and mounted only into the engine
container. Start from the example (the engine starts with no keys — public
sources are used without them):

```bash
cp amass/datasources.example.yaml amass/datasources.yaml   # required: the file is bind-mounted
docker compose --profile amass up -d amass
```

`amass/config.yaml` (scope empty on purpose — the collector passes each
target's domain) is mounted the same way.

### Usage

```bash
# Enable for a specific target in targets.yaml:
# collectors:
#   amass:
#     enabled: true
#     active: false                  # zone transfers + cert grabs touch the target
#     brute: false
#     progress_timeout_minutes: 10
#     timeout_seconds: 1800
```

> ⚠️ **Active mode** (`active: true`) attempts zone transfers and TLS
> certificate name grabs against the target's own servers, and brute forcing
> generates large volumes of DNS queries. Keep both off unless the target's
> `authorization` explicitly covers active probing.

---

## Tavily

The Tavily collector performs web-search-based due diligence on an authorised
entity. It is intentionally opt-in, and it stays off unless a target enables
`collectors.tavily.enabled: true`.

**This collector is disabled by default** (`collectors.tavily.enabled: false`).

### What it searches

- adverse news and public reporting
- sanctions, regulatory actions and litigation
- ownership structure and published shareholder data
- beneficial ownership and legal-entity relationships
- source URLs and summarised excerpts from public web results

Each query searches the target's domain name as a quoted exact term across
third-party sources (news, registries, court records); it never scopes the
search to the target's own domain, because adverse media is published
elsewhere. Use `include_domains` / `exclude_domains` to restrict the sources.
The exact match is deliberate for due diligence (no false positives from a
generic word), but it also means mentions of the entity's trade name alone are
not reached: a target is a domain, not a company name. A page returned by
several queries, in any scheme/case/trailing-slash variant, yields one `url`
observable and one note. A query that fails after its retries is recorded in
a note; the run fails only when every query failed.

### Usage

```yaml
collectors:
  tavily:
    enabled: true
    search_depth: basic
    max_results: 5
    include_domains: []
    exclude_domains: []
    max_calls_per_run: 3
    timeout_seconds: 120
```

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Opt-in switch; the collector is only registered for a run when it is `true` |
| `search_depth` | `basic` | `basic` or `advanced` (Tavily pricing differs) |
| `max_results` | `5` | Results requested and kept per query, 1–20, clamped by `TAVILY_MAX_RESULTS` |
| `include_domains` / `exclude_domains` | `[]` | Result-domain allowlist / denylist; empty falls back to the global settings |
| `include_answer` | `false` | Also request Tavily's synthesised answer, kept as one bounded note per query |
| `max_calls_per_run` | `3` | Search requests per run, 1–20, clamped by `TAVILY_MAX_CALLS_PER_RUN`; three query templates ship, so the default covers all of them |
| `timeout_seconds` | `TAVILY_TIMEOUT_SECONDS` (`120`) | Wall-clock budget for the whole collector run, retries and backoff included |

Requests are retried with exponential backoff only on HTTP 429, 5xx and
transport errors; any other 4xx (an invalid key, a rejected payload) fails the
query immediately. Result URLs are kept only with an `http` or `https` scheme.

---

## Configuration

Every variable is listed with an inline comment in
[`.env.example`](.env.example); copy it to `.env` and edit.
[`orchestrator/config.py`](orchestrator/config.py) is the authoritative
definition — anything not declared there is ignored by the application.

Two groups of variables live in the same `.env`:

- **Application settings** (`ORCHESTRATOR_*`, `LLM_*`, `ALERT_*`, `SPIDERFOOT_URL`,
  `SOCIALOSINT_URL`, …) — declared in `config.py`, read by the orchestrator
  process. Defaults there target a bare-metal run (`localhost` URLs,
  `./orchestrator.db`).
- **Compose-only settings** (`OPENCTI_ADMIN_*`, `MINIO_*`, `RABBITMQ_*`, `MISP_*`,
  `KEYCLOAK_*`, `AUTH_*`, `OIDC_*`, `SOCIALOSINT_LLM_*` and the SocialOSINT
  platform credentials, …) — consumed by `docker-compose*.yml` to configure the
  other services. `.env.example` carries the container-network values
  (`http://opencti:8080`, `/app/data/…`), which override the bare-metal defaults
  when running under Docker.

**Set before this leaves a laptop:**

| Variable | Default | Why it matters |
| --- | --- | --- |
| `ORCHESTRATOR_API_KEY` | *(empty)* | Empty means **the API is open**. See [API authentication](#api-authentication-phase-5). |
| `OPENCTI_ADMIN_TOKEN` | *(empty)* | Must match the token OpenCTI was bootstrapped with, or ingest fails. |
| `OPENCTI_ADMIN_PASSWORD` | `ChangeMe!` | Placeholder — OpenCTI's web login. |
| `MINIO_ROOT_PASSWORD` | `ChangeMinio!` | Placeholder. |
| `RABBITMQ_DEFAULT_PASS` | `guest` | Placeholder. |
| `ORCHESTRATOR_SECRET_KEY` | `insecure-dev-key` | Placeholder. |
| `ALERT_WEBHOOK_SECRET` | *(empty)* | Without it webhook payloads are unsigned. |

**Commonly tuned:**

| Variable | Default | Meaning |
| --- | --- | --- |
| `ORCHESTRATOR_LANGUAGE` | `es` | Operator-facing language, `es` or `en` ([ADR-004](docs/adr/ADR-004-language-policy.md)). |
| `ORCHESTRATOR_LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`. |
| `ORCHESTRATOR_LOG_FORMAT` | `text` | `text` for a terminal, `json` for a log shipper. |
| `ORCHESTRATOR_METRICS_ENABLED` | `true` | `false` makes `GET /metrics` return 404. |
| `ORCHESTRATOR_ENV_FILE` | `.env` | Bootstrap dotenv path used while building `Settings()`. Set empty to disable dotenv loading (tests do this to avoid reading a developer's local `.env`). |
| `ORCHESTRATOR_DATABASE_URL` | `sqlite+aiosqlite:////app/data/orchestrator.db` | Container path is the persistent volume; use `./orchestrator.db` bare-metal. |
| `TARGETS_FILE` | `targets.yaml` | Re-read on every API and scheduler call. |
| `OPENCTI_SSL_VERIFY` | `true` | Set `false` only for local/self-signed TLS in dev. |
| `SPIDERFOOT_MODULES` | `sfp_dnsresolve,sfp_whois,sfp_sslcert` | Fallback when a target lists no modules. |
| `SPIDERFOOT_URL` | `http://spiderfoot:5001` | SpiderFoot service URL on the internal network. |
| `SPIDERFOOT_TIMEOUT_SECONDS` | `600` | Timeout for one SpiderFoot collection run. |
| `LLM_PROVIDER` / `LLM_MODEL` / `LLM_BASE_URL` | `ollama` / `llama3.2` / `http://ollama:11434` | Synthesis backend; `ollama` keeps data on-prem. `none` switches synthesis off for every target. `nebius` uses the Token Factory OpenAI-compatible endpoint. |
| `LLM_MODEL_REASONING` | *(empty)* | Optional model override for synthesis and relationship-heavy reasoning calls on the cloud providers (`anthropic`, `openai`, `nebius`); falls back to `LLM_MODEL`. Ollama always serves `OLLAMA_MODEL`. |
| `LLM_MODEL_FAST` | *(empty)* | Optional model override for lightweight classification/extraction calls on the cloud providers; falls back to `LLM_MODEL`. |
| `OLLAMA_MODEL` | `llama3.2` | Model Ollama serves for targets with `llm: local` (separate from `LLM_MODEL`, which names the cloud model). |
| `LLM_TIMEOUT_SECONDS` | `120` | End-to-end timeout for a synthesis request. |
| `LLM_MAX_TOKENS` | `2048` | Upper bound on the model reply. |
| `LLM_MAX_OBSERVABLES_IN_PROMPT` | `200` | Cap observables sent to the synthesizer prompt. |
| `SYNTHESIS_HISTORY_RUNS` | `5` | Prior runs included as synthesis context. |
| `SYNTHESIS_OPENCTI_CONTEXT` | `false` | If `true`, enrich synthesis with OpenCTI context. |
| `OPENAI_API_KEY` | *(empty)* | Required when `LLM_PROVIDER=openai`. |
| `OPENAI_BASE_URL` | *(empty)* | Optional base URL for OpenAI-compatible endpoints. |
| `NEBIUS_API_KEY` | *(empty)* | Required when `LLM_PROVIDER=nebius`. |
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | Nebius Token Factory OpenAI-compatible base URL. |
| `ANTHROPIC_API_KEY` | *(empty)* | Required when `LLM_PROVIDER=anthropic`. |
| `OPENCTI_INGEST_RETRIES` / `OPENCTI_INGEST_BACKOFF_SECONDS` | `3` / `2.0` | Retries after a *transient* OpenCTI error, and the base wait (doubled each retry, ±25 % jitter, 30 s cap). An invalid token is never retried. |
| `OPENCTI_OUTBOX_CRON` | `*/5 * * * *` | UTC cron for OpenCTI outbox drain retries. |
| `OPENCTI_OUTBOX_MAX_ATTEMPTS` | `6` | Total OpenCTI outbox attempts including first ingest. |
| `OPENCTI_OUTBOX_BASE_DELAY_SECONDS` | `60.0` | Base delay for outbox exponential backoff. |
| `OPENCTI_OUTBOX_JITTER_RATIO` | `0.25` | Jitter ratio applied to outbox retry delays. |
| `SOCIALOSINT_URL` | `http://socialosint:8000` | SocialOSINT service URL. |
| `SOCIALOSINT_TIMEOUT_SECONDS` | `300` | Total wall-clock bound for a full SocialOSINT run. |
| `AMASS_ENGINE_URL` | `http://amass:4000` | Amass engine sidecar URL (compose profile `amass`). |
| `AMASS_DATA_DIR` | `/app/amass/data` | Volume shared with the engine; `asset.db` is read from here. |
| `AMASS_ENUM_BIN` / `AMASS_SUBS_BIN` | `oam_enum` / `oam_subs` | Amass CLI clients (absolute paths when running outside Docker). |
| `AMASS_TIMEOUT_SECONDS` | `1800` | Default wall-clock bound for a full Amass run (enum + subs). |
| `TAVILY_API_KEY` | *(empty)* | Required when `collectors.tavily.enabled=true`; leave blank to keep the collector off. |
| `TAVILY_SEARCH_DEPTH` | `basic` | Tavily query depth: `basic` or `advanced`. |
| `TAVILY_MAX_RESULTS` | `5` | Global ceiling for results per query, 1–20; the per-target `max_results` is clamped to it. |
| `TAVILY_TIMEOUT_SECONDS` | `120` | Default wall-clock budget of a whole Tavily run per target, retries included (`timeout_seconds` in `targets.yaml` overrides it). |
| `TAVILY_MAX_CALLS_PER_RUN` | `3` | Global ceiling for search requests per run, 0–20; the per-target `max_calls_per_run` is clamped to it and `0` switches the collector off for every target (skipped, not failed). |
| `TAVILY_INCLUDE_DOMAINS` | *(empty)* | Optional comma-separated allowlist of result domains (`example.com,news.example.com`). |
| `TAVILY_EXCLUDE_DOMAINS` | *(empty)* | Optional comma-separated denylist of result domains. |
| `ALERT_TIMEOUT_SECONDS` | `10` | Timeout for webhook/email alert send attempts. |
| `ALERT_SMTP_PORT` | `587` | SMTP port for email alerts. |
| `ALERT_SMTP_USER` | *(empty)* | SMTP username for email alerts. |
| `ALERT_SMTP_PASSWORD` | *(empty)* | SMTP password for email alerts. |
| `ALERT_SMTP_FROM` | *(empty)* | Sender address for email alerts. |
| `ALERT_SMTP_STARTTLS` | `true` | Use STARTTLS for SMTP connections. |
| `SHODAN_API_KEY` | *(empty)* | Optional key passed to OpenOSINT enrichment modules. |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional key passed to OpenOSINT enrichment modules. |
| `CENSYS_API_ID` | *(empty)* | Optional key passed to OpenOSINT enrichment modules. |
| `CENSYS_API_SECRET` | *(empty)* | Optional key passed to OpenOSINT enrichment modules. |

Optional enrichment keys (`SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`,
`CENSYS_API_ID`, `CENSYS_API_SECRET`) are passed through to OpenOSINT and may
be left unset.

---

## API

The orchestrator API is available at `http://orchestrator:8000` on the Docker
network and at `http://localhost:8000` from the host. With the optional
[authenticated front door](#optional-authenticated-front-door) enabled, use
`http://localhost:${AUTH_PROXY_PORT:-8002}` for browser access. Public routes
are `GET /`, `GET /docs`, `GET /docs/*`, `GET /openapi.json`, `GET /redoc`,
`GET /health`, `GET /metrics`, `GET /console` and `GET /console/i18n.json`.
Every other endpoint requires an API key; see
[API authentication](#api-authentication-phase-5) and
[ADR-006](docs/adr/ADR-006-oidc-proxy.md).

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Landing page with links to console, docs and health (no API key) |
| `GET` | `/health` | Liveness check (no API key) |
| `GET` | `/metrics` | Prometheus metrics (no API key) |
| `GET` | `/console/i18n.json` | Console translation catalogue (public; no target/run data) |
| `GET` | `/console` | Operator console shell (public, no data; every call it makes needs the API key, entered on the page) |
| `GET` | `/analytics/risk-trends` | Per-target risk and new-observable trends for the console risk view |
| `GET` | `/targets` | List configured targets |
| `GET` | `/targets/{id}` | Get a single target |
| `POST` | `/targets/{id}/run` | Trigger a collection run — `202`, returns `run_id`, runs in background |
| `POST` | `/scheduler/reload/preview` | Preview target cron changes from `targets.yaml` without mutating jobs |
| `POST` | `/scheduler/reload` | Reload target cron jobs from `targets.yaml` without restarting the process |
| `POST` | `/alerts/dlq/replay` | Replay dead-letter alert deliveries (`channel` = `webhook` \| `email`, `limit` = `1..1000`) |
| `POST` | `/opencti/outbox/replay` | Replay dead-letter OpenCTI bundles (`run_id`, `limit` = `1..1000`) and drain the due ones now |
| `GET` | `/runs` | 100 most recent runs, newest first; `?target_id=` filters |
| `GET` | `/runs/{id}` | A run's status, counts, and `alerts[]` dispatch audit |
| `GET` | `/runs/{id}/delta` | Net-new observables for that run (from the DB, not the files) |
| `GET` | `/runs/{id}/report` | Markdown report for a completed run (`text/plain`) |
| `GET` | `/runs/{id}/finding` | LLM-synthesized finding for a completed run |

Interactive docs are at `/docs` (OpenAPI at `/openapi.json`).

**Run status** — `pending` → `running` → one of:

| Status | Meaning |
| --- | --- |
| `success` | Every enabled collector succeeded |
| `partial` | At least one collector succeeded and something failed — a collector, or the OpenCTI ingest of a bundle |
| `failed` | Every collector failed |

An OpenCTI ingest failure counts as an error too: the run ends `partial` with
`opencti-sink: …` in its `error` field, the failure is counted in
`osint_orchestrator_opencti_ingest_total{outcome="failure"}`, and the
observables whose bundle did not land stay un-ingested and are re-reported as
new on the following run. Failed bundles are persisted in `opencti_outbox` and
retried asynchronously by the `opencti-outbox` scheduler worker — one
transaction per bundle, so a crash mid-drain never re-sends what already
landed. Only *transient* failures are retried; a permanent one (invalid
token, rejected bundle) goes straight to `dead_letter`, is logged at
`WARNING` and counted in `opencti_outbox_dead_letter` — fix the cause, then
`POST /opencti/outbox/replay`. Once a deferred bundle lands, its observables
are marked ingested and registered as seen, so later runs and
`GET /runs/{id}/delta` report them correctly; the row keeps its audit trail
but drops the STIX payload (ADR-003).

**Error responses** carry a `detail` string localised per
[ADR-004](docs/adr/ADR-004-language-policy.md): `404` for an unknown target,
run, report or finding; `400` for a target that exists but is `enabled: false`;
`401` for a missing or wrong API key; `409` when a run is already active for
the target.

---

## Target Configuration

Edit `targets.yaml` ([`targets.example.yaml`](targets.example.yaml) is a
commented starting point). **`authorization` and `purpose` are mandatory** —
they are logged with every run for the audit trail.

```yaml
targets:
  - id: my-domain
    enabled: true
    fqdn: example.com
    authorization: "Self-owned. Authorised by: Jane Doe on 2026-09-01"
    purpose: "Continuous exposure monitoring"
    collectors:
      openosint:
        enabled: true
        investigation_type: domain
      spiderfoot:
        enabled: true
        modules: []       # empty = use SPIDERFOOT_MODULES from .env
    schedule:
      cron: "0 8 * * *"  # 08:00 UTC daily
    llm: local            # keeps data on-prem (Ollama)
```

### Field reference

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | *required* | Stable identifier; used in paths, metrics labels and report directories |
| `fqdn` | *required* | The seed entity handed to the collectors |
| `authorization` | *required* | Who approved this target and when |
| `purpose` | *required* | Why it is monitored |
| `enabled` | `true` | `false` skips the cron job; a manual run returns `400` |
| `llm` | `local` | `local` \| `anthropic` \| `openai` \| `nebius` — overrides `LLM_PROVIDER` |
| `language` | *(inherit)* | `es` \| `en` — overrides `ORCHESTRATOR_LANGUAGE` |
| `report_dir` | `daily_reports` | Root directory for this target's artifacts |

`collectors.openosint`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | |
| `investigation_type` | `domain` | `auto` \| `domain` \| `email` \| `username` \| `ip` \| `phone` \| `url` \| `hash` \| `person` |
| `max_depth` | `2` | BFS hops from the seed entity |
| `max_entities` | `40` | Distinct entities to pivot from |
| `max_tool_calls` | `60` | Tool invocations for the whole run |
| `tool_timeout_seconds` | `30` | Per-tool-call ceiling |

The four budget keys are hard bounds on the pivot search. Without them a
scheduled run can expand without limit.

`collectors.spiderfoot`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | |
| `modules` | `[]` | SpiderFoot module names (`sfp_*`); empty falls back to `SPIDERFOOT_MODULES` |
| `timeout_seconds` | `600` | How long to wait for the whole scan |

`collectors.socialosint`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Opt-in (Phase 4b); requires the `socialosint` compose service |
| `usernames` | `[]` | Handles to investigate; empty list ⇒ collector skipped |
| `platforms` | `[twitter, reddit, github, bluesky, hackernews]` | Valid values add `mastodon`; platforms without credentials in `.env` are skipped with a warning |
| `timeout_seconds` | `SOCIALOSINT_TIMEOUT_SECONDS` (`300`) | Total wall-clock bound for the complete workflow; created service sessions are deleted best-effort on exit |

`collectors.amass`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Opt-in; requires the `amass` compose service (see [Amass](#amass)) |
| `active` | `false` | Zone transfers and certificate name grabs against the target (`oam_enum -active`) |
| `brute` | `false` | Wordlist brute forcing after the passive searches (`oam_enum -brute`) |
| `include` / `exclude` | `[]` | Data-source names to restrict the run to / to leave out |
| `progress_timeout_minutes` | `10` | Minutes without new findings before the enumeration stops |
| `timeout_seconds` | `AMASS_TIMEOUT_SECONDS` (`1800`) | Hard wall-clock bound for the whole collector (enum + subs); the CLI process is killed on expiry |

`schedule`:

| Key | Default | Meaning |
| --- | --- | --- |
| `cron` | `"0 8 * * *"` | Five-field [APScheduler](https://apscheduler.readthedocs.io) expression, UTC |
| `misfire_grace_time_seconds` | `3600` | Skip a run missed by more than this instead of firing it late |

`alerts`: see [Alerts](#alerts-phase-4a).

The file is re-read on each API and scheduler call, so target edits take effect
on the next run. Cron schedules are loaded into APScheduler jobs; when you edit
`schedule.cron` or `enabled`, apply the change immediately with:

```bash
curl -X POST -H "X-API-Key: $KEY" http://localhost:8000/scheduler/reload/preview
curl -X POST -H "X-API-Key: $KEY" http://localhost:8000/scheduler/reload
```

---

## Language

Operator-facing output — daily reports, LLM synthesis, API error details — is
rendered in Spanish by default. Source, logs, commits and docs are English.
The rule and its rationale are in
[ADR-004](docs/adr/ADR-004-language-policy.md).

```bash
ORCHESTRATOR_LANGUAGE=es    # es | en — global default
```

Override per target in `targets.yaml`, for when one target's reports go to a
different reader:

```yaml
targets:
  - id: my-domain
    language: en      # omit to inherit ORCHESTRATOR_LANGUAGE
```

An unrecognised value is logged and ignored rather than raised, so a typo
degrades the language of a report instead of stopping the collection.
Identifiers that are compared or persisted — `risk_level`, `RunStatus`, STIX
types — stay English in every language.

---

## Reports (Phase 2)

Each run writes artifacts to `daily_reports/YYYY-MM-DD/<target_id>/` (UTC date):

- `report.md` — operator report with traceability fields, collector status, delta-first section, full inventory, relationships, errors, and a Phase 3 synthesis placeholder.
- `bundle.stix.json` — deterministic merged STIX bundle for the run.
- `delta.json` — only observables marked as new since the previous run.
- `report.pdf` — best-effort rendering via `fpdf2` (optional; if unavailable or failing, run/reporting still succeeds for the other files).

The orchestrator also regenerates `daily_reports/YYYY-MM-DD/index.md` after each run as the daily executive summary (one row per target).

---

## Alerts (Phase 4a)

After every run the orchestrator evaluates dispatch rules and sends configured
channels. Attempts are recorded in `alerts`; failed deliveries are persisted
in `alert_deliveries` for exponential-backoff retries and DLQ handling.

### Channels

| Channel | Required variables |
| --- | --- |
| **Webhook** | `ALERT_WEBHOOK_URL` (+ `ALERT_WEBHOOK_SECRET` for signing) |
| **Email (SMTP)** | `ALERT_SMTP_HOST`, `ALERT_EMAIL_TO` (+ optional auth/TLS vars) |

A channel without its required variables is skipped with a warning logged **once** at
startup.

### Retry queue and DLQ

The queue is the only retry loop: a notifier makes exactly one attempt per
call, so `ALERT_RETRY_MAX_ATTEMPTS` is the real number of network calls.
Each delivery is claimed and committed before the send and finalised right
after, so a crash or two concurrent drains can cost one duplicate at most.
A failure the receiver will repeat — a `4xx` other than `429`, an SMTP
authentication or recipient refusal, a channel that is not configured —
skips the retries and goes to `dead_letter` immediately; timeouts, `5xx`
and `429` are retried with exponential backoff.

| Variable | Default | Description |
| --- | --- | --- |
| `ALERT_RETRY_CRON` | `*/5 * * * *` | UTC cron for retry worker (`alert-retry` scheduler job). |
| `ALERT_RETRY_MAX_ATTEMPTS` | `4` | Total attempts per message, including first synchronous send. |
| `ALERT_RETRY_BASE_DELAY_SECONDS` | `30` | Exponential backoff base delay. |
| `ALERT_RETRY_JITTER_RATIO` | `0.25` | ± jitter multiplier applied to each retry delay. |

When attempts are exhausted, the message moves to `dead_letter` status and can
be replayed manually:

```bash
curl -X POST -H "X-API-Key: $KEY" \
  "http://localhost:8000/alerts/dlq/replay?channel=webhook&limit=50"
```

### Dispatch rules (per target)

```yaml
alerts:
  enabled: true           # default true
  on_new_observables: true  # alert when there are new observables
  min_risk_level: high    # alert when risk is high or critical even without new obs.
  include_values: true    # set false to omit observable values from the payload
```

### Webhook JSON schema

> ⚠️ **Privacy**: when `include_values: true` (default) the webhook payload contains
> observable values such as domain names, IP addresses, and email addresses. Set
> `include_values: false` to send only counts and types.

```json
{
  "target_id":            "example-domain",
  "target_fqdn":          "example.com",
  "run_id":               42,
  "run_status":           "success",
  "risk_level":           "high",
  "new_observables": [
    {"stix_type": "domain-name", "value": "sub.example.com", "stix_id": "domain-name--<uuid>"}
  ],
  "new_observable_count": 1,
  "report_path":          "/app/daily_reports/2026-09-08/example-domain/report.md",
  "finding_summary":      "Newly exposed subdomain detected.",
  "generated_at":         "2026-09-08T08:03:21.456789Z"
}
```

**Signature verification** — every request carries `X-Orchestrator-Signature: sha256=<hex>`.
Verify it in the receiver:

```python
import hashlib, hmac

def verify_signature(body: bytes, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

---

## Retention

Old run records and `daily_reports/` directories are purged automatically by a
nightly background job.

| Variable | Default | Description |
| --- | --- | --- |
| `ORCHESTRATOR_RETENTION_DAYS` | `90` | Keep data for this many days. Set to `0` to disable. |
| `ORCHESTRATOR_RETENTION_CRON` | `30 3 * * *` | UTC cron schedule for the purge job. |

> **Compliance:** `90` is an operational default, not a regulatory retention
> period. If these reports form part of an Uruguayan obliged party's due
> diligence evidence, article 15 of Decree 379/018 sets a five-year minimum.
> Configure a compatible period (for example, `1825` days as a floor subject
> to professional review) or archive artifacts in controlled external storage
> before the purge.

The job deletes rows from `runs`, `run_observables`, `findings`, `alerts`,
`alert_deliveries`, and `opencti_outbox` whose `finished_at` (or `started_at`
for never-finished runs) is older than the threshold. The `seen_observables`
table is **never** touched — it is the delta memory between runs.

Report directories named `daily_reports/YYYY-MM-DD` whose date is before the
threshold are also removed.  Directories with non-date names are left intact.

---

## API authentication (Phase 5)

Every endpoint except `GET /`, `GET /docs`, `GET /openapi.json`, `GET /redoc`, `GET /health`, `GET /metrics`, `GET /console` and `GET /console/i18n.json` requires an API key.
Present it as `X-API-Key: <key>` or `Authorization: Bearer <key>`.

```bash
ORCHESTRATOR_API_KEY=            # Generate: openssl rand -hex 32
                                 # comma-separate two keys while rotating
```

```bash
curl -H "X-API-Key: $ORCHESTRATOR_API_KEY" http://localhost:8000/targets
```

An empty `ORCHESTRATOR_API_KEY` leaves the API **open** and logs a warning at
startup — fine on a laptop, not fine anywhere else. Rejections are `401` with
a localised `detail` and `WWW-Authenticate: Bearer`. The reasoning (why a
static key and not OAuth) is in [ADR-005](docs/adr/ADR-005-api-auth-and-single-instance.md).

**Rotating a key** without a cut-over window: list old and new together
(`ORCHESTRATOR_API_KEY=old,new`), restart, move every caller to the new key,
then drop the old one and restart again. Keys are compared in constant time and
all configured keys are checked on every request, so a rejection takes the same
time whichever slot would have matched.

---

## Observability (Phase 5)

### Logs

```bash
ORCHESTRATOR_LOG_LEVEL=INFO      # DEBUG | INFO | WARNING | ERROR
ORCHESTRATOR_LOG_FORMAT=text     # text | json
```

With `json`, every line is one object a log shipper can index without a regex:

```json
{"ts":"2026-09-08T08:03:21.456Z","level":"INFO","logger":"orchestrator.pipeline","msg":"Pipeline done: target=example-domain run_id=42 status=success new_observables=3","target_id":"example-domain","run_id":42,"status":"success","new_observables":3,"collectors":["openosint","spiderfoot"]}
```

Each HTTP request carries a request id (send your own in `X-Request-ID` or one
is generated), echoed in the response header and stamped on every log line
emitted while handling it. uvicorn's access and error logs use the same format.
Background runs started by the scheduler log `-`, so a line without a
caller-supplied id is a scheduled run rather than a lost correlation.

### Metrics

`GET /metrics` serves Prometheus metrics (no API key; disable with
`ORCHESTRATOR_METRICS_ENABLED=false`). All names are prefixed
`osint_orchestrator_` and label values are bounded — never an observable value
or a run id.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `http_requests_total` | `method`, `path` (route template), `status` | API traffic |
| `http_request_duration_seconds` | `method`, `path` (route template) | API latency — no `status` label, so latency cannot be split by response code |
| `runs_total` | `target_id`, `status` | Completed runs by final status (`success`, `partial`, `failed`) |
| `runs_in_progress` | `target_id` | Runs currently executing |
| `run_duration_seconds` | `target_id` | Full pipeline duration histogram |
| `collector_runs_total` | `collector`, `target_id`, `outcome` | Per-collector outcome (`success`, `failure`, `error`) |
| `collector_duration_seconds` | `collector` | Per-collector duration — no `target_id` label, so duration cannot be split by target |
| `run_observables` | `target_id`, `kind` (`total`, `new`) | Observables in the most recent run |
| `new_observables_total` | `target_id` | Net-new, ingested observables (the alert/delta definition) |
| `target_last_success_timestamp_seconds` | `target_id` | Last successful run timestamp (use `time() - metric` for freshness age) |
| `opencti_ingest_total` | `target_id`, `outcome` | STIX bundles pushed to OpenCTI |
| `opencti_ingest_retries_total` | `target_id` | Retries after a transient OpenCTI error (pycti's internal per-object retries are not counted) |
| `opencti_outbox_pending` | — | Pending OpenCTI bundles waiting for retry |
| `opencti_outbox_oldest_age_seconds` | — | Age of oldest pending OpenCTI outbox bundle |
| `opencti_outbox_deliveries_total` | `outcome` | Outbox outcomes (`sent`, `failed`, `dead_letter`) |
| `opencti_outbox_retries_total` | `target_id` | OpenCTI outbox retry attempts |
| `opencti_outbox_dead_letter` | — | OpenCTI bundles parked in the dead-letter queue (need operator action) |
| `alert_deliveries_pending` | — | Alert deliveries waiting for a retry |
| `alert_deliveries_dead_letter` | — | Alert deliveries parked in the dead-letter queue (need operator action) |
| `synthesis_total` | `target_id`, `status` (`ok`, `skipped`, `failed`) | LLM synthesis attempts |
| `llm_requests_total` | `provider`, `model`, `status` | LLM API requests by provider (`anthropic`, `openai`, `nebius`, `ollama`), model and status (`ok`, `http_429`, `http_5xx`, `timeout`, `error`, `schema_downgrade`). One sample per SDK completion call: the Anthropic SDK's single internal retry is not sampled. |
| `llm_tokens_total` | `provider`, `model`, `direction` (`input`, `output`) | LLM token usage by provider and model, split by prompt vs completion direction |
| `alerts_total` | `channel`, `status` | Alert lifecycle events (`sent`, `failed`, `retried`, `dlq`) |
| `scheduled_jobs` | — | Cron jobs registered in the scheduler |
| `build_info` | `version` | Build metadata |

Three alerts worth having first:

```promql
# A run failed outright in the last day
increase(osint_orchestrator_runs_total{status="failed"}[1d]) > 0

# Findings are reaching OpenCTI
increase(osint_orchestrator_opencti_ingest_total{outcome="failure"}[1h]) > 0

# The scheduler lost its jobs (targets.yaml unreadable at startup)
osint_orchestrator_scheduled_jobs == 0
```

Operational SLO starter pack:

```promql
# Freshness age per target (seconds since last successful run)
time() - osint_orchestrator_target_last_success_timestamp_seconds

# Health semaphore: 0=fresh (<24h), 1=stale (>=24h)
(time() - osint_orchestrator_target_last_success_timestamp_seconds) >= bool 86400

# 7-day success ratio by target
sum by (target_id) (increase(osint_orchestrator_runs_total{status="success"}[7d]))
/
sum by (target_id) (increase(osint_orchestrator_runs_total[7d]))
```

---

## Business guides

- [Executive project presentation (Spanish)](docs/business/presentacion-ejecutiva-orquestacion-osint.es.md) · [English](docs/business/executive-project-presentation.md)

Full documentation index: [`docs/README.md`](docs/README.md).

---

## Kubernetes (Phase 5)

A Helm chart in [`deploy/helm/osint-orchestrator`](deploy/helm/osint-orchestrator/)
deploys the orchestrator only; OpenCTI, SpiderFoot and Ollama are deployed with
their own charts and referenced by URL.

```bash
helm upgrade --install osint-orchestrator deploy/helm/osint-orchestrator \
  --namespace osint --create-namespace -f my-values.yaml
```

> The orchestrator is **single-instance by design** (SQLite + in-process
> scheduler): `replicaCount` stays at 1, the strategy is `Recreate` and one
> `ReadWriteOnce` volume holds the database and the daily reports. See
> [ADR-005](docs/adr/ADR-005-api-auth-and-single-instance.md) for the trigger
> that would change this.

The [chart README](deploy/helm/osint-orchestrator/README.md) covers secrets
(`existingSecret`), the `targets.yaml` ConfigMap, the Prometheus
`ServiceMonitor` and the values people actually change.

---

## Development

```bash
# Install dev dependencies (pulls the pinned openosint fork; needs git)
pip install -e ".[dev]"

# Lint
ruff check orchestrator/ tests/unit/
ruff format --check orchestrator/ tests/unit/

# Unit tests (no Docker needed)
pytest tests/unit/ -v

# Integration tests (requires docker compose up)
pytest tests/integration/ -m integration -v

# Helm chart
helm lint deploy/helm/osint-orchestrator --strict
helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0 > /dev/null
```

`--strict` is what CI runs, so a lint without it can pass locally and still
block the PR. `--kube-version` is required because the chart declares
`kubeVersion: >=1.25.0-0` and `helm template` otherwise assumes an old default.

Contribution workflow and conventions: [`CONTRIBUTING.md`](CONTRIBUTING.md).

### Repository layout

```text
orchestrator/
  api.py               FastAPI app, routes, request-id middleware
  auth.py              API-key dependency (X-API-Key / Bearer)
  config.py            pydantic-settings — the environment contract
  database.py          async engine and session factory
  i18n.py              operator-facing strings, es + en (ADR-004)
  logging_config.py    text/JSON formatters, request-id contextvar
  metrics.py           Prometheus collectors
  models.py            SQLModel tables + targets.yaml schema + CollectorResult v1.0 contract
  pipeline.py          collect → normalise → ingest → synthesise → report → alert
  scheduler.py         APScheduler cron jobs built from targets.yaml
  collectors/          openosint, spiderfoot, socialosint, amass
  normalizer/stix.py   findings → STIX 2.1 bundle, deterministic ids
  sinks/__init__.py    pycti ingest: auth probe, transient-only retry, off-loop
  synthesizer/         LLM providers: ollama, anthropic, openai-compatible
  reports/             report.md, index.md, optional PDF
  alerts/              webhook + SMTP dispatch
deploy/helm/           Kubernetes chart
docs/adr/              architecture decisions (English + Spanish)
tests/unit/            no Docker required
tests/integration/     requires the stack up; marker: integration
```

Conventions: ruff with `E,F,I,UP,B,SIM,N` at a 100-character line length;
`pytest` in `asyncio_mode = auto`; git dependencies pinned by full commit SHA
and Docker images by explicit tag, never `:latest`.

---

## Database Migrations

The orchestrator uses [Alembic](https://alembic.sqlalchemy.org/) to manage schema migrations.
The service applies all pending migrations automatically **on every startup** — no manual step needed in normal operation.

### How it works

- Migration scripts live in `orchestrator/migrations/versions/`.
- On startup, `create_db_and_tables()` calls `alembic upgrade head`.
- **Existing databases** without an `alembic_version` table (created before Alembic was introduced) are automatically stamped at the baseline revision before any upgrade runs, so no data is lost.

### Generating a new migration

After changing a SQLModel in `orchestrator/models.py`:

```bash
# Apply all current migrations first (so Alembic has a baseline to diff against).
alembic upgrade head

# Generate a migration from the diff between models and the live schema.
alembic revision --autogenerate -m "add my_new_column to runs"
```

Review the generated file in `orchestrator/migrations/versions/` and adjust if necessary.

### Applying migrations manually

```bash
alembic upgrade head          # apply all pending migrations
alembic current               # show the current revision
alembic history --verbose     # list all revisions
alembic downgrade -1          # roll back one step
```

### CI check

The CI pipeline runs `alembic upgrade head` on a temporary SQLite database and then
`alembic check` — this fails the build if a model was changed without a corresponding migration.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Elasticsearch exits seconds after `docker compose up` | `vm.max_map_count` below 262144 on the host — see [Hardware](#hardware-requirements) |
| `curl :8080/health` refused for the first minutes | OpenCTI and Elasticsearch take 2–3 min; follow `docker compose logs -f opencti` |
| Containers killed by the OOM killer | Host below 16 GB, or `ELASTIC_MEMORY_SIZE` too high for it |
| `401` on every call | `ORCHESTRATOR_API_KEY` is set but the header is missing or wrong; `/health` and `/metrics` never need one |
| The API answers without a key | `ORCHESTRATOR_API_KEY` is empty — the startup log says so explicitly |
| `404` on `/metrics` | `ORCHESTRATOR_METRICS_ENABLED=false` |
| `400` on `POST /targets/{id}/run` | The target exists but is `enabled: false` |
| `pip install -e .` cannot resolve `openosint` | The dependency is a `git+https` pin, so a git client must be on `PATH` |
| A SpiderFoot scan never finishes | Raise the target's `timeout_seconds`; check the module names are real `sfp_*` modules in that image |
| Run is `partial` with `opencti-sink:` in `error` | The bundle never reached OpenCTI — check `osint_orchestrator_opencti_ingest_total{outcome="failure"}`, `OPENCTI_URL` and `OPENCTI_ADMIN_TOKEN`; the observables are re-reported as new next run |
| Reports come out in the wrong language | `ORCHESTRATOR_LANGUAGE`, or the target's `language`; an unrecognised value is logged and ignored |
| A run finishes with no finding / `synthesis_total{status="failed"}` grows | The LLM endpoint is unreachable — compose ships no Ollama service; check `LLM_BASE_URL` or switch `LLM_PROVIDER` (see [Quick Start](#2-start-the-stack)) |
| Browser login loops or `502` on `:8002` with the auth overlay | Keycloak not healthy yet, or `AUTH_PROXY_PORT`/`AUTH_REDIRECT_URL` disagree — both must use the same port (`.env.example` ships 8002) |
| A changed `cron` has no effect | Cron expressions are registered at startup — restart the orchestrator |
| `osint_orchestrator_scheduled_jobs` is lower than expected | A target is `enabled: false`, or its `cron` is not five fields — both are skipped, the second with an `ERROR` log |
| `osint_orchestrator_scheduled_jobs` is 0 | `targets.yaml` was not found at `TARGETS_FILE` when the app started (a `WARNING` names the path) |

---

## Phases

| Phase | Status | Description |
| --- | --- | --- |
| **0** | ✅ Done | ADRs, pyproject, CI, docker-compose, `/health` |
| **1** | ✅ Done | OpenOSINT collector (in-process via `investigate()`) → STIX normalizer → OpenCTI ingest with deterministic, spec-compliant STIX ids |
| **2** | ✅ Done | SpiderFoot collector + scheduler + daily reports (`report.md`, `bundle.stix.json`, `delta.json`, optional `report.pdf`, daily `index.md`) |
| **3** | ✅ Done | LLM synthesis (Ollama / Anthropic / OpenAI) per target |
| **4a** | ✅ Done | Observable-seen fix (#8), DB-based delta endpoint (#10), webhook + email alerts |
| **4b** | ✅ Done | SocialOSINT collector (HTTP, opt-in) + MISP real stack + `connector-misp` |
| **5** | ✅ Done | API-key auth, JSON logs + request ids, Prometheus `/metrics`, Helm chart |

---

## Architecture Decisions

- [ADR-001: Modular Monolith](docs/adr/ADR-001-modular-monolith.md)
- [ADR-002: STIX 2.1 as the Internal Data Contract](docs/adr/ADR-002-stix-as-contract.md)
- [ADR-003: OpenCTI as the Single Source of Truth](docs/adr/ADR-003-opencti-as-store.md)
- [ADR-004: Spanish for Operators, English for Code](docs/adr/ADR-004-language-policy.md)
- [ADR-005: Static API Keys, Structured Observability and a Single-Instance Deployment](docs/adr/ADR-005-api-auth-and-single-instance.md)
- [ADR-006: Optional OIDC Proxy as a Perimeter Layer](docs/adr/ADR-006-oidc-proxy.md)

Each ADR has a Spanish companion alongside it (`-es.md`).

---

## Tool Notes

- **openosint**: pinned to the fork [`careb36/OpenOSINT`](https://github.com/careb36/OpenOSINT) (MIT), **not** the PyPI release. The collector calls `openosint.investigate.investigate()` — the documented public Python API for downstream consumers — which upstream 2.27.0 on PyPI does not ship. The dependency is pinned by commit so a push to the fork cannot silently change what a build resolves to; bump it deliberately. Because it is a git reference, `pip install` needs a git client (the Dockerfile installs one).
- **SpiderFoot**: built locally from the upstream GitHub repository (`smicallef/spiderfoot`, default branch — no registry image is pulled; result is tagged `spiderfoot:local`). Port 5001. No `/api/v1/` prefix — endpoints are at root path (`/startscan`, `/scanstatus`, etc.). Because the build context tracks a branch rather than a tag, rebuilds can pick up upstream changes; pin the context to a commit (`context: https://github.com/smicallef/spiderfoot.git#<sha>`) if you need reproducibility.
- **OWASP SocialOSINT**: source at [bm-github/owasp-social-osint-agent](https://github.com/bm-github/owasp-social-osint-agent). Entry point is CLI + JSON mode (no standalone HTTP API). Integrated in Phase 4b.
- **OWASP Amass**: official image `owaspamass/amass:v5.1.1` (Apache-2.0), pinned by tag. The engine runs as a sidecar; its HTTP API only manages sessions, so results are read with `oam_subs` from the SQLite asset database on the shared volume (the orchestrator image copies `oam_enum`/`oam_subs` from the same upstream image). `-silent` on `oam_subs` also silences the names, which is why the collector passes it only to `oam_enum`.
- **MISP**: via official [OpenCTI↔MISP connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp). No custom connector code in this repo.
- **TheHive**: v4 is discontinued; TheHive 5 is commercial. Not included pending licence evaluation.

---

## Licence

MIT — see [LICENSE](LICENSE).

## Project documents

[CONTRIBUTING](CONTRIBUTING.md) · [SECURITY](SECURITY.md) · [CHANGELOG](CHANGELOG.md) · [Documentation index](docs/README.md)

---

## Running on Nebius Token Factory + NVIDIA Nemotron

1. Set `LLM_PROVIDER=nebius`.
2. Add your API key in `NEBIUS_API_KEY`.
3. Keep `NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1` unless your account team provides a different endpoint.
4. Choose models:
   - `LLM_MODEL_REASONING` for synthesis and relationship-heavy reasoning, for example `nvidia/nemotron-3-super-120b-a12b` (or `nvidia/Nemotron-3-Ultra-550b-a55b`).
   - `LLM_MODEL_FAST` for lightweight classification/extraction, for example `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` (or `nvidia/Nemotron-3_5-Lightning`).
   - Model ids are case-sensitive and the catalogue changes; list what your key can use with `curl -H "Authorization: Bearer $NEBIUS_API_KEY" https://api.tokenfactory.nebius.com/v1/models`. An id that is not in that list fails every synthesis.
   - If either is empty, it falls back to `LLM_MODEL`.
5. Run with your normal stack (`docker compose up -d --build`; the image installs the `llm` extra, which brings the `openai` SDK this provider needs — a local `pip install` needs `pip install -e ".[llm]"`) and verify the pipeline as usual (`POST /targets/{id}/run`, then inspect `/runs/{id}/finding`).

Notes:
- Nebius uses the same OpenAI-compatible provider path as `openai` (no duplicated integration code).
- Synthesis requests use the reasoning route.
- JSON-schema response format is requested first; a provider that rejects `response_format` (400/422) gets the same request once more without it, counted as `schema_downgrade` and not as a failed attempt, and the reply goes through the tolerant JSON parser.
- Retries: up to 3 attempts on 408, 409, 429, any 5xx and transport errors, honouring `Retry-After`, all inside `LLM_TIMEOUT_SECONDS` — the budget bounds every attempt and backoff of one call.
- The finding records the provider (`openai`, `nebius`, `anthropic`, `ollama` — the same value as the metrics' `provider` label) and the model that actually served the request (`/runs/{id}/finding`).
