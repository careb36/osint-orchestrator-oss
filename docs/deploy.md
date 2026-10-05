# Deploying the demo

The demo image ([`Dockerfile.demo`](../Dockerfile.demo)) runs the orchestrator
in [demo mode](operations.md#demo-mode): one container, SQLite, port `7860`,
uid `1000`. Keys are read from the environment and never baked into the image.

## Environment

| Variable | Value |
| --- | --- |
| `NEBIUS_API_KEY`, `TAVILY_API_KEY` | Secrets |
| `ORCHESTRATOR_API_KEY`, `ORCHESTRATOR_SECRET_KEY` | Secrets; generate each with `openssl rand -hex 32` |
| `LLM_PROVIDER` | `nebius` |
| `LLM_MODEL_REASONING`, `LLM_MODEL_FAST` | Nemotron ids served to your key (`GET /v1/models`) |
| `DEMO_TRUSTED_PROXY_HOPS` | Number of proxies in front of the container (`1` behind a single platform proxy) |
| `DEMO_*` limits | Optional; defaults in [configuration.md](configuration.md). Behind a platform proxy keep `DEMO_MAX_RUNS_PER_IP_PER_DAY` low; locally (`docker-compose.demo.yml`) it equals the global cap because every browser shares Docker's bridge address |

The image already sets `DEMO_MODE=true`, `OPENCTI_ENABLED=false`, the allowlist
path and the database path. The container refuses to start if a required value
is missing, and the log names it.

Storage is the container's file system: runs made by visitors are lost on a
restart unless the platform provides a persistent volume for `/app/data` and
`/app/daily_reports`. Seeded runs are re-imported on every fresh start.

## Hugging Face Spaces

Checked against the [Docker Spaces documentation](https://huggingface.co/docs/hub/spaces-sdks-docker);
**not yet executed** for this project.

1. Create a Space with the **Docker** SDK.
2. In the Space's `README.md` front matter set `sdk: docker` and
   `app_port: 7860`.
3. Add the secrets and variables of the table above in *Settings → Variables
   and secrets*. They are injected as environment variables at run time.
4. Push this repository's content to the Space with `Dockerfile.demo` copied to
   `Dockerfile` (Spaces build the file named `Dockerfile` at the repository
   root).
5. Open `/demo` on the Space URL. `/health` answers without a key.

## Nebius serverless endpoint

**Not yet verified.** The [Nebius documentation](https://docs.nebius.com/serverless/endpoints/manage)
describes creating an endpoint from a container image with ports, environment
variables and optional token authentication. The expected steps are: push the
image built from `Dockerfile.demo` to a registry, create an endpoint from that
image exposing port `7860`, set the variables of the table above, and leave the
endpoint's own token authentication off so `/demo` stays public (the protected
routes keep requiring `ORCHESTRATOR_API_KEY`).
