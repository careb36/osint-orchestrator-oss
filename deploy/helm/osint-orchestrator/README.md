# osint-orchestrator Helm chart

Deploys the **orchestrator only**. OpenCTI (with Elasticsearch, Redis,
RabbitMQ, MinIO and its workers) and SpiderFoot are deployed with their own
charts and referenced by URL in `values.yaml`:

| Component | How to deploy | Value |
|---|---|---|
| OpenCTI | [OpenCTI Helm chart](https://github.com/devops-ia/helm-opencti) or the vendor's manifests | `config.openctiUrl` |
| SpiderFoot | any Deployment of `ghcr.io/smicallef/spiderfoot` exposing port 5001 | `config.spiderfootUrl` |
| Ollama (optional) | [Ollama Helm chart](https://github.com/otwld/ollama-helm) | `config.llm.baseUrl` |

## Single instance, by design

The orchestrator stores operational state in SQLite and runs its cron
scheduler in-process. **Keep `replicaCount: 1`.** The Deployment uses the
`Recreate` strategy and one `ReadWriteOnce` volume for the database and the
daily reports. See ADR-005 in the repository for when that decision gets
revisited.

## Install

```bash
# 1. Build and push the image (none is published yet)
docker build -t registry.example.com/osint-orchestrator:0.1.0 .
docker push registry.example.com/osint-orchestrator:0.1.0

# 2. Secrets — keep them out of values files
kubectl -n osint create secret generic osint-orchestrator \
  --from-literal=OPENCTI_ADMIN_TOKEN="$(uuidgen)" \
  --from-literal=ORCHESTRATOR_API_KEY="$(openssl rand -hex 32)" \
  --from-literal=ORCHESTRATOR_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=ALERT_WEBHOOK_SECRET="$(openssl rand -hex 32)"

# 3. Targets — the audit trail (authorization + purpose) lives here
cat > my-values.yaml <<'EOF'
image:
  repository: registry.example.com/osint-orchestrator
  tag: "0.1.0"
secrets:
  existingSecret: osint-orchestrator
config:
  openctiUrl: http://opencti.opencti.svc:8080
  spiderfootUrl: http://spiderfoot.osint.svc:5001
targets:
  targets:
    - id: example-domain
      fqdn: example.com
      authorization: "Self-owned. Authorised by: Jane Doe on 2026-09-01"
      purpose: "Continuous exposure monitoring"
      schedule:
        cron: "0 8 * * *"
EOF

# 4. Install
helm upgrade --install osint-orchestrator deploy/helm/osint-orchestrator \
  --namespace osint --create-namespace -f my-values.yaml
```

Secrets rendered from `secrets.values` are convenient for a lab; in
production point `secrets.existingSecret` at a Secret managed by External
Secrets, Sealed Secrets or your vault of choice. Any key present in that
Secret is exported to the container as an environment variable, so it may
carry extra variables (SMTP credentials, LLM keys) beyond the ones listed in
`values.yaml`.

## Observability

- **Logs**: `config.logFormat: json` (default) — one JSON object per line
  with `ts`, `level`, `logger`, `msg`, `request_id` and the pipeline context
  (`target_id`, `run_id`, `collector`).
- **Metrics**: `GET /metrics` (no API key needed). Pods carry
  `prometheus.io/scrape` annotations by default; set
  `metrics.serviceMonitor.enabled: true` for the Prometheus Operator.
- **Probes**: liveness uses `GET /health` (200 while the process answers);
  readiness and startup use `GET /ready`, which answers 503 while the database
  is offline or the scheduler is not running.

## Values

See [`values.yaml`](values.yaml); every key is commented. The ones people
actually change:

| Key | Default | Meaning |
|---|---|---|
| `image.repository` / `image.tag` | `ghcr.io/careb36/osint-orchestrator-oss` / appVersion | Where you pushed the image |
| `secrets.existingSecret` | `""` | Secret carrying `OPENCTI_ADMIN_TOKEN`, `ORCHESTRATOR_API_KEY`, ... |
| `config.openctiUrl` | `http://opencti:8080` | In-cluster OpenCTI URL |
| `config.spiderfootUrl` | `http://spiderfoot:5001` | In-cluster SpiderFoot URL |
| `config.language` | `es` | Operator-facing language (ADR-004) |
| `config.logFormat` | `json` | `json` or `text` |
| `targets.targets` / `targets.existingConfigMap` | `[]` / `""` | The `targets.yaml` content |
| `persistence.size` | `5Gi` | Database + daily reports volume |
| `ingress.enabled` | `false` | Expose the API (put the API key in front of it, always) |
| `metrics.serviceMonitor.enabled` | `false` | Prometheus Operator ServiceMonitor |

## Upgrade notes

Changing anything under `config`, `targets.targets` or `secrets.values`
rolls the pod (checksum annotations). `targets.yaml` is read at startup and
on each API/scheduler call, so target edits take effect on the next run
without a restart once the ConfigMap propagates — but the cron *schedule*
is registered at startup, so a changed cron needs the roll the checksum
gives it.
