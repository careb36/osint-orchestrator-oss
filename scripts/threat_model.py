"""
OWASP pytm threat model of the OSINT Orchestrator.

Model source of truth: docs/architecture.md, docs/adr/ (001-011),
docker-compose*.yml, the Dockerfiles, orchestrator/config.py,
orchestrator/auth.py, orchestrator/alerts/__init__.py and the collectors.

pytm is a modelling tool, not a runtime dependency of the service: it lives in
a throwaway virtualenv and never in pyproject.toml (see docs/operations.md,
"Threat model"). Regenerate the report with:

    python3 -m venv .venv-pytm
    .venv-pytm/bin/pip install pytm==1.4.0
    .venv-pytm/bin/python scripts/threat_model.py

Two contracts keep the report honest:

- Every finding needs a triage response for its (threat, element class), or
  an explicit (element, threat) override, else the run fails. A response is
  written for the kind of element it applies to: a control of the
  orchestrator never closes a finding on a sidecar or a vendor service.
- Every (threat, element) pair the model fires is listed in
  scripts/threat_model_findings.txt. A new pair (a new element, a new flow, a
  control removed) or a vanished one fails the run until a reviewer runs
  `--accept`, which rewrites the ledger; its diff is reviewed with the PR.

Controls mirror what each component actually ships. Deliberate gaps are left
open on purpose so they surface as findings with an accepted response: plain
HTTP on loopback and the compose bridge (the shipped OIDC overlay terminates
no TLS either), unauthenticated sidecars, no encryption at rest, static
long-lived keys, MISP certificate verification off in local dev, the optional
webhook signature.
"""

import sys
from pathlib import Path

try:
    from pytm import (
        LLM,
        TM,
        Actor,
        Boundary,
        Classification,
        Controls,
        Data,
        Dataflow,
        Datastore,
        ExternalEntity,
        Lifetime,
        Process,
        Server,
        TLSVersion,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - tool venv missing
    raise SystemExit(
        "pytm is not installed in this interpreter. Create the tool venv and pin it:\n"
        "    python3 -m venv .venv-pytm && .venv-pytm/bin/pip install pytm==1.4.0\n"
        "    .venv-pytm/bin/python scripts/threat_model.py"
    ) from exc

HERE = Path(__file__).resolve()
REPORT = HERE.parents[1] / "docs" / "threat-model.md"
LEDGER = HERE.with_name("threat_model_findings.txt")

tm = TM("OSINT Orchestrator")
tm.description = (
    "Modular monolith (ADR-001): one FastAPI process with an in-process APScheduler and a "
    "SQLite store drives OSINT collectors, qualifies evidence with an LLM, normalises findings "
    "to STIX 2.1 (ADR-002), ingests them into OpenCTI (ADR-003/008), seals a signed report chain "
    "per run (ADR-007) and dispatches alerts by webhook and e-mail. Access uses static API keys "
    "and a single instance (ADR-005), with an optional OIDC proxy perimeter (ADR-006) and an "
    "external STIX intake (ADR-011). Operator prose is Spanish, code English (ADR-004)."
)
tm.assumptions = [
    "Single-instance deployment on a trusted Docker host; loopback-published ports are reachable "
    "only from that host.",
    "The Docker host and the compose network are operated by the same team as the orchestrator.",
    "ORCHESTRATOR_API_KEY is set. require_api_key is a no-op with an empty key (open mode, "
    "documented in ADR-005 and ADR-006); that mode is out of this model's scope.",
    "The shipped docker-compose.auth.yml terminates no TLS: oauth2-proxy listens on plain HTTP "
    "on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false, and the browser logs in at "
    "Keycloak's own HTTP endpoint (KC_HOSTNAME http://localhost:8085, OIDC_BROWSER_LOGIN_URL). "
    "A TLS terminator in front of both, with KC_HOSTNAME and the login URL on the https:// "
    "name, is a production hardening step, modelled as absent.",
    "Alert channels are modelled with their defaults: SMTP with STARTTLS "
    "(ALERT_SMTP_STARTTLS=true) and the webhook over an https:// URL of the operator's with "
    "the optional HMAC signature (ALERT_WEBHOOK_SECRET) unset. ALERT_WEBHOOK_URL accepts any "
    "URL (config.py) and the notifier posts to it as given; an http:// webhook would carry the "
    "alert payload and the URL's own token in clear and is outside this model's scope.",
    "Collectors only query targets authorised in targets.yaml (operator attestation per target).",
    "OpenCTI, MISP, Amass, SocialOSINT and the OIDC overlay are optional deployments; the model "
    "covers them when enabled.",
    "ORCHESTRATOR_SECRET_KEY is a private, randomly generated value. The default "
    "insecure-dev-key only earns a startup warning (auth.py); with it, or with an empty key, "
    "anyone can forge a manifest, and the integrity claims of this model do not hold.",
    "The shipped compose has no Ollama service (docs/operations.md): `llm: local` needs an "
    "operator-provisioned Ollama on the same host, attached to the compose network or on "
    "loopback, which LLM_BASE_URL points at; that prerequisite is modelled inside the trusted "
    "compose boundary. OllamaClient posts to whatever URL is configured (providers/ollama.py), "
    "so a remote LLM_BASE_URL turns `llm: local` into the cloud-provider case of this model; a "
    "remote Ollama is not modelled separately.",
    "The operator's browser is outside the model. The console keeps ORCHESTRATOR_API_KEY in "
    "sessionStorage and, with 'Remember me', in localStorage in clear (ui/src/lib/api.ts), so "
    "a key retained in a shared or compromised browser is the operator's residual risk. "
    "Hardening: no 'Remember me' on shared machines and rotation through the comma-separated "
    "key set.",
]

# ── Boundaries ──────────────────────────────────────────────────────────────
internet = Boundary("Public Internet")
edge = Boundary("OIDC edge (optional, ADR-006)")
compose = Boundary("Docker compose network (trusted host)")
opencti_b = Boundary("OpenCTI platform (separate admin domain)")

# ── Data assets ─────────────────────────────────────────────────────────────
api_key = Data(
    name="ORCHESTRATOR_API_KEY",
    description="Static operator API key, comma-separated rotation set (ADR-005); the console keeps it in the browser's sessionStorage, and in localStorage with 'Remember me'.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
opencti_token = Data(
    name="OPENCTI_ADMIN_TOKEN",
    description="OpenCTI admin token shared by the sink and every connector.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
llm_key = Data(
    name="LLM provider API key",
    description="Cloud provider key (Nebius/OpenAI/Anthropic) when a cloud route is configured.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
tavily_key = Data(
    name="TAVILY_API_KEY",
    description="Tavily Search API key, sent as the Tavily client's own credential.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
misp_key = Data(
    name="MISP_KEY",
    description="MISP API key the OpenCTI MISP connector polls events with.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
smtp_credentials = Data(
    name="ALERT_SMTP_USER / ALERT_SMTP_PASSWORD",
    description="Optional SMTP AUTH credentials of the alert mailer.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
keycloak_password = Data(
    name="Operator Keycloak credentials",
    description="Username and password typed into Keycloak's login page behind the OIDC overlay.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
oidc_client_secret = Data(
    name="AUTH_CLIENT_SECRET",
    description="oauth2-proxy's OIDC client secret for the Keycloak token endpoint.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
oidc_tokens = Data(
    name="OIDC tokens",
    description="Authorization code, access and ID tokens exchanged with Keycloak.",
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
    classification=Classification.SECRET,
)
socialosint_llm_key = Data(
    name="SOCIALOSINT_LLM_API_KEY",
    description="SocialOSINT's own LLM endpoint key (text and vision analysis).",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
platform_credentials = Data(
    name="SocialOSINT platform tokens",
    description="Twitter, Reddit, GitHub, Bluesky and Mastodon credentials the sidecar collects with.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
minio_credentials = Data(
    name="MINIO_ROOT_USER / MINIO_ROOT_PASSWORD",
    description="OpenCTI's object-store credentials.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
rabbitmq_credentials = Data(
    name="RABBITMQ_DEFAULT_USER / RABBITMQ_DEFAULT_PASS",
    description="OpenCTI's queue credentials.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
amass_provider_keys = Data(
    name="Amass data-source keys",
    description="API keys in amass/datasources.yaml, mounted read-only into the engine only.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
webhook_url_token = Data(
    name="Hosted webhook URL token",
    description="Slack, Teams and Discord webhook URLs carry their secret in the path; the alert code keeps it out of logs.",
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
    classification=Classification.SECRET,
)
misp_db_password = Data(
    name="MISP database password",
    description="MISP_MYSQL_PASSWORD, shared by misp and misp-db (docker-compose.misp.yml); Redis runs without one.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
opencti_admin_password = Data(
    name="OpenCTI admin credentials",
    description="APP__ADMIN__EMAIL and APP__ADMIN__PASSWORD typed into the OpenCTI web UI on loopback :8080.",
    isCredentials=True,
    credentialsLife=Lifetime.MANUAL,
    classification=Classification.SECRET,
)
opencti_ui_session = Data(
    name="OpenCTI UI session",
    description="Session cookie of the OpenCTI web UI.",
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
    classification=Classification.SECRET,
)
reference_datasets = Data(
    name="OpenCTI reference datasets",
    description="sectors.json and geography.json fetched by connector-opencti from the datasets repository's master branch; ingested as identities, locations and markings.",
    classification=Classification.PUBLIC,
)
model_replies = Data(
    name="Model replies",
    description="JSON replies of the fast and reasoning routes (qualification, synthesis): untrusted until schema-validated, then consumed as data.",
    classification=Classification.RESTRICTED,
)
target_inventory = Data(
    name="Target inventory",
    description="targets.yaml: entity names, authorisation and purpose per target, schedules, collector and LLM choices; read at startup and on reload (targets.py).",
    classification=Classification.RESTRICTED,
)
operator_session = Data(
    name="oauth2-proxy session cookie",
    description="OIDC session of the operator behind the optional proxy.",
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
    classification=Classification.SECRET,
)
evidence = Data(
    isPII=True,
    name="Qualified evidence & STIX bundle",
    description="Collector output qualified by the LLM, normalised to STIX 2.1; untrusted web text inside.",
    classification=Classification.RESTRICTED,
    isStored=True,
    isDestEncryptedAtRest=False,
)
run_artefacts = Data(
    isPII=True,
    name="Sealed run artefacts",
    description="report.md, bundle, delta, evidence and the HMAC-signed manifest chain (ADR-007).",
    classification=Classification.RESTRICTED,
    isStored=True,
    isDestEncryptedAtRest=False,
)
search_queries = Data(
    name="Due-diligence search queries",
    description="Entity names and the fixed due-diligence questions the Tavily collector asks about them.",
    classification=Classification.RESTRICTED,
)
prompts = Data(
    isPII=True,
    name="LLM prompts with collected text",
    description="Flattened, delimited untrusted collector text plus entity context sent to a model.",
    classification=Classification.RESTRICTED,
)
alert_payload = Data(
    isPII=True,
    name="Alert event",
    description="Target, run status, risk level, synthesis summary and, when enabled, the new observables.",
    classification=Classification.RESTRICTED,
)
social_profiles = Data(
    name="Collected social profiles and posts",
    description="Profiles, posts and images SocialOSINT gathers about named people; plaintext JSON in its cache.",
    classification=Classification.SENSITIVE,
    isPII=True,
    isStored=True,
    isDestEncryptedAtRest=False,
)
metrics_exposition = Data(
    name="Prometheus exposition",
    description="Target ids, run status, durations and observable counts as metric labels and values (metrics.py).",
    classification=Classification.RESTRICTED,
)

# ── Actors & external entities ──────────────────────────────────────────────
operator = Actor("Operator browser")
operator.inBoundary = internet

anonymous = Actor("Anonymous caller")
anonymous.inBoundary = internet
anonymous.description = "Unauthenticated readers of GET /health and GET /metrics."

stix_producer = ExternalEntity("External STIX producer")
stix_producer.inBoundary = internet
stix_producer.description = "Third-party tooling posting bundles to POST /bundles (ADR-011)."

public_web = ExternalEntity("Public web / OSINT sources")
public_web.inBoundary = internet

datasets_repo = ExternalEntity("OpenCTI datasets repository (GitHub)")
datasets_repo.inBoundary = internet
datasets_repo.description = (
    "raw.githubusercontent.com/OpenCTI-Platform/datasets, master branch: a mutable reference."
)

webhook_receiver = ExternalEntity("Alert webhook receiver")
webhook_receiver.inBoundary = internet
webhook_receiver.description = (
    "ALERT_WEBHOOK_URL (Slack, Teams, Discord or a custom endpoint). The payload is signed "
    "with HMAC-SHA256 only when ALERT_WEBHOOK_SECRET is set. Modelled over https:// only; "
    "the configuration accepts an http:// URL too (assumptions)."
)

socialosint_llm = LLM("SocialOSINT's LLM endpoint")
socialosint_llm.inBoundary = internet
socialosint_llm.protocol = "HTTPS"
socialosint_llm.isThirdParty = True
socialosint_llm.processesPersonalData = True  # profiles, posts and images of named people
socialosint_llm.hasRAG = True  # collected profiles and posts are the prompt
socialosint_llm.description = (
    "SOCIALOSINT_LLM_BASE_URL (OpenRouter, OpenAI or another OpenAI-compatible endpoint): "
    "text and vision analysis whose reply is a free-text Markdown report."
)
socialosint_llm.controls = Controls(
    isEncrypted=True, authenticatesSource=True, authenticationScheme="SOCIALOSINT_LLM_API_KEY"
)

social_platforms = ExternalEntity("Social platforms")
social_platforms.inBoundary = internet
social_platforms.description = "Twitter, Reddit, GitHub, Bluesky, Mastodon: SocialOSINT's sources."

tavily = Server("Tavily search API")
tavily.inBoundary = internet
tavily.protocol = "HTTPS"
tavily.controls = Controls(
    isEncrypted=True, authenticatesSource=True, authenticationScheme="TAVILY_API_KEY"
)

cloud_llm = LLM("Cloud LLM provider")
cloud_llm.inBoundary = internet
cloud_llm.protocol = "HTTPS"
cloud_llm.isThirdParty = True
cloud_llm.processesPersonalData = True  # observables in the prompt: e-mail, phone, person names
cloud_llm.hasRAG = True  # retrieved snippets and titles are inserted into the prompt (qualify.py)
cloud_llm.controls = Controls(
    isEncrypted=True, authenticatesSource=True, authenticationScheme="provider API key"
)

smtp_relay = Server("SMTP relay (alert e-mail)")
smtp_relay.inBoundary = internet
smtp_relay.protocol = "SMTP"
smtp_relay.description = (
    "ALERT_SMTP_HOST. STARTTLS with certificate verification by default; "
    "ALERT_SMTP_STARTTLS=false sends mail and SMTP AUTH in clear. SMTP AUTH happens only "
    "when ALERT_SMTP_USER is set; the default submits unauthenticated."
)
smtp_relay.controls = Controls(
    isEncrypted=True,
    authenticatesSource=False,  # smtp.login() runs only with ALERT_SMTP_USER (alerts/__init__.py)
    authenticationScheme="SMTP AUTH only with ALERT_SMTP_USER",
)

# ── OIDC edge (optional overlay) ────────────────────────────────────────────
proxy = Process("oauth2-proxy")
proxy.inBoundary = edge
proxy.protocol = "HTTP"
proxy.description = (
    "Published on 127.0.0.1:8002 as plain HTTP (OAUTH2_PROXY_HTTP_ADDRESS); no TLS listener."
)
proxy.controls = Controls(
    implementsAuthenticationScheme=True,
    authenticationScheme="OIDC authorization code (Keycloak)",
    # v7.7.1 encrypts the session state with OAUTH2_PROXY_COOKIE_SECRET; the hardcoded
    # OAUTH2_PROXY_COOKIE_SECURE=false only drops the Secure attribute (CR01).
    encryptsCookies=True,
    usesStrongSessionIdentifiers=True,
    implementsCSRFToken=True,
    verifySessionIdentifiers=True,
    isEncrypted=False,  # HTTP listener; a TLS terminator is a hardening step
)

keycloak = Server("Keycloak")
keycloak.inBoundary = edge
keycloak.protocol = "HTTP"
keycloak.usesSessionTokens = True
keycloak.controls = Controls(
    isEncrypted=False,  # HTTP inside the compose network
    isEncryptedAtRest=False,
    implementsAuthenticationScheme=True,
    authenticationScheme="realm users; bootstrap admin on first boot",
    usesMFA=False,
)

keycloak_db = Datastore("Keycloak data volume (keycloak-data)")
keycloak_db.inBoundary = edge
keycloak_db.description = (
    "start-dev with the embedded database under /opt/keycloak/data: realm users and their "
    "password hashes, the oauth2-proxy client secret, sessions and events. Dev mode by "
    "Keycloak's own account; a production Keycloak needs an external database."
)
keycloak_db.isSQL = True
keycloak_db.controls = Controls(isEncryptedAtRest=False)

# ── Orchestrator (compose network) ──────────────────────────────────────────
orchestrator = Process("Orchestrator API (FastAPI + APScheduler)")
orchestrator.inBoundary = compose
orchestrator.protocol = "HTTP"
orchestrator.implementsAPI = True
orchestrator.usesEnvironmentVariables = True
orchestrator.handlesResources = True
# One container, one code base: the API and the scheduler share these.
ORCHESTRATOR_CONTROLS = dict(
    isHardened=True,  # Dockerfile: USER 1000, pinned base image and dependencies
    hasAccessControl=True,
    implementsAuthenticationScheme=True,
    authenticationScheme="static X-API-Key / Bearer (ADR-005), assumed configured",
    authorizesSource=True,
    implementsServerSideValidation=True,  # pydantic models on every route body
    validatesInput=True,
    sanitizesInput=True,  # collected text reaches models delimited and flattened
    validatesHeaders=True,
    validatesContentType=False,  # POST /bundles parses request.json() without checking it
    implementsStrictHTTPValidation=True,
    encodesOutput=True,  # React escaping + strict CSP, no inline script
    disablesiFrames=True,  # CSP frame-ancestors 'none'
    disablesDTD=True,  # no XML parser anywhere in the service
    definesConnectionTimeout=True,  # *_TIMEOUT_SECONDS on every client
    # Per-run caps bound the collectors and the models, but POST /bundles reads the
    # whole body with request.json() and nothing limits its size.
    handlesResourceConsumption=False,
    handlesInterruptions=True,  # outbox + retry queues (OpenCTI, alerts)
    handlesCrashes=True,  # restart policy + APScheduler misfire grace
    providesIntegrity=True,  # HMAC-signed manifest chain (ADR-007); not code signing
    usesSecureFunctions=True,
    tracksExecutionFlow=True,
    implementsPOLP=False,  # one operator key, no per-user roles (ADR-005)
    usesMFA=False,
)
orchestrator.controls = Controls(**ORCHESTRATOR_CONTROLS)

scheduler = Process("APScheduler cron jobs")
scheduler.inBoundary = compose
scheduler.description = (
    "In-process scheduler: target crons, outbox and alert retries, retention purge. "
    "Same container and controls as the API; no network surface of its own."
)
scheduler.controls = Controls(**ORCHESTRATOR_CONTROLS)

sqlite = Datastore("SQLite run store")
sqlite.inBoundary = compose
sqlite.isSQL = True
sqlite.controls = Controls(
    isEncryptedAtRest=False,  # volume-backed plaintext SQLite
    usesParameterizedInput=True,  # SQLModel / SQLAlchemy ORM
)

targets_yaml = Datastore("targets.yaml")
targets_yaml.inBoundary = compose
targets_yaml.description = (
    "Target inventory, schedules and per-target authorisation; mounted read-only."
)
targets_yaml.hasWriteAccess = False
targets_yaml.controls = Controls(isEncryptedAtRest=False)

reports = Datastore("daily_reports (sealed runs)")
reports.inBoundary = compose
reports.controls = Controls(isEncryptedAtRest=False, providesIntegrity=True)  # signed chain

amass_db = Datastore("Amass asset database (shared volume)")
amass_db.inBoundary = compose
amass_db.description = (
    "asset.db on the amass-data volume: written by the engine, read by oam_subs "
    "from the orchestrator image."
)
amass_db.isSQL = True
amass_db.isShared = True  # amass-data is mounted read-write by the engine and the orchestrator
amass_db.controls = Controls(isEncryptedAtRest=False)

spiderfoot = Server("SpiderFoot")
spiderfoot.inBoundary = compose
spiderfoot.protocol = "HTTP"
spiderfoot.description = (
    "Built from a pinned commit; web UI and API without authentication, loopback only."
)
spiderfoot.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

spiderfoot_db = Datastore("SpiderFoot scan database (spiderfoot-data volume)")
spiderfoot_db.inBoundary = compose
spiderfoot_db.description = (
    "spiderfoot-data mounted at /home/spiderfoot/.spiderfoot: upstream keeps scan results "
    "and logs in SQLite. The collector copies a scan's events into its own evidence and "
    "leaves the scan in place; the orchestrator's retention purge never reaches this volume."
)
spiderfoot_db.isSQL = True
spiderfoot_db.controls = Controls(isEncryptedAtRest=False)

amass = Server("Amass v5 engine")
amass.inBoundary = compose
amass.protocol = "HTTP"
amass.description = (
    "owaspamass/amass:v5.1.1 engine; HTTP API on the compose network without authentication. "
    "The image's own user is not asserted here."
)
amass.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

socialosint = Server("SocialOSINT sidecar")
socialosint.inBoundary = compose
socialosint.protocol = "HTTP"
socialosint.description = "Dockerfile.socialosint sets no USER: the sidecar runs as root."
socialosint.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

socialosint_cache = Datastore("SocialOSINT cache volume")
socialosint_cache.inBoundary = compose
socialosint_cache.description = (
    "socialosint-data mounted at /app/data: the upstream CacheManager keeps collected "
    "profiles and posts as plaintext JSON. Deleting a session removes the session file, not "
    "the cache, and the orchestrator's retention purge never reaches this volume."
)
socialosint_cache.controls = Controls(isEncryptedAtRest=False)

ollama_api = Server("Ollama HTTP API")
ollama_api.inBoundary = compose
ollama_api.protocol = "HTTP"
ollama_api.description = (
    "Operator-provisioned Ollama (the shipped compose has none): HTTP API without "
    "authentication on the same host; the model behind it is the LLM element."
)
ollama_api.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

ollama = LLM("Ollama (local models)")
ollama.inBoundary = compose
ollama.isThirdParty = False
ollama.processesPersonalData = True  # same prompts; local only under the LLM_BASE_URL assumption
ollama.hasRAG = True  # same retrieval-augmented prompts
ollama.controls = Controls(isEncrypted=False, authenticatesSource=False)

misp = Server("MISP")
misp.inBoundary = compose
misp.protocol = "HTTPS"
misp.description = "misp-docker with its self-signed certificate; polled by connector-misp."
misp.controls = Controls(
    isEncrypted=True, authenticatesSource=True, authenticationScheme="MISP API key"
)

misp_store = Datastore("MISP backing stores (MariaDB, Redis)")
misp_store.inBoundary = compose
misp_store.description = (
    "misp-db (mariadb) on misp-db-data, misp-redis (redis, no password) on misp-redis-data and "
    "misp-data for attachments: events, attributes and MISP's own users and keys."
)
misp_store.isSQL = True
misp_store.controls = Controls(isEncryptedAtRest=False)

misp_db = Server("MariaDB (MISP)")
misp_db.inBoundary = compose
misp_db.protocol = "MySQL"
misp_db.description = "mariadb:10.11.19 with MYSQL_USER/MYSQL_PASSWORD (MISP_MYSQL_PASSWORD); MySQL in clear on the compose network."
misp_db.controls = Controls(
    isEncrypted=False,
    authenticatesSource=True,
    hasAccessControl=True,
    authenticationScheme="MySQL user / password",
)

misp_redis = Server("Redis (MISP)")
misp_redis.inBoundary = compose
misp_redis.protocol = "RESP"
misp_redis.description = "redis:8.0.6 without a password (ENABLE_REDIS_EMPTY_PASSWORD): no authentication, not published on the host."
misp_redis.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

misp_modules = Server("misp-modules")
misp_modules.inBoundary = compose
misp_modules.protocol = "HTTP"
misp_modules.description = (
    "misp-docker's misp-modules sidecar (pinned): the enrichment and import modules MISP calls "
    "over HTTP (MISP_MODULES_FQDN); no authentication, not published on the host."
)
misp_modules.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

# ── OpenCTI platform ────────────────────────────────────────────────────────
opencti = Server("OpenCTI platform")
opencti.inBoundary = opencti_b
opencti.protocol = "HTTP"
opencti.usesSessionTokens = True
opencti.controls = Controls(
    hasAccessControl=True,
    implementsAuthenticationScheme=True,
    authenticationScheme="admin token / GraphQL session",
    isEncrypted=False,  # compose-internal HTTP
)

elasticsearch = Server("Elasticsearch")
elasticsearch.inBoundary = opencti_b
elasticsearch.protocol = "HTTP"
elasticsearch.description = (
    "elasticsearch:8.14.3 single-node with xpack.security.enabled=false: no authentication, "
    "no TLS, not published on the host."
)
elasticsearch.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

opencti_redis = Server("Redis (OpenCTI)")
opencti_redis.inBoundary = opencti_b
opencti_redis.protocol = "RESP"
opencti_redis.description = (
    "redis:8.0.6 without requirepass: no authentication, not published on the host."
)
opencti_redis.controls = Controls(
    isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False
)

minio = Server("MinIO")
minio.inBoundary = opencti_b
minio.protocol = "HTTP"
minio.description = "MinIO with MINIO_ROOT_USER/PASSWORD as access and secret key; plain HTTP on the compose network."
minio.controls = Controls(
    isEncrypted=False,
    authenticatesSource=True,
    hasAccessControl=True,
    authenticationScheme="access key / secret key",
)

rabbitmq = Server("RabbitMQ")
rabbitmq.inBoundary = opencti_b
rabbitmq.protocol = "AMQP"
rabbitmq.description = (
    "rabbitmq:3.13.7 with RABBITMQ_DEFAULT_USER/PASS; AMQP in clear on the compose network."
)
rabbitmq.controls = Controls(
    isEncrypted=False,
    authenticatesSource=True,
    hasAccessControl=True,
    authenticationScheme="user / password",
)

opencti_store = Datastore("OpenCTI backing stores")
opencti_store.inBoundary = opencti_b
opencti_store.description = "Elasticsearch indices, MinIO objects, RabbitMQ queues, Redis."
opencti_store.isShared = True
opencti_store.controls = Controls(isEncryptedAtRest=False)

connector_misp = Process("connector-misp")
connector_misp.inBoundary = opencti_b
connector_misp.description = (
    "OpenCTI MISP connector: polls MISP over HTTPS with MISP_SSL_VERIFY=false, "
    "writes to OpenCTI over HTTP with OPENCTI_ADMIN_TOKEN."
)
connector_misp.controls = Controls()  # vendor image; nothing asserted

connector_opencti = Process("connector-opencti")
connector_opencti.inBoundary = opencti_b
connector_opencti.description = (
    "OpenCTI datasets connector (pinned image): every 7 days it downloads sectors.json and "
    "geography.json from the datasets repository's master branch over HTTPS and ingests them "
    "into OpenCTI over HTTP with OPENCTI_ADMIN_TOKEN (scope marking-definition, identity, "
    "location)."
)
connector_opencti.controls = Controls()  # vendor image; nothing asserted

opencti_worker = Process("OpenCTI worker")
opencti_worker.inBoundary = opencti_b
opencti_worker.description = (
    "opencti/worker (two replicas, pinned): consumes the ingestion queues and writes the "
    "bundles into the platform with OPENCTI_ADMIN_TOKEN over HTTP (connector-base-env)."
)
opencti_worker.controls = Controls()  # vendor image; nothing asserted

connector_import_stix = Process("connector-import-file-stix")
connector_import_stix.inBoundary = opencti_b
connector_import_stix.description = (
    "Built-in import connector (pinned): parses the STIX JSON and XML files uploaded to the "
    "platform (CONNECTOR_AUTO=true) and writes them back with OPENCTI_ADMIN_TOKEN over HTTP."
)
connector_import_stix.controls = Controls()  # vendor image; nothing asserted

# ── Element classes (the triage is written per class, see TRIAGE) ───────────
CLASSES: dict[str, list] = {
    "orchestrator": [orchestrator, scheduler],
    "sidecar": [spiderfoot, amass, socialosint, ollama, ollama_api],
    "vendor": [
        tavily,
        cloud_llm,
        socialosint_llm,
        smtp_relay,
        webhook_receiver,
        proxy,
        keycloak,
        misp,
        opencti,
        opencti_store,
        connector_misp,
        connector_opencti,
        opencti_worker,
        connector_import_stix,
        keycloak_db,
        misp_store,
        elasticsearch,
        opencti_redis,
        minio,
        rabbitmq,
        misp_db,
        misp_redis,
        misp_modules,
    ],
    "store": [sqlite, targets_yaml, reports, amass_db, socialosint_cache, spiderfoot_db],
    "actor": [operator, anonymous, stix_producer, public_web, datasets_repo, social_platforms],
}
CLASS_OF = {el.name: cls for cls, els in CLASSES.items() for el in els}

# ── Handling limits (what the data-leak rules DS06 and DR01 compare against) ─
# pytm compares each asset's classification with the limit of the flow's source, its sink
# and the flow itself; left at the UNKNOWN default, every classified asset "leaks" on every
# hop. The limits say what each endpoint is entrusted with: SECRET where a service receives
# its own credentials, the classification a store is meant to hold, and PUBLIC for the open
# web and anonymous callers, so the target name reaching an OSINT source stays a finding.
_LIMITS: dict[Classification, list] = {
    Classification.SECRET: [
        orchestrator,
        scheduler,
        operator,
        stix_producer,
        proxy,
        keycloak,
        tavily,
        cloud_llm,
        socialosint_llm,
        social_platforms,
        smtp_relay,
        webhook_receiver,
        misp,
        opencti,
        opencti_store,
        connector_misp,
        connector_opencti,
        opencti_worker,
        connector_import_stix,
        keycloak_db,
        misp_store,
        elasticsearch,
        opencti_redis,
        minio,
        rabbitmq,
        misp_db,
        misp_redis,
        misp_modules,
        amass,  # provider keys mounted from datasources.yaml
        socialosint,  # platform tokens in its environment
    ],
    Classification.SENSITIVE: [socialosint_cache],
    Classification.RESTRICTED: [
        sqlite,
        targets_yaml,
        reports,
        amass_db,
        spiderfoot_db,
        spiderfoot,
        ollama_api,
        ollama,
    ],
    Classification.PUBLIC: [anonymous, public_web, datasets_repo],
}
for _limit, _elements in _LIMITS.items():
    for _element in _elements:
        _element.maxClassification = _limit


def flow(source, sink, name: str, **kwargs) -> Dataflow:
    # A channel may carry what its transport protects: anything on the trusted host
    # (ADR-005) or under TLS; only PUBLIC data in clear across the internet boundary.
    if "maxClassification" not in kwargs:
        controls = kwargs.get("controls")
        encrypted = controls is not None and bool(controls.isEncrypted)
        leaves_host = internet in (source.inBoundary, sink.inBoundary)
        kwargs["maxClassification"] = (
            Classification.PUBLIC if leaves_host and not encrypted else Classification.SECRET
        )
    return Dataflow(source, sink, name, **kwargs)


# ── Dataflows ───────────────────────────────────────────────────────────────
# Operator and perimeter
flow(
    operator,
    proxy,
    "Operator session (OIDC, shipped overlay)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    usesSessionTokens=True,
    data=[operator_session, api_key],  # the console sends X-API-Key through the proxy too
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    proxy,
    orchestrator,
    "Proxied console/API calls",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    usesSessionTokens=True,
    # ADR-006: the key still authenticates the client; the overlay also forwards the
    # Authorization header and access token (OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER,
    # OAUTH2_PROXY_PASS_ACCESS_TOKEN).
    data=[operator_session, api_key, oidc_tokens],
    controls=Controls(isEncrypted=False, authenticatesSource=True),
)
flow(
    keycloak,
    keycloak_db,
    "Persist realm users, client secret and sessions",
    protocol="file",
    data=[keycloak_password, oidc_client_secret, oidc_tokens],
    controls=Controls(isEncrypted=False),
)
flow(
    keycloak_db,
    keycloak,
    "Read realm, users and sessions",
    protocol="file",
    data=[keycloak_password, oidc_client_secret, oidc_tokens],
    controls=Controls(isEncrypted=False),
)
flow(
    proxy,
    keycloak,
    "Token redeem / userinfo",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[oidc_client_secret, oidc_tokens],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    operator,
    keycloak,
    "Operator login (Keycloak authorization endpoint, shipped overlay)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[keycloak_password, oidc_tokens],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    operator,
    opencti,
    "OpenCTI UI login and session (loopback :8080, HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    usesSessionTokens=True,
    data=[opencti_admin_password, opencti_ui_session],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    operator,
    orchestrator,
    "Direct loopback API/console (no overlay)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[api_key],
    controls=Controls(isEncrypted=False, authenticatesSource=True),
)
flow(
    orchestrator,
    anonymous,
    "GET /health, /metrics",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    # The exposition leaves the API for whoever asks: served without an API key, scrapers
    # are not API clients (api.py prometheus_metrics).
    data=[metrics_exposition],
    controls=Controls(isEncrypted=False, authenticatesSource=False, hasAccessControl=False),
)
flow(
    stix_producer,
    orchestrator,
    "POST /bundles (STIX intake)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[api_key, evidence],
    controls=Controls(isEncrypted=False, authenticatesSource=True, validatesInput=True),
)
flow(
    scheduler,
    orchestrator,
    "Cron dispatch (in-process)",
    protocol="inproc",
    controls=Controls(authenticatesSource=True),
)

# Collectors
flow(
    orchestrator,
    spiderfoot,
    "Scan control & results",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    orchestrator,
    amass,
    "Enumeration submit (oam_enum)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    amass,
    amass_db,
    "Engine writes asset.db",
    protocol="file",
    data=[evidence],
    controls=Controls(isEncrypted=False),
)
flow(
    amass_db,
    orchestrator,
    "Read discovered names (oam_subs, shared volume)",
    protocol="file",
    data=[evidence],
    controls=Controls(isEncrypted=False),
)
flow(
    amass,
    public_web,
    "Passive data-source queries (datasources.yaml keys)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[amass_provider_keys, evidence],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)
flow(
    amass,
    public_web,
    "DNS resolution and active probes (zone transfers, certificate grabs when enabled)",
    protocol="DNS",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    orchestrator,
    socialosint,
    "Platform collection jobs",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    socialosint,
    socialosint_llm,
    "SocialOSINT text and vision prompts (own endpoint and key)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[socialosint_llm_key, social_profiles],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)
flow(
    socialosint,
    social_platforms,
    "Platform collection (operator's API tokens)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[platform_credentials, social_profiles],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)
flow(
    socialosint,
    socialosint_cache,
    "Cache collected profiles and posts (/app/data)",
    protocol="file",
    data=[social_profiles],
    controls=Controls(isEncrypted=False),
)
flow(
    socialosint_cache,
    socialosint,
    "Read cached profiles for later sessions",
    protocol="file",
    data=[social_profiles],
    controls=Controls(isEncrypted=False),
)
flow(
    orchestrator,
    tavily,
    "Due-diligence queries",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[tavily_key, search_queries],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)
flow(
    spiderfoot,
    public_web,
    "DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois)",
    protocol="DNS",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    spiderfoot,
    public_web,
    "TLS certificate and HTTPS fetches (sfp_sslcert)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[evidence],
    controls=Controls(isEncrypted=True),
)
flow(
    spiderfoot,
    spiderfoot_db,
    "Write scan results and logs",
    protocol="file",
    data=[evidence],
    controls=Controls(isEncrypted=False),
)
flow(
    spiderfoot_db,
    spiderfoot,
    "Read scan results for the API",
    protocol="file",
    data=[evidence],
    controls=Controls(isEncrypted=False),
)
flow(
    orchestrator,
    public_web,
    "DNS and WHOIS pivots (OpenOSINT)",
    protocol="DNS",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    orchestrator,
    public_web,
    "HTTPS source lookups (OpenOSINT)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[evidence],
    controls=Controls(isEncrypted=True),
)

# Models
flow(
    orchestrator,
    ollama_api,
    "Qualification & synthesis prompts (local HTTP API)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[prompts],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    ollama_api,
    ollama,
    "Local model inference",
    protocol="inproc",
    data=[prompts],
    controls=Controls(authenticatesSource=True),
)
flow(
    orchestrator,
    cloud_llm,
    "Qualification & synthesis prompts (cloud)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[prompts, llm_key],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)

# Responses: the results, replies, reports and evidence that travel back.
flow(
    spiderfoot,
    orchestrator,
    "Scan results (JSON events, HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesSource=False),
)
flow(
    socialosint,
    orchestrator,
    "Analysis report (Markdown, HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    data=[social_profiles],
    controls=Controls(isEncrypted=False, authenticatesSource=False),
)
flow(
    tavily,
    orchestrator,
    "Search results (HTTPS)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    isResponse=True,
    data=[evidence],
    controls=Controls(isEncrypted=True),
)
flow(
    cloud_llm,
    orchestrator,
    "Model replies (JSON, HTTPS)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    isResponse=True,
    data=[model_replies],
    controls=Controls(isEncrypted=True),
)
flow(
    ollama_api,
    orchestrator,
    "Model replies (JSON, local HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    data=[model_replies],
    controls=Controls(isEncrypted=False),
)
flow(
    socialosint_llm,
    socialosint,
    "Text and vision analysis (Markdown, HTTPS)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    isResponse=True,
    data=[social_profiles],
    controls=Controls(isEncrypted=True),
)
flow(
    misp,
    connector_misp,
    "Polled events (HTTPS, certificate unverified)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    isResponse=True,
    data=[evidence],
    controls=Controls(isEncrypted=True, authenticatesSource=False),
)
flow(
    keycloak,
    proxy,
    "Tokens and userinfo (HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    data=[oidc_tokens],
    controls=Controls(isEncrypted=False),
)
flow(
    orchestrator,
    operator,
    "Reports, findings and evidence (direct loopback)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    data=[run_artefacts, evidence],
    controls=Controls(isEncrypted=False),
)
flow(
    orchestrator,
    proxy,
    "Proxied responses (reports, findings, evidence)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    data=[run_artefacts, evidence],
    controls=Controls(isEncrypted=False),
)
flow(
    proxy,
    operator,
    "Proxied responses to the browser (shipped overlay)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    isResponse=True,
    usesSessionTokens=True,
    data=[run_artefacts, evidence, operator_session],
    controls=Controls(isEncrypted=False),
)

# Stores
flow(
    orchestrator,
    sqlite,
    "Run/state SQL",
    protocol="SQL",
    data=[evidence],
    controls=Controls(isEncrypted=False, usesParameterizedInput=True),
)
flow(
    orchestrator,
    reports,
    "Seal run artefacts + manifest",
    protocol="file",
    data=[run_artefacts],
    controls=Controls(isEncrypted=False, providesIntegrity=True),
)
flow(
    targets_yaml,
    orchestrator,
    "Read target inventory",
    protocol="file",
    data=[target_inventory],
    controls=Controls(isEncrypted=False),
)

# OpenCTI and MISP
flow(
    orchestrator,
    opencti,
    "STIX ingest (pycti, outbox retries)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[opencti_token, evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    opencti,
    elasticsearch,
    "Elasticsearch indices",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    opencti,
    minio,
    "MinIO objects",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[minio_credentials, evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    opencti,
    rabbitmq,
    "RabbitMQ queues",
    protocol="AMQP",
    tlsVersion=TLSVersion.NONE,
    data=[rabbitmq_credentials, evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    opencti,
    opencti_redis,
    "Redis cache (no authentication)",
    protocol="RESP",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    misp,
    misp_db,
    "MISP database (MySQL, compose-internal)",
    protocol="MySQL",
    tlsVersion=TLSVersion.NONE,
    data=[misp_db_password, evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    misp,
    misp_redis,
    "MISP cache and queues (Redis, no password)",
    protocol="RESP",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
# Persistence: each backing server writes its own volume of the platform's stores.
for _server, _store, _what in (
    (elasticsearch, opencti_store, "Elasticsearch persists its indices (volume)"),
    (minio, opencti_store, "MinIO persists objects (volume)"),
    (rabbitmq, opencti_store, "RabbitMQ persists queues (volume)"),
    (opencti_redis, opencti_store, "Redis persists its snapshot (volume)"),
    (misp_db, misp_store, "MariaDB persists on misp-db-data"),
    (misp_redis, misp_store, "Redis persists on misp-redis-data"),
):
    flow(
        _server,
        _store,
        _what,
        protocol="file",
        data=[evidence],
        controls=Controls(isEncrypted=False),
    )
flow(
    connector_opencti,
    datasets_repo,
    "Reference dataset download (GitHub master, mutable)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[reference_datasets],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)
flow(
    connector_opencti,
    opencti,
    "Reference dataset ingestion (OPENCTI_ADMIN_TOKEN, HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[opencti_token, reference_datasets],
    controls=Controls(isEncrypted=False, authenticatesSource=True),
)
flow(
    opencti_worker,
    rabbitmq,
    "Worker consumes the ingestion queues (AMQP, in clear)",
    protocol="AMQP",
    tlsVersion=TLSVersion.NONE,
    data=[rabbitmq_credentials, evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    opencti_worker,
    opencti,
    "Worker writes processed bundles (OPENCTI_ADMIN_TOKEN, HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[opencti_token, evidence],
    controls=Controls(isEncrypted=False, authenticatesSource=True),
)
flow(
    connector_import_stix,
    opencti,
    "Fetch uploaded files and push the parsed bundle (OPENCTI_ADMIN_TOKEN, HTTP)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[opencti_token, evidence],
    controls=Controls(isEncrypted=False, authenticatesSource=True),
)
flow(
    misp,
    misp_modules,
    "Enrichment and import modules (HTTP, compose-internal)",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)
flow(
    connector_misp,
    misp,
    "connector-misp polls MISP events",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[misp_key, evidence],
    # MISP_SSL_VERIFY=false in local dev: the self-signed certificate is not checked.
    controls=Controls(
        isEncrypted=True, authenticatesDestination=False, checksDestinationRevocation=False
    ),
)
flow(
    connector_misp,
    opencti,
    "connector-misp writes to OpenCTI",
    protocol="HTTP",
    tlsVersion=TLSVersion.NONE,
    data=[opencti_token, evidence],
    controls=Controls(isEncrypted=False, authenticatesDestination=False),
)

# Alerts
flow(
    orchestrator,
    webhook_receiver,
    "Alert webhook (ALERT_WEBHOOK_URL)",
    protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv12,
    data=[webhook_url_token, alert_payload],
    # Signature only with ALERT_WEBHOOK_SECRET; the default is unsigned.
    controls=Controls(isEncrypted=True, authenticatesDestination=True, providesIntegrity=False),
)
flow(
    orchestrator,
    smtp_relay,
    "Alert e-mail (SMTP, STARTTLS by default)",
    protocol="SMTP",
    tlsVersion=TLSVersion.TLSv12,
    data=[alert_payload, smtp_credentials],
    controls=Controls(isEncrypted=True, authenticatesDestination=True),
)

# ── Triage ──────────────────────────────────────────────────────────────────
# Every fired threat gets an explicit response (pytm Finding.response):
#   mitigated   → a control of that element already addresses it (cite where)
#   transferred → the risk lives in a vendor component we consume as shipped
#   accepted    → documented decision (ADR / local-dev scope) with a hardening note
# A response is written per element class, because the same threat means
# something different on the orchestrator, on an unauthenticated sidecar, on a
# vendor service, on a store or on a flow. "*" applies to every class.
Response = tuple[str, str]

_XML = (
    "transferred",
    "The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. "
    "Any XML handling lives inside the sidecar or vendor service and is upstream code.",
)
_SMUGGLING_SIDECAR = (
    "accepted",
    "No proxy is chained in front of the sidecars: the orchestrator reaches them directly on "
    "the compose bridge, so smuggling needs a position on the host (ADR-005).",
)
_SMUGGLING_VENDOR = (
    "transferred",
    "HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the "
    "orchestrator sends well-formed requests from httpx, pycti and smtplib.",
)
_NO_SESSIONS = (
    "accepted",
    "SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they "
    "are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared "
    "hosts: authentication in front of SpiderFoot and network policies between services.",
)
_VENDOR_SESSIONS = (
    "transferred",
    "Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay "
    "is the vendor's; the orchestrator presents only API tokens.",
)
_VENDOR_PROCESS = (
    "transferred",
    "oauth2-proxy, connector-misp, connector-opencti, connector-import-file-stix and the "
    "OpenCTI worker run as their pinned vendor images ship them; what happens "
    "inside them is upstream code.",
)
_VENDOR_AUTH = (
    "transferred",
    "Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, "
    "connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the "
    "vendor's.",
)
_LLM = (
    "accepted",
    "Collected text reaches the model delimited and flattened, replies are JSON-schema "
    "validated, and the model has no tools, so an injected instruction cannot execute "
    "anything. It can still skew the assessment: a schema-valid risk level feeds "
    "alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a "
    "risk-threshold alert. Residual risk accepted: the new-observables rule fires "
    "independently of the model, the evidence and rationale stay visible to the analyst, "
    "and model output is an aid, not a determination (README, Responsible use).",
)

_DISCOVERY = (
    " The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of "
    "the target's surface) is plaintext by nature: it carries the target name and what the "
    "public already serves, never a credential, and its answers are treated as untrusted input."
)
_SIDECAR_INPUT = (
    "accepted",
    "Input handling inside the sidecar is upstream code the orchestrator does not change; the "
    "sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is "
    "parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root "
    "filesystems, keeping the pinned images current.",
)
_VENDOR_INPUT = (
    "transferred",
    "Input handling inside the vendor service is the vendor's; the orchestrator sends it "
    "well-formed requests built from validated data and renders nothing it serves.",
)
# pytm's input-handling family: SQL/LDAP/command/format-string/path/XSS/encoding threats that
# fire on any server or process without its own validation controls. The orchestrator asserts
# its controls; for sidecars and vendors the honest answer is the same for every member.
_INPUT_FAMILY = (
    "AA04",
    "DE02",
    "DS01",
    "DS04",
    "HA01",
    "INP03",
    "INP04",
    "INP05",
    "INP07",
    "INP08",
    "INP09",
    "INP10",
    "INP11",
    "INP12",
    "INP13",
    "INP14",
    "INP16",
    "INP18",
    "INP20",
    "INP23",
    "INP25",
    "INP26",
    "INP27",
    "INP28",
    "INP29",
    "INP30",
    "INP31",
    "INP32",
    "INP33",
    "INP35",
    "INP41",
    "SC02",
    "SC04",
)

TRIAGE: dict[str, dict[str, Response]] = {
    **{tid: {"sidecar": _SIDECAR_INPUT, "vendor": _VENDOR_INPUT} for tid in _INPUT_FAMILY},
    # ── Very High ──
    "AC06": {  # Using Malicious Files
        "sidecar": (
            "accepted",
            "The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and "
            "SocialOSINT output is parsed into CollectorResult inside the collector module "
            "(docs/architecture.md). The sidecars' own file handling is upstream code running "
            "loopback-only from pinned images. Hardening: read-only root filesystems and dropped "
            "capabilities for the sidecars.",
        ),
        "vendor": (
            "transferred",
            "Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the "
            "orchestrator uploads no files to them and renders nothing they serve.",
        ),
    },
    "AC14": {  # Catching exception throw/signal from privileged block
        "orchestrator": (
            "mitigated",
            "The pipeline isolates every step (collect, qualify, normalise, synthesise, seal, "
            "alert): a raised error fails the run, never a privileged transaction; the process "
            "runs as uid 1000 with no setuid paths (Dockerfile).",
        ),
        "vendor": _VENDOR_PROCESS,
    },
    "AC17": {"sidecar": _NO_SESSIONS, "vendor": _VENDOR_SESSIONS},  # Session Hijacking
    "AC18": {"vendor": _VENDOR_SESSIONS},  # Session Hijacking - ClientSide
    "CR02": {  # Cross Site Tracing
        "vendor": (
            "transferred",
            "TRACE handling at Keycloak and OpenCTI is the vendor image's; both sit on the "
            "compose network or loopback (ADR-005) and nothing the orchestrator serves issues "
            "TRACE. Hardening: a TLS terminator in front of them that drops TRACE.",
        ),
        "flow": (
            "accepted",
            "FastAPI answers TRACE with 405 and the console ships no inline script that could "
            "read reflected headers; the plaintext proxied hop itself is the DS06 decision "
            "(shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.",
        ),
    },
    "INP15": {  # IMAP/SMTP Command Injection
        "vendor": (
            "transferred",
            "SMTP command handling is the relay's. The orchestrator talks to it through smtplib "
            "with the configured host, port and credentials, and the message is a MIMEText whose "
            "headers the email package encodes; collected text only ever lands in the body as "
            "message data, never in an SMTP command.",
        ),
    },
    "AC21": {  # Cross Site Request Forgery
        "orchestrator": (
            "mitigated",
            "Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there "
            "is no ambient credential to forge cross-site; the console CSP sets form-action "
            "'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's "
            "CSRF token.",
        ),
        "vendor": (
            "transferred",
            "connector-misp has no browser-facing surface; CSRF on vendor UIs is the vendor's "
            "(oauth2-proxy implements its own CSRF token).",
        ),
    },
    "DS06": {  # Data Leak
        "flow": (
            "accepted",
            "Handling limits are declared per endpoint (SECRET where a service receives its own "
            "credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on "
            "the trusted host or under TLS, PUBLIC in clear across the internet boundary), so "
            "what fires here is deliberate: every lookup tells the public source which name is "
            "being researched (search queries and discovery traffic, plaintext DNS/WHOIS "
            "included; Amass's provider keys go to the providers that issued them, over TLS), "
            "and the operator's API key, OIDC session, Keycloak password and OpenCTI admin "
            "password and UI session cross the host boundary in clear on :8000, :8080 and the "
            "shipped OIDC overlay, which terminates no TLS (ADR-005), and the reports, findings "
            "and evidence come back to the operator the same way. The "
            "disclosure to the sources queried is inherent to OSINT and bounded by the per-target "
            "authorisation. Hardening: a TLS terminator in front of :8000, :8002, OpenCTI's UI "
            "(:8080, APP__BASE_URL on the https:// name) and Keycloak's browser endpoint "
            "(:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name."
            + _DISCOVERY,
        ),
    },
    "INP02": {  # Overflow Buffers
        "orchestrator": (
            "mitigated",
            "Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by "
            "validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and "
            "LLM_MAX_OBSERVABLES_IN_PROMPT.",
        ),
        "vendor": _VENDOR_PROCESS,
    },
    # ── High ──
    "AA03": {  # Exploitation of Trusted Credentials
        "sidecar": _NO_SESSIONS,
        "vendor": (
            "accepted",
            "Static long-lived tokens are the integration contract with OpenCTI "
            "(OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; "
            "they live only in .env and environment variables and rotate manually. Hardening: a "
            "dedicated least-privilege token per connector and periodic rotation.",
        ),
    },
    "AC12": {  # Privilege Escalation
        "orchestrator": (
            "mitigated",
            "No privilege separation exists inside the monolith (ADR-001): the container runs as "
            "uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator "
            "role, so there is no higher privilege to escalate to.",
        ),
        "vendor": _VENDOR_PROCESS,
    },
    "AC15": {  # Schema Poisoning
        "orchestrator": (
            "mitigated",
            "STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with "
            "deterministic ids; inbound bundles are contract-validated (ADR-011) and model "
            "replies are JSON-schema validated before storage.",
        ),
        "vendor": (
            "transferred",
            "Schema handling inside oauth2-proxy and connector-misp is upstream's; the "
            "orchestrator validates everything it receives from either side.",
        ),
    },
    "AC16": {  # Session Credential Falsification through Prediction
        "sidecar": _NO_SESSIONS,
        "vendor": (
            "transferred",
            "Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the "
            "vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance "
            "in .env.example).",
        ),
    },
    "AC19": {"vendor": _VENDOR_SESSIONS},  # Reusing Session IDs
    "AC20": {"vendor": _VENDOR_SESSIONS},  # Reusing Session IDs - ClientSide
    "AC23": {  # Credentials Disclosure
        "flow": (
            "accepted",
            "Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider "
            "key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the "
            "loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose "
            "bridge from the sink and from connector-misp. They are never logged (parameterized "
            "logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 "
            "and Keycloak's browser endpoint, and TLS to OpenCTI.",
        ),
    },
    "API01": {  # Exploit Test APIs
        "orchestrator": (
            "mitigated",
            "No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data "
            "route behind it still requires the API key (tests assert 401 without it).",
        ),
        "vendor": _VENDOR_PROCESS,
    },
    "CR01": {  # Session Sidejacking
        "vendor": _VENDOR_SESSIONS,
        "flow": (
            "accepted",
            "The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes "
            "OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed "
            "to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front "
            "of the proxy and of Keycloak's browser endpoint (KC_HOSTNAME and "
            "OIDC_BROWSER_LOGIN_URL on the https:// name) and a Compose override that sets "
            "OAUTH2_PROXY_COOKIE_SECURE to true. OpenCTI's own UI session on loopback :8080 "
            "(APP__BASE_URL http://localhost:8080) is the same case: plain HTTP on the trusted "
            "host, a TLS terminator and an https:// APP__BASE_URL in production.",
        ),
    },
    "CR03": {  # Dictionary-based Password Attack
        "orchestrator": (
            "mitigated",
            "The orchestrator holds no passwords: key-only authentication (ADR-005) with a "
            "constant-time comparison against the configured key set.",
        ),
        "sidecar": _NO_SESSIONS,
        "vendor": (
            "transferred",
            "Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.",
        ),
    },
    "CR06": {  # Communication Channel Manipulation
        "flow": (
            "accepted",
            "Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel "
            "is pinned (git dependencies by "
            "40-character SHA, images by explicit tag). Host-internal hops are plaintext by "
            "decision (DS06) and can be manipulated only from the host itself. Hardening as in "
            "DS06." + _DISCOVERY,
        ),
    },
    "DE04": {  # Audit Log Manipulation
        "store": (
            "mitigated",
            "Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with "
            "daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is "
            "mounted read-only. The Amass asset database carries collector input, not audit "
            "data. Application logs are stdout for the operator's shipper.",
        ),
        "vendor": (
            "transferred",
            "The platform's own audit trail (OpenCTI, Keycloak events, MISP logs) lives in its "
            "backing stores and is the platform's.",
        ),
    },
    "DR01": {  # Unprotected Sensitive Data
        "flow": (
            "accepted",
            "Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass "
            "asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI "
            "stores) and host-internal hops carry it in clear, the personal data of the "
            "target's public footprint (observables in evidence, artefacts, prompts and alerts) "
            "included; credentials and personal data travel only to the service they belong "
            "to, under TLS when they leave the host. Hardening: encrypted volumes or disk "
            "encryption, TLS between services." + _DISCOVERY,
        ),
    },
    "INP22": {"*": _XML},  # XML Attribute Blowup
    "INP24": {  # Filter Failure through Buffer Overflow
        "orchestrator": (
            "mitigated",
            "Bounded query parameters (ge/le), capped result lists and per-run budgets "
            "(LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter "
            "processing.",
        ),
        "vendor": _VENDOR_PROCESS,
    },
    "INP34": {"*": _XML},  # SOAP Array Overflow
    "INP37": {"sidecar": _SMUGGLING_SIDECAR, "vendor": _SMUGGLING_VENDOR},  # Request Smuggling
    "LLM01": {"*": _LLM},  # Direct Prompt Injection
    "LLM02": {  # Indirect Prompt Injection via Retrieved Content
        "*": (
            "accepted",
            "Retrieval-augmented by design: qualify.py and the synthesis put the collectors' "
            "snippets, titles and observables into the prompt, so attacker-controlled source "
            "text reaches the local or cloud model, with no content filter in front of it. It "
            "arrives delimited and flattened, the model has no tools and its reply is "
            "JSON-schema validated and consumed as data, so an injected instruction executes "
            "nothing; what it can do is skew the category, relevance or risk level of an item "
            "that an analyst reviews next to its source (LLM01's residual risk). Hardening: "
            "the per-item and LLM_MAX_OBSERVABLES_IN_PROMPT caps stay, and a local model for "
            "workloads heavy in untrusted text.",
        ),
    },
    "LLM03": {  # Sensitive Data Leakage to Third-Party Provider
        "vendor": (
            "accepted",
            "The prompts carry personal data of the target's public footprint with no redaction: "
            "the orchestrator sends the observables it collected (domains, URLs, e-mail "
            "addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and "
            "images to its own endpoint. Both go only to the provider the operator configured, "
            "over TLS; `llm: local` keeps the orchestrator's prompts on the host only while "
            "LLM_BASE_URL points at the local Ollama (assumption above: the client posts "
            "wherever it is configured), so verify that endpoint before relying on it. Hardening: a "
            "provider under a data-processing agreement with retention and training opted out, "
            "or local models for sensitive workloads.",
        ),
    },
    "LLM08": {  # Sensitive Information Disclosure Through Output
        "*": (
            "accepted",
            "A reply is consumed as data, never executed: the orchestrator's synthesis is "
            "JSON-schema validated and SocialOSINT's report is attached as an unverified note, "
            "and both are stored and rendered escaped under the console's CSP. What a reply can "
            "echo is the public footprint the prompt carried, which the evidence already holds; "
            "nothing filters personal-data patterns out of a summary before it is stored. "
            "Hardening: output redaction or DLP before a finding or note is persisted.",
        ),
    },
    "LLM07": {  # Jailbreaking and Safety Bypass
        "*": (
            "accepted",
            "Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a "
            "plausible-looking but wrong assessment that an analyst must review; it drives no "
            "action beyond the alert-threshold comparison.",
        ),
    },
    "SC03": {  # Embedding Scripts within Scripts
        "sidecar": (
            "accepted",
            "The orchestrator renders nothing from the sidecars; its own console is CSP-locked "
            "(default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.",
        ),
        "vendor": (
            "transferred",
            "The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.",
        ),
    },
    "SC05": {  # Removing Important Client Functionality
        "sidecar": (
            "accepted",
            "No security decision of the orchestrator lives in a sidecar's client code; "
            "SpiderFoot's UI is loopback-only.",
        ),
        "vendor": ("transferred", "Client-side functionality of vendor UIs is the vendor's."),
    },
    # ── Medium ──
    "AA01": {  # Authentication Abuse/ByPass
        "orchestrator": (
            "mitigated",
            "Every data route depends on require_api_key (401 asserted by tests) under the "
            "assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are "
            "intentionally open; the console shell carries no data (ADR-010).",
        ),
        "sidecar": _NO_SESSIONS,
        "vendor": _VENDOR_AUTH,
    },
    "AA02": {  # Principal Spoof
        "orchestrator": (
            "mitigated",
            "Identity is proven per request by the shared secret, never self-asserted; the OIDC "
            "overlay adds an authenticated person (ADR-006).",
        ),
        "sidecar": (
            "accepted",
            "The sidecars accept anything on the compose network as the orchestrator (AA01).",
        ),
        "vendor": _VENDOR_AUTH,
    },
    "AC01": {  # Privilege Abuse
        "orchestrator": (
            "accepted",
            "One operator role by design (ADR-005/010); alert acknowledgements record a name as "
            "an audit hint, not an authorization.",
        ),
        "sidecar": (
            "accepted",
            "No roles on the sidecars: every caller can do everything they do (AA01).",
        ),
        "vendor": _VENDOR_AUTH,
        "store": (
            "accepted",
            "One process owns each volume (uid 1000 for the orchestrator's stores, the engine for "
            "asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is "
            "no finer privilege to "
            "abuse. Hardening: volume permissions and "
            "read-only mounts where possible.",
        ),
    },
    "AC02": {  # Shared Data Manipulation
        "vendor": (
            "transferred",
            "OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and "
            "hardened by the OpenCTI platform deployment.",
        ),
        "store": (
            "accepted",
            "The Amass asset database is shared between the engine and the orchestrator on one "
            "volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text.",
        ),
    },
    "AC05": {  # Content Spoofing
        "flow": (
            "accepted",
            "Everything that arrives through these flows is treated as untrusted text: escaped "
            "by React under CSP in the console, delimited in prompts, validated as STIX on "
            "intake. Spoofing the content of a host-internal plaintext hop needs a position on "
            "the host (DS06)." + _DISCOVERY,
        ),
    },
    "AC07": {  # Exploiting Incorrectly Configured Access Control
        "sidecar": (
            "accepted",
            "There is no access control to misconfigure on the sidecars (AA01).",
        ),
        "vendor": _VENDOR_AUTH,
    },
    "AC08": {  # Manipulate Registry Information
        "*": (
            "accepted",
            "Service discovery is static compose DNS on the trusted network; there is no "
            "registry to manipulate from outside the host.",
        ),
    },
    "AC09": {  # Functionality Misuse
        "sidecar": (
            "accepted",
            "Anything on the compose network can drive an unauthenticated sidecar (AA01); the "
            "orchestrator's own triggers are guarded by the in-progress 409 rule and per-target "
            "schedules.",
        ),
        "vendor": _VENDOR_AUTH,
    },
    "AC11": {"sidecar": _NO_SESSIONS, "vendor": _VENDOR_SESSIONS},  # Credential Manipulation
    "AC13": {  # Hijacking a privileged process
        "orchestrator": (
            "mitigated",
            "The single process runs unprivileged (uid 1000) with no privilege-drop window to "
            "hijack.",
        ),
        "vendor": _VENDOR_PROCESS,
    },
    "CR04": {"vendor": _VENDOR_SESSIONS},  # Session Credential Falsification through Forging
    "CR08": {  # Client-Server Protocol Manipulation
        "flow": (
            "accepted",
            "The orchestrator validates protocol and headers on everything it serves and "
            "sends well-formed requests; POST /bundles parses its body as JSON without checking "
            "the declared media type, and the schema validation that follows is what bounds it. "
            "Manipulating a host-internal plaintext hop needs a position on the host (DS06)."
            + _DISCOVERY,
        ),
    },
    "DE01": {  # Interception
        "flow": (
            "accepted",
            "Host-internal plaintext flows (loopback, compose bridge, in-process, files) are "
            "within the trusted boundary of ADR-005; what leaves the host with a credential or "
            "evidence inside is TLS." + _DISCOVERY,
        ),
    },
    "DE03": {  # Sniffing Attacks
        "flow": (
            "accepted",
            "The rule fires on the absence of a VPN, which no hop uses; what protects each hop "
            "differs. Internet hops carry credentials and evidence under TLS 1.2+ with "
            "certificate verification (Tavily, the cloud and SocialOSINT LLM endpoints, the "
            "social platforms, GitHub's datasets, the webhook over https://, SMTP with "
            "STARTTLS), so sniffing them needs a broken TLS, not a position on the path. "
            "Host-internal hops are plaintext by decision ADR-005 and sniffing them needs a "
            "position on the host, out of the modelled scope. The exception on record: "
            "connector-misp polls MISP with MISP_SSL_VERIFY=false, TLS without certificate "
            "verification, so a position on the compose network could impersonate MISP "
            "(hardening: a trusted certificate and MISP_SSL_VERIFY=true)." + _DISCOVERY,
        ),
    },
    "DO02": {  # Excessive Allocation
        "orchestrator": (
            "accepted",
            "Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, "
            "LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with "
            "request.json() before validating it and no middleware caps uploads, so an "
            "authenticated producer can exhaust memory with one request. Hardening: a body-size "
            "limit at the reverse proxy or TLS terminator in front of :8000.",
        ),
        "sidecar": _SIDECAR_INPUT,
        "vendor": _VENDOR_INPUT,
        "store": (
            "accepted",
            "Stores grow with runs: the scheduler's retention purge bounds SQLite rows and "
            "daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: "
            "disk quotas and monitoring on the volumes.",
        ),
    },
    "DO01": {  # Flooding
        "orchestrator": (
            "accepted",
            "No rate limiting in the service; concurrency is bounded (409 on an active run, "
            "retry budgets, per-run call caps) and the API is loopback-only by default. "
            "Hardening: rate limiting at the proxy or TLS terminator.",
        ),
        "sidecar": (
            "accepted",
            "The sidecars can be flooded by anything on the compose network; the orchestrator "
            "bounds its own use with timeouts and per-run caps.",
        ),
        "vendor": ("transferred", "Rate limiting of vendor services is the vendor's."),
    },
    "INP17": {  # XSS Using MIME Type Mismatch
        "sidecar": (
            "accepted",
            "The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; "
            "SpiderFoot's UI is loopback-only.",
        ),
        "vendor": ("transferred", "MIME handling of vendor web UIs is the vendor's."),
    },
    "INP19": {"*": _XML},  # XML External Entities Blowup
    "INP21": {"*": _XML},  # DTD Injection
    "INP36": {"sidecar": _SMUGGLING_SIDECAR, "vendor": _SMUGGLING_VENDOR},  # Response Smuggling
    # ── Low / Very Low ──
    "CR05": {  # Encryption Brute Forcing
        "sidecar": (
            "accepted",
            "Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and "
            "HMACs are 128-256-bit CSPRNG material.",
        ),
        "vendor": ("transferred", "Cryptography inside vendor services is the vendor's."),
        "store": ("accepted", "Nothing is encrypted at rest to brute-force (DR01)."),
    },
    "HA03": {  # Web Application Fingerprinting
        "vendor": (
            "transferred",
            "Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP "
            "are loopback-only here, Tavily and the SMTP relay are public services.",
        ),
        "sidecar": (
            "accepted",
            "SpiderFoot's unauthenticated UI is upstream design; compose publishes it on "
            "loopback only, limiting fingerprinting to the host itself.",
        ),
    },
    "DS03": {  # Footprinting
        "vendor": (
            "transferred",
            "Footprinting a vendor service is the vendor's concern; the loopback-only ones expose "
            "no external surface from this deployment.",
        ),
        "sidecar": (
            "accepted",
            "Footprinting of the loopback-only SpiderFoot service yields no external surface; "
            "documented in compose comments.",
        ),
    },
}

# (element, threat) pairs whose answer differs from their class.
_SOCIALOSINT_LLM = (
    "accepted",
    "SocialOSINT sends its own prompts (profiles, posts, images) to this endpoint and gets a "
    "free-text Markdown report back. The orchestrator attaches that report as a note labelled "
    "unverified (collectors/socialosint.py), never as observables, with no schema validation; "
    "the console renders it escaped and nothing acts on it. Residual risk: a manipulated "
    "report misleads the analyst who reads the note.",
)
_UNAUTHENTICATED_BACKING: Response = (
    "accepted",
    "Runs without authentication by the compose file's decision (xpack.security.enabled=false "
    "for Elasticsearch, no requirepass for Redis, none at all in misp-modules): reachable only "
    "on the compose network, never "
    "published on the host, and only its own platform talks to it (ADR-005). Hardening for "
    "shared hosts: enable the service's authentication (xpack security, requirepass) and TLS, "
    "or network policies that pin each backing service to its platform.",
)
OVERRIDES: dict[tuple[str, str], Response] = {
    ("OpenCTI UI login and session (loopback :8080, HTTP)", "CR02"): (
        "transferred",
        "TRACE handling on OpenCTI's web UI is the platform's; the UI is published on loopback "
        "only and nothing the orchestrator serves issues TRACE. Hardening: a TLS terminator in "
        "front of :8080 that drops TRACE.",
    ),
    ("Reference dataset download (GitHub master, mutable)", "CR06"): (
        "accepted",
        "The one unpinned input on record: connector-opencti fetches sectors.json and "
        "geography.json from the datasets repository's master branch, a mutable reference, over "
        "TLS to GitHub. A tampered file would land in OpenCTI as reference identities, "
        "locations and markings, never as a finding about a target, and the orchestrator reads "
        "nothing back from them. Hardening: pin CONFIG_SECTORS_FILE_URL and "
        "CONFIG_GEOGRAPHY_FILE_URL to a commit, or mirror the files.",
    ),
    ("Alert webhook (ALERT_WEBHOOK_URL)", "AC05"): (
        "accepted",
        "With ALERT_WEBHOOK_SECRET unset (the modelled default) the receiver gets no "
        "orchestrator signature, so a custom endpoint without caller authentication cannot "
        "tell a forged alert from a real one; hosted Slack, Teams and Discord URLs authenticate "
        "the sender through the URL's own token instead. Hardening: set ALERT_WEBHOOK_SECRET "
        "and verify the HMAC-SHA256 signature at the receiver.",
    ),
    ("GET /health, /metrics", "DS06"): (
        "accepted",
        "GET /metrics answers without an API key by design (scrapers are not API clients; "
        "ORCHESTRATOR_METRICS_ENABLED defaults to true): target ids, run status, durations and "
        "observable counts go to whoever reaches :8000, which ADR-005 limits to the trusted "
        "host. Hardening: ORCHESTRATOR_METRICS_ENABLED=false, or a scraper-only network policy "
        "or an authenticating TLS terminator in front of /metrics.",
    ),
    ("SpiderFoot scan database (spiderfoot-data volume)", "DE04"): (
        "accepted",
        "Outside the manifest chain: scan rows and logs are plain SQLite the sidecar rewrites. "
        "The orchestrator reads a scan's events once, at collection, into evidence it then "
        "seals, and verifies nothing against this database afterwards, so a later edit here "
        "changes no sealed run but misleads whoever reads SpiderFoot's own UI. Hardening: "
        "volume permissions and deleting scans after collection.",
    ),
    ("SpiderFoot scan database (spiderfoot-data volume)", "DO02"): (
        "accepted",
        "No retention: completed scans stay in the database (the collector stops only the "
        "scans it abandons) and purge_expired cleans run rows and daily_reports only, so the "
        "volume grows with every run. Hardening: delete each scan after collection or run a "
        "purge job, and put a disk quota on the volume.",
    ),
    ("SocialOSINT cache volume", "DE04"): (
        "accepted",
        "The cache is outside the manifest chain: profiles and posts under /app/data are plain "
        "files the sidecar rewrites at will, with no signature or audit log, and the "
        "orchestrator only ever reads the sidecar's report, so an edit there is invisible to "
        "it. Hardening: an ephemeral or read-only volume and file permissions.",
    ),
    ("SocialOSINT cache volume", "DO02"): (
        "accepted",
        "No retention reaches this volume: the sidecar's CacheManager keeps profiles and posts "
        "under /app/data until the operator removes the volume or prunes it, and deleting a "
        "session removes only the session file. The orchestrator keeps nothing of it beyond the "
        "unverified note. Hardening: an ephemeral (tmpfs) volume or a purge job for /app/data, "
        "sized to the retention the operator owes the people in those profiles.",
    ),
    ("SocialOSINT's LLM endpoint", "LLM01"): _SOCIALOSINT_LLM,
    ("SocialOSINT's LLM endpoint", "LLM02"): _SOCIALOSINT_LLM,
    ("SocialOSINT's LLM endpoint", "LLM07"): _SOCIALOSINT_LLM,
    ("SQLite run store", "DE04"): (
        "accepted",
        "Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the "
        "manifest hash, signature, chain link and artefact files (evidence.py), not a row's "
        "status, collectors or timestamps, so an edit to those fields with the manifest intact "
        "goes undetected. Hardening: database file permissions, backups and disk encryption.",
    ),
}
# Authentication is disabled by this repository's compose files, not by the vendor: every
# authentication, access-control and misuse threat on these services is the deployment's.
for _element in ("Elasticsearch", "Redis (OpenCTI)", "Redis (MISP)", "misp-modules"):
    for _threat in ("AA01", "AA02", "AA03", "AC01", "AC07", "AC09", "AC11", "AC16", "AC17", "CR03"):
        OVERRIDES[(_element, _threat)] = _UNAUTHENTICATED_BACKING
_SMTP_NO_AUTH: Response = (
    "accepted",
    "The orchestrator submits without SMTP AUTH unless ALERT_SMTP_USER is set (the modelled "
    "default): who may submit is then the relay's policy (a network restriction or mandatory "
    "AUTH on a submission relay), and STARTTLS with certificate verification authenticates "
    "the relay, not the sender. Hardening: ALERT_SMTP_USER and ALERT_SMTP_PASSWORD.",
)
for _threat in ("AA01", "AA02", "AC01", "AC07", "AC09"):
    OVERRIDES[("SMTP relay (alert e-mail)", _threat)] = _SMTP_NO_AUTH


def element_class(finding) -> str:
    if isinstance(finding.element, Dataflow):
        return "flow"
    return CLASS_OF.get(str(finding.target), "unknown")


def triage(finding) -> Response | None:
    override = OVERRIDES.get((str(finding.target), finding.threat_id))
    if override is not None:
        return override
    by_class = TRIAGE.get(finding.threat_id, {})
    return by_class.get(element_class(finding)) or by_class.get("*")


# ── Resolve ─────────────────────────────────────────────────────────────────
tm.resolve()
findings = tm.findings

untriaged = sorted(
    {(f.threat_id, element_class(f), str(f.target)) for f in findings if triage(f) is None}
)
if untriaged:
    for threat_id, cls, target in untriaged:
        print(f"untriaged: {threat_id} [{cls}] {target}", file=sys.stderr)
    raise SystemExit(f"{len(untriaged)} finding(s) without a triage response; add them to TRIAGE")

for f in findings:
    f.response, f.triage_note = triage(f)

# ── Ledger of reviewed (threat, element) pairs ──────────────────────────────
ledger_now = sorted({f"{f.threat_id}\t{element_class(f)}\t{f.target}" for f in findings})
ledger_file = LEDGER.read_text(encoding="utf-8").splitlines() if LEDGER.exists() else []
if "--accept" in sys.argv[1:]:
    LEDGER.write_text("\n".join(ledger_now) + "\n", encoding="utf-8")
elif ledger_now != ledger_file:
    new = sorted(set(ledger_now) - set(ledger_file))
    gone = sorted(set(ledger_file) - set(ledger_now))
    for line in new:
        print(f"new finding:  {line}", file=sys.stderr)
    for line in gone:
        print(f"gone finding: {line}", file=sys.stderr)
    raise SystemExit(
        f"{len(new)} new and {len(gone)} vanished (threat, element) pair(s) since "
        f"{LEDGER.name}; review them and re-run with --accept"
    )

# ── Report ──────────────────────────────────────────────────────────────────
by_sev: dict[str, list] = {}
for f in findings:
    by_sev.setdefault(str(getattr(f, "severity", "") or "unrated"), []).append(f)
by_resp: dict[str, list] = {}
for f in findings:
    by_resp.setdefault(f.response, []).append(f)

lines = [
    "# Threat model — OSINT Orchestrator (OWASP pytm, threat library 114 threats)",
    "",
    tm.description,
    "",
    "## Assumptions",
    "",
    *[f"- {a}" for a in tm.assumptions],
    "",
    "## Element classes",
    "",
    "A response is written per class: the same threat means something different on the "
    "orchestrator, on an unauthenticated sidecar, on a vendor service, on a store or on a flow.",
    "",
    *[
        f"- **{cls}**: {', '.join(el.name for el in els)}"
        for cls, els in CLASSES.items()
        if cls != "actor"
    ],
    "- **flow**: every dataflow, named by what it carries",
    "",
    f"## Findings: {len(findings)} across {len({f.threat_id for f in findings})} distinct threats",
    "",
    "Every finding carries a triage response:",
    "",
    *[f"- **{resp}**: {len(group)} finding(s)" for resp, group in sorted(by_resp.items())],
    "",
    "## Triage summary by threat and element class",
    "",
    "| Threat | Severity | Class | Response | Rationale |",
    "| --- | --- | --- | --- | --- |",
]
summary: dict[tuple[str, str, str, str], tuple[str, str]] = {}
for f in findings:
    # One row per distinct answer, so an override inside a class keeps its own row.
    summary.setdefault(
        (f.threat_id, element_class(f), f.response, f.triage_note), (f.severity, f.description)
    )
for (tid, cls, resp, note), (sev, desc) in sorted(summary.items()):
    lines.append(f"| {tid} {desc} | {sev} | {cls} | {resp} | {note} |")

lines += ["", "## Full findings", ""]
order = {"very high": 0, "high": 1, "medium": 2, "low": 3, "very low": 4}
for sev in sorted(by_sev, key=lambda s: order.get(s.lower(), 9)):
    group = by_sev[sev]
    lines += [f"### Severity: {sev} ({len(group)})", ""]
    for f in sorted(group, key=lambda x: int(x.id)):
        lines += [
            f"#### F-{f.id} — {f.description}  `{f.threat_id}`",
            "",
            f"- **Element:** {f.target} ({element_class(f)})",
            f"- **Response:** {f.response} — {f.triage_note}",
        ]
        if getattr(f, "mitigations", ""):
            lines.append(f"- **pytm mitigations:** {f.mitigations}")
        lines.append("")
REPORT.write_text("\n".join(lines), encoding="utf-8")

print(f"findings: {len(findings)}")
for sev in sorted(by_sev, key=lambda s: order.get(s.lower(), 9)):
    print(f"  {sev}: {len(by_sev[sev])}")
print("triage:")
for resp, group in sorted(by_resp.items()):
    print(f"  {resp}: {len(group)}")
print(f"report: {REPORT}")
print(f"ledger: {LEDGER} ({len(ledger_now)} pairs)")
