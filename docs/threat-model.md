# Threat model — OSINT Orchestrator (OWASP pytm, threat library 114 threats)

Modular monolith (ADR-001): one FastAPI process with an in-process APScheduler and a SQLite store drives OSINT collectors, qualifies evidence with an LLM, normalises findings to STIX 2.1 (ADR-002), ingests them into OpenCTI (ADR-003/008), seals a signed report chain per run (ADR-007) and dispatches alerts by webhook and e-mail. Access uses static API keys and a single instance (ADR-005), with an optional OIDC proxy perimeter (ADR-006) and an external STIX intake (ADR-011). Operator prose is Spanish, code English (ADR-004).

## Assumptions

- Single-instance deployment on a trusted Docker host; loopback-published ports are reachable only from that host.
- The Docker host and the compose network are operated by the same team as the orchestrator.
- ORCHESTRATOR_API_KEY is set. require_api_key is a no-op with an empty key (open mode, documented in ADR-005 and ADR-006); that mode is out of this model's scope.
- The shipped docker-compose.auth.yml terminates no TLS: oauth2-proxy listens on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false, and the browser logs in at Keycloak's own HTTP endpoint (KC_HOSTNAME http://localhost:8085, OIDC_BROWSER_LOGIN_URL). A TLS terminator in front of both, with KC_HOSTNAME and the login URL on the https:// name, is a production hardening step, modelled as absent.
- Alert channels are modelled with their defaults: SMTP with STARTTLS (ALERT_SMTP_STARTTLS=true) and the webhook over an https:// URL of the operator's with the optional HMAC signature (ALERT_WEBHOOK_SECRET) unset. ALERT_WEBHOOK_URL accepts any URL (config.py) and the notifier posts to it as given; an http:// webhook would carry the alert payload and the URL's own token in clear and is outside this model's scope.
- Collectors only query targets authorised in targets.yaml (operator attestation per target).
- OpenCTI, MISP, Amass, SocialOSINT and the OIDC overlay are optional deployments; the model covers them when enabled.
- ORCHESTRATOR_SECRET_KEY is a private, randomly generated value. The default insecure-dev-key only earns a startup warning (auth.py); with it, or with an empty key, anyone can forge a manifest, and the integrity claims of this model do not hold.
- LLM_BASE_URL points at the Ollama service of the shipped compose (same host, compose network). OllamaClient posts to whatever URL is configured (providers/ollama.py), so a remote LLM_BASE_URL turns `llm: local` into the cloud-provider case of this model; a remote Ollama is not modelled separately.

## Element classes

A response is written per class: the same threat means something different on the orchestrator, on an unauthenticated sidecar, on a vendor service, on a store or on a flow.

- **orchestrator**: Orchestrator API (FastAPI + APScheduler), APScheduler cron jobs
- **sidecar**: SpiderFoot, Amass v5 engine, SocialOSINT sidecar, Ollama (local models), Ollama HTTP API
- **vendor**: Tavily search API, Cloud LLM provider, SocialOSINT's LLM endpoint, SMTP relay (alert e-mail), Alert webhook receiver, oauth2-proxy, Keycloak, MISP, OpenCTI platform, OpenCTI backing stores, connector-misp, Keycloak data volume (keycloak-data), MISP backing stores (MariaDB, Redis), Elasticsearch, Redis (OpenCTI), MinIO, RabbitMQ, MariaDB (MISP), Redis (MISP)
- **store**: SQLite run store, targets.yaml, daily_reports (sealed runs), Amass asset database (shared volume), SocialOSINT cache volume, SpiderFoot scan database (spiderfoot-data volume)
- **flow**: every dataflow, named by what it carries

## Findings: 1092 across 88 distinct threats

Every finding carries a triage response:

- **accepted**: 522 finding(s)
- **mitigated**: 21 finding(s)
- **transferred**: 549 finding(s)

## Triage summary by threat and element class

| Threat | Severity | Class | Response | Rationale |
| --- | --- | --- | --- | --- |
| AA01 Authentication Abuse/ByPass | Medium | orchestrator | mitigated | Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010). |
| AA01 Authentication Abuse/ByPass | Medium | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AA01 Authentication Abuse/ByPass | Medium | vendor | accepted | Runs without authentication by the compose file's decision (xpack.security.enabled=false for Elasticsearch, no requirepass for Redis): reachable only on the compose network, never published on the host, and only its own platform talks to it (ADR-005). Hardening for shared hosts: enable the service's authentication (xpack security, requirepass) and TLS, or network policies that pin each backing service to its platform. |
| AA01 Authentication Abuse/ByPass | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's. |
| AA02 Principal Spoof | Medium | orchestrator | mitigated | Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006). |
| AA02 Principal Spoof | Medium | sidecar | accepted | The sidecars accept anything on the compose network as the orchestrator (AA01). |
| AA02 Principal Spoof | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's. |
| AA03 Exploitation of Trusted Credentials | High | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AA03 Exploitation of Trusted Credentials | High | vendor | accepted | Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation. |
| AA04 Exploiting Trust in Client | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| AA04 Exploiting Trust in Client | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| AC01 Privilege Abuse | Medium | sidecar | accepted | No roles on the sidecars: every caller can do everything they do (AA01). |
| AC01 Privilege Abuse | Medium | store | accepted | One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible. |
| AC01 Privilege Abuse | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's. |
| AC02 Shared Data Manipulation | Medium | store | accepted | The Amass asset database is shared between the engine and the orchestrator on one volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text. |
| AC02 Shared Data Manipulation | Medium | vendor | transferred | OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and hardened by the OpenCTI platform deployment. |
| AC05 Content Spoofing | Medium | flow | accepted | Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| AC06 Using Malicious Files | Very High | sidecar | accepted | The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars. |
| AC06 Using Malicious Files | Very High | vendor | transferred | Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve. |
| AC07 Exploiting Incorrectly Configured Access Control Security Levels | Medium | sidecar | accepted | There is no access control to misconfigure on the sidecars (AA01). |
| AC07 Exploiting Incorrectly Configured Access Control Security Levels | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's. |
| AC08 Manipulate Registry Information | Medium | sidecar | accepted | Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host. |
| AC08 Manipulate Registry Information | Medium | vendor | accepted | Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host. |
| AC09 Functionality Misuse | Medium | sidecar | accepted | Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules. |
| AC09 Functionality Misuse | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's. |
| AC11 Session Credential Falsification through Manipulation | Medium | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AC11 Session Credential Falsification through Manipulation | Medium | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| AC12 Privilege Escalation | High | orchestrator | mitigated | No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to. |
| AC12 Privilege Escalation | High | vendor | transferred | oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code. |
| AC13 Hijacking a privileged process | Medium | orchestrator | mitigated | The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack. |
| AC13 Hijacking a privileged process | Medium | vendor | transferred | oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code. |
| AC14 Catching exception throw/signal from privileged block | Very High | orchestrator | mitigated | The pipeline isolates every step (collect, qualify, normalise, synthesise, seal, alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile). |
| AC14 Catching exception throw/signal from privileged block | Very High | vendor | transferred | oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code. |
| AC15 Schema Poisoning | High | orchestrator | mitigated | STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage. |
| AC15 Schema Poisoning | High | vendor | transferred | Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side. |
| AC16 Session Credential Falsification through Prediction | High | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AC16 Session Credential Falsification through Prediction | High | vendor | transferred | Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example). |
| AC17 Session Hijacking - ServerSide | Very High | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AC17 Session Hijacking - ServerSide | Very High | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| AC18 Session Hijacking - ClientSide | Very High | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| AC19 Reusing Session IDs (aka Session Replay) - ServerSide | High | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| AC20 Reusing Session IDs (aka Session Replay) - ClientSide | High | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| AC21 Cross Site Request Forgery | Very High | orchestrator | mitigated | Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token. |
| AC21 Cross Site Request Forgery | Very High | vendor | transferred | connector-misp has no browser-facing surface; CSRF on vendor UIs is the vendor's (oauth2-proxy implements its own CSRF token). |
| AC23 Credentials Disclosure | High | flow | accepted | Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI. |
| API01 Exploit Test APIs | High | orchestrator | mitigated | No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it). |
| CR01 Session Sidejacking | High | flow | accepted | The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and of Keycloak's browser endpoint (KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name) and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true. |
| CR01 Session Sidejacking | High | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| CR02 Cross Site Tracing | Very High | flow | accepted | FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE. |
| CR02 Cross Site Tracing | Very High | vendor | transferred | TRACE handling at Keycloak and OpenCTI is the vendor image's; both sit on the compose network or loopback (ADR-005) and nothing the orchestrator serves issues TRACE. Hardening: a TLS terminator in front of them that drops TRACE. |
| CR03 Dictionary-based Password Attack | High | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| CR03 Dictionary-based Password Attack | High | vendor | transferred | Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay. |
| CR04 Session Credential Falsification through Forging | Medium | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| CR05 Encryption Brute Forcing | Low | sidecar | accepted | Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material. |
| CR05 Encryption Brute Forcing | Low | store | accepted | Nothing is encrypted at rest to brute-force (DR01). |
| CR05 Encryption Brute Forcing | Low | vendor | transferred | Cryptography inside vendor services is the vendor's. |
| CR06 Communication Channel Manipulation | High | flow | accepted | Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| CR08 Client-Server Protocol Manipulation | Medium | flow | accepted | The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| DE01 Interception | Medium | flow | accepted | Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| DE02 Double Encoding | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DE02 Double Encoding | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DE03 Sniffing Attacks | Medium | flow | accepted | Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| DE04 Audit Log Manipulation | High | store | accepted | Outside the manifest chain: scan rows and logs are plain SQLite the sidecar rewrites. The orchestrator reads a scan's events once, at collection, into evidence it then seals, and verifies nothing against this database afterwards, so a later edit here changes no sealed run but misleads whoever reads SpiderFoot's own UI. Hardening: volume permissions and deleting scans after collection. |
| DE04 Audit Log Manipulation | High | store | accepted | Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption. |
| DE04 Audit Log Manipulation | High | store | accepted | The cache is outside the manifest chain: profiles and posts under /app/data are plain files the sidecar rewrites at will, with no signature or audit log, and the orchestrator only ever reads the sidecar's report, so an edit there is invisible to it. Hardening: an ephemeral or read-only volume and file permissions. |
| DE04 Audit Log Manipulation | High | store | mitigated | Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper. |
| DE04 Audit Log Manipulation | High | vendor | transferred | The platform's own audit trail (OpenCTI, Keycloak events, MISP logs) lives in its backing stores and is the platform's. |
| DO01 Flooding | Medium | orchestrator | accepted | No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator. |
| DO01 Flooding | Medium | sidecar | accepted | The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps. |
| DO01 Flooding | Medium | vendor | transferred | Rate limiting of vendor services is the vendor's. |
| DO02 Excessive Allocation | Medium | orchestrator | accepted | Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000. |
| DO02 Excessive Allocation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DO02 Excessive Allocation | Medium | store | accepted | No retention reaches this volume: the sidecar's CacheManager keeps profiles and posts under /app/data until the operator removes the volume or prunes it, and deleting a session removes only the session file. The orchestrator keeps nothing of it beyond the unverified note. Hardening: an ephemeral (tmpfs) volume or a purge job for /app/data, sized to the retention the operator owes the people in those profiles. |
| DO02 Excessive Allocation | Medium | store | accepted | No retention: completed scans stay in the database (the collector stops only the scans it abandons) and purge_expired cleans run rows and daily_reports only, so the volume grows with every run. Hardening: delete each scan after collection or run a purge job, and put a disk quota on the volume. |
| DO02 Excessive Allocation | Medium | store | accepted | Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes. |
| DO02 Excessive Allocation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DR01 Unprotected Sensitive Data | High | flow | accepted | Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| DS01 Excavation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS01 Excavation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS03 Footprinting | Very Low | sidecar | accepted | Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments. |
| DS03 Footprinting | Very Low | vendor | transferred | Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment. |
| DS04 XSS Targeting Error Pages | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS04 XSS Targeting Error Pages | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS06 Data Leak | Very High | flow | accepted | GET /metrics answers without an API key by design (scrapers are not API clients; ORCHESTRATOR_METRICS_ENABLED defaults to true): target ids, run status, durations and observable counts go to whoever reaches :8000, which ADR-005 limits to the trusted host. Hardening: ORCHESTRATOR_METRICS_ENABLED=false, or a scraper-only network policy or an authenticating TLS terminator in front of /metrics. |
| DS06 Data Leak | Very High | flow | accepted | Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| HA01 Path Traversal | Very High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| HA01 Path Traversal | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| HA03 Web Application Fingerprinting | Low | sidecar | accepted | SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself. |
| HA03 Web Application Fingerprinting | Low | vendor | transferred | Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services. |
| INP02 Overflow Buffers | Very High | orchestrator | mitigated | Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT. |
| INP02 Overflow Buffers | Very High | vendor | transferred | oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code. |
| INP03 Server Side Include (SSI) Injection | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP03 Server Side Include (SSI) Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP04 HTTP Request Splitting | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP04 HTTP Request Splitting | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP05 Command Line Execution through SQL Injection | Very High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP05 Command Line Execution through SQL Injection | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP07 Buffer Manipulation | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP08 Format String Injection | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP08 Format String Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP09 LDAP Injection | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP09 LDAP Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP10 Parameter Injection | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP10 Parameter Injection | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP11 Relative Path Traversal | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP11 Relative Path Traversal | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP12 Client-side Injection-induced Buffer Overflow | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP13 Command Delimiters | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP14 Input Data Manipulation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP14 Input Data Manipulation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP15 IMAP/SMTP Command Injection | Medium | vendor | transferred | SMTP command handling is the relay's. The orchestrator talks to it through smtplib with the configured host, port and credentials, and the message is a MIMEText whose headers the email package encodes; collected text only ever lands in the body as message data, never in an SMTP command. |
| INP16 PHP Remote File Inclusion | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP16 PHP Remote File Inclusion | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP17 XSS Using MIME Type Mismatch | Medium | sidecar | accepted | The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only. |
| INP17 XSS Using MIME Type Mismatch | Medium | vendor | transferred | MIME handling of vendor web UIs is the vendor's. |
| INP18 Fuzzing and observing application log data/errors for application mapping | Low | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP18 Fuzzing and observing application log data/errors for application mapping | Low | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP19 XML External Entities Blowup | Medium | sidecar | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP19 XML External Entities Blowup | Medium | vendor | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP20 iFrame Overlay | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP21 DTD Injection | Medium | sidecar | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP21 DTD Injection | Medium | vendor | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP22 XML Attribute Blowup | High | sidecar | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP22 XML Attribute Blowup | High | vendor | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP23 File Content Injection | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP24 Filter Failure through Buffer Overflow | High | orchestrator | mitigated | Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing. |
| INP24 Filter Failure through Buffer Overflow | High | vendor | transferred | oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code. |
| INP25 Resource Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP26 Code Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP27 XSS Targeting HTML Attributes | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP28 XSS Targeting URI Placeholders | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP28 XSS Targeting URI Placeholders | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP29 XSS Using Doubled Characters | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP29 XSS Using Doubled Characters | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP30 XSS Using Invalid Characters | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP31 Command Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP32 XML Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP33 Remote Code Inclusion | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP34 SOAP Array Overflow | High | sidecar | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP34 SOAP Array Overflow | High | vendor | transferred | The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code. |
| INP35 Leverage Alternate Encoding | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| INP36 HTTP Response Smuggling | Medium | sidecar | accepted | No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005). |
| INP36 HTTP Response Smuggling | Medium | vendor | transferred | HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib. |
| INP37 HTTP Request Smuggling | High | sidecar | accepted | No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005). |
| INP37 HTTP Request Smuggling | High | vendor | transferred | HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib. |
| INP41 Argument Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| LLM01 Direct Prompt Injection | High | sidecar | accepted | Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use). |
| LLM01 Direct Prompt Injection | High | vendor | accepted | Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use). |
| LLM01 Direct Prompt Injection | High | vendor | accepted | SocialOSINT sends its own prompts (profiles, posts, images) to this endpoint and gets a free-text Markdown report back. The orchestrator attaches that report as a note labelled unverified (collectors/socialosint.py), never as observables, with no schema validation; the console renders it escaped and nothing acts on it. Residual risk: a manipulated report misleads the analyst who reads the note. |
| LLM03 Sensitive Data Leakage to Third-Party Provider | High | vendor | accepted | The prompts carry personal data of the target's public footprint with no redaction: the orchestrator sends the observables it collected (domains, URLs, e-mail addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and images to its own endpoint. Both go only to the provider the operator configured, over TLS; `llm: local` keeps the orchestrator's prompts on the host only while LLM_BASE_URL points at the local Ollama (assumption above: the client posts wherever it is configured), so verify that endpoint before relying on it. Hardening: a provider under a data-processing agreement with retention and training opted out, or local models for sensitive workloads. |
| LLM07 Jailbreaking and Safety Bypass | High | sidecar | accepted | Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison. |
| LLM07 Jailbreaking and Safety Bypass | High | vendor | accepted | Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison. |
| LLM07 Jailbreaking and Safety Bypass | High | vendor | accepted | SocialOSINT sends its own prompts (profiles, posts, images) to this endpoint and gets a free-text Markdown report back. The orchestrator attaches that report as a note labelled unverified (collectors/socialosint.py), never as observables, with no schema validation; the console renders it escaped and nothing acts on it. Residual risk: a manipulated report misleads the analyst who reads the note. |
| LLM08 Sensitive Information Disclosure Through Output | High | sidecar | accepted | A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted. |
| LLM08 Sensitive Information Disclosure Through Output | High | vendor | accepted | A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted. |
| SC02 XSS Targeting Non-Script Elements | Very High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| SC02 XSS Targeting Non-Script Elements | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| SC03 Embedding Scripts within Scripts | High | sidecar | accepted | The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only. |
| SC03 Embedding Scripts within Scripts | High | vendor | transferred | The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's. |
| SC04 XSS Using Alternate Syntax | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| SC04 XSS Using Alternate Syntax | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| SC05 Removing Important Client Functionality | High | sidecar | accepted | No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only. |
| SC05 Removing Important Client Functionality | High | vendor | transferred | Client-side functionality of vendor UIs is the vendor's. |

## Full findings

### Severity: Very High (106)

#### F-6 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-11 — Path Traversal  `HA01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-20 — Using Malicious Files  `AC06`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-22 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-46 — Session Hijacking - ServerSide  `AC17`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-52 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-57 — Path Traversal  `HA01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-66 — Using Malicious Files  `AC06`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-68 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-93 — Session Hijacking - ServerSide  `AC17`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-94 — Overflow Buffers  `INP02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-98 — Buffer Manipulation  `INP07`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-107 — File Content Injection  `INP23`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-110 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-123 — Session Hijacking - ClientSide  `AC18`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-129 — Cross Site Tracing  `CR02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — TRACE handling at Keycloak and OpenCTI is the vendor image's; both sit on the compose network or loopback (ADR-005) and nothing the orchestrator serves issues TRACE. Hardening: a TLS terminator in front of them that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-130 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-136 — Path Traversal  `HA01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-144 — Using Malicious Files  `AC06`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-146 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-172 — Session Hijacking - ServerSide  `AC17`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-178 — Overflow Buffers  `INP02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-186 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The pipeline isolates every step (collect, qualify, normalise, synthesise, seal, alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile).
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-189 — Cross Site Request Forgery  `AC21`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-190 — Overflow Buffers  `INP02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-199 — Cross Site Request Forgery  `AC21`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-219 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-225 — Path Traversal  `HA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-234 — Using Malicious Files  `AC06`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-236 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-261 — Session Hijacking - ServerSide  `AC17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-268 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-274 — Path Traversal  `HA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-283 — Using Malicious Files  `AC06`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-285 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-310 — Session Hijacking - ServerSide  `AC17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-313 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-319 — Path Traversal  `HA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-328 — Using Malicious Files  `AC06`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-330 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-355 — Session Hijacking - ServerSide  `AC17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-362 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-368 — Path Traversal  `HA01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-377 — Using Malicious Files  `AC06`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-379 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-404 — Session Hijacking - ServerSide  `AC17`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-409 — Command Line Execution through SQL Injection  `INP05`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-414 — Path Traversal  `HA01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-423 — Using Malicious Files  `AC06`

- **Element:** MISP (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-425 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-449 — Session Hijacking - ServerSide  `AC17`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-455 — Command Line Execution through SQL Injection  `INP05`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-460 — Path Traversal  `HA01`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-469 — Using Malicious Files  `AC06`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-471 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-493 — Session Hijacking - ServerSide  `AC17`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-495 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-501 — Path Traversal  `HA01`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-510 — Using Malicious Files  `AC06`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-512 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-537 — Session Hijacking - ServerSide  `AC17`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-541 — Cross Site Tracing  `CR02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — TRACE handling at Keycloak and OpenCTI is the vendor image's; both sit on the compose network or loopback (ADR-005) and nothing the orchestrator serves issues TRACE. Hardening: a TLS terminator in front of them that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-542 — Command Line Execution through SQL Injection  `INP05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-548 — Path Traversal  `HA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-556 — Using Malicious Files  `AC06`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-558 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-582 — Session Hijacking - ServerSide  `AC17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-586 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-592 — Path Traversal  `HA01`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-601 — Using Malicious Files  `AC06`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-603 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-628 — Session Hijacking - ServerSide  `AC17`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-630 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-636 — Path Traversal  `HA01`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-645 — Using Malicious Files  `AC06`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-647 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-672 — Session Hijacking - ServerSide  `AC17`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-675 — Command Line Execution through SQL Injection  `INP05`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-680 — Path Traversal  `HA01`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-689 — Using Malicious Files  `AC06`

- **Element:** MinIO (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-691 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-713 — Session Hijacking - ServerSide  `AC17`

- **Element:** MinIO (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-715 — Command Line Execution through SQL Injection  `INP05`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-720 — Path Traversal  `HA01`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-729 — Using Malicious Files  `AC06`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-731 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-753 — Session Hijacking - ServerSide  `AC17`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-759 — Overflow Buffers  `INP02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-763 — Buffer Manipulation  `INP07`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-773 — File Content Injection  `INP23`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-776 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-789 — Session Hijacking - ClientSide  `AC18`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-792 — Cross Site Request Forgery  `AC21`

- **Element:** connector-misp (vendor)
- **Response:** transferred — connector-misp has no browser-facing surface; CSRF on vendor UIs is the vendor's (oauth2-proxy implements its own CSRF token).
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-794 — Cross Site Tracing  `CR02`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-800 — Data Leak  `DS06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-804 — Cross Site Tracing  `CR02`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-838 — Data Leak  `DS06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-846 — Data Leak  `DS06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-854 — Data Leak  `DS06`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — GET /metrics answers without an API key by design (scrapers are not API clients; ORCHESTRATOR_METRICS_ENABLED defaults to true): target ids, run status, durations and observable counts go to whoever reaches :8000, which ADR-005 limits to the trusted host. Hardening: ORCHESTRATOR_METRICS_ENABLED=false, or a scraper-only network policy or an authenticating TLS terminator in front of /metrics.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-861 — Data Leak  `DS06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-893 — Data Leak  `DS06`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-900 — Data Leak  `DS06`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-939 — Data Leak  `DS06`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-945 — Data Leak  `DS06`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-961 — Data Leak  `DS06`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-967 — Data Leak  `DS06`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint (:8085), with KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

### Severity: High (403)

#### F-1 — Direct Prompt Injection  `LLM01`

- **Element:** SocialOSINT's LLM endpoint (vendor)
- **Response:** accepted — SocialOSINT sends its own prompts (profiles, posts, images) to this endpoint and gets a free-text Markdown report back. The orchestrator attaches that report as a note labelled unverified (collectors/socialosint.py), never as observables, with no schema validation; the console renders it escaped and nothing acts on it. Residual risk: a manipulated report misleads the analyst who reads the note.
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-2 — Sensitive Data Leakage to Third-Party Provider  `LLM03`

- **Element:** SocialOSINT's LLM endpoint (vendor)
- **Response:** accepted — The prompts carry personal data of the target's public footprint with no redaction: the orchestrator sends the observables it collected (domains, URLs, e-mail addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and images to its own endpoint. Both go only to the provider the operator configured, over TLS; `llm: local` keeps the orchestrator's prompts on the host only while LLM_BASE_URL points at the local Ollama (assumption above: the client posts wherever it is configured), so verify that endpoint before relying on it. Hardening: a provider under a data-processing agreement with retention and training opted out, or local models for sensitive workloads.
- **pytm mitigations:** Implement data masking or anonymization before sending data to the LLM. Use contractual agreements (DPAs) with the provider. Enable opt-out of data retention and training where available. Consider self-hosted alternatives for sensitive workloads. Encrypt data in transit.

#### F-3 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** SocialOSINT's LLM endpoint (vendor)
- **Response:** accepted — SocialOSINT sends its own prompts (profiles, posts, images) to this endpoint and gets a free-text Markdown report back. The orchestrator attaches that report as a note labelled unverified (collectors/socialosint.py), never as observables, with no schema validation; the console renders it escaped and nothing acts on it. Residual risk: a manipulated report misleads the analyst who reads the note.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-4 — Sensitive Information Disclosure Through Output  `LLM08`

- **Element:** SocialOSINT's LLM endpoint (vendor)
- **Response:** accepted — A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted.
- **pytm mitigations:** Implement output filtering to detect and redact sensitive data patterns (PII, credentials, etc.). Use output encoding appropriate to the consumption context. Apply data loss prevention (DLP) controls on LLM outputs. Minimize the amount of sensitive data in the LLM's context.

#### F-5 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-13 — Format String Injection  `INP08`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-14 — LDAP Injection  `INP09`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-16 — Relative Path Traversal  `INP11`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-18 — Dictionary-based Password Attack  `CR03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-24 — Embedding Scripts within Scripts  `SC03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-25 — PHP Remote File Inclusion  `INP16`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-27 — XSS Using Alternate Syntax  `SC04`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-30 — Removing Important Client Functionality  `SC05`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-32 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Tavily search API (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-35 — Exploiting Trust in Client  `AA04`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-39 — XML Attribute Blowup  `INP22`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-40 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-42 — SOAP Array Overflow  `INP34`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-44 — HTTP Request Smuggling  `INP37`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-45 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-47 — Direct Prompt Injection  `LLM01`

- **Element:** Cloud LLM provider (vendor)
- **Response:** accepted — Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-48 — Sensitive Data Leakage to Third-Party Provider  `LLM03`

- **Element:** Cloud LLM provider (vendor)
- **Response:** accepted — The prompts carry personal data of the target's public footprint with no redaction: the orchestrator sends the observables it collected (domains, URLs, e-mail addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and images to its own endpoint. Both go only to the provider the operator configured, over TLS; `llm: local` keeps the orchestrator's prompts on the host only while LLM_BASE_URL points at the local Ollama (assumption above: the client posts wherever it is configured), so verify that endpoint before relying on it. Hardening: a provider under a data-processing agreement with retention and training opted out, or local models for sensitive workloads.
- **pytm mitigations:** Implement data masking or anonymization before sending data to the LLM. Use contractual agreements (DPAs) with the provider. Enable opt-out of data retention and training where available. Consider self-hosted alternatives for sensitive workloads. Encrypt data in transit.

#### F-49 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Cloud LLM provider (vendor)
- **Response:** accepted — Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-50 — Sensitive Information Disclosure Through Output  `LLM08`

- **Element:** Cloud LLM provider (vendor)
- **Response:** accepted — A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted.
- **pytm mitigations:** Implement output filtering to detect and redact sensitive data patterns (PII, credentials, etc.). Use output encoding appropriate to the consumption context. Apply data loss prevention (DLP) controls on LLM outputs. Minimize the amount of sensitive data in the LLM's context.

#### F-51 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-59 — Format String Injection  `INP08`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-60 — LDAP Injection  `INP09`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-62 — Relative Path Traversal  `INP11`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-64 — Dictionary-based Password Attack  `CR03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-71 — Embedding Scripts within Scripts  `SC03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-72 — PHP Remote File Inclusion  `INP16`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-74 — XSS Using Alternate Syntax  `SC04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-77 — Removing Important Client Functionality  `SC05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-79 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-82 — Exploiting Trust in Client  `AA04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-86 — XML Attribute Blowup  `INP22`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-87 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-89 — SOAP Array Overflow  `INP34`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-91 — HTTP Request Smuggling  `INP37`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-92 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-101 — Format String Injection  `INP08`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-102 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-103 — Command Delimiters  `INP13`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-106 — iFrame Overlay  `INP20`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-108 — Privilege Escalation  `AC12`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-111 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-112 — Resource Injection  `INP25`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-113 — Code Injection  `INP26`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-115 — XSS Targeting URI Placeholders  `INP28`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-118 — Command Injection  `INP31`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-119 — XML Injection  `INP32`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-120 — Remote Code Inclusion  `INP33`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-121 — Leverage Alternate Encoding  `INP35`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-122 — Schema Poisoning  `AC15`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-124 — Argument Injection  `INP41`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-125 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-126 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-127 — Session Sidejacking  `CR01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-128 — HTTP Request Splitting  `INP04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-138 — Format String Injection  `INP08`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-139 — LDAP Injection  `INP09`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-141 — Relative Path Traversal  `INP11`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-148 — Embedding Scripts within Scripts  `SC03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-149 — PHP Remote File Inclusion  `INP16`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-153 — XSS Using Alternate Syntax  `SC04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-156 — Removing Important Client Functionality  `SC05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-158 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Keycloak (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-161 — Exploiting Trust in Client  `AA04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-165 — XML Attribute Blowup  `INP22`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-166 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-168 — SOAP Array Overflow  `INP34`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-170 — HTTP Request Smuggling  `INP37`

- **Element:** Keycloak (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-171 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-173 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-177 — Audit Log Manipulation  `DE04`

- **Element:** Keycloak data volume (keycloak-data) (vendor)
- **Response:** transferred — The platform's own audit trail (OpenCTI, Keycloak events, MISP logs) lives in its backing stores and is the platform's.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-180 — Exploit Test APIs  `API01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it).
- **pytm mitigations:** Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.

#### F-184 — Privilege Escalation  `AC12`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-187 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-188 — Schema Poisoning  `AC15`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-195 — Privilege Escalation  `AC12`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-197 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-198 — Schema Poisoning  `AC15`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-203 — Audit Log Manipulation  `DE04`

- **Element:** SQLite run store (store)
- **Response:** accepted — Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-207 — Audit Log Manipulation  `DE04`

- **Element:** targets.yaml (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-211 — Audit Log Manipulation  `DE04`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-216 — Audit Log Manipulation  `DE04`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-217 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-218 — HTTP Request Splitting  `INP04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-227 — Format String Injection  `INP08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-228 — LDAP Injection  `INP09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-230 — Relative Path Traversal  `INP11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-232 — Dictionary-based Password Attack  `CR03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-238 — Embedding Scripts within Scripts  `SC03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-239 — PHP Remote File Inclusion  `INP16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-242 — XSS Using Alternate Syntax  `SC04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-245 — Removing Important Client Functionality  `SC05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-247 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-250 — Exploiting Trust in Client  `AA04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-254 — XML Attribute Blowup  `INP22`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-255 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-257 — SOAP Array Overflow  `INP34`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-259 — HTTP Request Smuggling  `INP37`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-260 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-265 — Audit Log Manipulation  `DE04`

- **Element:** SpiderFoot scan database (spiderfoot-data volume) (store)
- **Response:** accepted — Outside the manifest chain: scan rows and logs are plain SQLite the sidecar rewrites. The orchestrator reads a scan's events once, at collection, into evidence it then seals, and verifies nothing against this database afterwards, so a later edit here changes no sealed run but misleads whoever reads SpiderFoot's own UI. Hardening: volume permissions and deleting scans after collection.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-266 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-267 — HTTP Request Splitting  `INP04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-276 — Format String Injection  `INP08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-277 — LDAP Injection  `INP09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-279 — Relative Path Traversal  `INP11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-281 — Dictionary-based Password Attack  `CR03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-287 — Embedding Scripts within Scripts  `SC03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-288 — PHP Remote File Inclusion  `INP16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-291 — XSS Using Alternate Syntax  `SC04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-294 — Removing Important Client Functionality  `SC05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-296 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-299 — Exploiting Trust in Client  `AA04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-303 — XML Attribute Blowup  `INP22`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-304 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-306 — SOAP Array Overflow  `INP34`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-308 — HTTP Request Smuggling  `INP37`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-309 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-311 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-312 — HTTP Request Splitting  `INP04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-321 — Format String Injection  `INP08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-322 — LDAP Injection  `INP09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-324 — Relative Path Traversal  `INP11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-326 — Dictionary-based Password Attack  `CR03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-332 — Embedding Scripts within Scripts  `SC03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-333 — PHP Remote File Inclusion  `INP16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-336 — XSS Using Alternate Syntax  `SC04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-339 — Removing Important Client Functionality  `SC05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-341 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-344 — Exploiting Trust in Client  `AA04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-348 — XML Attribute Blowup  `INP22`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-349 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-351 — SOAP Array Overflow  `INP34`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-353 — HTTP Request Smuggling  `INP37`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-354 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-359 — Audit Log Manipulation  `DE04`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — The cache is outside the manifest chain: profiles and posts under /app/data are plain files the sidecar rewrites at will, with no signature or audit log, and the orchestrator only ever reads the sidecar's report, so an edit there is invisible to it. Hardening: an ephemeral or read-only volume and file permissions.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-360 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-361 — HTTP Request Splitting  `INP04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-370 — Format String Injection  `INP08`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-371 — LDAP Injection  `INP09`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-373 — Relative Path Traversal  `INP11`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-375 — Dictionary-based Password Attack  `CR03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-381 — Embedding Scripts within Scripts  `SC03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-382 — PHP Remote File Inclusion  `INP16`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-385 — XSS Using Alternate Syntax  `SC04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-388 — Removing Important Client Functionality  `SC05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-390 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-393 — Exploiting Trust in Client  `AA04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-397 — XML Attribute Blowup  `INP22`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-398 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-400 — SOAP Array Overflow  `INP34`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-402 — HTTP Request Smuggling  `INP37`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-403 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-405 — Direct Prompt Injection  `LLM01`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-406 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-407 — Sensitive Information Disclosure Through Output  `LLM08`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted.
- **pytm mitigations:** Implement output filtering to detect and redact sensitive data patterns (PII, credentials, etc.). Use output encoding appropriate to the consumption context. Apply data loss prevention (DLP) controls on LLM outputs. Minimize the amount of sensitive data in the LLM's context.

#### F-408 — Server Side Include (SSI) Injection  `INP03`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-416 — Format String Injection  `INP08`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-417 — LDAP Injection  `INP09`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-419 — Relative Path Traversal  `INP11`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-421 — Dictionary-based Password Attack  `CR03`

- **Element:** MISP (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-427 — Embedding Scripts within Scripts  `SC03`

- **Element:** MISP (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-428 — PHP Remote File Inclusion  `INP16`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-430 — XSS Using Alternate Syntax  `SC04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-433 — Removing Important Client Functionality  `SC05`

- **Element:** MISP (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-435 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MISP (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-438 — Exploiting Trust in Client  `AA04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-442 — XML Attribute Blowup  `INP22`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-443 — XSS Targeting URI Placeholders  `INP28`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-445 — SOAP Array Overflow  `INP34`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-447 — HTTP Request Smuggling  `INP37`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-448 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MISP (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-453 — Audit Log Manipulation  `DE04`

- **Element:** MISP backing stores (MariaDB, Redis) (vendor)
- **Response:** transferred — The platform's own audit trail (OpenCTI, Keycloak events, MISP logs) lives in its backing stores and is the platform's.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-454 — Server Side Include (SSI) Injection  `INP03`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-462 — Format String Injection  `INP08`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-463 — LDAP Injection  `INP09`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-465 — Relative Path Traversal  `INP11`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-467 — Dictionary-based Password Attack  `CR03`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-472 — Embedding Scripts within Scripts  `SC03`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-473 — PHP Remote File Inclusion  `INP16`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-475 — XSS Using Alternate Syntax  `SC04`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-477 — Removing Important Client Functionality  `SC05`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-479 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-482 — Exploiting Trust in Client  `AA04`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-486 — XML Attribute Blowup  `INP22`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-487 — XSS Targeting URI Placeholders  `INP28`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-489 — SOAP Array Overflow  `INP34`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-491 — HTTP Request Smuggling  `INP37`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-492 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-494 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-503 — Format String Injection  `INP08`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-504 — LDAP Injection  `INP09`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-506 — Relative Path Traversal  `INP11`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-508 — Dictionary-based Password Attack  `CR03`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-514 — Embedding Scripts within Scripts  `SC03`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-515 — PHP Remote File Inclusion  `INP16`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-518 — XSS Using Alternate Syntax  `SC04`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-521 — Removing Important Client Functionality  `SC05`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-523 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Redis (MISP) (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-526 — Exploiting Trust in Client  `AA04`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-530 — XML Attribute Blowup  `INP22`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-531 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-533 — SOAP Array Overflow  `INP34`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-535 — HTTP Request Smuggling  `INP37`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-536 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-538 — Server Side Include (SSI) Injection  `INP03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-539 — Session Sidejacking  `CR01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-540 — HTTP Request Splitting  `INP04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-550 — Format String Injection  `INP08`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-551 — LDAP Injection  `INP09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-553 — Relative Path Traversal  `INP11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-559 — Embedding Scripts within Scripts  `SC03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-560 — PHP Remote File Inclusion  `INP16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-564 — XSS Using Alternate Syntax  `SC04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-566 — Removing Important Client Functionality  `SC05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-568 — Exploitation of Trusted Credentials  `AA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-571 — Exploiting Trust in Client  `AA04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-575 — XML Attribute Blowup  `INP22`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-576 — XSS Targeting URI Placeholders  `INP28`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-578 — SOAP Array Overflow  `INP34`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-580 — HTTP Request Smuggling  `INP37`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-581 — Session Credential Falsification through Prediction  `AC16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-583 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-584 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-585 — HTTP Request Splitting  `INP04`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-594 — Format String Injection  `INP08`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-595 — LDAP Injection  `INP09`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-597 — Relative Path Traversal  `INP11`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-599 — Dictionary-based Password Attack  `CR03`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-605 — Embedding Scripts within Scripts  `SC03`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-606 — PHP Remote File Inclusion  `INP16`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-609 — XSS Using Alternate Syntax  `SC04`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-612 — Removing Important Client Functionality  `SC05`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-614 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Elasticsearch (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-617 — Exploiting Trust in Client  `AA04`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-621 — XML Attribute Blowup  `INP22`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-622 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-624 — SOAP Array Overflow  `INP34`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-626 — HTTP Request Smuggling  `INP37`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-627 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-629 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-638 — Format String Injection  `INP08`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-639 — LDAP Injection  `INP09`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-641 — Relative Path Traversal  `INP11`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-643 — Dictionary-based Password Attack  `CR03`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-649 — Embedding Scripts within Scripts  `SC03`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-650 — PHP Remote File Inclusion  `INP16`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-653 — XSS Using Alternate Syntax  `SC04`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-656 — Removing Important Client Functionality  `SC05`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-658 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-661 — Exploiting Trust in Client  `AA04`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-665 — XML Attribute Blowup  `INP22`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-666 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-668 — SOAP Array Overflow  `INP34`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-670 — HTTP Request Smuggling  `INP37`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-671 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-673 — Server Side Include (SSI) Injection  `INP03`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-674 — HTTP Request Splitting  `INP04`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-682 — Format String Injection  `INP08`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-683 — LDAP Injection  `INP09`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-685 — Relative Path Traversal  `INP11`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-687 — Dictionary-based Password Attack  `CR03`

- **Element:** MinIO (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-692 — Embedding Scripts within Scripts  `SC03`

- **Element:** MinIO (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-693 — PHP Remote File Inclusion  `INP16`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-695 — XSS Using Alternate Syntax  `SC04`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-697 — Removing Important Client Functionality  `SC05`

- **Element:** MinIO (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-699 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MinIO (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-702 — Exploiting Trust in Client  `AA04`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-706 — XML Attribute Blowup  `INP22`

- **Element:** MinIO (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-707 — XSS Targeting URI Placeholders  `INP28`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-709 — SOAP Array Overflow  `INP34`

- **Element:** MinIO (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-711 — HTTP Request Smuggling  `INP37`

- **Element:** MinIO (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-712 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MinIO (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-714 — Server Side Include (SSI) Injection  `INP03`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-722 — Format String Injection  `INP08`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-723 — LDAP Injection  `INP09`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-725 — Relative Path Traversal  `INP11`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-727 — Dictionary-based Password Attack  `CR03`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-732 — Embedding Scripts within Scripts  `SC03`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-733 — PHP Remote File Inclusion  `INP16`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-735 — XSS Using Alternate Syntax  `SC04`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-737 — Removing Important Client Functionality  `SC05`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-739 — Exploitation of Trusted Credentials  `AA03`

- **Element:** RabbitMQ (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-742 — Exploiting Trust in Client  `AA04`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-746 — XML Attribute Blowup  `INP22`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-747 — XSS Targeting URI Placeholders  `INP28`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-749 — SOAP Array Overflow  `INP34`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-751 — HTTP Request Smuggling  `INP37`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-752 — Session Credential Falsification through Prediction  `AC16`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-758 — Audit Log Manipulation  `DE04`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — The platform's own audit trail (OpenCTI, Keycloak events, MISP logs) lives in its backing stores and is the platform's.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-766 — Format String Injection  `INP08`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-767 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-768 — Command Delimiters  `INP13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-770 — Dictionary-based Password Attack  `CR03`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-772 — iFrame Overlay  `INP20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-774 — Privilege Escalation  `AC12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-777 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-778 — Resource Injection  `INP25`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-779 — Code Injection  `INP26`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-781 — XSS Targeting URI Placeholders  `INP28`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-784 — Command Injection  `INP31`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-785 — XML Injection  `INP32`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-786 — Remote Code Inclusion  `INP33`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-787 — Leverage Alternate Encoding  `INP35`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-788 — Schema Poisoning  `AC15`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-790 — Argument Injection  `INP41`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-791 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-793 — Session Sidejacking  `CR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and of Keycloak's browser endpoint (KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name) and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-798 — Communication Channel Manipulation  `CR06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-801 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-802 — Credentials Disclosure  `AC23`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-803 — Session Sidejacking  `CR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and of Keycloak's browser endpoint (KC_HOSTNAME and OIDC_BROWSER_LOGIN_URL on the https:// name) and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-808 — Communication Channel Manipulation  `CR06`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-810 — Unprotected Sensitive Data  `DR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-811 — Credentials Disclosure  `AC23`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-815 — Communication Channel Manipulation  `CR06`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-817 — Unprotected Sensitive Data  `DR01`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-818 — Credentials Disclosure  `AC23`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-822 — Communication Channel Manipulation  `CR06`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-824 — Unprotected Sensitive Data  `DR01`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-825 — Credentials Disclosure  `AC23`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-829 — Communication Channel Manipulation  `CR06`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-831 — Unprotected Sensitive Data  `DR01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-832 — Credentials Disclosure  `AC23`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-836 — Communication Channel Manipulation  `CR06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-839 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-840 — Credentials Disclosure  `AC23`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-844 — Communication Channel Manipulation  `CR06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-847 — Unprotected Sensitive Data  `DR01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-848 — Credentials Disclosure  `AC23`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-852 — Communication Channel Manipulation  `CR06`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-855 — Unprotected Sensitive Data  `DR01`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-859 — Communication Channel Manipulation  `CR06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-862 — Unprotected Sensitive Data  `DR01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-863 — Credentials Disclosure  `AC23`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-867 — Communication Channel Manipulation  `CR06`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-872 — Communication Channel Manipulation  `CR06`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-877 — Communication Channel Manipulation  `CR06`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-882 — Communication Channel Manipulation  `CR06`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-887 — Communication Channel Manipulation  `CR06`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-892 — Communication Channel Manipulation  `CR06`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-894 — Credentials Disclosure  `AC23`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-898 — Communication Channel Manipulation  `CR06`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-901 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-905 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-910 — Communication Channel Manipulation  `CR06`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-911 — Credentials Disclosure  `AC23`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-915 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-916 — Credentials Disclosure  `AC23`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-920 — Communication Channel Manipulation  `CR06`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-922 — Unprotected Sensitive Data  `DR01`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-926 — Communication Channel Manipulation  `CR06`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-928 — Unprotected Sensitive Data  `DR01`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-932 — Communication Channel Manipulation  `CR06`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-933 — Credentials Disclosure  `AC23`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-937 — Communication Channel Manipulation  `CR06`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-940 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-944 — Communication Channel Manipulation  `CR06`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-949 — Communication Channel Manipulation  `CR06`

- **Element:** Write scan results and logs (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-954 — Communication Channel Manipulation  `CR06`

- **Element:** Read scan results for the API (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-959 — Communication Channel Manipulation  `CR06`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-962 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-966 — Communication Channel Manipulation  `CR06`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-971 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-976 — Communication Channel Manipulation  `CR06`

- **Element:** Local model inference (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-981 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-982 — Credentials Disclosure  `AC23`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-986 — Communication Channel Manipulation  `CR06`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-991 — Communication Channel Manipulation  `CR06`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-996 — Communication Channel Manipulation  `CR06`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1001 — Communication Channel Manipulation  `CR06`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1003 — Unprotected Sensitive Data  `DR01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-1004 — Credentials Disclosure  `AC23`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1008 — Communication Channel Manipulation  `CR06`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1013 — Communication Channel Manipulation  `CR06`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1015 — Unprotected Sensitive Data  `DR01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-1016 — Credentials Disclosure  `AC23`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1020 — Communication Channel Manipulation  `CR06`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1022 — Unprotected Sensitive Data  `DR01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-1023 — Credentials Disclosure  `AC23`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1027 — Communication Channel Manipulation  `CR06`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1032 — Communication Channel Manipulation  `CR06`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1034 — Unprotected Sensitive Data  `DR01`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-1035 — Credentials Disclosure  `AC23`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1039 — Communication Channel Manipulation  `CR06`

- **Element:** MISP cache and queues (Redis, no password) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1044 — Communication Channel Manipulation  `CR06`

- **Element:** Elasticsearch persists its indices (volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1049 — Communication Channel Manipulation  `CR06`

- **Element:** MinIO persists objects (volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1054 — Communication Channel Manipulation  `CR06`

- **Element:** RabbitMQ persists queues (volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1059 — Communication Channel Manipulation  `CR06`

- **Element:** Redis persists its snapshot (volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1064 — Communication Channel Manipulation  `CR06`

- **Element:** MariaDB persists on misp-db-data (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1069 — Communication Channel Manipulation  `CR06`

- **Element:** Redis persists on misp-redis-data (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1074 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1075 — Credentials Disclosure  `AC23`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1079 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1081 — Unprotected Sensitive Data  `DR01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SpiderFoot scan database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-1082 — Credentials Disclosure  `AC23`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1086 — Communication Channel Manipulation  `CR06`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1087 — Credentials Disclosure  `AC23`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-1091 — Communication Channel Manipulation  `CR06`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-1092 — Credentials Disclosure  `AC23`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000, :8002 and Keycloak's browser endpoint, and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

### Severity: Medium (514)

#### F-7 — Excavation  `DS01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-8 — Double Encoding  `DE02`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-9 — Privilege Abuse  `AC01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-10 — Flooding  `DO01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-12 — Excessive Allocation  `DO02`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-15 — Parameter Injection  `INP10`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-17 — Input Data Manipulation  `INP14`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-23 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-26 — XSS Targeting Error Pages  `DS04`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-29 — Manipulate Registry Information  `AC08`

- **Element:** Tavily search API (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-31 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-33 — Functionality Misuse  `AC09`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-36 — XML External Entities Blowup  `INP19`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-37 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-38 — DTD Injection  `INP21`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-41 — XSS Using Doubled Characters  `INP29`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-43 — HTTP Response Smuggling  `INP36`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-53 — Excavation  `DS01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-54 — Double Encoding  `DE02`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-55 — Privilege Abuse  `AC01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-56 — Flooding  `DO01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-58 — Excessive Allocation  `DO02`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-61 — Parameter Injection  `INP10`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-63 — Input Data Manipulation  `INP14`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-69 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-70 — IMAP/SMTP Command Injection  `INP15`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — SMTP command handling is the relay's. The orchestrator talks to it through smtplib with the configured host, port and credentials, and the message is a MIMEText whose headers the email package encodes; collected text only ever lands in the body as message data, never in an SMTP command.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary. Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter. Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-73 — XSS Targeting Error Pages  `DS04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-76 — Manipulate Registry Information  `AC08`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-78 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-80 — Functionality Misuse  `AC09`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-83 — XML External Entities Blowup  `INP19`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-84 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-85 — DTD Injection  `INP21`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-88 — XSS Using Doubled Characters  `INP29`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-90 — HTTP Response Smuggling  `INP36`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-95 — Authentication Abuse/ByPass  `AA01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-96 — Double Encoding  `DE02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-97 — Privilege Abuse  `AC01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-99 — Flooding  `DO01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-100 — Excessive Allocation  `DO02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-104 — Input Data Manipulation  `INP14`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-105 — Principal Spoof  `AA02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-109 — Hijacking a privileged process  `AC13`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-114 — XSS Targeting HTML Attributes  `INP27`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-116 — XSS Using Doubled Characters  `INP29`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-117 — XSS Using Invalid Characters  `INP30`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-131 — Authentication Abuse/ByPass  `AA01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-132 — Excavation  `DS01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-133 — Double Encoding  `DE02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-134 — Privilege Abuse  `AC01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-135 — Flooding  `DO01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-137 — Excessive Allocation  `DO02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-140 — Parameter Injection  `INP10`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-142 — Input Data Manipulation  `INP14`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-147 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-150 — Principal Spoof  `AA02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-151 — Session Credential Falsification through Forging  `CR04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-152 — XSS Targeting Error Pages  `DS04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-155 — Manipulate Registry Information  `AC08`

- **Element:** Keycloak (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-157 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Keycloak (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-159 — Functionality Misuse  `AC09`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-162 — XML External Entities Blowup  `INP19`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-163 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-164 — DTD Injection  `INP21`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-167 — XSS Using Doubled Characters  `INP29`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-169 — HTTP Response Smuggling  `INP36`

- **Element:** Keycloak (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-174 — Privilege Abuse  `AC01`

- **Element:** Keycloak data volume (keycloak-data) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-175 — Excessive Allocation  `DO02`

- **Element:** Keycloak data volume (keycloak-data) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-179 — Authentication Abuse/ByPass  `AA01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-181 — Flooding  `DO01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-182 — Excessive Allocation  `DO02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-183 — Principal Spoof  `AA02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-185 — Hijacking a privileged process  `AC13`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-191 — Authentication Abuse/ByPass  `AA01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-192 — Flooding  `DO01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-193 — Excessive Allocation  `DO02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-194 — Principal Spoof  `AA02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-196 — Hijacking a privileged process  `AC13`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-200 — Privilege Abuse  `AC01`

- **Element:** SQLite run store (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-201 — Excessive Allocation  `DO02`

- **Element:** SQLite run store (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-204 — Privilege Abuse  `AC01`

- **Element:** targets.yaml (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-205 — Excessive Allocation  `DO02`

- **Element:** targets.yaml (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-208 — Privilege Abuse  `AC01`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-209 — Excessive Allocation  `DO02`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-212 — Privilege Abuse  `AC01`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-213 — Shared Data Manipulation  `AC02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — The Amass asset database is shared between the engine and the orchestrator on one volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-214 — Excessive Allocation  `DO02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-220 — Authentication Abuse/ByPass  `AA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-221 — Excavation  `DS01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-222 — Double Encoding  `DE02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-223 — Privilege Abuse  `AC01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-224 — Flooding  `DO01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-226 — Excessive Allocation  `DO02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-229 — Parameter Injection  `INP10`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-231 — Input Data Manipulation  `INP14`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-237 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-240 — Principal Spoof  `AA02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-241 — XSS Targeting Error Pages  `DS04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-244 — Manipulate Registry Information  `AC08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-246 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-248 — Functionality Misuse  `AC09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-251 — XML External Entities Blowup  `INP19`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-252 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-253 — DTD Injection  `INP21`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-256 — XSS Using Doubled Characters  `INP29`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-258 — HTTP Response Smuggling  `INP36`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-262 — Privilege Abuse  `AC01`

- **Element:** SpiderFoot scan database (spiderfoot-data volume) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-263 — Excessive Allocation  `DO02`

- **Element:** SpiderFoot scan database (spiderfoot-data volume) (store)
- **Response:** accepted — No retention: completed scans stay in the database (the collector stops only the scans it abandons) and purge_expired cleans run rows and daily_reports only, so the volume grows with every run. Hardening: delete each scan after collection or run a purge job, and put a disk quota on the volume.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-269 — Authentication Abuse/ByPass  `AA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-270 — Excavation  `DS01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-271 — Double Encoding  `DE02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-272 — Privilege Abuse  `AC01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-273 — Flooding  `DO01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-275 — Excessive Allocation  `DO02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-278 — Parameter Injection  `INP10`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-280 — Input Data Manipulation  `INP14`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-286 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-289 — Principal Spoof  `AA02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-290 — XSS Targeting Error Pages  `DS04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-293 — Manipulate Registry Information  `AC08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-295 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-297 — Functionality Misuse  `AC09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-300 — XML External Entities Blowup  `INP19`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-301 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-302 — DTD Injection  `INP21`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-305 — XSS Using Doubled Characters  `INP29`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-307 — HTTP Response Smuggling  `INP36`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-314 — Authentication Abuse/ByPass  `AA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-315 — Excavation  `DS01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-316 — Double Encoding  `DE02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-317 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-318 — Flooding  `DO01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-320 — Excessive Allocation  `DO02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-323 — Parameter Injection  `INP10`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-325 — Input Data Manipulation  `INP14`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-331 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-334 — Principal Spoof  `AA02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-335 — XSS Targeting Error Pages  `DS04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-338 — Manipulate Registry Information  `AC08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-340 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-342 — Functionality Misuse  `AC09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-345 — XML External Entities Blowup  `INP19`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-346 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-347 — DTD Injection  `INP21`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-350 — XSS Using Doubled Characters  `INP29`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-352 — HTTP Response Smuggling  `INP36`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-356 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, SpiderFoot and the SocialOSINT sidecar for their own volumes); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-357 — Excessive Allocation  `DO02`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — No retention reaches this volume: the sidecar's CacheManager keeps profiles and posts under /app/data until the operator removes the volume or prunes it, and deleting a session removes only the session file. The orchestrator keeps nothing of it beyond the unverified note. Hardening: an ephemeral (tmpfs) volume or a purge job for /app/data, sized to the retention the operator owes the people in those profiles.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-363 — Authentication Abuse/ByPass  `AA01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-364 — Excavation  `DS01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-365 — Double Encoding  `DE02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-366 — Privilege Abuse  `AC01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-367 — Flooding  `DO01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-369 — Excessive Allocation  `DO02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-372 — Parameter Injection  `INP10`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-374 — Input Data Manipulation  `INP14`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-380 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-383 — Principal Spoof  `AA02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-384 — XSS Targeting Error Pages  `DS04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-387 — Manipulate Registry Information  `AC08`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-389 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-391 — Functionality Misuse  `AC09`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-394 — XML External Entities Blowup  `INP19`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-395 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-396 — DTD Injection  `INP21`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-399 — XSS Using Doubled Characters  `INP29`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-401 — HTTP Response Smuggling  `INP36`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-410 — Excavation  `DS01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-411 — Double Encoding  `DE02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-412 — Privilege Abuse  `AC01`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-413 — Flooding  `DO01`

- **Element:** MISP (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-415 — Excessive Allocation  `DO02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-418 — Parameter Injection  `INP10`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-420 — Input Data Manipulation  `INP14`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-426 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-429 — XSS Targeting Error Pages  `DS04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-432 — Manipulate Registry Information  `AC08`

- **Element:** MISP (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-434 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MISP (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-436 — Functionality Misuse  `AC09`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-439 — XML External Entities Blowup  `INP19`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-440 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-441 — DTD Injection  `INP21`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-444 — XSS Using Doubled Characters  `INP29`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-446 — HTTP Response Smuggling  `INP36`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-450 — Privilege Abuse  `AC01`

- **Element:** MISP backing stores (MariaDB, Redis) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-451 — Excessive Allocation  `DO02`

- **Element:** MISP backing stores (MariaDB, Redis) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-456 — Excavation  `DS01`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-457 — Double Encoding  `DE02`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-458 — Privilege Abuse  `AC01`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-459 — Flooding  `DO01`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-461 — Excessive Allocation  `DO02`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-464 — Parameter Injection  `INP10`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-466 — Input Data Manipulation  `INP14`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-474 — XSS Targeting Error Pages  `DS04`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-478 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-480 — Functionality Misuse  `AC09`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-483 — XML External Entities Blowup  `INP19`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-484 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-485 — DTD Injection  `INP21`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-488 — XSS Using Doubled Characters  `INP29`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-490 — HTTP Response Smuggling  `INP36`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-496 — Authentication Abuse/ByPass  `AA01`

- **Element:** Redis (MISP) (vendor)
- **Response:** accepted — Runs without authentication by the compose file's decision (xpack.security.enabled=false for Elasticsearch, no requirepass for Redis): reachable only on the compose network, never published on the host, and only its own platform talks to it (ADR-005). Hardening for shared hosts: enable the service's authentication (xpack security, requirepass) and TLS, or network policies that pin each backing service to its platform.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-497 — Excavation  `DS01`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-498 — Double Encoding  `DE02`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-499 — Privilege Abuse  `AC01`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-500 — Flooding  `DO01`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-502 — Excessive Allocation  `DO02`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-505 — Parameter Injection  `INP10`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-507 — Input Data Manipulation  `INP14`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-513 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-516 — Principal Spoof  `AA02`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-517 — XSS Targeting Error Pages  `DS04`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-520 — Manipulate Registry Information  `AC08`

- **Element:** Redis (MISP) (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-522 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-524 — Functionality Misuse  `AC09`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-527 — XML External Entities Blowup  `INP19`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-528 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-529 — DTD Injection  `INP21`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-532 — XSS Using Doubled Characters  `INP29`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-534 — HTTP Response Smuggling  `INP36`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-543 — Authentication Abuse/ByPass  `AA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-544 — Excavation  `DS01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-545 — Double Encoding  `DE02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-546 — Privilege Abuse  `AC01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-547 — Flooding  `DO01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-549 — Excessive Allocation  `DO02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-552 — Parameter Injection  `INP10`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-554 — Input Data Manipulation  `INP14`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-561 — Principal Spoof  `AA02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-562 — Session Credential Falsification through Forging  `CR04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-563 — XSS Targeting Error Pages  `DS04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-567 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-569 — Functionality Misuse  `AC09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-572 — XML External Entities Blowup  `INP19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-573 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-574 — DTD Injection  `INP21`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-577 — XSS Using Doubled Characters  `INP29`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-579 — HTTP Response Smuggling  `INP36`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-587 — Authentication Abuse/ByPass  `AA01`

- **Element:** Elasticsearch (vendor)
- **Response:** accepted — Runs without authentication by the compose file's decision (xpack.security.enabled=false for Elasticsearch, no requirepass for Redis): reachable only on the compose network, never published on the host, and only its own platform talks to it (ADR-005). Hardening for shared hosts: enable the service's authentication (xpack security, requirepass) and TLS, or network policies that pin each backing service to its platform.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-588 — Excavation  `DS01`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-589 — Double Encoding  `DE02`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-590 — Privilege Abuse  `AC01`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-591 — Flooding  `DO01`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-593 — Excessive Allocation  `DO02`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-596 — Parameter Injection  `INP10`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-598 — Input Data Manipulation  `INP14`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-604 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-607 — Principal Spoof  `AA02`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-608 — XSS Targeting Error Pages  `DS04`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-611 — Manipulate Registry Information  `AC08`

- **Element:** Elasticsearch (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-613 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-615 — Functionality Misuse  `AC09`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-618 — XML External Entities Blowup  `INP19`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-619 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-620 — DTD Injection  `INP21`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-623 — XSS Using Doubled Characters  `INP29`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-625 — HTTP Response Smuggling  `INP36`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-631 — Authentication Abuse/ByPass  `AA01`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** accepted — Runs without authentication by the compose file's decision (xpack.security.enabled=false for Elasticsearch, no requirepass for Redis): reachable only on the compose network, never published on the host, and only its own platform talks to it (ADR-005). Hardening for shared hosts: enable the service's authentication (xpack security, requirepass) and TLS, or network policies that pin each backing service to its platform.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-632 — Excavation  `DS01`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-633 — Double Encoding  `DE02`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-634 — Privilege Abuse  `AC01`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-635 — Flooding  `DO01`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-637 — Excessive Allocation  `DO02`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-640 — Parameter Injection  `INP10`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-642 — Input Data Manipulation  `INP14`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-648 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-651 — Principal Spoof  `AA02`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-652 — XSS Targeting Error Pages  `DS04`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-655 — Manipulate Registry Information  `AC08`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-657 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-659 — Functionality Misuse  `AC09`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-662 — XML External Entities Blowup  `INP19`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-663 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-664 — DTD Injection  `INP21`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-667 — XSS Using Doubled Characters  `INP29`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-669 — HTTP Response Smuggling  `INP36`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-676 — Excavation  `DS01`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-677 — Double Encoding  `DE02`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-678 — Privilege Abuse  `AC01`

- **Element:** MinIO (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-679 — Flooding  `DO01`

- **Element:** MinIO (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-681 — Excessive Allocation  `DO02`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-684 — Parameter Injection  `INP10`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-686 — Input Data Manipulation  `INP14`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-694 — XSS Targeting Error Pages  `DS04`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-698 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MinIO (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-700 — Functionality Misuse  `AC09`

- **Element:** MinIO (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-703 — XML External Entities Blowup  `INP19`

- **Element:** MinIO (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-704 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MinIO (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-705 — DTD Injection  `INP21`

- **Element:** MinIO (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-708 — XSS Using Doubled Characters  `INP29`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-710 — HTTP Response Smuggling  `INP36`

- **Element:** MinIO (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-716 — Excavation  `DS01`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-717 — Double Encoding  `DE02`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-718 — Privilege Abuse  `AC01`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-719 — Flooding  `DO01`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-721 — Excessive Allocation  `DO02`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-724 — Parameter Injection  `INP10`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-726 — Input Data Manipulation  `INP14`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-734 — XSS Targeting Error Pages  `DS04`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-738 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-740 — Functionality Misuse  `AC09`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-743 — XML External Entities Blowup  `INP19`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-744 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-745 — DTD Injection  `INP21`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-748 — XSS Using Doubled Characters  `INP29`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-750 — HTTP Response Smuggling  `INP36`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-754 — Privilege Abuse  `AC01`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-755 — Shared Data Manipulation  `AC02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and hardened by the OpenCTI platform deployment.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-756 — Excessive Allocation  `DO02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-760 — Authentication Abuse/ByPass  `AA01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-761 — Double Encoding  `DE02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-762 — Privilege Abuse  `AC01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-764 — Flooding  `DO01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-765 — Excessive Allocation  `DO02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-769 — Input Data Manipulation  `INP14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-771 — Principal Spoof  `AA02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy, connector-misp and the credentialed backing services (MinIO, RabbitMQ, MariaDB) are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-775 — Hijacking a privileged process  `AC13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-780 — XSS Targeting HTML Attributes  `INP27`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-782 — XSS Using Doubled Characters  `INP29`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-783 — XSS Using Invalid Characters  `INP30`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-795 — Interception  `DE01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-796 — Content Spoofing  `AC05`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-797 — Sniffing Attacks  `DE03`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-799 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-805 — Interception  `DE01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-806 — Content Spoofing  `AC05`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-807 — Sniffing Attacks  `DE03`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-809 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-812 — Interception  `DE01`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-813 — Content Spoofing  `AC05`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-814 — Sniffing Attacks  `DE03`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-816 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Persist realm users, client secret and sessions (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-819 — Interception  `DE01`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-820 — Content Spoofing  `AC05`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-821 — Sniffing Attacks  `DE03`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-823 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read realm, users and sessions (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-826 — Interception  `DE01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-827 — Content Spoofing  `AC05`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-828 — Sniffing Attacks  `DE03`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-830 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-833 — Interception  `DE01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-834 — Content Spoofing  `AC05`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-835 — Sniffing Attacks  `DE03`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-837 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-841 — Interception  `DE01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-842 — Content Spoofing  `AC05`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-843 — Sniffing Attacks  `DE03`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-845 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-849 — Interception  `DE01`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-850 — Content Spoofing  `AC05`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-851 — Sniffing Attacks  `DE03`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-853 — Client-Server Protocol Manipulation  `CR08`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-856 — Interception  `DE01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-857 — Content Spoofing  `AC05`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-858 — Sniffing Attacks  `DE03`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-860 — Client-Server Protocol Manipulation  `CR08`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-864 — Interception  `DE01`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-865 — Content Spoofing  `AC05`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-866 — Sniffing Attacks  `DE03`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-868 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-869 — Interception  `DE01`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-870 — Content Spoofing  `AC05`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-871 — Sniffing Attacks  `DE03`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-873 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Scan control & results (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-874 — Interception  `DE01`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-875 — Content Spoofing  `AC05`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-876 — Sniffing Attacks  `DE03`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-878 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-879 — Interception  `DE01`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-880 — Content Spoofing  `AC05`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-881 — Sniffing Attacks  `DE03`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-883 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-884 — Interception  `DE01`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-885 — Content Spoofing  `AC05`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-886 — Sniffing Attacks  `DE03`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-888 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-889 — Interception  `DE01`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-890 — Content Spoofing  `AC05`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-891 — Sniffing Attacks  `DE03`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-895 — Interception  `DE01`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-896 — Content Spoofing  `AC05`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-897 — Sniffing Attacks  `DE03`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-899 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-902 — Interception  `DE01`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-903 — Content Spoofing  `AC05`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-904 — Sniffing Attacks  `DE03`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-906 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-907 — Interception  `DE01`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-908 — Content Spoofing  `AC05`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-909 — Sniffing Attacks  `DE03`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-912 — Interception  `DE01`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-913 — Content Spoofing  `AC05`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-914 — Sniffing Attacks  `DE03`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-917 — Interception  `DE01`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-918 — Content Spoofing  `AC05`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-919 — Sniffing Attacks  `DE03`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-921 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-923 — Interception  `DE01`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-924 — Content Spoofing  `AC05`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-925 — Sniffing Attacks  `DE03`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-927 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-929 — Interception  `DE01`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-930 — Content Spoofing  `AC05`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-931 — Sniffing Attacks  `DE03`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-934 — Interception  `DE01`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-935 — Content Spoofing  `AC05`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-936 — Sniffing Attacks  `DE03`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-938 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-941 — Interception  `DE01`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-942 — Content Spoofing  `AC05`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-943 — Sniffing Attacks  `DE03`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-946 — Interception  `DE01`

- **Element:** Write scan results and logs (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-947 — Content Spoofing  `AC05`

- **Element:** Write scan results and logs (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-948 — Sniffing Attacks  `DE03`

- **Element:** Write scan results and logs (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-950 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Write scan results and logs (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-951 — Interception  `DE01`

- **Element:** Read scan results for the API (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-952 — Content Spoofing  `AC05`

- **Element:** Read scan results for the API (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-953 — Sniffing Attacks  `DE03`

- **Element:** Read scan results for the API (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-955 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read scan results for the API (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-956 — Interception  `DE01`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-957 — Content Spoofing  `AC05`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-958 — Sniffing Attacks  `DE03`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-960 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-963 — Interception  `DE01`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-964 — Content Spoofing  `AC05`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-965 — Sniffing Attacks  `DE03`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-968 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-969 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-970 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-972 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-973 — Interception  `DE01`

- **Element:** Local model inference (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-974 — Content Spoofing  `AC05`

- **Element:** Local model inference (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-975 — Sniffing Attacks  `DE03`

- **Element:** Local model inference (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-977 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Local model inference (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-978 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-979 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-980 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-983 — Interception  `DE01`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-984 — Content Spoofing  `AC05`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-985 — Sniffing Attacks  `DE03`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-987 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-988 — Interception  `DE01`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-989 — Content Spoofing  `AC05`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-990 — Sniffing Attacks  `DE03`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-992 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-993 — Interception  `DE01`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-994 — Content Spoofing  `AC05`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-995 — Sniffing Attacks  `DE03`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-997 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read target inventory (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-998 — Interception  `DE01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-999 — Content Spoofing  `AC05`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1000 — Sniffing Attacks  `DE03`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1002 — Client-Server Protocol Manipulation  `CR08`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1005 — Interception  `DE01`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1006 — Content Spoofing  `AC05`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1007 — Sniffing Attacks  `DE03`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1009 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1010 — Interception  `DE01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1011 — Content Spoofing  `AC05`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1012 — Sniffing Attacks  `DE03`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1014 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MinIO objects (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1017 — Interception  `DE01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1018 — Content Spoofing  `AC05`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1019 — Sniffing Attacks  `DE03`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1021 — Client-Server Protocol Manipulation  `CR08`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1024 — Interception  `DE01`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1025 — Content Spoofing  `AC05`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1026 — Sniffing Attacks  `DE03`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1028 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1029 — Interception  `DE01`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1030 — Content Spoofing  `AC05`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1031 — Sniffing Attacks  `DE03`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1033 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MISP database (MySQL, compose-internal) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1036 — Interception  `DE01`

- **Element:** MISP cache and queues (Redis, no password) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1037 — Content Spoofing  `AC05`

- **Element:** MISP cache and queues (Redis, no password) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1038 — Sniffing Attacks  `DE03`

- **Element:** MISP cache and queues (Redis, no password) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1040 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MISP cache and queues (Redis, no password) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1041 — Interception  `DE01`

- **Element:** Elasticsearch persists its indices (volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1042 — Content Spoofing  `AC05`

- **Element:** Elasticsearch persists its indices (volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1043 — Sniffing Attacks  `DE03`

- **Element:** Elasticsearch persists its indices (volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1045 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Elasticsearch persists its indices (volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1046 — Interception  `DE01`

- **Element:** MinIO persists objects (volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1047 — Content Spoofing  `AC05`

- **Element:** MinIO persists objects (volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1048 — Sniffing Attacks  `DE03`

- **Element:** MinIO persists objects (volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1050 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MinIO persists objects (volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1051 — Interception  `DE01`

- **Element:** RabbitMQ persists queues (volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1052 — Content Spoofing  `AC05`

- **Element:** RabbitMQ persists queues (volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1053 — Sniffing Attacks  `DE03`

- **Element:** RabbitMQ persists queues (volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1055 — Client-Server Protocol Manipulation  `CR08`

- **Element:** RabbitMQ persists queues (volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1056 — Interception  `DE01`

- **Element:** Redis persists its snapshot (volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1057 — Content Spoofing  `AC05`

- **Element:** Redis persists its snapshot (volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1058 — Sniffing Attacks  `DE03`

- **Element:** Redis persists its snapshot (volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1060 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Redis persists its snapshot (volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1061 — Interception  `DE01`

- **Element:** MariaDB persists on misp-db-data (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1062 — Content Spoofing  `AC05`

- **Element:** MariaDB persists on misp-db-data (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1063 — Sniffing Attacks  `DE03`

- **Element:** MariaDB persists on misp-db-data (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1065 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MariaDB persists on misp-db-data (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1066 — Interception  `DE01`

- **Element:** Redis persists on misp-redis-data (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1067 — Content Spoofing  `AC05`

- **Element:** Redis persists on misp-redis-data (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1068 — Sniffing Attacks  `DE03`

- **Element:** Redis persists on misp-redis-data (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1070 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Redis persists on misp-redis-data (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1071 — Interception  `DE01`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1072 — Content Spoofing  `AC05`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1073 — Sniffing Attacks  `DE03`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1076 — Interception  `DE01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1077 — Content Spoofing  `AC05`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1078 — Sniffing Attacks  `DE03`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1080 — Client-Server Protocol Manipulation  `CR08`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-1083 — Interception  `DE01`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1084 — Content Spoofing  `AC05`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1085 — Sniffing Attacks  `DE03`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-1088 — Interception  `DE01`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-1089 — Content Spoofing  `AC05`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-1090 — Sniffing Attacks  `DE03`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

### Severity: Low (54)

#### F-21 — Web Application Fingerprinting  `HA03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-28 — Encryption Brute Forcing  `CR05`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-34 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-67 — Web Application Fingerprinting  `HA03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-75 — Encryption Brute Forcing  `CR05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-81 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-145 — Web Application Fingerprinting  `HA03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-154 — Encryption Brute Forcing  `CR05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-160 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-176 — Encryption Brute Forcing  `CR05`

- **Element:** Keycloak data volume (keycloak-data) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-202 — Encryption Brute Forcing  `CR05`

- **Element:** SQLite run store (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-206 — Encryption Brute Forcing  `CR05`

- **Element:** targets.yaml (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-210 — Encryption Brute Forcing  `CR05`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-215 — Encryption Brute Forcing  `CR05`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-235 — Web Application Fingerprinting  `HA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-243 — Encryption Brute Forcing  `CR05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-249 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-264 — Encryption Brute Forcing  `CR05`

- **Element:** SpiderFoot scan database (spiderfoot-data volume) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-284 — Web Application Fingerprinting  `HA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-292 — Encryption Brute Forcing  `CR05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-298 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-329 — Web Application Fingerprinting  `HA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-337 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-343 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-358 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-378 — Web Application Fingerprinting  `HA03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-386 — Encryption Brute Forcing  `CR05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-392 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-424 — Web Application Fingerprinting  `HA03`

- **Element:** MISP (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-431 — Encryption Brute Forcing  `CR05`

- **Element:** MISP (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-437 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-452 — Encryption Brute Forcing  `CR05`

- **Element:** MISP backing stores (MariaDB, Redis) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-470 — Web Application Fingerprinting  `HA03`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-476 — Encryption Brute Forcing  `CR05`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-481 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-511 — Web Application Fingerprinting  `HA03`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-519 — Encryption Brute Forcing  `CR05`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-525 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-557 — Web Application Fingerprinting  `HA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-565 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-570 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-602 — Web Application Fingerprinting  `HA03`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-610 — Encryption Brute Forcing  `CR05`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-616 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-646 — Web Application Fingerprinting  `HA03`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-654 — Encryption Brute Forcing  `CR05`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-660 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-690 — Web Application Fingerprinting  `HA03`

- **Element:** MinIO (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-696 — Encryption Brute Forcing  `CR05`

- **Element:** MinIO (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-701 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** MinIO (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-730 — Web Application Fingerprinting  `HA03`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-736 — Encryption Brute Forcing  `CR05`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-741 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-757 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

### Severity: Very Low (15)

#### F-19 — Footprinting  `DS03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-65 — Footprinting  `DS03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-143 — Footprinting  `DS03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-233 — Footprinting  `DS03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-282 — Footprinting  `DS03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-327 — Footprinting  `DS03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-376 — Footprinting  `DS03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-422 — Footprinting  `DS03`

- **Element:** MISP (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-468 — Footprinting  `DS03`

- **Element:** MariaDB (MISP) (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-509 — Footprinting  `DS03`

- **Element:** Redis (MISP) (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-555 — Footprinting  `DS03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-600 — Footprinting  `DS03`

- **Element:** Elasticsearch (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-644 — Footprinting  `DS03`

- **Element:** Redis (OpenCTI) (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-688 — Footprinting  `DS03`

- **Element:** MinIO (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-728 — Footprinting  `DS03`

- **Element:** RabbitMQ (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.
